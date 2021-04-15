use rand::prelude::*;
use std::convert::TryFrom;
use std::sync::Arc;
use structopt::StructOpt;
use tokio::sync::RwLock;
use tonic::transport::Uri;
use tracing::*;

use futures::future::join_all;

mod driver;
use driver::DriverClient;
mod malicious_driver;
use malicious_driver::MaliciousDriverClient;

use eyre::eyre;
use json::JsonValue;

const NEIGHBOURHOOD_DISTANCE: usize = 100;
const TICK_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(30);

#[derive(StructOpt)]
struct Options {
    /// Location of the configuration file
    conf: String,

    /// How many times to drive
    #[structopt(short, long)]
    count: Option<usize>,
}

struct Conf {
    /// width x height
    dims: (usize, usize),

    /// Neighbourhood fault tolerance
    max_neighbourhood_faults: usize,

    /// Correct Clients
    correct: Vec<Uri>,

    /// Malicious Clients
    malicious: Vec<Uri>,
}

struct State {
    epoch: usize,

    /// Position of the correct nodes
    /// The indeces match indeces to Conf::correct
    ///
    grid: Vec<(usize, usize)>,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    // do not remove
    let _guard = tracing_utils::setup(env!("CARGO_PKG_NAME"))?;
    true_main().await
}

#[instrument]
async fn true_main() -> eyre::Result<()> {
    let options = Options::from_args();
    let conf = Conf::try_from(&json::parse(&std::fs::read_to_string(&options.conf)?)?)?;
    let state = Arc::new(RwLock::new(State::new(&conf)));

    if let Some(c) = options.count {
        for _ in 0..c {
            futures::join!(
                update_epoch(&conf, state.clone()),
                tokio::time::sleep(TICK_INTERVAL)
            )
            .0?;
        }
    } else {
        loop {
            futures::join!(
                update_epoch(&conf, state.clone()),
                tokio::time::sleep(TICK_INTERVAL)
            )
            .0?;
        }
    }

    Ok(())
}

async fn update_epoch(conf: &Conf, state: Arc<RwLock<State>>) -> eyre::Result<()> {
    async fn update_correct(
        idx: usize,
        uri: &Uri,
        conf: &Conf,
        state: Arc<RwLock<State>>,
    ) -> eyre::Result<()> {
        let client = DriverClient::new(uri.clone())?;
        let guard = state.read().await;
        let visible = guard.get_visible_neighbourhood(conf, idx);
        let reply = client
            .update_epoch(guard.epoch, guard.grid[idx], visible)
            .await?;
        info!(
            event = "We asked the server to do the thing and got a reply",
            ?reply
        );

        Ok(())
    }
    async fn update_malicious(
        idx: usize,
        uri: &Uri,
        conf: &Conf,
        state: Arc<RwLock<State>>,
    ) -> eyre::Result<()> {
        let client = MaliciousDriverClient::new(uri.clone())?;
        let guard = state.read().await;
        let corrects = guard.get_correct_clients(conf);
        let reply = client
            .update_epoch(guard.epoch, corrects, conf.get_malicious_neighbours(idx))
            .await?;
        info!(
            event = "We asked the server to do the thing and got a reply",
            ?reply
        );

        Ok(())
    }

    let mut c_futs = Vec::with_capacity(conf.size());
    let mut m_futs = Vec::with_capacity(conf.size());
    for (idx, uri) in conf.correct.iter().enumerate() {
        c_futs.push(update_correct(idx, uri, conf, state.clone()))
    }

    for (idx, uri) in conf.malicious.iter().enumerate() {
        m_futs.push(update_malicious(idx, uri, conf, state.clone()))
    }

    let (c_errs, m_errs) = futures::join!(join_all(c_futs), join_all(m_futs));
    if let Some(e) = c_errs.into_iter().find(|r| r.is_err()) {
        e?
    }
    if let Some(e) = m_errs.into_iter().find(|r| r.is_err()) {
        e?
    }

    state.write().await.advance(conf);
    Ok(())
}

/// Defines whether a and b are in the same neighbourhood (ie: should be able to communicate)
/// This is defined by the Manhattan distance between the nodes.
/// The Manhattan distance (also refered to grid distance or L1 distance) is just the sum of the
/// components in the difference vector.
///
/// Other interesting distances could be the Euclidean distance (plane distance or L2 distance) or,
/// more generally, the Ln distance.
///
/// The Ln distance is defined as the nth-root of the sum of the nth powers of the components of
/// the difference vector.
///
fn neighbourhood(a: &(usize, usize), b: &(usize, usize)) -> bool {
    (((a.0 as isize - b.0 as isize) + (a.1 as isize - b.1 as isize)).abs() as usize)
        < NEIGHBOURHOOD_DISTANCE
}

impl State {
    fn new(conf: &Conf) -> Self {
        let mut rng = thread_rng();
        State {
            epoch: 0,
            grid: (0..conf.n_correct())
                .map(|_| (rng.gen_range(0..conf.dims.0), rng.gen_range(0..conf.dims.1)))
                .collect(),
        }
    }

    /// Generate neighbourhoods for a correct client.
    /// An neighbourhood is a vector of (Uri, x, y) tuples.
    ///
    /// Here neighbourhood is definded by the `neighbourhood` function
    /// (it could be further abstracted, but there is no need)
    ///
    fn get_visible_neighbourhood(&self, conf: &Conf, idx: usize) -> Vec<Uri> {
        fn fill_neighbourhood(mut neighbourhood: Vec<Uri>, conf: &Conf) -> Vec<Uri> {
            let mut rng = thread_rng();
            let n_malicious: usize = rng.gen_range(0..(conf.max_neighbourhood_faults + 1));
            neighbourhood.reserve(n_malicious);
            for uri in conf.malicious.choose_multiple(&mut rng, n_malicious) {
                neighbourhood.push(uri.clone())
            }

            neighbourhood
        }
        fill_neighbourhood(
            self.grid
                .iter()
                .enumerate()
                .filter(|(_, a)| neighbourhood(&self.grid[idx], a))
                .map(|(i, _)| conf.correct[i].clone())
                .collect(),
            conf,
        )
    }

    /// Generate the full set of correct Uri's, with positions.
    /// This is what the malicious nodes receive.
    fn get_correct_clients(&self, conf: &Conf) -> Vec<(Uri, (usize, usize))> {
        self.grid
            .iter()
            .enumerate()
            .map(|(idx, p)| (conf.correct[idx].clone(), *p))
            .collect()
    }

    /// Advance the epoch
    fn advance(&mut self, conf: &Conf) {
        let mut rng = thread_rng();
        self.epoch += 1;
        self.grid = (0..conf.n_correct())
            .map(|_| (rng.gen_range(0..conf.dims.0), rng.gen_range(0..conf.dims.1)))
            .collect()
    }
}

impl Conf {
    /// number of malicious nodes
    fn n_malicious(&self) -> usize {
        self.malicious.len()
    }

    /// number of correct nodes
    fn n_correct(&self) -> usize {
        self.correct.len()
    }

    /// number of nodes
    fn size(&self) -> usize {
        self.n_malicious() + self.n_correct()
    }

    /// Get all malicious nodes except the node itself
    fn get_malicious_neighbours(&self, node_idx: usize) -> Vec<Uri> {
        self.malicious
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != node_idx)
            .map(|(_, v)| v)
            .cloned()
            .collect()
    }
}

impl TryFrom<&JsonValue> for Conf {
    type Error = eyre::Report;

    fn try_from(json: &JsonValue) -> eyre::Result<Conf> {
        if !json.has_key("width") {
            return Err(eyre!("configuration requires a width"));
        }
        if !json.has_key("height") {
            return Err(eyre!("configuration requires a height"));
        }
        if !json.has_key("max_neighbourhood_faults") {
            return Err(eyre!("configuration requires the maximum number of faults in the neighbourhood of a node"));
        }
        if !json.has_key("clients") {
            return Err(eyre!("configuration requires a list of clients"));
        }

        if json["width"].as_usize().is_none() {
            return Err(eyre!("width needs to be an unsigned integer"));
        }
        if json["height"].as_usize().is_none() {
            return Err(eyre!("height needs to be an unsigned integer"));
        }
        let dims = (
            json["width"].as_usize().unwrap(),
            json["height"].as_usize().unwrap(),
        );

        if json["max_neighbourhood_faults"].as_usize().is_none() {
            return Err(eyre!(
                "max_neighbourhood_faults needs to be an unsigned integer"
            ));
        }
        let max_neighbourhood_faults = json["max_neighbourhood_faults"].as_usize().unwrap();

        if !json["clients"].is_array() {
            return Err(eyre!("clients needs to be an array"));
        }

        let mut correct = Vec::with_capacity(json["clients"].len());
        let mut malicious = Vec::with_capacity(json["clients"].len());
        for c in json["clients"].members() {
            if !c.has_key("uri") {
                return Err(eyre!("client requires an URI"));
            }
            if !c["uri"].is_string() {
                return Err(eyre!("client URI must be a string"));
            }
            if !c.has_key("malicious") {
                return Err(eyre!("client requires malicious flag"));
            }
            if !c["malicious"].is_boolean() {
                return Err(eyre!("malicious flag must be a bool"));
            }

            let uri: Uri = c["uri"].as_str().unwrap().parse()?;
            if c["malicious"].as_bool().unwrap() {
                malicious.push(uri);
            } else {
                correct.push(uri);
            }
        }

        Ok(Conf {
            dims,
            max_neighbourhood_faults,
            malicious,
            correct,
        })
    }
}

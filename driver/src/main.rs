use rand::prelude::*;
use std::sync::Arc;
use std::{collections::HashMap, convert::TryFrom};
use structopt::StructOpt;
use tokio::sync::RwLock;
use tonic::transport::Uri;
use tracing::*;

use futures::future::join_all;

use model::keys::EntityId;

mod driver;
use driver::DriverClient;
mod malicious_driver;
use malicious_driver::MaliciousDriverClient;
use model::neighbourhood::are_neighbours;
use model::Position;

use eyre::eyre;
use json::JsonValue;

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
    correct: Vec<EntityId>,

    /// Malicious Clients
    malicious: Vec<(EntityId, u32)>,

    /// Mapping of IDs to URIs
    id_to_uri: HashMap<EntityId, Uri>,
}

struct State {
    epoch: usize,

    /// Position of the correct nodes
    /// The indeces match indeces to Conf::correct
    ///
    grid: Vec<Position>,
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

    initial_config(&conf).await?;

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
            .update_epoch(
                guard.epoch,
                guard.grid[idx],
                visible,
                conf.max_neighbourhood_faults,
            )
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
        let (malicious, type_code) = conf.get_malicious_neighbours(idx);
        let reply = client
            .update_epoch(
                guard.epoch,
                corrects,
                malicious,
                conf.max_neighbourhood_faults,
                type_code,
            )
            .await?;
        info!(
            event = "We asked the server to do the thing and got a reply",
            ?reply
        );

        Ok(())
    }

    let mut c_futs = Vec::with_capacity(conf.size());
    let mut m_futs = Vec::with_capacity(conf.size());
    for (idx, uri) in conf
        .correct
        .iter()
        .map(|&entity_id| conf.id_to_uri(entity_id))
        .enumerate()
    {
        c_futs.push(update_correct(idx, uri, conf, state.clone()))
    }

    for (idx, uri) in conf
        .malicious
        .iter()
        .map(|(entity_id, _)| conf.id_to_uri(*entity_id))
        .enumerate()
    {
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

impl State {
    fn new(conf: &Conf) -> Self {
        let mut rng = thread_rng();
        State {
            epoch: 0,
            grid: (0..conf.n_correct())
                .map(|_| {
                    Position(
                        rng.gen_range(0..conf.dims.0 as u64),
                        rng.gen_range(0..conf.dims.1 as u64),
                    )
                })
                .collect(),
        }
    }

    /// Generate neighbourhoods for a correct client.
    /// A neighbourhood is a vector of (EntityId, x, y) tuples.
    ///
    /// Here neighbourhood is definded by the `neighbourhood` function
    /// (it could be further abstracted, but there is no need)
    ///
    fn get_visible_neighbourhood(&self, conf: &Conf, idx: usize) -> Vec<EntityId> {
        /// Fill a neighbourhood with some malicious nodes
        /// (making sure they never exceed the incorrectness limit)
        ///
        fn fill_neighbourhood(mut neighbourhood: Vec<EntityId>, conf: &Conf) -> Vec<EntityId> {
            let mut rng = thread_rng();
            let n_malicious: usize = rng.gen_range(0..(conf.max_neighbourhood_faults + 1));
            neighbourhood.reserve(n_malicious);
            for (entity_id, _) in conf.malicious.choose_multiple(&mut rng, n_malicious) {
                neighbourhood.push(entity_id.clone())
            }

            neighbourhood
        }
        fill_neighbourhood(
            self.grid
                .iter()
                .enumerate()
                .filter(|(_, a)| are_neighbours(&self.grid[idx], a))
                .map(|(i, _)| conf.correct[i].clone())
                .collect(),
            conf,
        )
    }

    /// Generate the full set of correct EntityId's, with positions.
    /// This is what the malicious nodes receive.
    fn get_correct_clients(&self, conf: &Conf) -> Vec<(EntityId, Position)> {
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
            .map(|_| {
                Position(
                    rng.gen_range(0..conf.dims.0 as u64),
                    rng.gen_range(0..conf.dims.1 as u64),
                )
            })
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
    /// Also returns the node's type code
    /// Panic: if node_idx is not a valid index
    fn get_malicious_neighbours(&self, node_idx: usize) -> (Vec<EntityId>, u32) {
        let neigh = self
            .malicious
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != node_idx)
            .map(|(_, v)| v.0)
            .collect();
        let type_code = self
            .malicious
            .iter()
            .enumerate()
            .find(|(i, _)| *i == node_idx)
            .map(|(_, v)| v.1)
            .unwrap();
        (neigh, type_code)
    }

    fn id_to_uri(&self, id: EntityId) -> &Uri {
        &self.id_to_uri[&id]
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
        let mut id_to_uri = HashMap::new();
        for c in json["clients"].members() {
            if !c.has_key("entity_id") {
                return Err(eyre!("client requires an entity_id"));
            }
            if !c["entity_id"].is_number() {
                return Err(eyre!("client entity_id must be a string"));
            }
            if !c.has_key("uri") {
                return Err(eyre!("client requires an uri"));
            }
            if !c["uri"].is_string() {
                return Err(eyre!("client uri must be a string"));
            }

            let entity_id: EntityId = c["entity_id"].as_u32().unwrap();
            if c.has_key("malicious") {
                if !c["malicious"].is_string() {
                    return Err(eyre!("malicious flag must be a string"));
                }
                let m_type = c["malicious"].as_str().unwrap();
                let type_code = match m_type {
                    "honest_omnipresent" | "HbO" => 0,
                    "poor_verifier" | "PV" => 1,
                    "teleporter" | "T" => 2,
                    _ => return Err(eyre!("`malicious` must be one of\n - honest_omnipresent | HbO\n - poor_verifier | PV\n - teleporter | T"))

                };
                malicious.push((entity_id, type_code));
            } else {
                correct.push(entity_id);
            }

            let uri: Uri = c["uri"].as_str().unwrap().parse()?;
            id_to_uri.insert(entity_id, uri);
        }

        Ok(Conf {
            dims,
            max_neighbourhood_faults,
            malicious,
            correct,
            id_to_uri,
        })
    }
}

async fn initial_config(conf: &Conf) -> eyre::Result<()> {
    for uri in conf
        .correct
        .iter()
        .map(|&entity_id| conf.id_to_uri(entity_id))
    {
        let client = DriverClient::new(uri.clone())?;
        client.initial_config(&conf.id_to_uri).await?;

        debug!(event = "We sent the client the id to uri map");
    }
    for uri in conf
        .malicious
        .iter()
        .map(|(entity_id, _)| conf.id_to_uri(*entity_id))
    {
        let client = MaliciousDriverClient::new(uri.clone())?;
        client.initial_config(&conf.id_to_uri).await?;

        debug!(event = "We sent the client the id to uri map");
    }
    info!("We sent all clients the id to uri map");
    Ok(())
}

use rand::prelude::*;
use std::sync::Arc;
use std::{collections::HashMap, convert::TryFrom};
use tokio::sync::RwLock;
use tonic::transport::Uri;
use tracing::*;

use futures::future::join_all;

use model::keys::EntityId;

mod correct_user_driver;
use correct_user_driver::CorrectUserDriver;
mod malicious_user_driver;
use malicious_user_driver::MaliciousUserDriver;
mod correct_server_driver;
use correct_server_driver::CorrectServerDriver;
use model::neighbourhood::are_neighbours;
use model::Position;

use eyre::eyre;
use json::JsonValue;

#[derive(Clone)]
pub struct Conf {
    /// width x height
    pub dims: (usize, usize),

    /// Neighbourhood fault tolerance
    pub max_neighbourhood_faults: usize,

    /// Servers
    pub correct_servers: Vec<EntityId>,

    /// Correct Clients
    pub correct_users: Vec<EntityId>,

    /// Malicious Clients
    pub malicious_users: Vec<(EntityId, u32)>,

    /// Mapping of IDs to URIs
    pub id_to_uri: HashMap<EntityId, Uri>,
}

struct State {
    epoch: u64,

    /// Position of the correct nodes
    /// The indeces match indeces to Conf::correct
    ///
    grid: Vec<Position>,
}

pub struct Driver {
    state: Arc<RwLock<State>>,
    config: Conf,
}

impl Driver {
    pub async fn new(config: Conf) -> eyre::Result<Driver> {
        let driver = Driver {
            state: Arc::new(RwLock::new(State::new(&config))),
            config,
        };

        driver.initial_setup().await?;

        Ok(driver)
    }

    pub async fn tick(&self) -> eyre::Result<()> {
        let cs_futs: Vec<_> = self
            .config
            .correct_servers
            .iter()
            .map(|id| self.update_correct_server(*id))
            .collect();

        let cu_futs: Vec<_> = self
            .config
            .correct_users
            .iter()
            .map(|&entity_id| self.config.id_to_uri(entity_id))
            .enumerate()
            .map(|(idx, uri)| self.update_correct_user(idx, uri))
            .collect();

        let mu_futs: Vec<_> = self
            .config
            .malicious_users
            .iter()
            .map(|(entity_id, _)| self.config.id_to_uri(*entity_id))
            .enumerate()
            .map(|(idx, uri)| self.update_malicious_user(idx, uri))
            .collect();

        let (cs_errs, cu_errs, mu_errs) =
            tokio::join!(join_all(cs_futs), join_all(cu_futs), join_all(mu_futs));
        if let Some(e) = cs_errs.into_iter().find(|r| r.is_err()) {
            e?
        }
        if let Some(e) = cu_errs.into_iter().find(|r| r.is_err()) {
            e?
        }
        if let Some(e) = mu_errs.into_iter().find(|r| r.is_err()) {
            e?
        }

        self.state.write().await.advance(&self.config);
        Ok(())
    }

    pub async fn current_epoch(&self) -> u64 {
        self.state.read().await.epoch
    }

    #[instrument(skip(self))]
    async fn initial_setup(&self) -> eyre::Result<()> {
        for id in &self.config.correct_servers {
            debug!("Sending initial config to correct server {}", id);
            self.update_correct_server(*id).await?;
        }

        for uri in self
            .config
            .correct_users
            .iter()
            .map(|&entity_id| self.config.id_to_uri(entity_id))
        {
            debug!("Sending initial config to correct user at {}", &uri);
            let client = CorrectUserDriver::new(uri.clone())?;
            client.initial_config(&self.config.id_to_uri).await?;
        }

        for uri in self
            .config
            .malicious_users
            .iter()
            .map(|(entity_id, _)| self.config.id_to_uri(*entity_id))
        {
            debug!("Sending initial config to malicious user at {}", &uri);
            let client = MaliciousUserDriver::new(uri.clone())?;
            client.initial_config(&self.config.id_to_uri).await?;
        }

        info!("Initial setup complete");
        Ok(())
    }

    #[instrument(skip(self))]
    async fn update_correct_server(&self, id: EntityId) -> eyre::Result<()> {
        let uri = self.config.id_to_uri(id);
        let client = CorrectServerDriver::new(uri.clone())?;
        let state = self.state.read().await;
        let reply = client
            .update_config(state.epoch, self.config.max_neighbourhood_faults)
            .await?;
        info!(
            event = "We asked the server to do the thing and got a reply",
            ?reply
        );

        Ok(())
    }

    #[instrument(skip(self))]
    async fn update_correct_user(&self, idx: usize, uri: &Uri) -> eyre::Result<()> {
        let client = CorrectUserDriver::new(uri.clone())?;
        let state = self.state.read().await;
        let visible = state.get_visible_neighbourhood(&self.config, idx);
        let reply = client
            .update_epoch(
                state.epoch,
                state.grid[idx],
                visible,
                self.config.max_neighbourhood_faults,
            )
            .await?;
        info!(
            event = "We asked the server to do the thing and got a reply",
            ?reply
        );

        Ok(())
    }

    #[instrument(skip(self))]
    async fn update_malicious_user(&self, idx: usize, uri: &Uri) -> eyre::Result<()> {
        let client = MaliciousUserDriver::new(uri.clone())?;
        let state = self.state.read().await;
        let corrects = state.get_correct_users(&self.config);
        let (malicious, type_code) = self.config.get_malicious_neighbours(idx);
        let reply = client
            .update_epoch(
                state.epoch,
                corrects,
                malicious,
                self.config.max_neighbourhood_faults,
                type_code,
            )
            .await?;
        info!(
            event = "We asked the server to do the thing and got a reply",
            ?reply
        );

        Ok(())
    }
}

impl State {
    fn new(conf: &Conf) -> Self {
        let mut rng = thread_rng();
        State {
            epoch: 0,
            grid: (0..conf.n_correct_users())
                .map(|_| {
                    Position(
                        rng.gen_range(0..conf.dims.0 as u64),
                        rng.gen_range(0..conf.dims.1 as u64),
                    )
                })
                .collect(),
        }
    }

    /// Generate neighbourhoods for a correct user.
    /// A neighbourhood is a vector of (EntityId, x, y) tuples.
    ///
    /// Here neighbourhood is definded by the `neighbourhood` function
    /// (it could be further abstracted, but there is no need)
    ///
    fn get_visible_neighbourhood(&self, conf: &Conf, idx: usize) -> Vec<EntityId> {
        /// Fill a neighbourhood with some malicious users
        /// (making sure they never exceed the incorrectness limit)
        ///
        fn fill_neighbourhood(mut neighbourhood: Vec<EntityId>, conf: &Conf) -> Vec<EntityId> {
            let mut rng = thread_rng();
            let n_malicious: usize = rng.gen_range(0..(conf.max_neighbourhood_faults + 1));
            neighbourhood.reserve(n_malicious);
            for (entity_id, _) in conf.malicious_users.choose_multiple(&mut rng, n_malicious) {
                neighbourhood.push(*entity_id)
            }

            neighbourhood
        }
        fill_neighbourhood(
            self.grid
                .iter()
                .enumerate()
                .filter(|(_, a)| are_neighbours(&self.grid[idx], a))
                .map(|(i, _)| conf.correct_users[i])
                .collect(),
            conf,
        )
    }

    /// Generate the full set of correct EntityId's, with positions.
    /// This is what the malicious nodes receive.
    fn get_correct_users(&self, conf: &Conf) -> Vec<(EntityId, Position)> {
        self.grid
            .iter()
            .enumerate()
            .map(|(idx, p)| (conf.correct_users[idx], *p))
            .collect()
    }

    /// Advance the epoch
    fn advance(&mut self, conf: &Conf) {
        let mut rng = thread_rng();
        self.epoch += 1;
        self.grid = (0..conf.n_correct_users())
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
    /// number of correct users
    fn n_correct_users(&self) -> usize {
        self.correct_users.len()
    }

    /// Get all malicious users except the user itself
    /// Also returns the users's type code
    /// Panic: if user_idx is not a valid index
    fn get_malicious_neighbours(&self, user_idx: usize) -> (Vec<EntityId>, u32) {
        let neigh = self
            .malicious_users
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != user_idx)
            .map(|(_, v)| v.0)
            .collect();
        let type_code = self
            .malicious_users
            .iter()
            .enumerate()
            .find(|(i, _)| *i == user_idx)
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
        if !json.has_key("users") {
            return Err(eyre!("configuration requires a list of users"));
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

        if !json["users"].is_array() {
            return Err(eyre!("users needs to be an array"));
        }

        let mut correct_users = Vec::with_capacity(json["users"].len());
        let mut malicious_users = Vec::with_capacity(json["users"].len());
        let mut id_to_uri = HashMap::new();
        for c in json["users"].members() {
            if !c.has_key("entity_id") {
                return Err(eyre!("user requires an entity_id"));
            }
            if !c["entity_id"].is_number() {
                return Err(eyre!("user entity_id must be a string"));
            }
            if !c.has_key("uri") {
                return Err(eyre!("user requires an uri"));
            }
            if !c["uri"].is_string() {
                return Err(eyre!("user uri must be a string"));
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
                malicious_users.push((entity_id, type_code));
            } else {
                correct_users.push(entity_id);
            }

            let uri: Uri = c["uri"].as_str().unwrap().parse()?;
            id_to_uri.insert(entity_id, uri);
        }

        let mut correct_servers = Vec::with_capacity(json["servers"].len());
        for s in json["servers"].members() {
            if !s.has_key("entity_id") {
                return Err(eyre!("server requires an entity_id"));
            }
            if !s["entity_id"].is_number() {
                return Err(eyre!("server entity_id must be a string"));
            }
            if !s.has_key("uri") {
                return Err(eyre!("server requires an uri"));
            }
            if !s["uri"].is_string() {
                return Err(eyre!("server uri must be a string"));
            }

            let entity_id: EntityId = s["entity_id"].as_u32().unwrap();
            let uri: Uri = s["uri"].as_str().unwrap().parse()?;
            correct_servers.push(entity_id);
            id_to_uri.insert(entity_id, uri);
        }

        Ok(Conf {
            dims,
            max_neighbourhood_faults,
            correct_servers,
            malicious_users,
            correct_users,
            id_to_uri,
        })
    }
}

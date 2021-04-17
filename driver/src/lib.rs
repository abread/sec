use rand::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::Uri;
use tracing::*;

use futures::stream::{FuturesUnordered, StreamExt};
use futures::FutureExt;

use model::keys::EntityId;
use model::neighbourhood::are_neighbours;
use model::Position;

mod drivers;
use drivers::*;

mod conf;
pub use conf::Conf;

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
        let cs_futs = self
            .config
            .correct_servers
            .iter()
            .map(|id| self.update_correct_server(*id).boxed());

        let cu_futs = self
            .config
            .correct_users
            .iter()
            .map(|&entity_id| self.config.id_to_uri(entity_id))
            .enumerate()
            .map(|(idx, uri)| self.update_correct_user(idx, uri).boxed());

        let mu_futs = self
            .config
            .malicious_users
            .iter()
            .map(|(entity_id, _)| self.config.id_to_uri(*entity_id))
            .enumerate()
            .map(|(idx, uri)| self.update_malicious_user(idx, uri).boxed());

        let mut futs: FuturesUnordered<_> = cs_futs.chain(cu_futs).chain(mu_futs).collect();

        while let Some(res) = futs.next().await {
            if res.is_err() {
                res?;
            }
        }

        self.state.write().await.advance(&self.config);
        Ok(())
    }

    pub async fn current_epoch(&self) -> u64 {
        self.state.read().await.epoch
    }

    #[instrument(skip(self))]
    async fn initial_setup(&self) -> eyre::Result<()> {
        let cs_futs = self.config.correct_servers.iter().map(|id| {
            async move {
                debug!("Sending initial config to correct server {}", id);
                self.update_correct_server(*id).await
            }
            .boxed()
        });

        let cu_futs = self
            .config
            .correct_users
            .iter()
            .map(|&entity_id| self.config.id_to_uri(entity_id))
            .map(|uri| {
                async move {
                    debug!("Sending initial config to correct user at {}", &uri);
                    let client = CorrectUserDriver::new(uri.clone())?;
                    client
                        .initial_config(&self.config.id_to_uri)
                        .await
                        .map(|_| ())
                        .map_err(eyre::Report::from)
                }
                .boxed()
            });

        let mu_futs = self
            .config
            .malicious_users
            .iter()
            .map(|(entity_id, _)| self.config.id_to_uri(*entity_id))
            .map(|uri| {
                async move {
                    debug!("Sending initial config to malicious user at {}", &uri);
                    let client = MaliciousUserDriver::new(uri.clone())?;
                    client
                        .initial_config(&self.config.id_to_uri)
                        .await
                        .map(|_| ())
                        .map_err(eyre::Report::from)
                }
                .boxed()
            });

        let mut futs: FuturesUnordered<_> = cs_futs.chain(cu_futs).chain(mu_futs).collect();

        while let Some(res) = futs.next().await {
            if res.is_err() {
                res?;
            }
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

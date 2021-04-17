use tokio::sync::RwLock;
use tracing::*;

use futures::stream::{FuturesUnordered, StreamExt};
use futures::FutureExt;

use model::keys::EntityId;

mod drivers;
use drivers::*;

mod conf;
pub use conf::Conf;

mod state;
pub use state::State;

pub struct Driver {
    state: RwLock<State>,
    config: Conf,
}

impl Driver {
    pub async fn new(config: Conf) -> eyre::Result<Driver> {
        let driver = Driver {
            state: RwLock::new(State::new(&config)),
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
            .map(|id| self.update_correct_user(*id).boxed());

        let mu_futs = self
            .config
            .malicious_users
            .iter()
            .map(|(id, _)| self.update_malicious_user(*id).boxed());

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
        self.state.read().await.epoch()
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
        let uri = self.config.id_to_uri(id).clone();
        let client = CorrectServerDriver::new(uri)?;
        let state = self.state.read().await;

        let reply = client
            .update_config(state.epoch(), self.config.max_neighbourhood_faults)
            .await?;
        info!(
            event = "We asked the server to do the thing and got a reply",
            ?reply
        );

        Ok(())
    }

    #[instrument(skip(self))]
    async fn update_correct_user(&self, id: EntityId) -> eyre::Result<()> {
        let uri = self.config.id_to_uri(id).clone();
        let client = CorrectUserDriver::new(uri)?;
        let state = self.state.read().await;

        let visible = state.get_visible_neighbourhood(&self.config, id);
        let reply = client
            .update_epoch(
                state.epoch(),
                state.position_of(id),
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
    async fn update_malicious_user(&self, id: EntityId) -> eyre::Result<()> {
        let uri = self.config.id_to_uri(id).clone();
        let client = MaliciousUserDriver::new(uri)?;
        let state = self.state.read().await;

        let corrects = state.get_correct_users();
        let (malicious, type_code) = self.config.get_malicious_neighbours(id);

        let reply = client
            .update_epoch(
                state.epoch(),
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

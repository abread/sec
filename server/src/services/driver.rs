use std::sync::Arc;

use protos::driver::correct_server_driver_server::CorrectServerDriver;
use protos::driver::ServerConfigUpdate;
use protos::util::Empty;
use tokio::sync::RwLock;
use tonic::{Request, Response};

use tracing::*;
use tracing_utils::instrument_tonic_service;

#[derive(Default)]
pub struct Driver {
    state: Arc<RwLock<ServerConfig>>,
}

#[derive(Debug)]
pub struct ServerConfig {
    pub epoch: u64,

    /// f', maximum number of byzantine users in a region
    ///
    /// See [model::PositionProof] for more information.
    pub max_neigh_faults: usize,
}

impl Driver {
    pub fn state(&self) -> Arc<RwLock<ServerConfig>> {
        Arc::clone(&self.state)
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            epoch: 0,
            max_neigh_faults: usize::MAX,
        }
    }
}

type GrpcResult<T> = Result<Response<T>, tonic::Status>;

#[instrument_tonic_service]
#[tonic::async_trait]
impl CorrectServerDriver for Driver {
    #[instrument(skip(self))]
    async fn update_config(&self, request: Request<ServerConfigUpdate>) -> GrpcResult<Empty> {
        let request = request.into_inner();

        let mut state = self.state.write().await;
        state.epoch = request.new_epoch;
        state.max_neigh_faults = request.neighbour_faults as usize;

        info!(event = "New state received", ?state);

        Ok(Response::new(Empty {}))
    }
}

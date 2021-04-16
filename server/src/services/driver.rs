use std::sync::Arc;

use protos::util::Empty;
use protos::driver::ServerConfigUpdate;
use protos::driver::server_driver_server::ServerDriver as ServerDriverSvcTrait;
use tokio::sync::RwLock;
use tonic::{Request, Response};

use tracing_utils::instrument_tonic_service;
use tracing::*;

#[derive(Default)]
pub struct ServerDriver {
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

impl ServerDriver {
    pub fn new(max_neigh_faults: usize) -> Self {
        ServerDriver {
            state: Arc::new(RwLock::new(ServerConfig {
                epoch: 0,
                max_neigh_faults,
            }))
        }
    }

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
impl ServerDriverSvcTrait for ServerDriver {
    #[instrument(skip(self))]
    async fn update_config(&self, request: Request<ServerConfigUpdate>) -> GrpcResult<Empty> {
        let request= request.into_inner();

        let mut state = self.state.write().await;
        state.epoch = request.new_epoch;
        state.max_neigh_faults = request.max_faults as usize;

        info!(event="New state received", ?state);

        Ok(Response::new(Empty{}))
    }
}
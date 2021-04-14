use protos::driver::malicious_driver_server::MaliciousDriver;
use protos::driver::MaliciousEpochUpdateRequest;
use protos::util::Empty;

use tonic::{Request, Response, Status};
use tracing::info;
use tracing_utils::instrument_tonic_service;

use crate::state::{MaliciousClientState, Neighbour};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug)]
pub struct MaliciousDriverService {
    state: Arc<RwLock<MaliciousClientState>>,
}

impl MaliciousDriverService {
    pub fn new(state: Arc<RwLock<MaliciousClientState>>) -> Self {
        MaliciousDriverService { state }
    }

    async fn update_state(
        &self,
        epoch: usize,
        correct: Vec<Neighbour>,
        malicious: Vec<tonic::transport::Uri>,
    ) {
        self.state.write().await.update(epoch, correct, malicious);
    }
}

type GrpcResult<T> = Result<Response<T>, Status>;

#[instrument_tonic_service]
#[tonic::async_trait]
impl MaliciousDriver for MaliciousDriverService {
    async fn update_epoch(
        &self,
        request: Request<MaliciousEpochUpdateRequest>,
    ) -> GrpcResult<Empty> {
        let message = request.into_inner();
        self.update_state(
            message.new_epoch as usize,
            message
                .correct_neighbours
                .into_iter()
                .map(Neighbour::from_proto)
                .collect(),
            message
                .malicious_neighbour_uris
                .into_iter()
                .map(|s| s.parse().unwrap())
                .collect(),
        )
        .await;
        info!("Updated the local state");

        // TODO: think of malicious things to do
        info!("Working hard to do the thing...");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        info!("Thing done");
        Ok(Response::new(Empty {}))
    }
}

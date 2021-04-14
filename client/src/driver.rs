use protos::driver::driver_server::Driver;
use protos::driver::EpochUpdateRequest;
use protos::util::Empty;

use tonic::transport::Uri;
use tonic::{Request, Response, Status};
use tracing::info;
use tracing_utils::instrument_tonic_service;

use crate::state::CorrectClientState;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug)]
pub struct DriverService {
    state: Arc<RwLock<CorrectClientState>>,
}

impl DriverService {
    pub fn new(state: Arc<RwLock<CorrectClientState>>) -> Self {
        DriverService { state }
    }

    async fn update_state(&self, epoch: usize, position: (usize, usize), neighbours: Vec<Uri>) {
        self.state.write().await.update(epoch, position, neighbours);
    }
}

type GrpcResult<T> = Result<Response<T>, Status>;

#[instrument_tonic_service]
#[tonic::async_trait]
impl Driver for DriverService {
    async fn update_epoch(&self, request: Request<EpochUpdateRequest>) -> GrpcResult<Empty> {
        let message = request.into_inner();
        let position = message.new_position.unwrap();
        self.update_state(
            message.new_epoch as usize,
            (position.x as usize, position.y as usize),
            message
                .visible_neighbour_uris
                .into_iter()
                .map(|s| s.parse::<Uri>().unwrap())
                .collect(),
        )
        .await;
        info!("Updated the local state");

        // TODO: ask for proofs to everyone in neighbourhood
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        info!("Thing done");
        Ok(Response::new(Empty {}))
    }
}

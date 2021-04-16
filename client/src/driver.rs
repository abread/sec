use model::{keys::EntityId, Position};
use protos::driver::EpochUpdateRequest;
use protos::driver::{driver_server::Driver, InitialConfigRequest};
use protos::util::Empty;

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

    async fn update_state(
        &self,
        epoch: u64,
        position: Position,
        neighbours: Vec<EntityId>,
        max_faults: u64,
    ) {
        self.state
            .write()
            .await
            .update(epoch, position, neighbours, max_faults);
    }
}

type GrpcResult<T> = Result<Response<T>, Status>;

#[instrument_tonic_service]
#[tonic::async_trait]
impl Driver for DriverService {
    async fn initial_config(&self, request: Request<InitialConfigRequest>) -> GrpcResult<Empty> {
        let message = request.into_inner();
        self.state.write().await.add_mappings(message.id_uri_map);
        Ok(Response::new(Empty {}))
    }

    async fn update_epoch(&self, request: Request<EpochUpdateRequest>) -> GrpcResult<Empty> {
        let message = request.into_inner();
        let position = message.new_position.unwrap();
        let position = Position(position.x, position.y);
        self.update_state(
            message.new_epoch,
            position,
            message.visible_neighbour_ids,
            message.max_faults,
        )
        .await;
        info!("Updated the local state");

        // TODO: ask for proofs to everyone in neighbourhood
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        info!("Thing done");
        Ok(Response::new(Empty {}))
    }
}

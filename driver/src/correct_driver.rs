use std::collections::HashMap;

use model::keys::EntityId;
use model::Position;
use protos::driver::driver_client::DriverClient as GrpcDriverClient;
use protos::driver::EpochUpdateRequest;
use protos::driver::InitialConfigRequest;
use protos::util::Position as GrpcPosition;
use tonic::transport::{Channel, Uri};
use tonic::{Response, Status};
use tracing_utils::Request;

use thiserror::Error;
use tracing::instrument;

#[derive(Debug)]
pub struct CorrectDriverClient(Channel);

#[derive(Debug, Error)]
pub enum DriverClientError {
    #[error("Server sent unexpected status")]
    UnexpectedStatus(#[from] Status),

    #[error("Error creating remote")]
    InitializationError(#[source] tonic::transport::Error),
}

type Result<T> = std::result::Result<T, DriverClientError>;

impl CorrectDriverClient {
    pub fn new(uri: Uri) -> Result<Self> {
        let channel = Channel::builder(uri)
            .connect_lazy()
            .map_err(DriverClientError::InitializationError)?;

        Ok(CorrectDriverClient(channel))
    }

    #[instrument]
    pub async fn update_epoch(
        &self,
        epoch: u64,
        pos: Position,
        neighbours: Vec<EntityId>,
        max_faults: usize,
    ) -> Result<Response<protos::util::Empty>> {
        let mut client = GrpcDriverClient::new(self.0.clone());
        let request = Request!(EpochUpdateRequest {
            new_epoch: epoch,
            new_position: Some(GrpcPosition { x: pos.0, y: pos.1 }),
            visible_neighbour_ids: neighbours,
            max_faults: max_faults as u64
        });

        client.update_epoch(request).await.map_err(|e| e.into())
    }

    #[instrument]
    pub async fn initial_config(
        &self,
        id_to_uri: &HashMap<EntityId, Uri>,
    ) -> Result<Response<protos::util::Empty>> {
        let mut client = GrpcDriverClient::new(self.0.clone());
        let request = Request!(InitialConfigRequest {
            id_uri_map: id_to_uri.iter().map(|(&k, v)| (k, v.to_string())).collect(),
        });

        client.initial_config(request).await.map_err(|e| e.into())
    }
}

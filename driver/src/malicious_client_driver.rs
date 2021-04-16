use model::Position;
use std::collections::HashMap;

use model::keys::EntityId;
use protos::driver::malicious_driver_client::MaliciousDriverClient as GrpcMaliciousDriverClient;
use protos::driver::InitialConfigRequest;
use protos::driver::MaliciousEpochUpdateRequest;
use protos::util::Neighbour;
use protos::util::Position as GrpcPosition;
use tonic::transport::{Channel, Uri};
use tonic::{Response, Status};
use tracing_utils::Request;

use thiserror::Error;
use tracing::instrument;

#[derive(Debug)]
pub struct MaliciousClientDriver(Channel);

#[derive(Debug, Error)]
pub enum MaliciousClientDriverError {
    #[error("Server sent unexpected status")]
    UnexpectedStatus(#[from] Status),

    #[error("Error creating remote")]
    InitializationError(#[source] tonic::transport::Error),
}

type Result<T> = std::result::Result<T, MaliciousClientDriverError>;

impl MaliciousClientDriver {
    pub fn new(uri: Uri) -> Result<Self> {
        let channel = Channel::builder(uri)
            .connect_lazy()
            .map_err(MaliciousClientDriverError::InitializationError)?;

        Ok(MaliciousClientDriver(channel))
    }

    #[instrument]
    pub async fn update_epoch(
        &self,
        epoch: u64,
        correct_clients: Vec<(EntityId, Position)>,
        mal_neighbours: Vec<EntityId>,
        max_faults: usize,
        type_code: u32,
    ) -> Result<Response<protos::util::Empty>> {
        let mut client = GrpcMaliciousDriverClient::new(self.0.clone());
        let request = Request!(MaliciousEpochUpdateRequest {
            new_epoch: epoch as u64,
            correct_neighbours: correct_clients
                .into_iter()
                .map(|(id, pos)| Neighbour {
                    id,
                    pos: Some(GrpcPosition { x: pos.0, y: pos.1 })
                })
                .collect(),
            malicious_neighbour_ids: mal_neighbours,
            max_faults: max_faults as u64,
            type_code
        });

        client.update_epoch(request).await.map_err(|e| e.into())
    }

    #[instrument]
    pub async fn initial_config(
        &self,
        id_to_uri: &HashMap<EntityId, Uri>,
    ) -> Result<Response<protos::util::Empty>> {
        let mut client = GrpcMaliciousDriverClient::new(self.0.clone());
        let request = Request!(InitialConfigRequest {
            id_uri_map: id_to_uri.iter().map(|(&k, v)| (k, v.to_string())).collect(),
        });

        client.initial_config(request).await.map_err(|e| e.into())
    }
}

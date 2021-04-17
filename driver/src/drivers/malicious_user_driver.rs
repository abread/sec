use model::Position;
use std::collections::HashMap;

use model::keys::EntityId;
use protos::driver::malicious_user_driver_client::MaliciousUserDriverClient as GrpcMaliciousUserDriverClient;
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
pub struct MaliciousUserDriver(Channel);

#[derive(Debug, Error)]
pub enum MaliciousUserDriverError {
    #[error("Server sent unexpected status")]
    UnexpectedStatus(#[from] Status),

    #[error("Error creating remote")]
    InitializationError(#[source] tonic::transport::Error),
}

type Result<T> = std::result::Result<T, MaliciousUserDriverError>;

impl MaliciousUserDriver {
    pub fn new(uri: Uri) -> Result<Self> {
        let channel = Channel::builder(uri)
            .connect_lazy()
            .map_err(MaliciousUserDriverError::InitializationError)?;

        Ok(MaliciousUserDriver(channel))
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
        let mut client = GrpcMaliciousUserDriverClient::new(self.0.clone());
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
        let mut client = GrpcMaliciousUserDriverClient::new(self.0.clone());
        let request = Request!(InitialConfigRequest {
            id_uri_map: id_to_uri.iter().map(|(&k, v)| (k, v.to_string())).collect(),
        });

        client.initial_config(request).await.map_err(|e| e.into())
    }

    #[instrument]
    pub async fn prove_position(&self) -> Result<()> {
        let mut client = GrpcMaliciousUserDriverClient::new(self.0.clone());
        let request = Request!(protos::util::Empty {});

        client.prove_position(request).await?;
        Ok(())
    }
}

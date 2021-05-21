use model::keys::EntityId;
use protos::driver::correct_server_driver_client::CorrectServerDriverClient;
use protos::driver::InitialConfigRequest;
use protos::driver::ServerConfigUpdate;
use std::collections::HashMap;
use tonic::transport::{Channel, Uri};
use tonic::{Response, Status};
use tracing_utils::Request;

use thiserror::Error;
use tracing::instrument;

#[derive(Debug)]
pub struct CorrectServerDriver(Channel);

#[derive(Debug, Error)]
pub enum ServerDriverError {
    #[error("Server sent unexpected status")]
    UnexpectedStatus(#[from] Status),

    #[error("Error creating remote")]
    InitializationError(#[source] tonic::transport::Error),
}

type Result<T> = std::result::Result<T, ServerDriverError>;

impl CorrectServerDriver {
    pub fn new(uri: Uri) -> Result<Self> {
        let channel = Channel::builder(uri)
            .connect_lazy()
            .map_err(ServerDriverError::InitializationError)?;

        Ok(CorrectServerDriver(channel))
    }

    #[instrument]
    pub async fn update_config(
        &self,
        new_epoch: u64,
        neighbour_faults: u64,
        server_faults: u64,
        n_servers: u64,
    ) -> Result<Response<protos::util::Empty>> {
        let mut server = CorrectServerDriverClient::new(self.0.clone());
        let request = Request!(ServerConfigUpdate {
            new_epoch,
            neighbour_faults,
            server_faults,
        });

        server.update_config(request).await.map_err(|e| e.into())
    }

    #[instrument]
    pub async fn initial_config(
        &self,
        id_to_uri: &HashMap<EntityId, Uri>,
        servers: Vec<EntityId>,
    ) -> Result<Response<protos::util::Empty>> {
        let mut client = CorrectServerDriverClient::new(self.0.clone());
        let request = Request!(InitialConfigRequest {
            id_uri_map: id_to_uri.iter().map(|(&k, v)| (k, v.to_string())).collect(),
            servers
        });

        client.initial_config(request).await.map_err(|e| e.into())
    }
}

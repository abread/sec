use model::keys::EntityId;
use model::Position;
use protos::driver::server_driver_client::ServerDriverClient;
use protos::driver::ServerConfigUpdate;
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
        epoch: u64,
        max_faults: usize,
    ) -> Result<Response<protos::util::Empty>> {
        let mut server = ServerDriverClient::new(self.0.clone());
        let request = Request!(ServerConfigUpdate {
            new_epoch: epoch,
            max_faults: max_faults as u64
        });

        server.update_config(request).await.map_err(|e| e.into())
    }
}

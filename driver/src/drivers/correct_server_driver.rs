use protos::driver::correct_server_driver_client::CorrectServerDriverClient;
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
        neighbour_faults: usize,
        server_faults: usize,
    ) -> Result<Response<protos::util::Empty>> {
        let mut server = CorrectServerDriverClient::new(self.0.clone());
        let request = Request!(ServerConfigUpdate {
            new_epoch: epoch,
            neighbour_faults: neighbour_faults as u64,
            server_faults: server_faults as u64
        });

        server.update_config(request).await.map_err(|e| e.into())
    }
}

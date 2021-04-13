use protos::driver::driver_client::DriverClient as GrpcDriverClient;
use protos::driver::{EpochUpdateRequest, Position};
use tonic::transport::{Channel, Uri};
use tonic::{Response, Status};
use tracing_utils::Request;

use thiserror::Error;
use tracing::instrument;

#[derive(Debug)]
pub struct DriverClient(Channel);

#[derive(Debug, Error)]
pub enum DriverClientError {
    #[error("Server sent unexpected status")]
    UnexpectedStatus(#[from] Status),

    #[error("Error creating remote")]
    InitializationError(#[source] tonic::transport::Error),
}

type Result<T> = std::result::Result<T, DriverClientError>;

impl DriverClient {
    pub fn new(uri: Uri) -> Result<Self> {
        let channel = Channel::builder(uri)
            .connect_lazy()
            .map_err(DriverClientError::InitializationError)?;

        Ok(DriverClient(channel))
    }

    #[instrument]
    pub async fn update_epoch(
        &self,
        epoch: usize,
        pos: (usize, usize),
        neighbours: Vec<Uri>,
    ) -> Result<Response<protos::driver::Empty>> {
        let mut client = GrpcDriverClient::new(self.0.clone());
        let request = Request!(EpochUpdateRequest {
            new_epoch: epoch as u64,
            new_position: Some(Position {
                x: pos.0 as u64,
                y: pos.1 as u64
            }),
            visible_neighbour_uris: neighbours.into_iter().map(|x| format!("{}", x)).collect()
        });

        client.update_epoch(request).await.map_err(|e| e.into())
    }
}

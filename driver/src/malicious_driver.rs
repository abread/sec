use model::Position;
use protos::driver::malicious_driver_client::MaliciousDriverClient as GrpcMaliciousDriverClient;
use protos::driver::MaliciousEpochUpdateRequest;
use protos::util::Neighbour;
use protos::util::Position as GrpcPosition;
use tonic::transport::{Channel, Uri};
use tonic::{Response, Status};
use tracing_utils::Request;

use thiserror::Error;
use tracing::instrument;

#[derive(Debug)]
pub struct MaliciousDriverClient(Channel);

#[derive(Debug, Error)]
pub enum MaliciousDriverClientError {
    #[error("Server sent unexpected status")]
    UnexpectedStatus(#[from] Status),

    #[error("Error creating remote")]
    InitializationError(#[source] tonic::transport::Error),
}

type Result<T> = std::result::Result<T, MaliciousDriverClientError>;

impl MaliciousDriverClient {
    pub fn new(uri: Uri) -> Result<Self> {
        let channel = Channel::builder(uri)
            .connect_lazy()
            .map_err(MaliciousDriverClientError::InitializationError)?;

        Ok(MaliciousDriverClient(channel))
    }

    #[instrument]
    pub async fn update_epoch(
        &self,
        epoch: usize,
        correct_clients: Vec<(Uri, Position)>,
        mal_neighbours: Vec<Uri>,
    ) -> Result<Response<protos::util::Empty>> {
        let mut client = GrpcMaliciousDriverClient::new(self.0.clone());
        let request = Request!(MaliciousEpochUpdateRequest {
            new_epoch: epoch as u64,
            correct_neighbours: correct_clients
                .into_iter()
                .map(|(uri, pos)| Neighbour {
                    uri: format!("{}", uri),
                    pos: Some(GrpcPosition { x: pos.0, y: pos.1 })
                })
                .collect(),
            malicious_neighbour_uris: mal_neighbours
                .into_iter()
                .map(|x| format!("{}", x))
                .collect()
        });

        client.update_epoch(request).await.map_err(|e| e.into())
    }
}

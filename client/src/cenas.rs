use protos::cenas::cenas_client::CenasClient as GrpcCenasClient;
use tonic::transport::{Channel, Uri};
use tonic::{Response, Status};
use tracing_utils::Request;

use thiserror::Error;
use tracing::instrument;

#[derive(Debug)]
pub struct CenasClient(Channel);

#[derive(Debug, Error)]
pub enum CenasClientError {
    #[error("Server sent unexpected status")]
    UnexpectedStatus(#[from] Status),

    #[error("Error creating remote")]
    InitializationError(#[source] tonic::transport::Error),
}

type Result<T> = std::result::Result<T, CenasClientError>;

impl CenasClient {
    pub fn new(uri: Uri) -> Result<Self> {
        let channel = Channel::builder(uri)
            .connect_lazy()
            .map_err(CenasClientError::InitializationError)?;

        Ok(CenasClient(channel))
    }

    #[instrument]
    pub async fn dothething(&self) -> Result<Response<protos::util::Empty>> {
        let mut client = GrpcCenasClient::new(self.0.clone());
        let request = Request!(protos::util::Empty {});

        client.dothething(request).await.map_err(|e| e.into())
    }
}

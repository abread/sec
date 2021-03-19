use protos::cenas_client::CenasClient as GrpcCenasClient;
use tonic::transport::{Channel, ClientTlsConfig, Uri};
use tonic::{Request, Response, Status};

use tracing::instrument;
mod trace_utils;
use trace_utils::Instrumented;

use thiserror::Error;

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
    pub fn new(uri: Uri, tls_config: ClientTlsConfig) -> Result<Self> {
        let channel = Channel::builder(uri)
            .tls_config(tls_config)
            .and_then(|c| c.connect_lazy())
            .map_err(CenasClientError::InitializationError)?;

        Ok(CenasClient(channel))
    }

    #[instrument]
    pub async fn dothething(&self) -> Result<Response<protos::Empty>> {
        let mut client = GrpcCenasClient::new(self.0.clone());

        client
            .dothething(Request::new(protos::Empty {}).instrumented())
            .await
            .map_err(|e| e.into())
    }
}

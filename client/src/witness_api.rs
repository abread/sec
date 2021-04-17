use std::convert::TryInto;
use std::sync::Arc;
use std::time::Duration;

use protos::witness::witness_client::WitnessClient as GrpcWitnessClient;
use tonic::transport::{Channel, Uri};
use tower::timeout::Timeout;
use tracing_utils::Request;

use model::{
    keys::{EntityId, KeyStore},
    ProximityProof, ProximityProofRequest, ProximityProofValidationError, UnverifiedProximityProof,
};

use thiserror::Error;
use tracing::instrument;

use crate::state::{CorrectUserState, MaliciousUserState};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15); // 15s ought to be enough

#[derive(Debug)]
pub struct WitnessApiClient {
    channel: Channel,
    key_store: Arc<KeyStore>,
}

#[derive(Debug, Error)]
pub enum WitnessError {
    #[error("Error creating remote")]
    InitializationError(#[from] tonic::transport::Error),

    #[error("Error parsing response")]
    ResponseParseError(#[from] protos::witness::ParseError),

    #[error("Error executing request: {}", .0)]
    ServerError(String),

    #[error("Error verifying proof")]
    VerificationError(#[from] ProximityProofValidationError),
}

type Result<T> = std::result::Result<T, WitnessError>;

impl WitnessApiClient {
    pub fn new(uri: &Uri, key_store: Arc<KeyStore>) -> Result<Self> {
        let channel = Channel::builder(uri.clone())
            .connect_lazy()
            .map_err(WitnessError::InitializationError)?;

        Ok(WitnessApiClient { channel, key_store })
    }

    #[instrument]
    pub async fn get_proof(
        &self,
        proximity_proof_request: ProximityProofRequest,
    ) -> Result<UnverifiedProximityProof> {
        let grpc_request = Request!(proximity_proof_request.into());

        let mut grpc_client =
            GrpcWitnessClient::new(Timeout::new(self.channel.clone(), REQUEST_TIMEOUT));

        let proof = grpc_client
            .prove(grpc_request)
            .await
            .map_err(|err| WitnessError::ServerError(err.message().into()))?
            .into_inner()
            .try_into()?;

        Ok(proof)
    }
}

pub async fn request_proof_correct(
    state: &CorrectUserState,
    proximity_proof_request: ProximityProofRequest,
    witness_id: EntityId,
    key_store: Arc<KeyStore>,
) -> Result<ProximityProof> {
    let uri = state.id_to_uri(witness_id);
    let client = WitnessApiClient::new(uri, key_store.clone())?;
    let unverified_proof = client.get_proof(proximity_proof_request).await?;
    unverified_proof
        .verify(&key_store)
        .map_err(WitnessError::VerificationError)
}

pub async fn request_proof_malicious(
    state: &MaliciousUserState,
    proximity_proof_request: ProximityProofRequest,
    witness_id: EntityId,
    key_store: Arc<KeyStore>,
) -> Result<ProximityProof> {
    let uri = state.id_to_uri(witness_id);
    let client = WitnessApiClient::new(uri, key_store.clone())?;
    let unverified_proof = client.get_proof(proximity_proof_request).await?;
    unverified_proof
        .verify(&key_store)
        .map_err(WitnessError::VerificationError)
}

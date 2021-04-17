use std::sync::Arc;
use std::time::Duration;

use protos::util::Position as GrpcPosition;
use protos::witness::witness_client::WitnessClient as GrpcWitnessClient;
use protos::witness::ProximityProofRequest as GrpcProximityProofRequest;
use tonic::transport::{Channel, Uri};
use tower::timeout::Timeout;
use tracing_utils::Request;

use model::{
    keys::{EntityId, KeyStore, Signature},
    Position, ProximityProof, ProximityProofRequest, ProximityProofValidationError,
    UnverifiedProximityProof, UnverifiedProximityProofRequest,
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
    InitializationError(#[source] tonic::transport::Error),

    #[error("Error processing response")]
    ResponseError,

    #[error("Error executing request: {}", .0)]
    ServerError(String),

    #[error("Error verifying proof: {}", .0)]
    VerificationError(ProximityProofValidationError),
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
        let pos = proximity_proof_request.position();
        let grpc_request = Request!(GrpcProximityProofRequest {
            prover_id: *proximity_proof_request.prover_id(),
            prover_position: Some(GrpcPosition { x: pos.0, y: pos.1 }),
            epoch: proximity_proof_request.epoch(),
            signature: proximity_proof_request.signature().0.into(),
        });

        let mut grpc_client =
            GrpcWitnessClient::new(Timeout::new(self.channel.clone(), REQUEST_TIMEOUT));
        let resp = grpc_client
            .prove(grpc_request)
            .await
            .map_err(|err| WitnessError::ServerError(err.message().into()))?;
        let inner = resp.into_inner();
        let req = inner.request.ok_or(WitnessError::ResponseError)?;
        let request = UnverifiedProximityProofRequest {
            prover_id: req.prover_id,
            position: req
                .prover_position
                .ok_or(WitnessError::ResponseError)
                .map(|pos| Position(pos.x, pos.y))?,
            epoch: req.epoch,
            signature: Signature::from_slice(&req.signature).ok_or(WitnessError::ResponseError)?,
        };
        let witness_id = inner.witness_id;
        let w_position = inner.witness_position.unwrap();
        let witness_position = Position(w_position.x, w_position.y);
        let signature =
            Signature::from_slice(&inner.witness_signature).ok_or(WitnessError::ResponseError)?;
        Ok(UnverifiedProximityProof {
            request,
            witness_id,
            witness_position,
            signature,
        })
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

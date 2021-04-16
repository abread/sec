use protos::witness::witness_server::Witness;
use protos::witness::ProximityProofRequest;
use protos::witness::ProximityProofResponse;
use std::sync::Arc;

use tokio::sync::RwLock;
use tonic::{Request, Response, Status};
use tracing::{debug, info};
use tracing_utils::instrument_tonic_service;

use model::keys::{KeyStore, Signature};
use model::Position;
use model::ProximityProof;
use model::UnverifiedProximityProofRequest;

use crate::state::MaliciousClientState;

// need access to KeyStore and Position (maybe ID?)
#[derive(Debug)]
pub struct MaliciousWitnessService {
    key_store: Arc<KeyStore>,
    state: Arc<RwLock<MaliciousClientState>>,
}

impl MaliciousWitnessService {
    pub fn new(key_store: Arc<KeyStore>, state: Arc<RwLock<MaliciousClientState>>) -> Self {
        Self { key_store, state }
    }
}

type GrpcResult<T> = Result<Response<T>, Status>;

#[instrument_tonic_service]
#[tonic::async_trait]
impl Witness for MaliciousWitnessService {
    async fn prove(
        &self,
        request: Request<ProximityProofRequest>,
    ) -> GrpcResult<ProximityProofResponse> {
        info!("Received proof request");
        let request = request.into_inner();

        let epoch = request.epoch;
        let prover_id = request.prover_id;
        let signature = Signature::from_slice(&request.signature)
            .ok_or_else(|| Status::invalid_argument("Bad signature format"))?;

        let position = match request.prover_position {
            Some(ref position) => Position(position.x, position.y),
            None => {
                debug!("Missing proverPosition from request");
                return Err(Status::invalid_argument("Missing proverPosition"));
            }
        };

        let unverified_proximity_proof_request = UnverifiedProximityProofRequest {
            prover_id,
            position,
            epoch,
            signature,
        };

        let proximity_proof_request =
            match unverified_proximity_proof_request.verify(&self.key_store) {
                Ok(vppr) => vppr,
                Err(x) => {
                    debug!("Verification failed {}", x);
                    return Err(Status::unauthenticated("verification failed"));
                }
            };

        let current_epoch = self.state.read().await.epoch();
        if epoch != current_epoch {
            debug!("Message from epoch {}, expected {}", epoch, current_epoch);
            return Err(Status::out_of_range("message out of epoch"));
        }

        let proximity_proof = match ProximityProof::new(proximity_proof_request, &self.key_store) {
            Ok(pp) => pp,
            Err(e) => {
                debug!("Proof creation failed {}", e);
                return Err(Status::internal("proof creation failed"));
            }
        };

        let response = ProximityProofResponse {
            witness_id: *proximity_proof.witness_id(),
            request: Some(request.clone()),
            witness_signature: proximity_proof.signature().0.into(),
        };

        info!("Responding to proof request");
        Ok(Response::new(response))
    }
}

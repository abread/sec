use protos::witness::witness_server::Witness;
use protos::witness::ProximityProofRequest;
use protos::witness::ProximityProofResponse;

use tonic::{Request, Response, Status};
use tracing::{info, debug};
use tracing_utils::instrument_tonic_service;

use model::keys::KeyStore;
use model::UnverifiedProximityProofRequest;
use model::ProximityProof;
use model::Position;

// need access to KeyStore and Position (maybe ID?)
#[derive(Debug)]
pub(crate) struct WitnessService{
    key_store: KeyStore,
}

impl WitnessService {
    pub fn new(key_store: KeyStore) -> Self {
        Self{key_store}
    }
}

type GrpcResult<T> = Result<Response<T>, Status>;

#[instrument_tonic_service]
#[tonic::async_trait]
impl Witness for WitnessService {
    async fn prove(&self, request: Request<ProximityProofRequest>) -> GrpcResult<ProximityProofResponse> {
        info!("Received proof request");
        let epoch = request.get_ref().epoch;

        let prover_id = request.get_ref().prover_id;
        let signature = request.get_ref().signature.clone();

        let position = match request.get_ref().prover_position {
            Some(ref position) => {
                Position(position.x, position.y)
            },
            None => return Err(Status::invalid_argument("Missing proverPosition")),
        };

        let unverified_proximity_proof_request = UnverifiedProximityProofRequest {
            prover_id,
            position,
            epoch,
            signature,
        };

        let proximity_proof_request = match unverified_proximity_proof_request.verify(&self.key_store) {
            Ok(vcpr) => vcpr,
            Err(x) => {
                debug!("Verification failed {}", x);
                return Err(Status::unauthenticated("verification failed"));
            },
        };

        // TODO check that epoch is current epoch
        // TODO check if distance is short enough

        let proximity_proof = match ProximityProof::new(proximity_proof_request, &self.key_store) {
            Ok(pp) => pp,
            Err(e) => {
                debug!("Proof creation failed {}", e);
                return Err(Status::internal("proof creation failed"));
            }
        };

        let response = ProximityProofResponse {
            witness_id: *proximity_proof.witness_id(),
            request: Some(request.get_ref().clone()),
            witness_signature: proximity_proof.signature().into(),
        };

        info!("Responding to proof request");
        Ok(Response::new(response))
    }
}

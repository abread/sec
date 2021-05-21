use std::convert::TryInto;
use std::sync::Arc;

use protos::witness::witness_server::Witness;
use protos::witness::ParseError;
use protos::witness::ProximityProofRequest;
use protos::witness::ProximityProofResponse;

use tokio::sync::RwLock;
use tonic::{Request, Response, Status};
use tracing::*;
use tracing_utils::instrument_tonic_service;

use model::keys::KeyStore;
use model::neighbourhood::are_neighbours;
use model::{ProximityProof, UnverifiedProximityProofRequest};

use crate::state::CorrectUserState;

// need access to KeyStore and Position (maybe ID?)
#[derive(Debug)]
pub struct CorrectWitnessService {
    key_store: Arc<KeyStore>,
    state: Arc<RwLock<CorrectUserState>>,
}

impl CorrectWitnessService {
    pub fn new(key_store: Arc<KeyStore>, state: Arc<RwLock<CorrectUserState>>) -> Self {
        Self { key_store, state }
    }
}

type GrpcResult<T> = Result<Response<T>, Status>;

#[instrument_tonic_service]
#[tonic::async_trait]
impl Witness for CorrectWitnessService {
    #[instrument(skip(self))]
    async fn prove(
        &self,
        request: Request<ProximityProofRequest>,
    ) -> GrpcResult<ProximityProofResponse> {
        info!("Received proof request");
        let unverified_proximity_proof_request: UnverifiedProximityProofRequest = request
            .into_inner()
            .try_into()
            .map_err(|e: ParseError| Status::invalid_argument(e.to_string()))?;

        let proximity_proof_request =
            match unverified_proximity_proof_request.verify(&self.key_store) {
                Ok(vppr) => vppr,
                Err(x) => {
                    debug!(event="Verification failed", error=?x);
                    return Err(Status::unauthenticated("verification failed"));
                }
            };

        let (current_epoch, current_position) = {
            let guard = self.state.read().await;
            (guard.epoch(), guard.position())
        };
        if proximity_proof_request.epoch() != current_epoch {
            debug!(
                "Message from epoch {}, expected {}",
                proximity_proof_request.epoch(),
                current_epoch
            );
            return Err(Status::out_of_range("message out of epoch"));
        }

        if !are_neighbours(current_position, proximity_proof_request.position()) {
            warn!("Prover isn't a neighbour");
            return Err(Status::failed_precondition("prover not a neighbour"));
        }

        let proximity_proof =
            match ProximityProof::new(proximity_proof_request, current_position, &self.key_store) {
                Ok(pp) => pp,
                Err(e) => {
                    debug!("Proof creation failed {}", e);
                    return Err(Status::internal("proof creation failed"));
                }
            };

        let response = Response::new(proximity_proof.into());

        info!(event = "Responding to proof request", ?response);
        Ok(response)
    }
}

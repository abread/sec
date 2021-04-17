use std::convert::TryInto;
use std::sync::Arc;

use protos::witness::witness_server::Witness;
use protos::witness::ProximityProofRequest;
use protos::witness::ProximityProofResponse;
use protos::{util::Position as GrpcPosition, witness::ParseError};

use tokio::sync::RwLock;
use tonic::{Request, Response, Status};
use tracing::*;
use tracing_utils::instrument_tonic_service;

use model::keys::{KeyStore, Signature};
use model::Position;
use model::ProximityProof;
use model::UnverifiedProximityProofRequest;

use crate::state::{MaliciousType, MaliciousUserState};

// need access to KeyStore and Position (maybe ID?)
#[derive(Debug)]
pub struct MaliciousWitnessService {
    key_store: Arc<KeyStore>,
    state: Arc<RwLock<MaliciousUserState>>,
}

impl MaliciousWitnessService {
    pub fn new(key_store: Arc<KeyStore>, state: Arc<RwLock<MaliciousUserState>>) -> Self {
        Self { key_store, state }
    }
}

type GrpcResult<T> = Result<Response<T>, Status>;

#[instrument_tonic_service]
#[tonic::async_trait]
impl Witness for MaliciousWitnessService {
    #[instrument(skip(self))]
    async fn prove(
        &self,
        request: Request<ProximityProofRequest>,
    ) -> GrpcResult<ProximityProofResponse> {
        let unv_ppreq: UnverifiedProximityProofRequest = request
            .into_inner()
            .try_into()
            .map_err(|e: ParseError| Status::invalid_argument(e.to_string()))?;
        info!(event = "Received proof request", ?unv_ppreq);

        let (current_epoch, current_position, malicious_type) = {
            let guard = self.state.read().await;
            (
                guard.epoch(),
                Position(unv_ppreq.position.0 + 1, unv_ppreq.position.1 + 1),
                guard.malicious_type(),
            )
        };

        let proximity_proof_request = match malicious_type {
            MaliciousType::HonestOmnipresent => {
                if unv_ppreq.epoch != current_epoch {
                    debug!(
                        "Message from epoch {}, expected {}",
                        unv_ppreq.epoch, current_epoch
                    );
                    return Err(Status::out_of_range("message out of epoch"));
                }
                match unv_ppreq.verify(&self.key_store) {
                    Ok(verified_ppreq) => verified_ppreq,
                    Err(x) => {
                        debug!("Verification failed {}", x);
                        return Err(Status::unauthenticated("verification failed"));
                    }
                }
            }
            MaliciousType::PoorVerifier | MaliciousType::Teleporter => {
                // Safety: YOLO, this seems like a good place to start a code inspection
                // Rust seems really nice, telling us that this is unsafe.
                // Cool
                //
                unsafe { unv_ppreq.verify_unchecked() }
            }
        };

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

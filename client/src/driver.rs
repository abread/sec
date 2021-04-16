use model::{
    keys::EntityId, keys::KeyStore, neighbourhood::are_neighbours, Position, ProximityProofRequest,
    UnverifiedPositionProof,
};
use protos::driver::EpochUpdateRequest;
use protos::driver::{driver_server::Driver, InitialConfigRequest};
use protos::util::Empty;

use tonic::transport::Uri;
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};
use tracing_utils::instrument_tonic_service;

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::hdlt_api::HdltApiClient;
use crate::state::CorrectClientState;
use crate::witness_api::request_proof_correct;

use futures::stream::{FuturesUnordered, StreamExt};

#[derive(Debug)]
pub struct DriverService {
    state: Arc<RwLock<CorrectClientState>>,
    server_uri: Uri,
    key_store: Arc<KeyStore>,
}

impl DriverService {
    pub fn new(
        state: Arc<RwLock<CorrectClientState>>,
        key_store: Arc<KeyStore>,
        server_uri: Uri,
    ) -> Self {
        DriverService {
            state,
            key_store,
            server_uri,
        }
    }

    async fn update_state(
        &self,
        epoch: u64,
        position: Position,
        neighbours: Vec<EntityId>,
        max_faults: u64,
    ) {
        self.state
            .write()
            .await
            .update(epoch, position, neighbours, max_faults);
    }
}

type GrpcResult<T> = Result<Response<T>, Status>;

#[instrument_tonic_service]
#[tonic::async_trait]
impl Driver for DriverService {
    async fn initial_config(&self, request: Request<InitialConfigRequest>) -> GrpcResult<Empty> {
        let message = request.into_inner();
        self.state.write().await.add_mappings(message.id_uri_map);
        Ok(Response::new(Empty {}))
    }

    async fn update_epoch(&self, request: Request<EpochUpdateRequest>) -> GrpcResult<Empty> {
        async fn prove_location(
            state: &CorrectClientState,
            key_store: Arc<KeyStore>,
            server_uri: Uri,
        ) {
            let proof_request =
                ProximityProofRequest::new(state.epoch(), state.position().clone(), &key_store);
            let mut futs: FuturesUnordered<_> = state
                .neighbourhood()
                .map(|id| {
                    request_proof_correct(&state, proof_request.clone(), *id, key_store.clone())
                })
                .collect();
            let mut proofs = Vec::with_capacity(state.max_faults() as usize);

            while futs.len() > (state.max_faults() as usize - proofs.len())
                && proofs.len() < state.max_faults() as usize
            {
                futures::select! {
                    res = futs.select_next_some() => {
                        match res {
                            Ok(proof) => {
                                if !are_neighbours(state.position(), proof.witness_position()) {
                                    warn!("Received a proof from a non-neighbour (ie: a liar): {:?}", proof);
                                } else {
                                    proofs.push(proof);
                                }
                            },
                            Err(err) => {
                                warn!("Received an error: {:?}", err);
                            }
                        }
                    }

                    complete => break,
                }
            }

            if proofs.len() < state.max_faults() as usize {
                error!(
                    "Failed to obtain the required {} witnesses: received only {}",
                    state.max_faults(),
                    proofs.len()
                );
            } else {
                let server_api = match HdltApiClient::new(server_uri, key_store) {
                    Ok(p) => p,
                    Err(e) => {
                        error!("failed to connect to server to submit proof: {}", e);
                        return;
                    }
                };

                // @bsd: @abread, why should we have to decompose the verified proximity proofs?
                if let Err(e) = server_api
                    .submit_position_report(UnverifiedPositionProof {
                        witnesses: proofs.into_iter().map(|p| p.into()).collect(),
                    })
                    .await
                {
                    error!("failed to submit proof to server: {}", e);
                    return;
                }
            }
        }
        let message = request.into_inner();
        let position = message.new_position.unwrap();
        let position = Position(position.x, position.y);
        self.update_state(
            message.new_epoch,
            position,
            message.visible_neighbour_ids,
            message.max_faults,
        )
        .await;
        info!("Updated the local state");

        let state = self.state.read().await;
        prove_location(&state, self.key_store.clone(), self.server_uri.clone()).await;

        Ok(Response::new(Empty {}))
    }
}

use model::{
    keys::EntityId, keys::KeyStore, neighbourhood::are_neighbours, Position, ProximityProof,
    ProximityProofRequest, UnverifiedPositionProof,
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

use crate::hdlt_api::{HdltApiClient, HdltError};
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

/// Prove the user location to the server
/// First get proofs of proximity
/// Then submit those as a proof of location
///
async fn prove_location(state: &CorrectClientState, key_store: Arc<KeyStore>, server_uri: Uri) {
    let proofs = match request_location_proofs(&state, key_store.clone()).await {
        Ok(p) => p,
        Err(e) => {
            error!("failed to get proofs of location: {:?}", e);
            return;
        }
    };

    if let Err(e) = submit_position_proof(key_store, server_uri, proofs, state.epoch()).await {
        error!("failed to submit position report to server: {:?}", e);
    }
}

/// Gather proofs of proximity
async fn request_location_proofs(
    state: &CorrectClientState,
    key_store: Arc<KeyStore>,
) -> eyre::Result<Vec<ProximityProof>> {
    let proof_request = ProximityProofRequest::new(state.epoch(), *state.position(), &key_store);
    let mut futs: FuturesUnordered<_> = state
        .neighbourhood()
        .map(|id| request_proof_correct(&state, proof_request.clone(), id, key_store.clone()))
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
                            warn!("Received a proof from a non-neighbour (may be a byzantine node): {:?}", proof);
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
        warn!(
            "Failed to obtain the required {} witnesses: received only {}",
            state.max_faults(),
            proofs.len()
        );
        todo!();
    } else {
        Ok(proofs)
    }
}

/// Submit proof of location to server
async fn submit_position_proof(
    key_store: Arc<KeyStore>,
    server_uri: Uri,
    position_proofs: Vec<ProximityProof>,
    current_epoch: u64,
) -> Result<(), HdltError> {
    let server_api = HdltApiClient::new(server_uri, key_store, current_epoch)?;

    // @bsd: @abread, why should we have to decompose the verified proximity proofs?
    server_api
        .submit_position_report(UnverifiedPositionProof {
            witnesses: position_proofs.into_iter().map(|p| p.into()).collect(),
        })
        .await
}

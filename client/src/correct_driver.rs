use eyre::{eyre, WrapErr};
use model::{
    keys::EntityId, keys::KeyStore, neighbourhood::are_neighbours, Position, ProximityProof,
    ProximityProofRequest, UnverifiedPositionProof,
};
use protos::driver::EpochUpdateRequest;
use protos::driver::{correct_user_driver_server::CorrectUserDriver, InitialConfigRequest};
use protos::util::Empty;

use tonic::transport::Uri;
use tonic::{Code as StatusCode, Request, Response, Status};
use tracing::*;
use tracing_utils::instrument_tonic_service;

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::hdlt_api::{HdltApiClient, HdltError};
use crate::state::CorrectUserState;
use crate::witness_api::request_proof_correct;

use futures::stream::{FuturesUnordered, StreamExt};

#[derive(Debug)]
pub struct CorrectDriverService {
    state: Arc<RwLock<CorrectUserState>>,
    server_uris: Vec<(u32, Uri)>,
    key_store: Arc<KeyStore>,
}

impl CorrectDriverService {
    pub fn new(
        state: Arc<RwLock<CorrectUserState>>,
        key_store: Arc<KeyStore>,
        server_uris: Vec<(u32, Uri)>,
    ) -> Self {
        CorrectDriverService {
            state,
            server_uris,
            key_store,
        }
    }

    async fn update_state(
        &self,
        epoch: u64,
        position: Position,
        neighbours: Vec<EntityId>,
        neighbour_faults: u64,
        server_faults: u64,
    ) {
        self.state.write().await.update(
            epoch,
            position,
            neighbours,
            neighbour_faults,
            server_faults,
        );
    }
}

type GrpcResult<T> = Result<Response<T>, Status>;

#[instrument_tonic_service]
#[tonic::async_trait]
impl CorrectUserDriver for CorrectDriverService {
    #[instrument(skip(self))]
    async fn initial_config(&self, request: Request<InitialConfigRequest>) -> GrpcResult<Empty> {
        let message = request.into_inner();
        debug!("initial configuration received");

        self.state.write().await.add_mappings(message.id_uri_map);
        Ok(Response::new(Empty {}))
    }

    #[instrument(skip(self))]
    async fn update_epoch(&self, request: Request<EpochUpdateRequest>) -> GrpcResult<Empty> {
        let message = request.into_inner();
        let position = message.new_position.unwrap();
        let position = Position(position.x, position.y);
        self.update_state(
            message.new_epoch,
            position,
            message.visible_neighbour_ids,
            message.neighbour_faults,
            message.server_faults,
        )
        .await;
        info!("Updated the local state");

        Ok(Response::new(Empty {}))
    }

    #[instrument(skip(self))]
    async fn prove_position(&self, request: Request<Empty>) -> GrpcResult<Empty> {
        let state = self.state.read().await;
        prove_position(&state, self.key_store.clone(), self.server_uris.clone())
            .await
            .map_err(|e| Status::new(StatusCode::Aborted, format!("{:#?}", e)))?;

        Ok(Response::new(Empty {}))
    }
}

/// Prove the user location to the server
/// First get proofs of proximity
/// Then submit those as a proof of location
///
async fn prove_position(
    state: &CorrectUserState,
    key_store: Arc<KeyStore>,
    server_uris: Vec<(u32, Uri)>,
) -> eyre::Result<()> {
    let proofs = request_proximity_proofs(&state, key_store.clone())
        .await
        .wrap_err("failed to get proximity proofs")?;

    submit_position_proof(state, key_store, server_uris, proofs)
        .await
        .wrap_err("failed to submit position report to server")
}

/// Gather proofs of proximity
#[instrument(skip(key_store))]
async fn request_proximity_proofs(
    state: &CorrectUserState,
    key_store: Arc<KeyStore>,
) -> eyre::Result<Vec<ProximityProof>> {
    let proof_request = ProximityProofRequest::new(state.epoch(), state.position(), &key_store);
    let mut futs: FuturesUnordered<_> = state
        .neighbourhood()
        .map(|id| request_proof_correct(&state, proof_request.clone(), id, key_store.clone()))
        .collect();
    let mut proofs = Vec::with_capacity(state.neighbour_faults() as usize);

    while futs.len() > (state.neighbour_faults() as usize - proofs.len())
        && proofs.len() < state.neighbour_faults() as usize
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
                        warn!(event="Received an error", ?err);
                    }
                }
            }

            complete => break,
        }
    }

    if proofs.len() < state.neighbour_faults() as usize {
        Err(eyre!(
            "Failed to obtain the required {} witnesses: received only {}",
            state.neighbour_faults(),
            proofs.len()
        ))
    } else {
        Ok(proofs)
    }
}

/// Submit proof of location to server
#[instrument(skip(key_store))]
async fn submit_position_proof(
    state: &CorrectUserState,
    key_store: Arc<KeyStore>,
    server_uris: Vec<(u32, Uri)>,
    position_proofs: Vec<ProximityProof>,
) -> Result<(), HdltError> {
    let server_api = HdltApiClient::new(
        server_uris,
        key_store,
        state.epoch(),
        state.server_faults(),
        state.neighbour_faults(),
    )?;

    server_api
        .submit_position_report(UnverifiedPositionProof {
            witnesses: position_proofs.into_iter().map(|p| p.into()).collect(),
        })
        .await
}

use eyre::{eyre, WrapErr};
use model::{
    keys::EntityId, keys::KeyStore, neighbourhood::are_neighbours, Position, ProximityProof,
    ProximityProofRequest, UnverifiedPositionProof,
};
use protos::driver::MaliciousEpochUpdateRequest;
use protos::driver::{malicious_user_driver_server::MaliciousUserDriver, InitialConfigRequest};
use protos::util::Empty;

use tonic::transport::Uri;
use tonic::{Code as StatusCode, Request, Response, Status};
use tracing::*;
use tracing_utils::instrument_tonic_service;

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::hdlt_api::{HdltApiClient, HdltError};
use crate::state::{MaliciousType, MaliciousUserState, Neighbour};
use crate::witness_api::request_proof_malicious;

use futures::stream::{FuturesUnordered, StreamExt};

#[derive(Debug)]
pub struct MaliciousDriverService {
    state: Arc<RwLock<MaliciousUserState>>,
    server_uris: Vec<(u32, Uri)>,
    key_store: Arc<KeyStore>,
}

impl MaliciousDriverService {
    pub fn new(
        state: Arc<RwLock<MaliciousUserState>>,
        key_store: Arc<KeyStore>,
        server_uris: Vec<(u32, Uri)>,
    ) -> Self {
        MaliciousDriverService {
            state,
            server_uris,
            key_store,
        }
    }

    async fn update_state(
        &self,
        epoch: u64,
        correct: Vec<Neighbour>,
        malicious: Vec<EntityId>,
        type_code: u32,
        neighbour_faults: u64,
        server_faults: u64,
    ) {
        self.state.write().await.update(
            epoch,
            correct,
            malicious,
            type_code,
            neighbour_faults,
            server_faults,
        );
    }
}

type GrpcResult<T> = Result<Response<T>, Status>;

#[instrument_tonic_service]
#[tonic::async_trait]
impl MaliciousUserDriver for MaliciousDriverService {
    #[instrument(skip(self))]
    async fn initial_config(&self, request: Request<InitialConfigRequest>) -> GrpcResult<Empty> {
        let message = request.into_inner();
        debug!("initial configuration received");

        self.state.write().await.add_mappings(message.id_uri_map);
        Ok(Response::new(Empty {}))
    }

    #[instrument(skip(self))]
    async fn update_epoch(
        &self,
        request: Request<MaliciousEpochUpdateRequest>,
    ) -> GrpcResult<Empty> {
        let message = request.into_inner();
        self.update_state(
            message.new_epoch,
            message
                .correct_neighbours
                .into_iter()
                .map(Neighbour::from_proto)
                .collect(),
            message.malicious_neighbour_ids,
            message.type_code,
            message.neighbour_faults,
            message.server_faults,
        )
        .await;
        info!("Updated the local state");

        Ok(Response::new(Empty {}))
    }

    #[instrument(skip(self))]
    async fn prove_position(&self, request: Request<Empty>) -> GrpcResult<Empty> {
        let mut state = self.state.write().await;
        let position = match state.malicious_type() {
            MaliciousType::HonestOmnipresent | MaliciousType::PoorVerifier => {
                state.choose_position();
                state.position()
            }
            MaliciousType::Teleporter => state.generate_position(),
        };

        prove_position(
            &state,
            position,
            self.key_store.clone(),
            self.server_uris.clone(),
        )
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
    state: &MaliciousUserState,
    position: Position,
    key_store: Arc<KeyStore>,
    server_uris: Vec<(u32, Uri)>,
) -> eyre::Result<()> {
    let proofs = request_proximity_proofs(&state, position, key_store.clone())
        .await
        .wrap_err("could not get proximity proofs")?;

    submit_position_proof(
        key_store,
        server_uris,
        proofs,
        state.epoch(),
        state.server_faults(),
    )
    .await
    .wrap_err("failed to submit position proof to server")
}

/// Gather proofs of proximity
async fn request_proximity_proofs(
    state: &MaliciousUserState,
    position: Position,
    key_store: Arc<KeyStore>,
) -> eyre::Result<Vec<ProximityProof>> {
    let proof_request = ProximityProofRequest::new(state.epoch(), position, &key_store);
    let mut futs: FuturesUnordered<_> = state
        .neighbourhood(position)
        .map(|id| request_proof_malicious(&state, proof_request.clone(), id, key_store.clone()))
        .collect();
    let mut proofs = Vec::with_capacity(state.neighbour_faults() as usize);

    while futs.len() > (state.neighbour_faults() as usize - proofs.len())
        && proofs.len() < state.neighbour_faults() as usize
    {
        futures::select! {
            res = futs.select_next_some() => {
                match res {
                    Ok(proof) => {
                        if !are_neighbours(position, proof.witness_position()) {
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
async fn submit_position_proof(
    key_store: Arc<KeyStore>,
    server_uris: Vec<(u32, Uri)>,
    position_proofs: Vec<ProximityProof>,
    current_epoch: u64,
    server_faults: u64,
) -> Result<(), HdltError> {
    let server_api = HdltApiClient::new(server_uris, key_store, current_epoch, server_faults)?;

    server_api
        .submit_position_report(UnverifiedPositionProof {
            witnesses: position_proofs.into_iter().map(|p| p.into()).collect(),
        })
        .await
}

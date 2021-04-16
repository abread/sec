use model::{
    keys::EntityId, keys::KeyStore, neighbourhood::are_neighbours, Position, ProximityProof,
    ProximityProofRequest, UnverifiedPositionProof,
};
use protos::driver::MaliciousEpochUpdateRequest;
use protos::driver::{malicious_driver_server::MaliciousDriver, InitialConfigRequest};
use protos::util::Empty;

use tonic::transport::Uri;
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};
use tracing_utils::instrument_tonic_service;

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::hdlt_api::{HdltApiClient, HdltError};
use crate::state::{MaliciousClientState, MaliciousType, Neighbour};
use crate::witness_api::request_proof_malicious;

use futures::stream::{FuturesUnordered, StreamExt};

#[derive(Debug)]
pub struct MaliciousDriverService {
    state: Arc<RwLock<MaliciousClientState>>,
    server_uri: Uri,
    key_store: Arc<KeyStore>,
}

impl MaliciousDriverService {
    pub fn new(
        state: Arc<RwLock<MaliciousClientState>>,
        key_store: Arc<KeyStore>,
        server_uri: Uri,
    ) -> Self {
        MaliciousDriverService {
            state,
            key_store,
            server_uri,
        }
    }

    async fn update_state(
        &self,
        epoch: u64,
        correct: Vec<Neighbour>,
        malicious: Vec<EntityId>,
        type_code: u32,
        max_faults: u64,
    ) {
        self.state
            .write()
            .await
            .update(epoch, correct, malicious, type_code, max_faults);
    }
}

type GrpcResult<T> = Result<Response<T>, Status>;

#[instrument_tonic_service]
#[tonic::async_trait]
impl MaliciousDriver for MaliciousDriverService {
    async fn initial_config(&self, request: Request<InitialConfigRequest>) -> GrpcResult<Empty> {
        let message = request.into_inner();
        self.state.write().await.add_mappings(message.id_uri_map);
        Ok(Response::new(Empty {}))
    }

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
            message.max_faults,
        )
        .await;
        info!("Updated the local state");

        let mut state = self.state.write().await;
        let position = match state.malicious_type() {
            MaliciousType::HonestOmnipresent | MaliciousType::PoorVerifier => {
                state.choose_position();
                *state.position()
            }
            MaliciousType::Teleporter => state.generate_position(),
        };

        prove_location(
            &state,
            position,
            self.key_store.clone(),
            self.server_uri.clone(),
        )
        .await;

        Ok(Response::new(Empty {}))
    }
}

/// Prove the user location to the server
/// First get proofs of proximity
/// Then submit those as a proof of location
///
async fn prove_location(
    state: &MaliciousClientState,
    position: Position,
    key_store: Arc<KeyStore>,
    server_uri: Uri,
) {
    let proofs = match request_location_proofs(&state, position, key_store.clone()).await {
        Ok(p) => p,
        Err(e) => {
            error!("failed to get proofs of location: {:?}", e);
            return;
        }
    };

    if let Err(e) = submit_position_proof(key_store, server_uri, proofs).await {
        error!("failed to submit position report to server: {:?}", e);
    }
}

/// Gather proofs of proximity
async fn request_location_proofs(
    state: &MaliciousClientState,
    position: Position,
    key_store: Arc<KeyStore>,
) -> eyre::Result<Vec<ProximityProof>> {
    let proof_request = ProximityProofRequest::new(state.epoch(), position, &key_store);
    let mut futs: FuturesUnordered<_> = state
        .neighbourhood(&position)
        .map(|id| request_proof_malicious(&state, proof_request.clone(), id, key_store.clone()))
        .collect();
    let mut proofs = Vec::with_capacity(state.max_faults() as usize);

    while futs.len() > (state.max_faults() as usize - proofs.len())
        && proofs.len() < state.max_faults() as usize
    {
        futures::select! {
            res = futs.select_next_some() => {
                match res {
                    Ok(proof) => {
                        if !are_neighbours(&position, proof.witness_position()) {
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
) -> Result<(), HdltError> {
    let server_api = HdltApiClient::new(server_uri, key_store)?;

    // @bsd: @abread, why should we have to decompose the verified proximity proofs?
    server_api
        .submit_position_report(UnverifiedPositionProof {
            witnesses: position_proofs.into_iter().map(|p| p.into()).collect(),
        })
        .await
}

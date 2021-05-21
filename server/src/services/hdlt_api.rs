use std::sync::Arc;

use model::keys::{EntityId, KeyStore, Nonce, Role};
use model::{
    api::{ApiReply, ApiRequest, PoWProtected, RrMessage, RrRequest},
    PositionProof,
};
use model::{Position, PositionProofValidationError, UnverifiedPositionProof};
use protos::hdlt::hdlt_api_server::HdltApi;
use protos::hdlt::CipheredRrMessage;
use thiserror::Error;

use tokio::sync::RwLock;

use tonic::{Request, Response, Status};
use tracing::*;
use tracing_utils::instrument_tonic_service;

use crate::group_by::group_by;
use crate::hdlt_store::{HdltLocalStore, HdltLocalStoreError};

use super::driver::ServerConfig;

#[derive(Debug)]
pub struct HdltApiService {
    keystore: Arc<KeyStore>,
    store: Arc<HdltLocalStore>,
    config: Arc<RwLock<ServerConfig>>,
}

#[derive(Error, Debug)]
pub enum HdltApiError {
    #[error("Invalid Position Proof: {}", .0)]
    InvalidPositionProof(#[from] PositionProofValidationError),

    #[error("Invalid Proof of Work")]
    InvalidProofOfWork,

    #[error("Storage error: {}", .0)]
    StorageError(#[from] HdltLocalStoreError),

    #[error("Permission denied")]
    PermissionDenied,

    #[error("There is not enough data to satisfy your request")]
    NoData,
}

impl HdltApiService {
    pub fn new(
        keystore: Arc<KeyStore>,
        store: Arc<HdltLocalStore>,
        config: Arc<RwLock<ServerConfig>>,
    ) -> Self {
        HdltApiService {
            keystore,
            store,
            config,
        }
    }

    #[instrument(skip(self))]
    pub async fn obtain_position_report(
        &self,
        requestor_id: EntityId,
        prover_id: EntityId,
        epoch: u64,
    ) -> Result<(u64, Position), HdltApiError> {
        if requestor_id == prover_id || self.keystore.role_of(&requestor_id) == Some(Role::HaClient)
        {
            let max_neigh_faults = self.config.read().await.max_neigh_faults;
            let prox_proofs = self.store.query_epoch_prover(epoch, prover_id).await?;

            match PositionProof::new(prox_proofs, max_neigh_faults) {
                Ok(proof) => Ok((proof.epoch(), *proof.position())),
                Err(PositionProofValidationError::NotEnoughWitnesess { .. }) => {
                    Err(HdltApiError::NoData)
                }
                Err(e) => Err(e.into()),
            }
        } else {
            debug!("Permission denied");
            Err(HdltApiError::PermissionDenied)
        }
    }

    #[instrument(skip(self))]
    pub async fn get_position_reports(
        &self,
        requestor_id: EntityId,
        epoch_start: u64,
        epoch_end: u64,
    ) -> Result<Vec<(u64, PositionProof)>, HdltApiError> {
        let max_neigh_faults = self.config.read().await.max_neigh_faults;

        let prox_proofs_vec = self
            .store
            .query_epoch_prover_range(epoch_start..epoch_end, requestor_id)
            .await?;
        let mut results = Vec::with_capacity(prox_proofs_vec.len());

        for (epoch, prox_proofs) in prox_proofs_vec {
            match PositionProof::new(prox_proofs, max_neigh_faults) {
                Ok(proof) => results.push((epoch, proof)),
                Err(PositionProofValidationError::NotEnoughWitnesess { .. }) => {
                    // we ignore this, on purpose
                }
                Err(e) => return Err(e.into()),
            }
        }

        Ok(results)
    }

    #[instrument(skip(self))]
    pub async fn users_at_position(
        &self,
        requestor_id: EntityId,
        prover_position: Position,
        epoch: u64,
    ) -> Result<Vec<EntityId>, HdltApiError> {
        if self.keystore.role_of(&requestor_id) == Some(Role::HaClient) {
            let max_neigh_faults = self.config.read().await.max_neigh_faults;

            let all_prox_proofs = self
                .store
                .query_epoch_prover_position(epoch, prover_position)
                .await?;
            let uids = group_by(&all_prox_proofs, |a, b| a.prover_id() == b.prover_id())
                .map(|witnesses| PositionProof::new(witnesses.to_vec(), max_neigh_faults))
                .filter_map(|res| match res {
                    Ok(pos_proof) => Some(*pos_proof.prover_id()),
                    Err(PositionProofValidationError::NotEnoughWitnesess { .. }) => None,
                    Err(e) => unreachable!(
                        "DB stored bad stuff. This error should be impossible: {:?}",
                        e
                    ),
                })
                .collect();

            Ok(uids)
        } else {
            debug!("Permission denied");
            Err(HdltApiError::PermissionDenied)
        }
    }

    #[instrument(skip(self))]
    pub async fn submit_position_proof(
        &self,
        _requestor_id: EntityId,
        pow_protected_proof: &PoWProtected<UnverifiedPositionProof>,
    ) -> Result<(), HdltApiError> {
        let proof = pow_protected_proof
            .to_owned()
            .try_into_inner()
            .map_err(|_| HdltApiError::InvalidProofOfWork)?;

        let max_neigh_faults = self.config.read().await.max_neigh_faults;
        let proof = proof.verify(max_neigh_faults, self.keystore.as_ref())?;
        self.store.add_proof(proof).await?;

        Ok(())
    }
}

type GrpcResult<T> = Result<Response<T>, Status>;

#[instrument_tonic_service]
#[tonic::async_trait]
impl HdltApi for HdltApiService {
    #[instrument(skip(self))]
    async fn invoke(&self, request: Request<CipheredRrMessage>) -> GrpcResult<CipheredRrMessage> {
        let current_epoch = self.config.read().await.epoch;
        let (rr_message, requestor_id) = self.decipher_rr_message(request.into_inner());
        let request = rr_message
            .downcast_request(current_epoch)
            .expect("cannot downcast request-reply message to request");
        let grpc_error_mapper = self.grpc_error_mapper(requestor_id, &request, current_epoch);

        match request.as_ref() {
            ApiRequest::ObtainPositionReport { user_id, epoch } => self
                .obtain_position_report(requestor_id, *user_id, *epoch)
                .await
                .map(|(e, p)| ApiReply::PositionReport(e, p)),
            ApiRequest::RequestPositionReports {
                epoch_start,
                epoch_end,
            } => self
                .get_position_reports(requestor_id, *epoch_start, *epoch_end)
                .await
                .map(|v| {
                    v.into_iter()
                        .map(|(epoch, proof)| (epoch, proof.into()))
                        .collect()
                })
                .map(ApiReply::PositionReports),
            ApiRequest::ObtainUsersAtPosition { position, epoch } => self
                .users_at_position(requestor_id, *position, *epoch)
                .await
                .map(ApiReply::UsersAtPosition),
            ApiRequest::SubmitPositionReport(pow_protected_proof) => self
                .submit_position_proof(requestor_id, pow_protected_proof)
                .await
                .map(|_| ApiReply::Ok),
        }
        .map(|reply| RrMessage::new_reply(&request, current_epoch, reply))
        .map(|message| self.cipher_rr_message(message, requestor_id))
        .map(Response::new)
        .or_else(grpc_error_mapper)
    }
}

impl HdltApiService {
    fn grpc_error_mapper<'req, E: ToString>(
        &'req self,
        partner_id: EntityId,
        request: &'req RrRequest<ApiRequest>,
        epoch: u64,
    ) -> impl (Fn(E) -> GrpcResult<CipheredRrMessage>) + 'req {
        move |err| {
            let reply_payload = ApiReply::Error(err.to_string());
            let reply = RrMessage::new_reply(request, epoch, reply_payload);

            Ok(Response::new(self.cipher_rr_message(reply, partner_id)))
        }
    }

    fn decipher_rr_message(&self, message: CipheredRrMessage) -> (RrMessage<ApiRequest>, EntityId) {
        let nonce = Nonce::from_slice(&message.nonce).expect("invalid nonce in message");
        let plaintext = self
            .keystore
            .decipher(&message.sender_id, &message.ciphertext, &nonce)
            .expect("cannot decipher incoming message");
        let rr_message: RrMessage<ApiRequest> =
            bincode::deserialize(&plaintext).expect("cannot decode incoming message");

        (rr_message, message.sender_id)
    }

    fn cipher_rr_message(
        &self,
        message: RrMessage<ApiReply>,
        partner_id: EntityId,
    ) -> CipheredRrMessage {
        let plaintext = bincode::serialize(&message).expect("could not serialize reply");

        let (ciphertext, nonce) = self
            .keystore
            .cipher(&partner_id, &plaintext)
            .expect("could not cipher reply");

        CipheredRrMessage {
            sender_id: *self.keystore.my_id(),
            ciphertext,
            nonce: nonce.0.to_vec(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hdlt_store::test::build_store;
    use lazy_static::lazy_static;
    use model::keys::test_data::KeyStoreTestData;
    use model::keys::Signature;

    lazy_static! {
        static ref KEYSTORES: KeyStoreTestData = KeyStoreTestData::new();
    }

    async fn build_service() -> HdltApiService {
        HdltApiService::new(
            Arc::new(KEYSTORES.server.clone()),
            Arc::new(build_store().await),
            Arc::new(RwLock::new(ServerConfig {
                epoch: 0,
                max_neigh_faults: 1,
            })),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn obtain_position_report() {
        let service = build_service().await;

        // non-HA clients cannot see other users' positions
        let ha_client_id = *KEYSTORES.haclient.my_id();
        for id in KEYSTORES
            .iter()
            .map(|k| *k.my_id())
            .filter(|id| *id != ha_client_id)
        {
            assert!(matches!(
                service.obtain_position_report(id, 0, 0).await.unwrap_err(),
                HdltApiError::PermissionDenied
            ));
        }

        // HA client can see everyone's positions
        assert_eq!(
            service
                .obtain_position_report(ha_client_id, 0, 0)
                .await
                .unwrap(),
            (0, Position(0, 0))
        );
        assert_eq!(
            service
                .obtain_position_report(ha_client_id, 1, 0)
                .await
                .unwrap(),
            (0, Position(1, 0))
        );
        assert_eq!(
            service
                .obtain_position_report(ha_client_id, 0, 1)
                .await
                .unwrap(),
            (1, Position(0, 1))
        );
        assert_eq!(
            service
                .obtain_position_report(ha_client_id, 1, 1)
                .await
                .unwrap(),
            (1, Position(0, 1))
        );

        // users can see their own position
        assert_eq!(
            service.obtain_position_report(0, 0, 0).await.unwrap(),
            (0, Position(0, 0))
        );
        assert_eq!(
            service.obtain_position_report(1, 1, 0).await.unwrap(),
            (0, Position(1, 0))
        );
        assert_eq!(
            service.obtain_position_report(0, 0, 1).await.unwrap(),
            (1, Position(0, 1))
        );
        assert_eq!(
            service.obtain_position_report(1, 1, 1).await.unwrap(),
            (1, Position(0, 1))
        );

        // there may be no position data available
        assert!(matches!(
            service.obtain_position_report(50, 50, 0).await.unwrap_err(),
            HdltApiError::NoData
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn users_at_position() {
        let service = build_service().await;

        // non-HA clients cannot use this method at all
        let ha_client_id = *KEYSTORES.haclient.my_id();
        for id in KEYSTORES
            .iter()
            .map(|k| *k.my_id())
            .filter(|id| *id != ha_client_id)
        {
            assert!(matches!(
                service
                    .users_at_position(id, Position(0, 0), 0)
                    .await
                    .unwrap_err(),
                HdltApiError::PermissionDenied
            ));
        }

        // HA client can see it all
        assert_eq!(
            vec![0],
            service
                .users_at_position(ha_client_id, Position(0, 0), 0)
                .await
                .unwrap()
        );
        assert_eq!(
            vec![1],
            service
                .users_at_position(ha_client_id, Position(1, 0), 0)
                .await
                .unwrap()
        );
        assert_eq!(
            vec![0, 1],
            service
                .users_at_position(ha_client_id, Position(0, 1), 1)
                .await
                .unwrap()
        );

        // sometimes there's nothing to see
        assert!(service
            .users_at_position(ha_client_id, Position(123, 123), 67981463)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn add_proof() {
        let service = build_service().await;
        let mut bad_proof: UnverifiedPositionProof =
            crate::hdlt_store::test::PROOFS[0].clone().into();

        // just in case our test data for hdlt_store becomes valid at some point
        bad_proof.witnesses[0].signature = Signature::from_slice(&[42u8; 64]).unwrap();

        assert!(matches!(
            service
                .submit_position_proof(1234, &PoWProtected::new(bad_proof))
                .await
                .unwrap_err(),
            HdltApiError::InvalidPositionProof(..)
        ));

        let good_proof: UnverifiedPositionProof = {
            use model::{PositionProof, ProximityProof, ProximityProofRequest};
            let preq = ProximityProofRequest::new(123, Position(123, 123), &KEYSTORES.user1);
            let pproof = ProximityProof::new(preq, Position(100, 100), &KEYSTORES.user2).unwrap();

            PositionProof::new(vec![pproof], 1).unwrap().into()
        };

        // always different keys -> always different PoW
        assert!(service
            .submit_position_proof(1234, &PoWProtected::new(good_proof))
            .await
            .is_ok());
    }
}

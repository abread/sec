use std::sync::Arc;

use model::keys::{EntityId, KeyStore, Nonce, Role};
use model::{
    api::{ApiReply, ApiRequest, RrMessage, RrRequest},
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
    ) -> Result<Position, HdltApiError> {
        if requestor_id == prover_id || self.keystore.role_of(&requestor_id) == Some(Role::HaClient)
        {
            let max_neigh_faults = self.config.read().await.max_neigh_faults;
            let prox_proofs = self.store.query_epoch_prover(epoch, prover_id).await?;

            match PositionProof::new(prox_proofs, max_neigh_faults) {
                Ok(proof) => Ok(*proof.position()),
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
        proof: UnverifiedPositionProof,
    ) -> Result<(), HdltApiError> {
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
                .map(ApiReply::PositionReport),
            ApiRequest::ObtainUsersAtPosition { position, epoch } => self
                .users_at_position(requestor_id, *position, *epoch)
                .await
                .map(ApiReply::UsersAtPosition),
            ApiRequest::SubmitPositionReport(proof) => self
                .submit_position_proof(requestor_id, proof.clone())
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
            Position(0, 0)
        );
        assert_eq!(
            service
                .obtain_position_report(ha_client_id, 1, 0)
                .await
                .unwrap(),
            Position(1, 0)
        );
        assert_eq!(
            service
                .obtain_position_report(ha_client_id, 0, 1)
                .await
                .unwrap(),
            Position(0, 1)
        );
        assert_eq!(
            service
                .obtain_position_report(ha_client_id, 1, 1)
                .await
                .unwrap(),
            Position(0, 1)
        );

        // users can see their own position
        assert_eq!(
            service.obtain_position_report(0, 0, 0).await.unwrap(),
            Position(0, 0)
        );
        assert_eq!(
            service.obtain_position_report(1, 1, 0).await.unwrap(),
            Position(1, 0)
        );
        assert_eq!(
            service.obtain_position_report(0, 0, 1).await.unwrap(),
            Position(0, 1)
        );
        assert_eq!(
            service.obtain_position_report(1, 1, 1).await.unwrap(),
            Position(0, 1)
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
                .submit_position_proof(1234, bad_proof)
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
        assert!(service
            .submit_position_proof(1234, good_proof)
            .await
            .is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn inconsistent_user() {
        use crate::hdlt_store::test::PROOFS;
        let store = HdltLocalStore::open_memory().await;

        let p1 = PROOFS[0].clone();
        store.add_proof(p1).await.unwrap();

        let p1_prover_id = *PROOFS[0].prover_id();
        let p1_witness_id = *PROOFS[0].witnesses()[0].witness_id();
        // correctness of the test itself
        assert_ne!(p1_prover_id, p1_witness_id);
        assert_eq!(p1_prover_id, 0);
        assert_eq!(p1_witness_id, 42);

        // Build a proof where the prover from p1 is stating to be somewhere else as a witness
        let mut p2: UnverifiedPositionProof = PROOFS[0].clone().into();
        p2.witnesses[0].request.prover_id = 1000;
        p2.witnesses[0].witness_id = p1_prover_id;
        p2.witnesses[0].witness_position = Position(1000, 1000);
        // Safety: always memory-sfe, test can have data with bad signatures
        let p2 = unsafe { p2.verify_unchecked() };
        assert!(matches!(
            store.add_proof(p2).await.unwrap_err(),
            HdltLocalStoreError::InconsistentUser(0)
        ));

        // Build a proof where a witness from p1 is stating to be somewhere else as a prover
        let mut p2: UnverifiedPositionProof = PROOFS[0].clone().into();
        p2.witnesses[0].request.prover_id = p1_witness_id;
        p2.witnesses[0].request.position = Position(1000, 1000);
        p2.witnesses[0].witness_id = 1000;
        // Safety: always memory-sfe, test can have data with bad signatures
        let p2 = unsafe { p2.verify_unchecked() };
        assert!(matches!(
            store.add_proof(p2).await.unwrap_err(),
            HdltLocalStoreError::InconsistentUser(42)
        ));

        // Build a proof where a witness from p1 is stating to be somewhere else as a witness
        let mut p3: UnverifiedPositionProof = PROOFS[0].clone().into();
        p3.witnesses[0].request.prover_id = 1000;
        p3.witnesses[0].witness_position = Position(404, 404);
        // Safety: always memory-sfe, test can have data with bad signatures
        let p3 = unsafe { p3.verify_unchecked() };
        assert!(matches!(
            store.add_proof(p3).await.unwrap_err(),
            HdltLocalStoreError::InconsistentUser(42)
        ));
    }
}

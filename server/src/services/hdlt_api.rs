use std::sync::Arc;

use model::{
    api::RrRequest,
    keys::{EntityId, KeyStore},
    Position, UnverifiedPositionProof,
};
use model::{
    api::{ApiReply, ApiRequest, RrMessage},
    keys::Role,
    PositionProofValidationError,
};
use protos::hdlt::hdlt_api_server::HdltApi;
use protos::hdlt::CipheredRrMessage;
use thiserror::Error;

use tonic::{Request, Response, Status};
use tracing::instrument;
use tracing_utils::instrument_tonic_service;

use crate::hdlt_store::{HdltLocalStore, HdltLocalStoreError};

#[derive(Debug)]
pub struct HdltApiService {
    keystore: Arc<KeyStore>,
    store: HdltLocalStore,
    quorum_size: usize,
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
    pub fn new(keystore: Arc<KeyStore>, store: HdltLocalStore, quorum_size: usize) -> Self {
        HdltApiService {
            keystore,
            store,
            quorum_size,
        }
    }

    #[instrument]
    pub fn obtain_position_report(
        &self,
        requestor_id: EntityId,
        user_id: EntityId,
        epoch: u64,
    ) -> Result<Position, HdltApiError> {
        if requestor_id == user_id || self.keystore.role_of(&requestor_id) == Some(Role::HaClient) {
            self.store
                .user_position_at_epoch(user_id, epoch)
                .ok_or(HdltApiError::NoData)
        } else {
            Err(HdltApiError::PermissionDenied)
        }
    }

    #[instrument]
    pub fn users_at_position(
        &self,
        requestor_id: EntityId,
        position: Position,
        epoch: u64,
    ) -> Result<Vec<EntityId>, HdltApiError> {
        if self.keystore.role_of(&requestor_id) == Some(Role::HaClient) {
            Ok(self.store.users_at_position_at_epoch(position, epoch))
        } else {
            Err(HdltApiError::PermissionDenied)
        }
    }

    #[instrument]
    pub fn submit_position_proof(
        &self,
        _requestor_id: EntityId,
        proof: UnverifiedPositionProof,
    ) -> Result<(), HdltApiError> {
        let proof = proof.verify(self.quorum_size, self.keystore.as_ref())?;
        self.store.add_proof(proof)?;

        Ok(())
    }
}

type GrpcResult<T> = Result<Response<T>, Status>;

#[instrument_tonic_service]
#[tonic::async_trait]
impl HdltApi for HdltApiService {
    async fn invoke(&self, request: Request<CipheredRrMessage>) -> GrpcResult<CipheredRrMessage> {
        let current_epoch = 0u64; // TODO
        let (rr_message, requestor_id) = self.decipher_rr_message(request.into_inner());
        let request = rr_message
            .downcast_request(current_epoch)
            .expect("cannot downcast request-reply message to request");
        let grpc_error_mapper = self.grpc_error_mapper(requestor_id, &request, current_epoch);

        match request.as_ref() {
            ApiRequest::ObtainPositionReport { user_id, epoch } => self
                .obtain_position_report(requestor_id, *user_id, *epoch)
                .map(ApiReply::PositionReport),
            ApiRequest::ObtainUsersAtPosition { position, epoch } => self
                .users_at_position(requestor_id, position.clone(), *epoch)
                .map(ApiReply::UsersAtPosition),
            ApiRequest::SubmitPositionReport(proof) => self
                .submit_position_proof(requestor_id, proof.clone())
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
        let plaintext = self
            .keystore
            .decipher(&message.sender_id, &message.ciphertext, &message.nonce)
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
            nonce: nonce.to_vec(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hdlt_store::test::STORE;
    use lazy_static::lazy_static;
    use model::keys::test_data::KeyStoreTestData;

    lazy_static! {
        static ref KEYSTORES: KeyStoreTestData = KeyStoreTestData::new();
        static ref SVC: HdltApiService =
            HdltApiService::new(Arc::new(KEYSTORES.server.clone()), STORE.clone(), 2);
    }

    #[test]
    fn obtain_position_report() {
        // non-HA clients cannot see other users' positions
        let ha_client_id = *KEYSTORES.haclient.my_id();
        for id in KEYSTORES
            .iter()
            .map(|k| *k.my_id())
            .filter(|id| *id != ha_client_id)
        {
            assert!(matches!(
                SVC.obtain_position_report(id, 0, 0).unwrap_err(),
                HdltApiError::PermissionDenied
            ));
        }

        // HA client can see everyone's positions
        assert_eq!(
            SVC.obtain_position_report(ha_client_id, 0, 0).unwrap(),
            Position(0, 0)
        );
        assert_eq!(
            SVC.obtain_position_report(ha_client_id, 1, 0).unwrap(),
            Position(1, 0)
        );
        assert_eq!(
            SVC.obtain_position_report(ha_client_id, 0, 1).unwrap(),
            Position(0, 1)
        );
        assert_eq!(
            SVC.obtain_position_report(ha_client_id, 1, 1).unwrap(),
            Position(0, 1)
        );

        // users can see their own position
        assert_eq!(SVC.obtain_position_report(0, 0, 0).unwrap(), Position(0, 0));
        assert_eq!(SVC.obtain_position_report(1, 1, 0).unwrap(), Position(1, 0));
        assert_eq!(SVC.obtain_position_report(0, 0, 1).unwrap(), Position(0, 1));
        assert_eq!(SVC.obtain_position_report(1, 1, 1).unwrap(), Position(0, 1));

        // there may be no position data available
        assert!(matches!(
            SVC.obtain_position_report(50, 50, 0).unwrap_err(),
            HdltApiError::NoData
        ));
    }

    #[test]
    fn users_at_position() {
        // non-HA clients cannot use this method at all
        let ha_client_id = *KEYSTORES.haclient.my_id();
        for id in KEYSTORES
            .iter()
            .map(|k| *k.my_id())
            .filter(|id| *id != ha_client_id)
        {
            assert!(matches!(
                SVC.users_at_position(id, Position(0, 0), 0).unwrap_err(),
                HdltApiError::PermissionDenied
            ));
        }

        // HA client can see it all
        assert_eq!(
            vec![0],
            SVC.users_at_position(ha_client_id, Position(0, 0), 0)
                .unwrap()
        );
        assert_eq!(
            vec![1],
            SVC.users_at_position(ha_client_id, Position(1, 0), 0)
                .unwrap()
        );
        assert_eq!(
            vec![0, 1],
            SVC.users_at_position(ha_client_id, Position(0, 1), 1)
                .unwrap()
        );

        // sometimes there's nothing to see
        assert!(SVC.users_at_position(ha_client_id, Position(123, 123), 67981463).unwrap().is_empty());
    }

    #[test]
    fn add_proof() {
        let mut bad_proof: UnverifiedPositionProof =
            crate::hdlt_store::test::PROOFS[0].clone().into();
        bad_proof.witnesses[0].signature = vec![42]; // just in case our test data for hdlt_store becomes valid at some point
        assert!(matches!(
            SVC.submit_position_proof(1234, bad_proof).unwrap_err(),
            HdltApiError::InvalidPositionProof(..)
        ));

        let good_proof: UnverifiedPositionProof = {
            use model::{PositionProof, ProximityProof, ProximityProofRequest};
            let preq = ProximityProofRequest::new(123, Position(123, 123), &KEYSTORES.user1);
            let pproof = ProximityProof::new(preq, &KEYSTORES.user2).unwrap();

            PositionProof::new(vec![pproof], 2).unwrap().into()
        };
        assert!(SVC.submit_position_proof(1234, good_proof).is_ok());
    }
}

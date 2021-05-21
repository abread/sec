use std::convert::TryInto;
use std::sync::Arc;

use super::driver::ServerConfig;
use crate::group_by::group_by;
use crate::hdlt_store::{HdltLocalStore, HdltLocalStoreError};
use model::{
    api::{ApiReply, ApiRequest, PoWCertified, RrMessage, RrMessageError, RrRequest},
    keys::{EntityId, KeyStore, KeyStoreError, Nonce, Role},
    Position, PositionProof, PositionProofValidationError, UnverifiedPositionProof,
};
use protos::hdlt::hdlt_api_client::HdltApiClient as GrpcHdltApiClient;
use protos::hdlt::hdlt_api_server::HdltApi;
use protos::hdlt::CipheredRrMessage;
use std::collections::HashMap;
use std::fmt::Debug;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;
use tonic::transport::{Channel, Uri};
use tonic::{Request, Response, Status};
use tower::timeout::Timeout;
use tracing::*;
use tracing_utils::instrument_tonic_service;
use tracing_utils::Request;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15); // 15s ought to be enough

type GrpcResult<T> = Result<Response<T>, Status>;
type HdltResult<T> = Result<T, HdltError>;

#[derive(Debug)]
pub struct HdltApiService {
    keystore: Arc<KeyStore>,
    store: Arc<HdltLocalStore>,
    answers: Arc<RwLock<HashMap<EntityId, AtomicReadAnswers>>>,
    server_listeners: Arc<RwLock<HashMap<EntityId, Vec<(EntityId, u64)>>>>,
    client_listeners: Arc<RwLock<HashMap<EntityId, Vec<(u64, EntityId, Uri)>>>>,
    config: Arc<RwLock<ServerConfig>>,
    server_uris: Vec<Uri>,
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

    #[error("invalid callback uri")]
    BadCallbackUri,
}

impl HdltApiService {
    pub fn new(
        keystore: Arc<KeyStore>,
        store: Arc<HdltLocalStore>,
        config: Arc<RwLock<ServerConfig>>,
        server_uris: Vec<Uri>,
    ) -> Self {
        HdltApiService {
            keystore,
            store,
            config,
            answers: Arc::new(RwLock::new(HashMap::new())),
            server_listeners: Arc::new(RwLock::new(HashMap::new())),
            client_listeners: Arc::new(RwLock::new(HashMap::new())),
            server_uris,
        }
    }

    #[instrument(skip(self))]
    pub async fn obtain_position_report(
        &self,
        request_id: u64,
        requestor_id: EntityId,
        prover_id: EntityId,
        epoch: u64,
        callback_uri: &str,
    ) -> Result<(u64, Position), HdltApiError> {
        if requestor_id == prover_id || self.keystore.role_of(requestor_id) == Some(Role::HaClient)
        {
            let callback_uri: Uri = callback_uri
                .try_into()
                .map_err(|_| HdltApiError::BadCallbackUri)?;

            let max_neigh_faults = self.config.read().await.max_neigh_faults;
            let prox_proofs = self.store.query_epoch_prover(epoch, prover_id).await?;
            self.client_listeners
                .write()
                .await
                .entry(prover_id)
                .or_insert(vec![(request_id, requestor_id, callback_uri.clone())])
                .push((request_id, requestor_id, callback_uri));

            match PositionProof::new(prox_proofs, max_neigh_faults as usize) {
                Ok(proof) => {
                    self.server_listeners
                        .write()
                        .await
                        .entry(prover_id)
                        .or_insert_with(|| vec![(requestor_id, request_id)])
                        .push((requestor_id, request_id));
                    self.add_value(
                        requestor_id,
                        request_id,
                        prover_id,
                        proof.clone().into(),
                        proof.epoch(),
                    )
                    .await?;
                    Ok((proof.epoch(), proof.position()))
                }
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
            match PositionProof::new(prox_proofs, max_neigh_faults as usize) {
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
        if self.keystore.role_of(requestor_id) == Some(Role::HaClient) {
            let max_neigh_faults = self.config.read().await.max_neigh_faults;

            let all_prox_proofs = self
                .store
                .query_epoch_prover_position(epoch, prover_position)
                .await?;
            let uids = group_by(&all_prox_proofs, |a, b| a.prover_id() == b.prover_id())
                .map(|witnesses| PositionProof::new(witnesses.to_vec(), max_neigh_faults as usize))
                .filter_map(|res| match res {
                    Ok(pos_proof) => Some(pos_proof.prover_id()),
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
        requestor_id: EntityId,
        pow_protected_proof: &PoWCertified<UnverifiedPositionProof>,
    ) -> Result<(), HdltApiError> {
        let proof = pow_protected_proof
            .to_owned()
            .try_into_inner()
            .map_err(|_| HdltApiError::InvalidProofOfWork)?;

        let max_neigh_faults = self.config.read().await.max_neigh_faults;
        let proof = proof.verify(max_neigh_faults as usize, self.keystore.as_ref())?;

        if proof.prover_id() != requestor_id {
            return Err(HdltApiError::PermissionDenied);
        }

        self.store.add_proof(proof.clone()).await?;

        self.send_to_server_listeners(requestor_id, proof.epoch(), proof.into())
            .await?;

        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn add_value(
        &self,
        requestor_id: EntityId,
        request_id: u64,
        client_id: EntityId,
        proof: UnverifiedPositionProof,
        epoch: u64,
    ) -> Result<(), HdltApiError> {
        let mut aguard = self.answers.write().await;

        if !aguard.contains_key(&client_id) {
            let cguard = self.config.read().await;
            aguard.insert(
                client_id,
                AtomicReadAnswers::new(
                    cguard.n_servers() as usize,
                    cguard.max_server_faults as usize,
                ),
            );
        }

        if let Some(val) = aguard
            .get_mut(&client_id)
            .unwrap()
            .push(requestor_id, epoch, proof)
        {
            self.send_to_client_listeners(val).await?; // TODO
            aguard.remove(&client_id);
        }

        Ok(())
    }

    async fn send_to_server_listeners(
        &self,
        register_id: EntityId,
        epoch: u64,
        proof: UnverifiedPositionProof,
    ) -> Result<(), HdltApiError> {
        if let Some(l) = self.server_listeners.write().await.get_mut(&register_id) {
            let config = self.config.read().await;

            let current_epoch = config.epoch;
            let id_uri_map = config.id_uri_map.clone();
            let keystore = self.keystore.clone();
            let listeners_to_send: Vec<_> = l.drain(..).collect();
            tokio::spawn(async move {
                let clients: Vec<_> = listeners_to_send
                    .into_iter()
                    .map(|(server_id, request_id)| {
                        (
                            HdltApiClient::new(
                                id_uri_map[&server_id].clone(),
                                server_id,
                                keystore.clone(),
                                current_epoch,
                            ),
                            request_id,
                        )
                    })
                    .filter(|(c, _)| c.is_ok())
                    .map(|(c, id)| (c.unwrap(), id))
                    .collect();

                futures::future::join_all(
                    clients
                        .iter()
                        .map(|(c, request_id)| {
                            c.return_value(*request_id, proof.clone(), epoch, register_id)
                        })
                        .collect::<Vec<_>>(),
                )
                .await;
            });
        }

        Ok(())
    }

    /// Send this value to all clients waiting on this register
    async fn send_to_client_listeners(
        &self,
        proof: UnverifiedPositionProof,
    ) -> Result<(), HdltApiError> {
        let (verified_proof, current_epoch) = {
            let config = self.config.read().await;
            (
                proof
                    .clone()
                    .verify(config.max_neigh_faults as usize, &self.keystore)?,
                config.epoch,
            )
        };

        let register_id = verified_proof.prover_id();

        if let Some(l) = self.client_listeners.write().await.get_mut(&register_id) {
            let keystore = self.keystore.clone();
            let listeners_to_send: Vec<_> = l.drain(..).collect();
            tokio::spawn(async move {
                let clients: Vec<_> = listeners_to_send
                    .into_iter()
                    .map(|(rid, client_id, uri)| {
                        (
                            rid,
                            HdltApiClient::new(uri, client_id, keystore.clone(), current_epoch),
                        )
                    })
                    .filter(|(_, c)| c.is_ok())
                    .map(|(rid, c)| (rid, c.unwrap()))
                    .collect();

                futures::future::join_all(
                    clients
                        .iter()
                        .map(|(rid, c)| {
                            c.return_value(
                                *rid,
                                proof.clone(),
                                verified_proof.epoch(),
                                verified_proof.prover_id(),
                            )
                        })
                        .collect::<Vec<_>>(),
                )
                .await;
            });
        }

        Ok(())
    }
}

#[derive(Debug)]
struct AtomicReadAnswers {
    n: usize,
    f: usize,
    answers: HashMap<u64, HashMap<EntityId, UnverifiedPositionProof>>,
    counts: HashMap<(u64, UnverifiedPositionProof), usize>,
}

impl AtomicReadAnswers {
    fn new(n: usize, f: usize) -> Self {
        Self {
            n,
            f,
            answers: HashMap::new(),
            counts: HashMap::new(),
        }
    }

    fn quorum_size(&self) -> usize {
        (self.n + self.f) / 2
    }

    fn push(
        &mut self,
        q: EntityId,
        epoch: u64,
        proof: UnverifiedPositionProof,
    ) -> Option<UnverifiedPositionProof> {
        let epoch_answers = self.answers.entry(epoch).or_default();

        #[allow(clippy::map_entry)]
        if !epoch_answers.contains_key(&q) {
            epoch_answers.insert(q, proof.clone());
            *self.counts.entry((epoch, proof.clone())).or_insert(1) += 1;

            if self.counts[&(epoch, proof.clone())] > self.quorum_size() {
                return Some(proof);
            }
        }

        None
    }
}

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
            ApiRequest::ObtainPositionReport {
                request_id,
                user_id,
                epoch,
                callback_uri,
            } => self
                .obtain_position_report(*request_id, requestor_id, *user_id, *epoch, callback_uri)
                .await
                .map(|_| ApiReply::Ok),
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
            ApiRequest::AddValue {
                request_id,
                proof,
                epoch,
                client_id,
            } => self
                .add_value(requestor_id, *request_id, *client_id, proof.clone(), *epoch)
                .await
                .map(|_| ApiReply::Ok),
            _ => unimplemented!("invalid option for server API"),
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
            .decipher(message.sender_id, &message.ciphertext, &nonce)
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
            .cipher(partner_id, &plaintext)
            .expect("could not cipher reply");

        CipheredRrMessage {
            sender_id: self.keystore.my_id(),
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
                max_server_faults: 0,
                servers: vec![],
                id_uri_map: HashMap::new(),
            })),
            vec![],
        )
    }

    /*
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn obtain_position_report() {
        let service = build_service().await;

        // non-HA clients cannot see other users' positions
        let ha_client_id = KEYSTORES.haclient.my_id();
        for id in KEYSTORES
            .iter()
            .map(|k| k.my_id())
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
    */

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn users_at_position() {
        let service = build_service().await;

        // non-HA clients cannot use this method at all
        let ha_client_id = KEYSTORES.haclient.my_id();
        for id in KEYSTORES
            .iter()
            .map(|k| k.my_id())
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
                .submit_position_proof(1, &PoWCertified::new(bad_proof))
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
        let good_proof = PoWCertified::new(good_proof);

        // can't submit someone else's stuff
        assert!(matches!(
            service.submit_position_proof(4321, &good_proof).await,
            Err(HdltApiError::PermissionDenied)
        ));

        // happy path
        assert!(service.submit_position_proof(1, &good_proof).await.is_ok());
    }
}

#[derive(Debug)]
pub struct HdltApiClient {
    /// All the GRPC channels
    channel: Channel,

    /// Server Id
    id: EntityId,

    /// Key store
    keystore: Arc<KeyStore>,

    /// Current epoch: works as a timestamp in the procotol,
    /// since there must only be one proof per epoch
    ///
    current_epoch: u64,
}

#[derive(Debug, Error)]
pub enum HdltError {
    #[error("Error creating remote")]
    InitializationError(#[source] tonic::transport::Error),

    #[error("Failed to serialize request")]
    SerializationError(#[source] Box<bincode::ErrorKind>),

    #[error("Failed to cipher request")]
    CipherError(#[source] KeyStoreError),

    #[error("Server sent unexpected status")]
    UnexpectedStatus(#[from] Status),

    #[error("Invalid nonce")]
    InvalidNonce,

    #[error("Failed to decipher reply")]
    DecipherError(#[source] KeyStoreError),

    #[error("Failed to deserialize reply")]
    DeserializationError(#[source] Box<bincode::ErrorKind>),

    #[error("Request reply protocol violation")]
    RequestReplyProtocolViolation(#[from] RrMessageError),

    #[error("Error executing request: {}", .0)]
    ServerError(String),

    #[error("Server sent unexpected reply message: {:#?}", .0)]
    UnexpectedReply(ApiReply),
}

impl HdltApiClient {
    pub fn new(
        uri: Uri,
        id: EntityId,
        keystore: Arc<KeyStore>,
        current_epoch: u64,
    ) -> HdltResult<Self> {
        let channel = Channel::builder(uri)
            .connect_lazy()
            .map_err(HdltError::InitializationError)?;

        Ok(HdltApiClient {
            channel,
            id,
            keystore,
            current_epoch,
        })
    }

    /// Server returns a value to the client
    ///
    #[instrument]
    pub async fn return_value<T: Into<UnverifiedPositionProof> + Debug>(
        &self,
        request_id: u64,
        proof: T,
        epoch: u64,
        client_id: EntityId,
    ) -> HdltResult<()> {
        let proof = proof.into();
        self.invoke_no_wait(ApiRequest::ReturnAtomicValue {
            request_id,
            proof,
            epoch,
            client_id,
        })
        .await
    }

    /// Server adds a value to the answer map
    ///
    /// Invokes a protocol write (with atomic semantics)
    ///
    #[instrument]
    pub async fn add_value<T: Into<UnverifiedPositionProof> + Debug>(
        &self,
        request_id: u64,
        proof: T,
        epoch: u64,
        client_id: EntityId,
    ) -> HdltResult<()> {
        let proof = proof.into();
        self.invoke_no_wait(ApiRequest::AddValue {
            request_id,
            proof,
            epoch,
            client_id,
        })
        .await
    }

    /// Server invokes a request at the server, confidentially
    /// Does not wait for replies
    ///
    ///
    async fn invoke_no_wait(&self, request: ApiRequest) -> HdltResult<()> {
        let (_request, grpc_request) =
            self.prepare_request(request, self.current_epoch, self.id)?;
        let mut grpc_client =
            GrpcHdltApiClient::new(Timeout::new(self.channel.clone(), REQUEST_TIMEOUT));
        grpc_client.invoke(grpc_request).await?;

        Ok(())
    }

    /// Prepare a request
    ///  - Install freshness information and request id (cookie)
    ///  - Cipher with integrity protection
    ///  - This has an implicit authenticated because both
    ///     the user and the server derive a key in the same way
    ///
    fn prepare_request(
        &self,
        payload: ApiRequest,
        current_epoch: u64,
        server_id: u32,
    ) -> HdltResult<(RrRequest<ApiRequest>, tonic::Request<CipheredRrMessage>)> {
        let request_msg = RrMessage::new_request(current_epoch, payload);

        let plaintext = bincode::serialize(&request_msg).map_err(HdltError::SerializationError)?;
        let (ciphertext, nonce) = self
            .keystore
            .cipher(server_id, &plaintext)
            .map_err(HdltError::CipherError)?;
        let grpc_request = Request!(CipheredRrMessage {
            sender_id: self.keystore.my_id(),
            ciphertext,
            nonce: nonce.0.to_vec(),
        });

        let request = request_msg.downcast_request(current_epoch).unwrap(); // impossible to fail

        Ok((request, grpc_request))
    }

    fn parse_response(
        &self,
        grpc_response: tonic::Response<CipheredRrMessage>,
        request: &RrRequest<ApiRequest>,
        current_epoch: u64,
        server_id: u32,
    ) -> HdltResult<ApiReply> {
        let grpc_response = grpc_response.into_inner();
        let nonce = Nonce::from_slice(&grpc_response.nonce).ok_or(HdltError::InvalidNonce)?;

        let plaintext = self
            .keystore
            .decipher(server_id, &grpc_response.ciphertext, &nonce)
            .map_err(HdltError::DecipherError)?;
        let reply_rr_message: RrMessage<ApiReply> =
            bincode::deserialize(&plaintext).map_err(HdltError::DeserializationError)?;

        Ok(reply_rr_message
            .downcast_reply(&request, current_epoch)?
            .into_inner())
    }
}

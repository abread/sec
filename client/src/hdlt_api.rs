use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use protos::hdlt::hdlt_api_client::HdltApiClient as GrpcHdltApiClient;
use protos::hdlt::CipheredRrMessage;
use tokio::sync::{oneshot, RwLock};
use tonic::transport::{Channel, Server, Uri};
use tonic::Status;
use tower::timeout::Timeout;
use tracing::*;
use tracing_utils::Request;

use model::{
    api::{ApiReply, ApiRequest, PoWCertified, RrMessage, RrMessageError, RrRequest},
    keys::{EntityId, KeyStore, KeyStoreError, Nonce},
    Position, PositionProofValidationError, UnverifiedPositionProof,
};

use thiserror::Error;
use tracing::instrument;

use crate::create_tcp_incoming;

static REQUEST_ID: AtomicU64 = AtomicU64::new(0);

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15); // 15s ought to be enough

#[derive(Debug)]
pub struct HdltApiClient {
    /// All the GRPC channels
    channels: Arc<RwLock<HashMap<u32, Channel>>>,

    /// Key store
    keystore: Arc<KeyStore>,

    /// Current epoch: works as a timestamp in the procotol,
    /// since there must only be one proof per epoch
    ///
    current_epoch: u64,

    /// Number of tolerated (arbirtrary) server faults
    ///
    neighbour_faults: u64,

    /// Number of tolerated (arbirtrary) server faults
    ///
    server_faults: u64,

    /// Notification mechanism
    notification: ReturnNotification,
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

    #[error("Oneshot channel failure")]
    ChannelError,

    #[error("Invalid Position Proof")]
    InvalidPositionProof(#[from] PositionProofValidationError),
}

type Result<T> = std::result::Result<T, HdltError>;

impl HdltApiClient {
    pub fn new(
        uris: Vec<(u32, Uri)>,
        keystore: Arc<KeyStore>,
        current_epoch: u64,
        server_faults: u64,
        neighbour_faults: u64,
    ) -> Result<Self> {
        let channels = Arc::new(RwLock::new(
            uris.into_iter()
                .map(|(id, uri)| {
                    Ok((
                        id,
                        Channel::builder(uri)
                            .connect_lazy()
                            .map_err(HdltError::InitializationError)?,
                    ))
                })
                .collect::<Result<HashMap<u32, Channel>>>()?,
        ));

        Ok(HdltApiClient {
            channels,
            keystore,
            current_epoch,
            server_faults,
            neighbour_faults,
            notification: ReturnNotification::new(),
        })
    }

    /// User submits position report to server
    ///
    /// Invokes a protocol write (with atomic semantics)
    ///
    #[instrument]
    pub async fn submit_position_report<P: Into<UnverifiedPositionProof> + Debug>(
        &self,
        proof: P,
    ) -> Result<()> {
        let pow_protected = PoWCertified::new(proof.into());
        self.invoke_atomic_write(ApiRequest::SubmitPositionReport(pow_protected))
            .await
            .and_then(|reply| match reply {
                ApiReply::Ok => Ok(()),
                ApiReply::Error(e) => Err(HdltError::ServerError(e)),
                other => Err(HdltError::UnexpectedReply(other)),
            })
    }

    /// Health authority obtains position report from the server
    /// ** or **
    /// User obtains its own position report from the server
    ///
    /// Invokes a protocol read (with atomic semantics)
    ///
    #[instrument]
    pub async fn obtain_position_report(&self, user_id: EntityId, epoch: u64) -> Result<Position> {
        self.invoke_atomic_read(ApiRequest::ObtainPositionReport {
            request_id: REQUEST_ID.fetch_add(1, Ordering::SeqCst),
            user_id,
            epoch,
            callback_uri: String::new(), // will be overriden
        })
        .await
        .and_then(|reply| match reply {
            ApiReply::PositionReport(_, loc) => Ok(loc),
            ApiReply::Error(e) => Err(HdltError::ServerError(e)),
            other => Err(HdltError::UnexpectedReply(other)),
        })
    }

    /// User obtains its own position reports from the server, for a specified range of epochs
    ///
    /// Invokes a protocol read (with regular semantics)
    ///
    #[instrument]
    pub async fn request_position_reports(
        &self,
        user_id: EntityId,
        epoch_range: std::ops::Range<u64>,
    ) -> Result<Vec<(u64, UnverifiedPositionProof)>> {
        self.invoke_regular_read(
            ApiRequest::RequestPositionReports {
                epoch_start: epoch_range.start,
                epoch_end: epoch_range.end,
            },
            |resp| resp.key(),
        )
        .await
        .and_then(|reply| match reply {
            ApiReply::PositionReports(locs) => Ok(locs),
            ApiReply::Error(e) => Err(HdltError::ServerError(e)),
            other => Err(HdltError::UnexpectedReply(other)),
        })
    }

    /// Health authority obtains all users at a position
    ///
    /// Invokes a protocol read (with regular semantics)
    ///
    #[instrument]
    pub async fn obtain_users_at_position(
        &self,
        position: Position,
        epoch: u64,
    ) -> Result<Vec<EntityId>> {
        self.invoke_regular_read(
            ApiRequest::ObtainUsersAtPosition { position, epoch },
            |resp| resp.key(),
        )
        .await
        .and_then(|reply| match reply {
            ApiReply::UsersAtPosition(users) => Ok(users),
            ApiReply::Error(e) => Err(HdltError::ServerError(e)),
            other => Err(HdltError::UnexpectedReply(other)),
        })
    }

    /// User invokes a request at the server, confidentially
    ///
    /// Implements the client side regular read protocol
    /// TODO: reason about the necessity of the request id (`rid`)
    ///
    async fn invoke_regular_read(
        &self,
        request: ApiRequest,
        key: fn(&ApiReply) -> u64,
    ) -> Result<ApiReply> {
        let num_servers = self.channels.read().await.len();
        let mut futs = FuturesUnordered::new();
        let mut grpc_clients = Vec::with_capacity(num_servers);
        for r in self.channels.read().await.iter() {
            let (request, grpc_request) =
                self.prepare_request(request.clone(), self.current_epoch, *r.0)?;
            let mut grpc_client =
                GrpcHdltApiClient::new(Timeout::new(r.1.clone(), REQUEST_TIMEOUT));
            let key = *r.0;
            let response_fut = grpc_client.invoke(grpc_request).await;
            futs.push(async move { (key, request, response_fut) });
            grpc_clients.push(grpc_client);
        }

        let mut resps = Vec::with_capacity(num_servers);
        loop {
            futures::select! {
                res = futs.select_next_some() => {
                    match res {
                        (server_id, request, Ok(grpc_response)) => resps.push(self.parse_response(grpc_response, &request, self.current_epoch, server_id)?),
                        (server_id, request, Err(e)) => {
                            warn!("calling {:?} on server {} failed: {:?}", request, server_id, e);
                        }
                    }

                    if resps.len() > (num_servers + self.server_faults as usize) / 2 {
                        break;
                    }
                }
            }
        }

        Ok(resps.into_iter().max_by_key(key).unwrap())
    }

    /// User invokes a request at the server, confidentially
    ///
    /// Implements the client side atomic read protocol
    /// TODO: reason about the necessity of the request id (`rid`)
    ///
    async fn invoke_atomic_read(&self, request: ApiRequest) -> Result<ApiReply> {
        let cb_service = CallbackService::new(
            self.current_epoch,
            self.keystore.clone(),
            self.notification.clone(),
        );

        // TODO: have some mechanism to choose the listening IP addr
        let (server_incoming, server_addr) = create_tcp_incoming(&"127.0.0.1:0".parse().unwrap())
            .await
            .expect("failed to create callback server");
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(protos::hdlt::hdlt_api_server::HdltApiServer::new(
                    cb_service,
                ))
                .serve_with_incoming(server_incoming)
                .await
                .expect("callback server error");
        });

        let callback_uri = format!("http://127.0.0.1:{}/", server_addr.port());
        let (request, req_id) = match request {
            ApiRequest::ObtainPositionReport {
                request_id,
                user_id,
                epoch,
                ..
            } => (
                ApiRequest::ObtainPositionReport {
                    request_id,
                    user_id,
                    epoch,
                    callback_uri,
                },
                request_id,
            ),
            _ => unreachable!("only implemented for ObtainPositionReport"),
        };

        let mut futs = Vec::new();
        for (k, v) in self
            .channels
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
        {
            let (request, grpc_request) =
                self.prepare_request(request.clone(), self.current_epoch.clone(), k.clone())?;
            futs.push(async move {
                let mut grpc_client = GrpcHdltApiClient::new(Timeout::new(v, REQUEST_TIMEOUT));
                let response = grpc_client.invoke(grpc_request).await;

                (k, request, response)
            });
        }

        let handle = tokio::spawn(async move { futures::future::join_all(futs).await });

        let rx = self.notification.wait_on(req_id).await;

        let res = rx.await.map_err(|_| HdltError::ChannelError)?;

        // close temporary server
        server.abort();
        handle.abort();
        Ok(ApiReply::PositionReport(
            res.2,
            res.0
                .verify(self.neighbour_faults as usize, &self.keystore)?
                .position(),
        ))
    }

    /// User invokes a request at the server, confidentially
    ///
    /// Implements the client side atomic write protocol
    /// Nice property: the epoch number can act as a timestamp
    ///
    async fn invoke_atomic_write(&self, request: ApiRequest) -> Result<ApiReply> {
        let num_servers = self.channels.read().await.len();
        let mut futs = FuturesUnordered::new();
        for (k, v) in self
            .channels
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
        {
            let (request, grpc_request) =
                self.prepare_request(request.clone(), self.current_epoch, k)?;

            futs.push(async move {
                let mut grpc_client =
                    GrpcHdltApiClient::new(Timeout::new(v.clone(), REQUEST_TIMEOUT));

                grpc_client
                    .invoke(grpc_request)
                    .await
                    .map_err(|e| e.into())
                    .and_then(|grpc_response| {
                        self.parse_response(grpc_response, &request, self.current_epoch, k)
                    })
                    .and_then(|reply| {
                        // on a write, all must reply with ok
                        if let ApiReply::Ok = reply {
                            Ok(())
                        } else {
                            Err(HdltError::UnexpectedReply(reply))
                        }
                    })
                    .map_err(|e| (k, request, e))
            });
        }

        let mut replies = 0usize;
        loop {
            futures::select! {
                res = futs.select_next_some() => {
                    match res {
                        Ok(()) => replies += 1,
                        Err((server_id, request, e)) => {
                            warn!("calling {:?} on server {} failed: {:?}", request, server_id, e);
                        }
                    }

                    if replies > (num_servers + self.server_faults as usize) / 2 {
                        break;
                    }
                }
            }
        }

        Ok(ApiReply::Ok)
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
    ) -> Result<(RrRequest<ApiRequest>, tonic::Request<CipheredRrMessage>)> {
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
    ) -> Result<ApiReply> {
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

type NotificationValue = (UnverifiedPositionProof, EntityId, u64);

#[derive(Debug)]
struct ReturnNotification(Arc<RwLock<HashMap<u64, oneshot::Sender<NotificationValue>>>>);
impl ReturnNotification {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(HashMap::new())))
    }

    pub async fn wait_on(&self, request_id: u64) -> oneshot::Receiver<NotificationValue> {
        let (tx, rx) = oneshot::channel();
        self.0.write().await.insert(request_id, tx);
        rx
    }

    pub async fn send(&self, request_id: u64, val: NotificationValue) {
        if let Some(tx) = self.0.write().await.remove(&request_id) {
            if let Err(_) = tx.send(val) {
                warn!("Sending failed: probably dropped receiver");
            }
        }
    }
}

impl Clone for ReturnNotification {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

struct CallbackService {
    current_epoch: u64,
    keystore: Arc<KeyStore>,
    notification: ReturnNotification,
}

impl<'a> CallbackService {
    pub fn new(
        current_epoch: u64,
        keystore: Arc<KeyStore>,
        notification: ReturnNotification,
    ) -> Self {
        CallbackService {
            current_epoch,
            keystore,
            notification,
        }
    }

    async fn return_value(
        &self,
        request_id: u64,
        proof: UnverifiedPositionProof,
        client_id: EntityId,
        epoch: u64,
    ) {
        self.notification
            .send(request_id, (proof, client_id, epoch))
            .await
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

#[tonic::async_trait]
impl protos::hdlt::hdlt_api_server::HdltApi for CallbackService {
    async fn invoke(
        &self,
        request: tonic::Request<CipheredRrMessage>,
    ) -> std::result::Result<tonic::Response<CipheredRrMessage>, tonic::Status> {
        let (rr_message, requestor_id) = self.decipher_rr_message(request.into_inner());
        let request = rr_message
            .downcast_request(self.current_epoch)
            .expect("cannot downcast request-reply message to request");

        match request.as_ref() {
            ApiRequest::ReturnAtomicValue {
                proof,
                client_id,
                epoch,
                request_id,
            } => {
                self.return_value(*request_id, proof.clone(), *client_id, *epoch)
                    .await
            }

            _ => (),
        }

        Ok(tonic::Response::new(self.cipher_rr_message(
            RrMessage::new_reply(&request, self.current_epoch, ApiReply::Ok),
            requestor_id,
        )))
    }
}

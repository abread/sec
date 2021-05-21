use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use futures::stream::{FuturesUnordered, StreamExt};
use protos::hdlt::hdlt_api_client::HdltApiClient as GrpcHdltApiClient;
use protos::hdlt::CipheredRrMessage;
use tonic::transport::{Channel, Uri};
use tonic::Status;
use tower::timeout::Timeout;
use tracing::*;
use tracing_utils::Request;

use model::{
    api::{ApiReply, ApiRequest, RrMessage, RrMessageError, RrRequest},
    keys::{EntityId, KeyStore, KeyStoreError, Nonce},
    Position, UnverifiedPositionProof,
};

use thiserror::Error;
use tracing::instrument;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15); // 15s ought to be enough

#[derive(Debug)]
pub struct HdltApiClient {
    channels: DashMap<u32, Channel>,
    keystore: Arc<KeyStore>,
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

type Result<T> = std::result::Result<T, HdltError>;

impl HdltApiClient {
    pub fn new(uris: Vec<(u32, Uri)>, keystore: Arc<KeyStore>, current_epoch: u64) -> Result<Self> {
        let channels = uris
            .into_iter()
            .map(|(id, uri)| {
                Ok((
                    id,
                    Channel::builder(uri)
                        .connect_lazy()
                        .map_err(HdltError::InitializationError)?,
                ))
            })
            .collect::<Result<DashMap<u32, Channel>>>()?;

        Ok(HdltApiClient {
            channels,
            keystore,
            current_epoch,
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
        self.invoke(ApiRequest::SubmitPositionReport(proof.into()))
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
        self.invoke(ApiRequest::ObtainPositionReport { user_id, epoch })
            .await
            .and_then(|reply| match reply {
                ApiReply::PositionReport(loc) => Ok(loc),
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
    ) -> Result<Vec<(u64, Position)>> {
        self.invoke(ApiRequest::RequestPositionReports {
            user_id,
            epoch_start: epoch_range.start,
            epoch_end: epoch_range.end,
        })
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
        self.invoke(ApiRequest::ObtainUsersAtPosition { position, epoch })
            .await
            .and_then(|reply| match reply {
                ApiReply::UsersAtPosition(users) => Ok(users),
                ApiReply::Error(e) => Err(HdltError::ServerError(e)),
                other => Err(HdltError::UnexpectedReply(other)),
            })
    }

    /// User invokes a request at the server, confidentially
    ///
    async fn invoke(&self, request: ApiRequest) -> Result<ApiReply> {
        let mut futs = FuturesUnordered::new();
        let mut grpc_clients = Vec::with_capacity(self.channels.len());
        for r in self.channels.iter() {
            let (request, grpc_request) =
                self.prepare_request(request.clone(), self.current_epoch, *r.key())?;
            let mut grpc_client =
                GrpcHdltApiClient::new(Timeout::new(r.value().clone(), REQUEST_TIMEOUT));
            let key = *r.key();
            let response_fut = grpc_client.invoke(grpc_request).await;
            futs.push(async move { (key, request, response_fut) });
            grpc_clients.push(grpc_client);
        }

        loop {
            futures::select! {
                res = futs.select_next_some() => {
                    match res {
                        (server_id, request, Ok(grpc_response)) => return self.parse_response(grpc_response, &request, self.current_epoch, server_id),
                        (server_id, request, Err(e)) => {
                            warn!("calling {:?} on server {} failed: {:?}", request, server_id, e);
                        }
                    }
                }
            }
        }
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
            .cipher(&server_id, &plaintext)
            .map_err(HdltError::CipherError)?;
        let grpc_request = Request!(CipheredRrMessage {
            sender_id: *self.keystore.my_id(),
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
            .decipher(&server_id, &grpc_response.ciphertext, &nonce)
            .map_err(HdltError::DecipherError)?;
        let reply_rr_message: RrMessage<ApiReply> =
            bincode::deserialize(&plaintext).map_err(HdltError::DeserializationError)?;

        Ok(reply_rr_message
            .downcast_reply(&request, current_epoch)?
            .into_inner())
    }
}

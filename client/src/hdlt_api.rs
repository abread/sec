use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use protos::hdlt::hdlt_api_client::HdltApiClient as GrpcHdltApiClient;
use protos::hdlt::CipheredRrMessage;
use tonic::transport::{Channel, Uri};
use tonic::Status;
use tower::timeout::Timeout;
use tracing_utils::Request;

use model::{
    api::{ApiReply, ApiRequest, RrMessage, RrMessageError, RrRequest},
    keys::{EntityId, KeyStore, KeyStoreError},
    Location, UnverifiedLocationProof,
};

use thiserror::Error;
use tracing::instrument;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15); // 15s ought to be enough

#[derive(Debug)]
pub struct HdltApiClient {
    channel: Channel,
    keystore: Arc<KeyStore>,
}

#[derive(Debug, Error)]
pub enum CenasClientError {
    #[error("Error creating remote")]
    InitializationError(#[source] tonic::transport::Error),

    #[error("Failed to serialize request")]
    SerializationError(#[source] Box<bincode::ErrorKind>),

    #[error("Failed to cipher request")]
    CipherError(#[source] KeyStoreError),

    #[error("Server sent unexpected status")]
    UnexpectedStatus(#[from] Status),

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

type Result<T> = std::result::Result<T, CenasClientError>;

impl HdltApiClient {
    pub fn new(uri: Uri, keystore: Arc<KeyStore>) -> Result<Self> {
        let channel = Channel::builder(uri)
            .connect_lazy()
            .map_err(CenasClientError::InitializationError)?;

        Ok(HdltApiClient { channel, keystore })
    }

    #[instrument]
    pub async fn submit_location_report<P: Into<UnverifiedLocationProof> + Debug>(
        &self,
        proof: P,
    ) -> Result<()> {
        self.invoke(ApiRequest::SubmitLocationReport(proof.into()))
            .await
            .and_then(|reply| match reply {
                ApiReply::Ok => Ok(()),
                ApiReply::Error(e) => Err(CenasClientError::ServerError(e)),
                other => Err(CenasClientError::UnexpectedReply(other)),
            })
    }

    #[instrument]
    pub async fn obtain_location_report(&self, user_id: EntityId, epoch: u64) -> Result<Location> {
        self.invoke(ApiRequest::ObtainLocationReport { user_id, epoch })
            .await
            .and_then(|reply| match reply {
                ApiReply::LocationReport(loc) => Ok(loc),
                ApiReply::Error(e) => Err(CenasClientError::ServerError(e)),
                other => Err(CenasClientError::UnexpectedReply(other)),
            })
    }

    #[instrument]
    pub async fn obtain_users_at_location(
        &self,
        location: Location,
        epoch: u64,
    ) -> Result<Vec<EntityId>> {
        self.invoke(ApiRequest::ObtainUsersAtLocation { location, epoch })
            .await
            .and_then(|reply| match reply {
                ApiReply::UsersAtLocation(users) => Ok(users),
                ApiReply::Error(e) => Err(CenasClientError::ServerError(e)),
                other => Err(CenasClientError::UnexpectedReply(other)),
            })
    }

    async fn invoke(&self, request: ApiRequest) -> Result<ApiReply> {
        let current_epoch = 0; // TODO
        let server_id: u32 = 0; // TODO

        let (request, grpc_request) = self.prepare_request(request, current_epoch, server_id)?;

        let mut grpc_client =
            GrpcHdltApiClient::new(Timeout::new(self.channel.clone(), REQUEST_TIMEOUT));
        let grpc_response = grpc_client.invoke(grpc_request).await?;

        self.parse_response(grpc_response, &request, current_epoch, server_id)
    }

    fn prepare_request(
        &self,
        payload: ApiRequest,
        current_epoch: u64,
        server_id: u32,
    ) -> Result<(RrRequest<ApiRequest>, tonic::Request<CipheredRrMessage>)> {
        let request_msg = RrMessage::new_request(current_epoch, payload);

        let plaintext =
            bincode::serialize(&request_msg).map_err(CenasClientError::SerializationError)?;
        let (ciphertext, nonce) = self
            .keystore
            .cipher(&server_id, &plaintext)
            .map_err(CenasClientError::CipherError)?;
        let grpc_request = Request!(CipheredRrMessage {
            sender_id: *self.keystore.my_id(),
            ciphertext,
            nonce: nonce.to_vec(),
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

        let plaintext = self
            .keystore
            .decipher(&server_id, &grpc_response.ciphertext, &grpc_response.nonce)
            .map_err(CenasClientError::DecipherError)?;
        let reply_rr_message: RrMessage<ApiReply> =
            bincode::deserialize(&plaintext).map_err(CenasClientError::DeserializationError)?;

        Ok(reply_rr_message
            .downcast_reply(&request, current_epoch)?
            .into_inner())
    }
}

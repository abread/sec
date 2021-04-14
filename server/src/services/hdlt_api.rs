use std::sync::Arc;

use model::api::{ApiReply, ApiRequest, RrMessage};
use model::{
    api::RrRequest,
    keys::{EntityId, KeyStore},
    Location, UnverifiedLocationProof,
};
use protos::hdlt::hdlt_api_server::HdltApi;
use protos::hdlt::CipheredRrMessage;

use tonic::{Request, Response, Status};
use tracing::instrument;
use tracing_utils::instrument_tonic_service;

#[derive(Debug)]
pub struct HdltApiService {
    keystore: Arc<KeyStore>,
}

impl HdltApiService {
    pub fn new(keystore: Arc<KeyStore>) -> Self {
        HdltApiService { keystore }
    }

    #[instrument]
    pub fn obtain_location_report(
        &self,
        requestor_id: EntityId,
        user_id: EntityId,
        epoch: u64,
    ) -> Result<Location, String> {
        // TODO
        Ok(Location(0, 0))
    }

    #[instrument]
    pub fn users_at_location(
        &self,
        requestor_id: EntityId,
        location: Location,
        epoch: u64,
    ) -> Result<Vec<EntityId>, String> {
        // TODO
        Ok(vec![])
    }

    #[instrument]
    pub fn submit_location_proof(
        &self,
        requestor_id: EntityId,
        proof: UnverifiedLocationProof,
    ) -> Result<(), String> {
        // TODO
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
            ApiRequest::ObtainLocationReport { user_id, epoch } => self
                .obtain_location_report(requestor_id, *user_id, *epoch)
                .map(ApiReply::LocationReport),
            ApiRequest::ObtainUsersAtLocation { location, epoch } => self
                .users_at_location(requestor_id, location.clone(), *epoch)
                .map(ApiReply::UsersAtLocation),
            ApiRequest::SubmitLocationReport(proof) => self
                .submit_location_proof(requestor_id, proof.clone())
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

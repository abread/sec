use crate::base64_serialization::Base64SerializationExt;
use crate::keys::{EntityId, KeyStore};
use crate::{
    ClosenessProofRequest, ClosenessProofRequestValidationError, Location,
    UnverifiedClosenessProofRequest,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClosenessProofValidationError {
    #[error("bad sig")]
    BadSignature,

    #[error("bad req")]
    BadRequest(#[from] ClosenessProofRequestValidationError),
}

#[derive(Serialize, Debug, PartialEq)]
pub struct ClosenessProof {
    request: ClosenessProofRequest,
    author_id: EntityId,
    #[serde(with = "Base64SerializationExt")]
    signature: Vec<u8>,
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct UnverifiedClosenessProof {
    request: UnverifiedClosenessProofRequest,
    author_id: EntityId,
    #[serde(with = "Base64SerializationExt")]
    signature: Vec<u8>,
}

impl UnverifiedClosenessProof {
    pub fn verify(
        self,
        keystore: &KeyStore,
    ) -> Result<ClosenessProof, ClosenessProofValidationError> {
        let request = self.request.verify(keystore)?;
        // TODO

        Ok(ClosenessProof {
            request,
            author_id: self.author_id,
            signature: self.signature,
        })
    }

    pub unsafe fn verify_unchecked(self) -> ClosenessProof {
        ClosenessProof {
            request: self.request.verify_unchecked(),
            author_id: self.author_id,
            signature: self.signature,
        }
    }
}

impl ClosenessProof {
    pub fn new(request: ClosenessProofRequest, keystore: &KeyStore) -> ClosenessProof {
        let author_id = keystore.my_id().to_owned();
        let signature = vec![]; // TODO

        ClosenessProof {
            request,
            author_id,
            signature,
        }
    }

    pub fn request(&self) -> &ClosenessProofRequest {
        &self.request
    }

    pub fn author_id(&self) -> &EntityId {
        &self.author_id
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn location(&self) -> &Location {
        &self.request.location()
    }

    pub fn epoch(&self) -> u64 {
        self.request.epoch()
    }
}

partial_eq_impl!(
    ClosenessProof,
    UnverifiedClosenessProof;
    request,
    author_id,
    signature
);

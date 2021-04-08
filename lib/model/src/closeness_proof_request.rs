use crate::keys::{EntityId, KeyStore};
use crate::base64_serialization::Base64SerializationExt;
use crate::Location;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum ClosenessProofRequestValidationError {}

#[derive(Debug, PartialEq, Serialize)]
pub struct ClosenessProofRequest {
    author_id: EntityId,
    location: Location,
    epoch: u64,
    #[serde(with = "Base64SerializationExt")]
    signature: Vec<u8>,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct UnverifiedClosenessProofRequest {
    pub author_id: EntityId,
    pub location: Location,
    pub epoch: u64,
    #[serde(with = "Base64SerializationExt")]
    pub signature: Vec<u8>,
}

impl UnverifiedClosenessProofRequest {
    pub fn verify(
        self,
        _keystore: &KeyStore,
    ) -> Result<ClosenessProofRequest, ClosenessProofRequestValidationError> {
        // TODO

        Ok(ClosenessProofRequest {
            author_id: self.author_id,
            location: self.location,
            epoch: self.epoch,
            signature: self.signature,
        })
    }

    pub unsafe fn verify_unchecked(self) -> ClosenessProofRequest {
        ClosenessProofRequest {
            author_id: self.author_id,
            location: self.location,
            epoch: self.epoch,
            signature: self.signature,
        }
    }
}

impl ClosenessProofRequest {
    pub fn new(epoch: u64, location: Location, keystore: &KeyStore) -> ClosenessProofRequest {
        let author_id = keystore.my_id().to_owned();
        let signature = vec![]; // TODO

        ClosenessProofRequest {
            author_id,
            location,
            epoch,
            signature,
        }
    }

    pub fn author_id(&self) -> &EntityId {
        &self.author_id
    }

    pub fn location(&self) -> &Location {
        &self.location
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}
partial_eq_impl!(
    ClosenessProofRequest,
    UnverifiedClosenessProofRequest;
    author_id,
    location,
    epoch,
    signature
);

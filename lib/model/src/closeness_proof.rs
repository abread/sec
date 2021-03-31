use thiserror::Error;
use crate::{ClosenessProofRequest, ClosenessProofRequestValidationError, Location, UnverifiedClosenessProofRequest};
use crate::keys::KeyStore;

type UserPublicKey = Vec<u8>;


#[derive(Error, Debug)]
pub enum ClosenessProofValidationError {
    #[error("bad sig")]
    BadSignature,

    #[error("bad req")]
    BadRequest(#[from] ClosenessProofRequestValidationError),
}

pub struct ClosenessProof {
    request: ClosenessProofRequest,
    author: UserPublicKey,
    location: Location,
    signature: Vec<u8>,
}

pub struct UnverifiedClosenessProof {
    request: UnverifiedClosenessProofRequest,
    author: UserPublicKey,
    location: Location,
    signature: Vec<u8>,
}

impl UnverifiedClosenessProof {
    pub fn verify(self, keystore: &KeyStore) -> Result<ClosenessProof, ClosenessProofValidationError> {
        let request = self.request.verify(keystore)?;
        // TODO

        Ok(ClosenessProof {
            request,
            author: self.author,
            location: self.location,
            signature: self.signature,
        })
    }

    pub unsafe fn verify_unchecked(self) -> ClosenessProof {
        ClosenessProof {
            request: self.request.verify_unchecked(),
            author: self.author,
            location: self.location,
            signature: self.signature,
        }
    }
}

impl ClosenessProof {
    pub fn new(request: ClosenessProofRequest, location: Location, keystore: &KeyStore) -> ClosenessProof {
        let author = keystore.my_public_key().to_owned();
        let signature = vec![]; // TODO

        ClosenessProof {
            request,
            author,
            location,
            signature,
        }
    }

    pub fn request(&self) -> &ClosenessProofRequest {
        &self.request
    }

    pub fn author(&self) -> &[u8] {
        &self.author
    }

    pub fn location(&self) -> &Location {
        &self.location
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn epoch(&self) -> u64 {
        self.request.epoch()
    }
}

partial_eq_impl!(ClosenessProof, UnverifiedClosenessProof : request, author, location, signature);
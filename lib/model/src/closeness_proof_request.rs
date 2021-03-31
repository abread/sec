use thiserror::Error;
use crate::Location;
use crate::keys::KeyStore;

type UserPublicKey = Vec<u8>;

#[derive(Error, Debug)]
pub enum ClosenessProofRequestValidationError {

}

pub struct ClosenessProofRequest {
    author: UserPublicKey,
    location: Location,
    epoch: u64,
    signature: Vec<u8>,
}

pub struct UnverifiedClosenessProofRequest {
    pub author: UserPublicKey,
    pub location: Location,
    pub epoch: u64,
    pub signature: Vec<u8>,
}

impl UnverifiedClosenessProofRequest {
    pub fn verify(self, _keystore: &KeyStore) -> Result<ClosenessProofRequest, ClosenessProofRequestValidationError> {
        // TODO

        Ok(ClosenessProofRequest {
            author: self.author,
            location: self.location,
            epoch: self.epoch,
            signature: self.signature,
        })
    }

    pub unsafe fn verify_unchecked(self) -> ClosenessProofRequest {
        ClosenessProofRequest {
            author: self.author,
            location: self.location,
            epoch: self.epoch,
            signature: self.signature,
        }
    }
}

impl ClosenessProofRequest {
    pub fn new(epoch: u64, location: Location, keystore: &KeyStore) -> ClosenessProofRequest {
        let author = keystore.my_public_key().to_owned();
        let signature = vec![]; // TODO

        ClosenessProofRequest {
            author,
            location,
            epoch,
            signature,
        }
    }

    pub fn author(&self) -> &[u8] {
        &self.author
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
partial_eq_impl!(ClosenessProofRequest, UnverifiedClosenessProofRequest : author, location, epoch, signature);
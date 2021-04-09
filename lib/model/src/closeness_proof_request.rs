use crate::base64_serialization::Base64SerializationExt;
use crate::keys::{EntityId, KeyStore, KeyStoreError, Role};
use crate::Location;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClosenessProofRequestValidationError {
    #[error("Author {} does not exist or isn't a user", .0)]
    AuthorNotFound(u32),

    #[error("Error validating signature")]
    BadSignature(#[from] KeyStoreError),
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ClosenessProofRequest {
    author_id: EntityId,
    location: Location,
    epoch: u64,
    #[serde(with = "Base64SerializationExt")]
    signature: Vec<u8>,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
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
        keystore: &KeyStore,
    ) -> Result<ClosenessProofRequest, ClosenessProofRequestValidationError> {
        if keystore.role_of(&self.author_id) != Some(Role::User) {
            return Err(ClosenessProofRequestValidationError::AuthorNotFound(
                self.author_id.clone(),
            ));
        }

        let bytes: Vec<u8> = [
            &self.author_id.to_be_bytes(),
            self.location.to_bytes().as_slice(),
            &self.epoch.to_be_bytes(),
        ]
        .concat();
        keystore.verify_signature(&self.author_id, &bytes, &self.signature)?;

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
        assert_eq!(
            keystore.my_role(),
            Role::User,
            "only users can create ClosenessProofRequests"
        );

        let req_bytes: Vec<u8> = [
            &author_id.to_be_bytes(),
            location.to_bytes().as_slice(),
            &epoch.to_be_bytes(),
        ]
        .concat();
        let signature = keystore.sign(&req_bytes).to_vec();

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

impl From<ClosenessProofRequest> for UnverifiedClosenessProofRequest {
    fn from(verified: ClosenessProofRequest) -> Self {
        UnverifiedClosenessProofRequest {
            author_id: verified.author_id,
            location: verified.location,
            epoch: verified.epoch,
            signature: verified.signature,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::keys::test_data::KeyStoreTestData;
    use lazy_static::lazy_static;

    lazy_static! {
        static ref KEYSTORES: KeyStoreTestData = KeyStoreTestData::new();
        static ref REQ1: ClosenessProofRequest =
            ClosenessProofRequest::new(1, Location(1.0, 1.0), &KEYSTORES.user1);
        static ref REQ2: ClosenessProofRequest =
            ClosenessProofRequest::new(2, Location(2.0, 2.0), &KEYSTORES.user2);
    }

    #[test]
    fn accessors() {
        let req = REQ1.clone();
        assert_eq!(req.author_id(), &1);
        assert_eq!(req.location(), &REQ1.location);
        assert_eq!(req.epoch(), REQ1.epoch);
        assert_eq!(req.signature(), &req.signature);
    }

    #[test]
    fn verified_unverified_equality() {
        let unverified: UnverifiedClosenessProofRequest = REQ2.clone().into();
        assert_eq!(&unverified, &*REQ2);

        let verified_serialized = serde_json::to_string(&*REQ2).unwrap();
        let unverified_deserialized: UnverifiedClosenessProofRequest = serde_json::from_str(&verified_serialized)
            .expect("could not deserialize UnverifiedClosenessProofRequest from serialized ClosenessProofRequest");

        assert_eq!(unverified, unverified_deserialized);
    }

    #[test]
    fn verify_ok() {
        let unverified: UnverifiedClosenessProofRequest = REQ2.clone().into();
        KEYSTORES.iter().for_each(|keystore| {
            let verified: ClosenessProofRequest = unverified.clone().verify(keystore).unwrap();
            assert_eq!(verified, *REQ2);
        });
    }

    macro_rules! verify_bad_test {
        ($name:ident -> $error:pat , |$unverified:ident| $bad_stuff:expr) => {
            #[test]
            fn $name() {
                let mut $unverified: UnverifiedClosenessProofRequest = REQ2.clone().into();
                $bad_stuff;

                KEYSTORES.iter().for_each(|keystore| {
                    assert!(matches!($unverified.clone().verify(keystore), Err($error)));
                });
            }
        };
    }

    verify_bad_test! {
        verify_bad_sig -> ClosenessProofRequestValidationError::BadSignature(_),
        |unverified| unverified.signature[0] = unverified.signature[0].wrapping_add(1)
    }

    verify_bad_test! {
        verify_bad_author_role_server -> ClosenessProofRequestValidationError::AuthorNotFound(_),
        |unverified| unverified.author_id = KEYSTORES.server.my_id().to_owned()
    }

    verify_bad_test! {
        verify_bad_author_role_haclient -> ClosenessProofRequestValidationError::AuthorNotFound(_),
        |unverified| unverified.author_id = KEYSTORES.haclient.my_id().to_owned()
    }

    verify_bad_test! {
        verify_inexistent_author -> ClosenessProofRequestValidationError::AuthorNotFound(_),
        |unverified| unverified.author_id = 404
    }

    #[test]
    #[should_panic(expected = "only users can create ClosenessProofRequests")]
    fn create_not_user_server() {
        ClosenessProofRequest::new(0, Location(1.0, 2.0), &KEYSTORES.server);
    }

    #[test]
    #[should_panic(expected = "only users can create ClosenessProofRequests")]
    fn create_not_user_haclient() {
        ClosenessProofRequest::new(0, Location(1.0, 2.0), &KEYSTORES.haclient);
    }
}

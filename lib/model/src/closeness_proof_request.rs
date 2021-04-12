use crate::base64_serialization::Base64SerializationExt;
use crate::keys::{EntityId, KeyStore, KeyStoreError, Role};
use crate::Location;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClosenessProofRequestValidationError {
    #[error("Prover {} does not exist or isn't a user", .0)]
    ProverNotFound(u32),

    #[error("Error validating signature")]
    BadSignature(#[from] KeyStoreError),
}

/// A call for location proof witnesses.
///
/// A valid [ClosenessProofRequest] must:
/// 1. have an entity with [Role::User] as its author (prover)
/// 2. be signed by the prover's signing key
///
/// Instances of this struct are guaranteed to be valid and therefore it implements [Serialize]
/// but not [Deserialize]. To deserialize a [ClosenessProofRequest] see [UnverifiedClosenessProofRequest::verify].
/// A serialized [ClosenessProofRequest] deserialized as an [UnverifiedClosenessProofRequest] is guaranteed to be equal to the original request.
///
/// **IMPORTANT**: a valid [ClosenessProofRequest] must have been created in the current or an earlier epoch.
/// This is not automatically guaranteed by the type system and **must be checked by callers**.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ClosenessProofRequest {
    /// Identifier of the request creator (trying to prove they're in [location](Self::location)).
    prover_id: EntityId,

    /// Location as stated by the prover
    location: Location,

    /// Epoch at the time of request creation.
    epoch: u64,

    /// Prover signature of the request
    #[serde(with = "Base64SerializationExt")]
    signature: Vec<u8>,
}

/// A unverified/untrusted call for location proof witnesess.
///
/// This type is meant to be used as a stepping stone to receive a [ClosenessProofRequest] from an outside source.
/// For this it implements [Deserialize], and can be [verify](Self::verify)-ed into a [ClosenessProofRequest].
/// A serialized [ClosenessProofRequest] deserialized as an [UnverifiedClosenessProofRequest] is guaranteed to be equal to the original request.
#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct UnverifiedClosenessProofRequest {
    /// Identifier of the request creator (trying to prove they're in [location](Self::location)).
    pub prover_id: EntityId,

    /// Location as stated by the prover
    pub location: Location,

    /// Epoch at the time of request creation.
    pub epoch: u64,

    /// Prover signature of the request
    #[serde(with = "Base64SerializationExt")]
    pub signature: Vec<u8>,
}

impl UnverifiedClosenessProofRequest {
    /// Verifies a request.
    ///
    /// As documented in [ClosenessProofRequest], any valid request must be signed by some user entity.
    pub fn verify(
        self,
        keystore: &KeyStore,
    ) -> Result<ClosenessProofRequest, ClosenessProofRequestValidationError> {
        if keystore.role_of(&self.prover_id) != Some(Role::User) {
            return Err(ClosenessProofRequestValidationError::ProverNotFound(
                self.prover_id.clone(),
            ));
        }

        let bytes: Vec<u8> = [
            &self.prover_id.to_be_bytes(),
            self.location.to_bytes().as_slice(),
            &self.epoch.to_be_bytes(),
        ]
        .concat();
        keystore.verify_signature(&self.prover_id, &bytes, &self.signature)?;

        Ok(ClosenessProofRequest {
            prover_id: self.prover_id,
            location: self.location,
            epoch: self.epoch,
            signature: self.signature,
        })
    }

    /// Marks a request as verified without actually checking anything.
    ///
    /// # Safety
    /// Caller must guarantee that the request is signed by a user entity.
    pub unsafe fn verify_unchecked(self) -> ClosenessProofRequest {
        ClosenessProofRequest {
            prover_id: self.prover_id,
            location: self.location,
            epoch: self.epoch,
            signature: self.signature,
        }
    }
}

impl ClosenessProofRequest {
    /// Creates a new ClosenessProofRequest for the current user in the current epoch and location.
    pub fn new(epoch: u64, location: Location, keystore: &KeyStore) -> ClosenessProofRequest {
        let prover_id = keystore.my_id().to_owned();
        assert_eq!(
            keystore.my_role(),
            Role::User,
            "only users can create ClosenessProofRequests"
        );

        let req_bytes: Vec<u8> = [
            &prover_id.to_be_bytes(),
            location.to_bytes().as_slice(),
            &epoch.to_be_bytes(),
        ]
        .concat();
        let signature = keystore.sign(&req_bytes).to_vec();

        ClosenessProofRequest {
            prover_id,
            location,
            epoch,
            signature,
        }
    }

    /// Identifier of the request creator (trying to prove they're in [location](Self::location)).
    pub fn prover_id(&self) -> &EntityId {
        &self.prover_id
    }

    /// Location as stated by the prover
    pub fn location(&self) -> &Location {
        &self.location
    }

    /// Epoch at the time of request creation.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Prover signature of the request
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

partial_eq_impl!(
    ClosenessProofRequest,
    UnverifiedClosenessProofRequest;
    prover_id,
    location,
    epoch,
    signature
);

impl From<ClosenessProofRequest> for UnverifiedClosenessProofRequest {
    fn from(verified: ClosenessProofRequest) -> Self {
        UnverifiedClosenessProofRequest {
            prover_id: verified.prover_id,
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
        assert_eq!(req.prover_id(), &1);
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
        verify_bad_prover_role_server -> ClosenessProofRequestValidationError::ProverNotFound(_),
        |unverified| unverified.prover_id = KEYSTORES.server.my_id().to_owned()
    }

    verify_bad_test! {
        verify_bad_prover_role_haclient -> ClosenessProofRequestValidationError::ProverNotFound(_),
        |unverified| unverified.prover_id = KEYSTORES.haclient.my_id().to_owned()
    }

    verify_bad_test! {
        verify_inexistent_prover -> ClosenessProofRequestValidationError::ProverNotFound(_),
        |unverified| unverified.prover_id = 404
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

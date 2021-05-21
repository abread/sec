use crate::base64_serialization::Base64SerializationExt;
use crate::keys::{EntityId, KeyStore, KeyStoreError, Role, Signature};
use crate::Position;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProximityProofRequestValidationError {
    #[error("Prover {} does not exist or isn't a user", .0)]
    ProverNotFound(u32),

    #[error("Error validating signature")]
    BadSignature(#[from] KeyStoreError),
}

/// A call for position proof witnesses.
///
/// A valid [ProximityProofRequest] must:
/// 1. have an entity with [Role::User] as its author (prover)
/// 2. be signed by the prover's signing key
///
/// Instances of this struct are guaranteed to be valid and therefore it implements [Serialize]
/// but not [Deserialize]. To deserialize a [ProximityProofRequest] see [UnverifiedProximityProofRequest::verify].
/// A serialized [ProximityProofRequest] deserialized as an [UnverifiedProximityProofRequest] is guaranteed to be equal to the original request.
///
/// **IMPORTANT**: a valid [ProximityProofRequest] must have been created in the current or an earlier epoch.
/// This is not automatically guaranteed by the type system and **must be checked by callers**.
#[derive(Clone, Debug, PartialEq)]
pub struct ProximityProofRequest {
    /// Identifier of the request creator (trying to prove they're in [position](Self::position)).
    prover_id: EntityId,

    /// Position as stated by the prover
    position: Position,

    /// Epoch at the time of request creation.
    epoch: u64,

    /// Prover signature of the request
    signature: Signature,
}

/// A unverified/untrusted call for position proof witnesess.
///
/// This type is meant to be used as a stepping stone to receive a [ProximityProofRequest] from an outside source.
/// For this it implements [Deserialize], and can be [verify](Self::verify)-ed into a [ProximityProofRequest].
/// A serialized [ProximityProofRequest] deserialized as an [UnverifiedProximityProofRequest] is guaranteed to be equal to the original request.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Hash, Eq)]
pub struct UnverifiedProximityProofRequest {
    /// Identifier of the request creator (trying to prove they're in [position](Self::position)).
    pub prover_id: EntityId,

    /// Position as stated by the prover
    pub position: Position,

    /// Epoch at the time of request creation.
    pub epoch: u64,

    /// Prover signature of the request
    #[serde(with = "Base64SerializationExt")]
    pub signature: Signature,
}

impl UnverifiedProximityProofRequest {
    /// Verifies a request.
    ///
    /// As documented in [ProximityProofRequest], any valid request must be signed by some user entity.
    pub fn verify(
        self,
        keystore: &KeyStore,
    ) -> Result<ProximityProofRequest, ProximityProofRequestValidationError> {
        if keystore.role_of(self.prover_id) != Some(Role::User) {
            return Err(ProximityProofRequestValidationError::ProverNotFound(
                self.prover_id,
            ));
        }

        let bytes: Vec<u8> = [
            &self.prover_id.to_be_bytes(),
            self.position.to_bytes().as_slice(),
            &self.epoch.to_be_bytes(),
        ]
        .concat();
        keystore.verify_signature(self.prover_id, &bytes, &self.signature)?;

        Ok(ProximityProofRequest {
            prover_id: self.prover_id,
            position: self.position,
            epoch: self.epoch,
            signature: self.signature,
        })
    }

    /// Marks a request as verified without actually checking anything.
    ///
    /// # Safety
    /// Caller must guarantee that the request is signed by a user entity.
    /// This function is always memory-safe, even if the above above conditions don't apply.
    pub unsafe fn verify_unchecked(self) -> ProximityProofRequest {
        ProximityProofRequest {
            prover_id: self.prover_id,
            position: self.position,
            epoch: self.epoch,
            signature: self.signature,
        }
    }
}

impl ProximityProofRequest {
    /// Creates a new ProximityProofRequest for the current user in the current epoch and position.
    pub fn new(epoch: u64, position: Position, keystore: &KeyStore) -> ProximityProofRequest {
        let prover_id = keystore.my_id().to_owned();
        assert_eq!(
            keystore.my_role(),
            Role::User,
            "only users can create ProximityProofRequests"
        );

        let req_bytes: Vec<u8> = [
            &prover_id.to_be_bytes(),
            position.to_bytes().as_slice(),
            &epoch.to_be_bytes(),
        ]
        .concat();
        let signature = keystore.sign(&req_bytes);

        ProximityProofRequest {
            prover_id,
            position,
            epoch,
            signature,
        }
    }

    /// Identifier of the request creator (trying to prove they're in [position](Self::position)).
    pub fn prover_id(&self) -> EntityId {
        self.prover_id
    }

    /// Position as stated by the prover
    pub fn position(&self) -> Position {
        self.position
    }

    /// Epoch at the time of request creation.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Prover signature of the request
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

partial_eq_impl!(
    ProximityProofRequest,
    UnverifiedProximityProofRequest;
    prover_id,
    position,
    epoch,
    signature
);

impl From<ProximityProofRequest> for UnverifiedProximityProofRequest {
    fn from(verified: ProximityProofRequest) -> Self {
        UnverifiedProximityProofRequest {
            prover_id: verified.prover_id,
            position: verified.position,
            epoch: verified.epoch,
            signature: verified.signature,
        }
    }
}

impl Serialize for ProximityProofRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        UnverifiedProximityProofRequest::serialize(&self.clone().into(), serializer)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::keys::test_data::KeyStoreTestData;
    use lazy_static::lazy_static;

    lazy_static! {
        static ref KEYSTORES: KeyStoreTestData = KeyStoreTestData::new();
        static ref REQ1: ProximityProofRequest =
            ProximityProofRequest::new(1, Position(1, 1), &KEYSTORES.user1);
        static ref REQ2: ProximityProofRequest =
            ProximityProofRequest::new(2, Position(2, 2), &KEYSTORES.user2);
    }

    #[test]
    fn accessors() {
        let req = REQ1.clone();
        assert_eq!(req.prover_id(), 1);
        assert_eq!(req.position(), REQ1.position);
        assert_eq!(req.epoch(), REQ1.epoch);
        assert_eq!(req.signature(), &req.signature);
    }

    #[test]
    fn verified_unverified_equality() {
        let unverified: UnverifiedProximityProofRequest = REQ2.clone().into();
        assert_eq!(&unverified, &*REQ2);

        let verified_serialized = serde_json::to_string(&*REQ2).unwrap();
        let unverified_deserialized: UnverifiedProximityProofRequest = serde_json::from_str(&verified_serialized)
            .expect("could not deserialize UnverifiedProximityProofRequest from serialized ProximityProofRequest");

        assert_eq!(unverified, unverified_deserialized);
    }

    #[test]
    fn verify_ok() {
        let unverified: UnverifiedProximityProofRequest = REQ2.clone().into();
        KEYSTORES.iter().for_each(|keystore| {
            let verified: ProximityProofRequest = unverified.clone().verify(keystore).unwrap();
            assert_eq!(verified, *REQ2);
        });
    }

    macro_rules! verify_bad_test {
        ($name:ident -> $error:pat , |$unverified:ident| $bad_stuff:expr) => {
            #[test]
            fn $name() {
                let mut $unverified: UnverifiedProximityProofRequest = REQ2.clone().into();
                $bad_stuff;

                KEYSTORES.iter().for_each(|keystore| {
                    assert!(matches!($unverified.clone().verify(keystore), Err($error)));
                });
            }
        };
    }

    verify_bad_test! {
        verify_bad_sig -> ProximityProofRequestValidationError::BadSignature(_),
        |unverified| unverified.signature.0[0] = unverified.signature.0[0].wrapping_add(1)
    }

    verify_bad_test! {
        verify_bad_prover_role_server -> ProximityProofRequestValidationError::ProverNotFound(_),
        |unverified| unverified.prover_id = KEYSTORES.server.my_id().to_owned()
    }

    verify_bad_test! {
        verify_bad_prover_role_haclient -> ProximityProofRequestValidationError::ProverNotFound(_),
        |unverified| unverified.prover_id = KEYSTORES.haclient.my_id().to_owned()
    }

    verify_bad_test! {
        verify_inexistent_prover -> ProximityProofRequestValidationError::ProverNotFound(_),
        |unverified| unverified.prover_id = 404
    }

    #[test]
    #[should_panic(expected = "only users can create ProximityProofRequests")]
    fn create_not_user_server() {
        ProximityProofRequest::new(0, Position(1, 2), &KEYSTORES.server);
    }

    #[test]
    #[should_panic(expected = "only users can create ProximityProofRequests")]
    fn create_not_user_haclient() {
        ProximityProofRequest::new(0, Position(1, 2), &KEYSTORES.haclient);
    }
}

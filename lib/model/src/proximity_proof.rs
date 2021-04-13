use crate::base64_serialization::Base64SerializationExt;
use crate::keys::{EntityId, KeyStore, KeyStoreError, Role};
use crate::{
    Location, ProximityProofRequest, ProximityProofRequestValidationError,
    UnverifiedProximityProofRequest,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProximityProofValidationError {
    #[error("Witness {} does not exist or isn't a user", .0)]
    WitnessNotFound(u32),

    #[error("Proof is signed by the author of the request")]
    SelfSigned,

    #[error("Invalid Signature")]
    BadSignature(#[from] KeyStoreError),

    #[error("Invalid ProximityProofRequest")]
    BadRequest(#[from] ProximityProofRequestValidationError),
}

/// A record of a location witness, where a witness asserts that another user was indeed where they said they were (or at least close enough).
///
/// A [ProximityProof] is a [ProximityProofRequest] signed by a witness, which can
/// be any user apart from the one that created the [ProximityProofRequest] in the first place.
///
/// Instances of this struct are guaranteed to be valid and therefore it implements [Serialize]
/// but not [Deserialize]. To deserialize a [ProximityProof] see [UnverifiedProximityProof::verify].
/// A serialized [ProximityProof] deserialized as an [UnverifiedProximityProof] is guaranteed to be equal to the original proof.
///
/// **IMPORTANT**: a valid [ProximityProof] must have been created after validating
/// the prover's location at the same epoch as the [ProximityProofRequest].
/// This is not automatically guaranteed by the type system and **must be checked by callers**.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ProximityProof {
    /// The prover location data being asserted by the witness.
    request: ProximityProofRequest,

    /// Witness, the user entity testifying that the user is close to the location they say they are.
    witness_id: EntityId,

    /// Witness signature of the request/prover location data.
    #[serde(with = "Base64SerializationExt")]
    signature: Vec<u8>,
}

/// An unverified record of a location witness, where a witness asserts that another user was indeed where they said they were.
///
/// This type is meant to be used as a stepping stone to receive a [ProximityProof] from an outside source.
/// For this it implements [Deserialize], and can be [verify](Self::verify)-ed into a [ProximityProof].
/// A serialized [ProximityProof] deserialized as an [UnverifiedProximityProof] is guaranteed to be equal to the original request.
#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct UnverifiedProximityProof {
    /// The prover location data being asserted by the witness.
    pub request: UnverifiedProximityProofRequest,

    /// Witness, the user entity testifying that the user is close to the location they say they are.
    pub witness_id: EntityId,

    /// Witness signature of the request/prover location data.
    #[serde(with = "Base64SerializationExt")]
    pub signature: Vec<u8>,
}

impl UnverifiedProximityProof {
    /// Verifies a proximity proof/testimony.
    ///
    /// As documented in [ProximityProof], any valid proof must be a [ProximityProofRequest] signed by a user entity that is not the prover (request author).
    pub fn verify(
        self,
        keystore: &KeyStore,
    ) -> Result<ProximityProof, ProximityProofValidationError> {
        if keystore.role_of(&self.witness_id) != Some(Role::User) {
            return Err(ProximityProofValidationError::WitnessNotFound(
                self.witness_id.to_owned(),
            ));
        }

        if self.witness_id == self.request.prover_id {
            return Err(ProximityProofValidationError::SelfSigned);
        }

        let request = self.request.verify(keystore)?;

        let bytes = [
            &request.prover_id().to_be_bytes(),
            request.location().to_bytes().as_slice(),
            &request.epoch().to_be_bytes(),
            request.signature(),
            &self.witness_id.to_be_bytes(),
        ]
        .concat();
        keystore.verify_signature(&self.witness_id, &bytes, &self.signature)?;

        Ok(ProximityProof {
            request,
            witness_id: self.witness_id,
            signature: self.signature,
        })
    }

    /// Marks a proof as verified without actually checking anything.
    ///
    /// # Safety
    /// Caller must guarantee that the request is valid, or in other words
    /// that it is safe to call [UnverifiedProximityProofRequest::verify_unchecked] on it; and
    /// that it is signed by a user entity that is not the author of the request (prover).
    pub unsafe fn verify_unchecked(self) -> ProximityProof {
        ProximityProof {
            // Safety: guaranteed by caller
            request: self.request.verify_unchecked(),
            witness_id: self.witness_id,
            signature: self.signature,
        }
    }
}

impl ProximityProof {
    /// Sign a [ProximityProofRequest] to construct a [ProximityProof] as the current user.
    ///
    /// Will return an error if the keystore owner is not a user, of if it is the author of the request.
    pub fn new(
        request: ProximityProofRequest,
        keystore: &KeyStore,
    ) -> Result<ProximityProof, ProximityProofValidationError> {
        if keystore.my_role() != Role::User {
            return Err(ProximityProofValidationError::WitnessNotFound(
                keystore.my_id().to_owned(),
            ));
        }

        if keystore.my_id() == request.prover_id() {
            return Err(ProximityProofValidationError::SelfSigned);
        }

        // Safety: ^ keystore is of a user that is not the request author.
        Ok(unsafe { Self::new_unchecked(request, keystore) })
    }

    /// Sign a [ProximityProofRequest] to construct a [ProximityProof] without performing checks.
    ///
    /// # Safety
    /// Keystore must belong to an entity with user role, and that is not the author of the request.
    pub unsafe fn new_unchecked(
        request: ProximityProofRequest,
        keystore: &KeyStore,
    ) -> ProximityProof {
        let witness_id = keystore.my_id().to_owned();

        let bytes: Vec<u8> = [
            &request.prover_id().to_be_bytes(),
            request.location().to_bytes().as_slice(),
            &request.epoch().to_be_bytes(),
            request.signature(),
            &witness_id.to_be_bytes(),
        ]
        .concat();
        let signature = keystore.sign(&bytes).to_vec();

        ProximityProof {
            request,
            witness_id,
            signature,
        }
    }

    /// The prover location data being asserted by the witness.
    pub fn request(&self) -> &ProximityProofRequest {
        &self.request
    }

    /// Witness, the user entity testifying that the user is close to the location they say they are.
    pub fn witness_id(&self) -> &EntityId {
        &self.witness_id
    }

    /// Witness signature of the request/prover location data.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Identifier of the request creator.
    ///
    /// Shortcut for [`proof.request().prover_id()`](ProximityProofRequest::prover_id)
    pub fn prover_id(&self) -> &EntityId {
        self.request.prover_id()
    }

    /// Epoch at the time of request creation.
    ///
    /// Shortcut for [`proof.request().location()`](ProximityProofRequest::location)
    pub fn location(&self) -> &Location {
        self.request.location()
    }

    /// Prover signature of the request
    ///
    /// Shortcut for [`proof.request().epoch()`](ProximityProofRequest::epoch)
    pub fn epoch(&self) -> u64 {
        self.request.epoch()
    }
}

partial_eq_impl!(
    ProximityProof,
    UnverifiedProximityProof;
    request,
    witness_id,
    signature
);

impl From<ProximityProof> for UnverifiedProximityProof {
    fn from(verified: ProximityProof) -> Self {
        UnverifiedProximityProof {
            request: verified.request.into(),
            witness_id: verified.witness_id,
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
        static ref REQ1: ProximityProofRequest =
            ProximityProofRequest::new(1, Location(1.0, 1.0), &KEYSTORES.user1);
        static ref REQ2: ProximityProofRequest =
            ProximityProofRequest::new(2, Location(2.0, 2.0), &KEYSTORES.user2);
        static ref PROOF1: ProximityProof =
            ProximityProof::new(REQ1.clone(), &KEYSTORES.user2).unwrap();
        static ref PROOF1_SELFSIGNED: ProximityProof =
            unsafe { ProximityProof::new_unchecked(REQ1.clone(), &KEYSTORES.user1) };
        static ref PROOF2: ProximityProof =
            ProximityProof::new(REQ2.clone(), &KEYSTORES.user1).unwrap();
    }

    #[test]
    fn accessors() {
        let proof = PROOF1.clone();
        assert_eq!(proof.request(), &*REQ1);
        assert_eq!(proof.witness_id(), &2);
        assert_eq!(proof.signature(), &proof.signature);
        assert_eq!(proof.location(), REQ1.location());
        assert_eq!(proof.epoch(), REQ1.epoch());
    }

    #[test]
    fn verified_unverified_equality() {
        let unverified: UnverifiedProximityProof = PROOF1.clone().into();
        assert_eq!(&unverified, &*PROOF1);

        let verified_serialized = serde_json::to_string(&*PROOF1).unwrap();
        let unverified_deserialized: UnverifiedProximityProof = serde_json::from_str(
            &verified_serialized,
        )
        .expect("could not deserialize UnverifiedProximityProof from serialized ProximityProof");

        assert_eq!(unverified, unverified_deserialized);
    }

    #[test]
    fn verify_ok() {
        let unverified: UnverifiedProximityProof = PROOF2.clone().into();
        KEYSTORES.iter().for_each(|keystore| {
            let verified: ProximityProof = unverified.clone().verify(keystore).unwrap();
            assert_eq!(verified, *PROOF2);
        });
    }

    macro_rules! verify_bad_test {
        ($name:ident -> $error:pat , |$unverified:ident| $bad_stuff:expr) => {
            #[test]
            fn $name() {
                #[allow(unused_assignments)]
                let mut $unverified: UnverifiedProximityProof = PROOF2.clone().into();
                $bad_stuff;

                KEYSTORES.iter().for_each(|keystore| {
                    assert!(matches!($unverified.clone().verify(keystore), Err($error)));
                });
            }
        };
    }

    verify_bad_test! {
        verify_bad_request -> ProximityProofValidationError::BadRequest(_),
        |unverified| unverified.request.signature[0] = unverified.request.signature[0].wrapping_add(1)
    }

    verify_bad_test! {
        verify_bad_sig -> ProximityProofValidationError::BadSignature(_),
        |unverified| unverified.signature[0] = unverified.signature[0].wrapping_add(1)
    }

    verify_bad_test! {
        verify_bad_prover_role_server -> ProximityProofValidationError::WitnessNotFound(_),
        |unverified| unverified.witness_id = KEYSTORES.server.my_id().to_owned()
    }

    verify_bad_test! {
        verify_bad_prover_role_haclient -> ProximityProofValidationError::WitnessNotFound(_),
        |unverified| unverified.witness_id = KEYSTORES.haclient.my_id().to_owned()
    }

    verify_bad_test! {
        verify_inexistent_prover -> ProximityProofValidationError::WitnessNotFound(_),
        |unverified| unverified.witness_id = 404
    }

    verify_bad_test! {
        verify_self_signed -> ProximityProofValidationError::SelfSigned,
        |unverified| unverified = PROOF1_SELFSIGNED.clone().into()
    }

    #[test]
    fn create_not_user_server() {
        assert!(matches!(
            ProximityProof::new(REQ1.clone(), &KEYSTORES.server),
            Err(ProximityProofValidationError::WitnessNotFound(_))
        ));
    }

    #[test]
    fn create_not_user_haclient() {
        assert!(matches!(
            ProximityProof::new(REQ1.clone(), &KEYSTORES.haclient),
            Err(ProximityProofValidationError::WitnessNotFound(_))
        ));
    }

    #[test]
    fn create_not_selfsigned() {
        assert!(matches!(
            ProximityProof::new(REQ1.clone(), &KEYSTORES.user1),
            Err(ProximityProofValidationError::SelfSigned)
        ));
    }
}

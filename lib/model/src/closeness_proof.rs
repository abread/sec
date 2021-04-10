use crate::base64_serialization::Base64SerializationExt;
use crate::keys::{EntityId, KeyStore, KeyStoreError, Role};
use crate::{
    ClosenessProofRequest, ClosenessProofRequestValidationError, Location,
    UnverifiedClosenessProofRequest,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClosenessProofValidationError {
    #[error("Author {} does not exist or isn't a user", .0)]
    AuthorNotFound(u32),

    #[error("Proof is signed by the author of the request")]
    SelfSigned,

    #[error("Invalid Signature")]
    BadSignature(#[from] KeyStoreError),

    #[error("Invalid ClosenessProofRequest")]
    BadRequest(#[from] ClosenessProofRequestValidationError),
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ClosenessProof {
    request: ClosenessProofRequest,
    author_id: EntityId,
    #[serde(with = "Base64SerializationExt")]
    signature: Vec<u8>,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct UnverifiedClosenessProof {
    pub request: UnverifiedClosenessProofRequest,
    pub author_id: EntityId,
    #[serde(with = "Base64SerializationExt")]
    pub signature: Vec<u8>,
}

impl UnverifiedClosenessProof {
    pub fn verify(
        self,
        keystore: &KeyStore,
    ) -> Result<ClosenessProof, ClosenessProofValidationError> {
        if keystore.role_of(&self.author_id) != Some(Role::User) {
            return Err(ClosenessProofValidationError::AuthorNotFound(self.author_id.to_owned()));
        }

        if self.author_id == self.request.author_id {
            return Err(ClosenessProofValidationError::SelfSigned);
        }

        let request = self.request.verify(keystore)?;

        let bytes = [
            &request.author_id().to_be_bytes(),
            request.location().to_bytes().as_slice(),
            &request.epoch().to_be_bytes(),
            request.signature(),
            &self.author_id.to_be_bytes(),
        ].concat();
        keystore.verify_signature(&self.author_id, &bytes, &self.signature)?;

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
        assert_eq!(
            keystore.my_role(),
            Role::User,
            "only users can create ClosenessProofRequests"
        );

        let bytes: Vec<u8> = [
            &request.author_id().to_be_bytes(),
            request.location().to_bytes().as_slice(),
            &request.epoch().to_be_bytes(),
            request.signature(),
            &author_id.to_be_bytes(),
        ].concat();
        let signature = keystore.sign(&bytes).to_vec();

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

impl From<ClosenessProof> for UnverifiedClosenessProof {
    fn from(verified: ClosenessProof) -> Self {
        UnverifiedClosenessProof {
            request: verified.request.into(),
            author_id: verified.author_id,
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
        static ref PROOF1: ClosenessProof = ClosenessProof::new(REQ1.clone(), &KEYSTORES.user2);
        static ref PROOF1_SELFSIGNED: ClosenessProof = unsafe { ClosenessProof::new_unchecked(REQ1.clone(), &KEYSTORES.user1) };
        static ref PROOF2: ClosenessProof = ClosenessProof::new(REQ2.clone(), &KEYSTORES.user1);
    }

    #[test]
    fn accessors() {
        let proof = PROOF1.clone();
        assert_eq!(proof.request(), &*REQ1);
        assert_eq!(proof.author_id(), &2);
        assert_eq!(proof.signature(), &proof.signature);
        assert_eq!(proof.location(), REQ1.location());
        assert_eq!(proof.epoch(), REQ1.epoch());
    }

    #[test]
    fn verified_unverified_equality() {
        let unverified: UnverifiedClosenessProof = PROOF1.clone().into();
        assert_eq!(&unverified, &*PROOF1);

        let verified_serialized = serde_json::to_string(&*PROOF1).unwrap();
        let unverified_deserialized: UnverifiedClosenessProof = serde_json::from_str(
            &verified_serialized,
        )
        .expect("could not deserialize UnverifiedClosenessProof from serialized ClosenessProof");

        assert_eq!(unverified, unverified_deserialized);
    }

    #[test]
    fn verify_ok() {
        let unverified: UnverifiedClosenessProof = PROOF2.clone().into();
        KEYSTORES.iter().for_each(|keystore| {
            let verified: ClosenessProof = unverified.clone().verify(keystore).unwrap();
            assert_eq!(verified, *PROOF2);
        });
    }

    macro_rules! verify_bad_test {
        ($name:ident -> $error:pat , |$unverified:ident| $bad_stuff:expr) => {
            #[test]
            fn $name() {
                #[allow(unused_assignments)]
                let mut $unverified: UnverifiedClosenessProof = PROOF2.clone().into();
                $bad_stuff;

                KEYSTORES.iter().for_each(|keystore| {
                    assert!(matches!($unverified.clone().verify(keystore), Err($error)));
                });
            }
        };
    }

    verify_bad_test! {
        verify_bad_request -> ClosenessProofValidationError::BadRequest(_),
        |unverified| unverified.request.signature[0] = unverified.request.signature[0].wrapping_add(1)
    }

    verify_bad_test! {
        verify_bad_sig -> ClosenessProofValidationError::BadSignature(_),
        |unverified| unverified.signature[0] = unverified.signature[0].wrapping_add(1)
    }

    verify_bad_test! {
        verify_bad_author_role_server -> ClosenessProofValidationError::AuthorNotFound(_),
        |unverified| unverified.author_id = KEYSTORES.server.my_id().to_owned()
    }

    verify_bad_test! {
        verify_bad_author_role_haclient -> ClosenessProofValidationError::AuthorNotFound(_),
        |unverified| unverified.author_id = KEYSTORES.haclient.my_id().to_owned()
    }

    verify_bad_test! {
        verify_inexistent_author -> ClosenessProofValidationError::AuthorNotFound(_),
        |unverified| unverified.author_id = 404
    }

    verify_bad_test! {
        verify_self_signed -> ClosenessProofValidationError::SelfSigned,
        |unverified| unverified = PROOF1_SELFSIGNED.clone().into()
    }

    #[test]
    #[should_panic(expected = "only users can create ClosenessProofRequests")]
    fn create_not_user_server() {
        ClosenessProof::new(REQ1.clone(), &KEYSTORES.server);
    }

    #[test]
    #[should_panic(expected = "only users can create ClosenessProofRequests")]
    fn create_not_user_haclient() {
        ClosenessProof::new(REQ1.clone(), &KEYSTORES.haclient);
    }
}

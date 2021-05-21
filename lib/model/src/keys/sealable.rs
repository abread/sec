use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sodiumoxide::crypto::pwhash::scryptsalsa208sha256 as pwhash;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305 as secretbox;
use thiserror::Error;

use crate::base64_serialization::Base64SerializationExt;

/// Wrapper struct to protect objects with a password.
///
/// It will derive a symmetric key from the password and use it to encrypt the object.
/// See [sodiumoxide::crypto::pwhash::scryptsalsa208sha256] for information on
/// the KDF being used, and [sodiumoxide::crypto::secretbox::xsalsa20poly1305]
/// for information on the symmetric cipher being used.
/// The salt and nonce required by these two algorithms are generated randomly
/// when sealing the object.
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub enum Sealable<T: Base64SerializationExt> {
    Unsealed(#[serde(with = "Base64SerializationExt")] T),
    Sealed {
        #[serde(with = "Base64SerializationExt")]
        ciphertext: Vec<u8>,

        #[serde(with = "Base64SerializationExt")]
        salt: pwhash::Salt,

        #[serde(with = "Base64SerializationExt")]
        nonce: secretbox::Nonce,
    },
}

#[derive(Debug, Error)]
pub enum SealableError {
    #[error("Failed to (de)serialize inner object")]
    SerializationError(#[from] serde_json::Error),

    #[error("Failed to decrypt object")]
    DecryptionError,

    #[error("Failed to derive object encryption key")]
    KeyDerivationError,

    #[error("Object is sealed. Unseal first to be able to perform this operation.")]
    ObjectSealed,
}

impl<T: Base64SerializationExt> Sealable<T> {
    /// Unseal object given the password. No-op if object is already unsealed.
    pub fn unseal(&mut self, password: &str) -> Result<(), SealableError>
    where
        T: DeserializeOwned,
    {
        if let Sealable::Sealed {
            ciphertext,
            salt,
            nonce,
        } = &*self
        {
            let mut key = secretbox::Key([0; secretbox::KEYBYTES]);
            pwhash::derive_key(
                &mut key.0,
                password.as_bytes(),
                salt,
                pwhash::OPSLIMIT_INTERACTIVE,
                pwhash::MEMLIMIT_INTERACTIVE,
            )
            .map_err(|_| SealableError::KeyDerivationError)?;

            let plaintext = secretbox::open(&ciphertext, nonce, &key)
                .map_err(|_| SealableError::DecryptionError)?;
            *self = Sealable::Unsealed(serde_json::from_slice(&plaintext)?);
        }
        // even if it was already unselaed, it's fine, just keep going

        Ok(())
    }

    /// Seal the (unsealed) object with the given password.
    pub fn seal(&mut self, password: &str) -> Result<(), SealableError>
    where
        T: Serialize,
    {
        if let Sealable::Unsealed(v) = self {
            let salt = pwhash::gen_salt();
            let mut key = secretbox::Key([0; secretbox::KEYBYTES]);
            pwhash::derive_key(
                &mut key.0,
                password.as_bytes(),
                &salt,
                pwhash::OPSLIMIT_INTERACTIVE,
                pwhash::MEMLIMIT_INTERACTIVE,
            )
            .map_err(|_| SealableError::KeyDerivationError)?;

            let nonce = secretbox::gen_nonce();
            let plaintext = serde_json::to_vec(&v)?;
            let ciphertext = secretbox::seal(&plaintext, &nonce, &key);

            *self = Sealable::Sealed {
                ciphertext,
                nonce,
                salt,
            };

            Ok(())
        } else {
            // it's already sealed yes, but with a potentially different password :/
            Err(SealableError::ObjectSealed)
        }
    }

    /// Get a reference to the inner object. Panics if object is sealed.
    pub fn get(&self) -> &T {
        if let Sealable::Unsealed(v) = self {
            v
        } else {
            panic!("Seal is sealed, can't get reference to inner value");
        }
    }

    /// Check if object is sealed.
    pub fn is_sealed(&self) -> bool {
        matches!(self, Sealable::Sealed { .. })
    }
}

#[cfg(test)]
#[test]
pub fn test() {
    const PASSWORD: &str = "password1234";

    let mut sealable = Sealable::Unsealed([4u8, 2]);
    sealable.seal(PASSWORD).unwrap();

    assert!(sealable.is_sealed());
    match &sealable {
        Sealable::Sealed { .. } => (),
        _ => unreachable!("should be sealed :/"),
    }

    sealable.unseal(PASSWORD).unwrap();
    assert_eq!(sealable.get(), &[4u8, 2]);
    assert!(!sealable.is_sealed());
}

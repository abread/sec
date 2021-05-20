use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sodiumoxide::crypto::pwhash::scryptsalsa208sha256 as pwhash;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305 as secretbox;

use crate::base64_serialization::Base64SerializationExt;

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub enum Sealable<T> {
    Unsealed(T),
    Sealed {
        #[serde(with = "Base64SerializationExt")]
        ciphertext: Vec<u8>,

        #[serde(with = "Base64SerializationExt")]
        salt: pwhash::Salt,

        #[serde(with = "Base64SerializationExt")]
        nonce: secretbox::Nonce,
    },
}

impl<T> Sealable<T> {
    pub fn unseal(&mut self, password: &str) -> Result<(), ()>
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
            )?;

            let plaintext = secretbox::open(&ciphertext, nonce, &key)?;
            *self = Sealable::Unsealed(serde_json::from_slice(&plaintext).map_err(|_| ())?);
        }
        // even if it was already unselaed, it's fine, just keep going

        Ok(())
    }

    pub fn seal(&mut self, password: &str) -> Result<(), ()>
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
            )?;

            let nonce = secretbox::gen_nonce();
            let plaintext = serde_json::to_vec(&v).map_err(|_| ())?;
            let ciphertext = secretbox::seal(&plaintext, &nonce, &key);

            *self = Sealable::Sealed {
                ciphertext,
                nonce,
                salt,
            };

            Ok(())
        } else {
            // it's already sealed yes, but with a potentially different password :/
            Err(())
        }
    }

    pub fn get(&self) -> &T {
        if let Sealable::Unsealed(v) = self {
            v
        } else {
            panic!("Seal is sealed, can't get reference to inner value");
        }
    }

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

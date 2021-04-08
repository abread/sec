use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{box_, sign};
pub use sodiumoxide::crypto::box_::NONCEBYTES;
pub use sodiumoxide::crypto::sign::SIGNATUREBYTES;
use thiserror::Error;

use super::key_base64_serialization::KeyBase64SerializationExt;
use super::Role;

pub type UserId = u32;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct UserPubComponent {
    pub id: UserId,
    pub role: Role,

    #[serde(with = "KeyBase64SerializationExt")]
    pub sig_pubkey: sign::PublicKey,
    #[serde(with = "KeyBase64SerializationExt")]
    pub cipher_pubkey: box_::PublicKey,
}

#[derive(PartialEq, Serialize, Deserialize)]
pub struct UserPrivComponent {
    pub id: UserId,

    pub role: Role,

    #[serde(with = "KeyBase64SerializationExt")]
    pub sig_skey: sign::SecretKey,

    #[serde(with = "KeyBase64SerializationExt")]
    pub cipher_skey: box_::SecretKey,
}

#[derive(Error, Debug)]
pub enum UserPrivComponentSaveError {
    #[error("Failed to serialize user")]
    SerializationError(#[from] serde_json::Error),

    #[error("Failed to write file")]
    IOError(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum UserPrivComponentLoadError {
    #[error("Failed to deserialize user")]
    DeserializationError(#[from] serde_json::Error),

    #[error("Failed to read file")]
    IOError(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum DecipherError {
    #[error("Bad nonce")]
    BadNonce,

    #[error("Data corrupted (authentication failed)")]
    DataCorrupted,
}

#[derive(Error, Debug)]
pub enum SignatureVerificationError {
    #[error("Bad signature (it's not a signature)")]
    BadSignature,

    #[error("Data corrupted (signature verification itself failed)")]
    DataCorrupted,
}

impl UserPrivComponent {
    pub fn new(id: UserId, role: Role) -> Self {
        let sig_skey = sign::gen_keypair().1;
        let cipher_skey = box_::gen_keypair().1;

        UserPrivComponent {
            id,
            role,
            sig_skey,
            cipher_skey,
        }
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, UserPrivComponentLoadError> {
        let encoded = fs::read_to_string(path)?;
        let user = serde_json::from_str(&encoded)?;
        Ok(user)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), UserPrivComponentSaveError> {
        let encoded = serde_json::to_string_pretty(&self)?;
        fs::write(path, encoded).map_err(|e| e.into())
    }

    pub fn pub_component(&self) -> UserPubComponent {
        UserPubComponent {
            id: self.id,
            role: self.role,
            sig_pubkey: self.sig_skey.public_key(),
            cipher_pubkey: self.cipher_skey.public_key(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATUREBYTES] {
        sign::sign_detached(message, &self.sig_skey).0
    }

    pub fn cipher(&self, partner: &UserPubComponent, plaintext: &[u8]) -> (Vec<u8>, [u8; NONCEBYTES]) {
        let nonce = box_::gen_nonce();

        let ciphertext = box_::seal(plaintext, &nonce, &partner.cipher_pubkey, &self.cipher_skey);

        (ciphertext, nonce.0)
    }

    pub fn decipher(&self, partner: &UserPubComponent, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, DecipherError> {
        let nonce = box_::Nonce::from_slice(nonce)
            .ok_or(DecipherError::BadNonce)?;

        box_::open(ciphertext, &nonce, &partner.cipher_pubkey, &self.cipher_skey)
            .map_err(|_| DecipherError::DataCorrupted)
    }
}

impl UserPubComponent {
    pub fn verify_signature<Sig: AsRef<[u8]>>(&self, message: &[u8], signature: Sig) -> Result<(), SignatureVerificationError> {
        let signature = sign::Signature::from_slice(signature.as_ref())
            .ok_or(SignatureVerificationError::BadSignature)?;

        if sign::verify_detached(&signature, message, &self.sig_pubkey) {
            Ok(())
        } else {
            Err(SignatureVerificationError::BadSignature)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tempdir::TempDir;

    #[test]
    fn test_load_save() {
        let tempdir = TempDir::new("userprivcomponent").unwrap();
        let path = tempdir.path().join("user.json");

        let user = UserPrivComponent::new(42, Role::Server);
        user.save_to_file(&path).unwrap();

        let loaded_user = UserPrivComponent::load_from_file(&path).unwrap();
        assert!(user == loaded_user);
    }

    #[test]
    fn priv_to_pub_equal() {
        crate::ensure_init();

        let user_priv = UserPrivComponent::new(1, Role::User);
        let user_pub_manual = UserPubComponent {
            id: 1,
            role: Role::User,
            sig_pubkey: user_priv.sig_skey.public_key(),
            cipher_pubkey: user_priv.cipher_skey.public_key(),
        };

        assert_eq!(user_pub_manual, user_priv.pub_component());
    }

    #[test]
    // smoke tests for sign/verify
    fn sign() {
        crate::ensure_init();
        let message = vec![1, 2, 3];
        let message_tampered = vec![3, 2, 1];
        let user = UserPrivComponent::new(1, Role::User);

        let signature = user.sign(&message);
        assert!(user.pub_component().verify_signature(&message, &signature).is_ok(), "signature with same user/message should be valid");
        assert!(user.pub_component().verify_signature(&message_tampered, &signature).is_err(), "signature with different message should be invalid");

        let other_user = UserPrivComponent::new(2, Role::User).pub_component();
        assert!(other_user.verify_signature(&message, &signature).is_err(), "signature with different user should be invalid");
        assert!(other_user.verify_signature(&message_tampered, &signature).is_err(), "signature with different user and message should be invalid");
    }

    #[test]
    // smoke tests for cipher/decipher
    fn cipher() {
        crate::ensure_init();
        let user1 = UserPrivComponent::new(1, Role::User);
        let user2 = UserPrivComponent::new(2, Role::User);
        let message = vec![4, 2];

        let (ciphertext, nonce) = user1.cipher(&user2.pub_component(), &message);
        assert_eq!(user2.decipher(&user1.pub_component(), &ciphertext, &nonce).unwrap(), message);
        assert_eq!(user1.decipher(&user2.pub_component(), &ciphertext, &nonce).unwrap(), message);

        assert!(user2.decipher(&user2.pub_component(), &ciphertext, &nonce).is_err());
        assert!(user1.decipher(&user1.pub_component(), &ciphertext, &nonce).is_err());

        let mut bad_ciphertext = ciphertext.clone();
        bad_ciphertext[0] = bad_ciphertext[0].wrapping_add(1);

        let mut bad_nonce = nonce.to_owned();
        bad_nonce[0] = bad_nonce[0].wrapping_add(1);

        assert!(user2.decipher(&user1.pub_component(), &bad_ciphertext, &nonce).is_err());
        assert!(user2.decipher(&user1.pub_component(), &ciphertext, &bad_nonce).is_err());
    }
}

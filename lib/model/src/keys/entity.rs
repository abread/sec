use std::fmt;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{box_::curve25519xsalsa20poly1305 as box_, sign::ed25519 as sign};
use thiserror::Error;

use super::sealable::{Sealable, SealableError};
use super::Role;
use crate::base64_serialization::Base64SerializationExt;

pub type EntityId = u32;

pub use sodiumoxide::crypto::box_::Nonce;
pub use sodiumoxide::crypto::sign::Signature;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct EntityPubComponent {
    pub id: EntityId,
    pub role: Role,

    #[serde(with = "Base64SerializationExt")]
    pub sig_pubkey: sign::PublicKey,
    #[serde(with = "Base64SerializationExt")]
    pub cipher_pubkey: box_::PublicKey,
}

#[derive(PartialEq, Serialize, Deserialize, Clone)]
pub struct EntityPrivComponent {
    pub id: EntityId,

    pub role: Role,

    pub sig_skey: Sealable<sign::SecretKey>,

    pub cipher_skey: Sealable<box_::SecretKey>,
}

#[derive(Error, Debug)]
pub enum EntityPrivComponentSaveError {
    #[error("Failed to serialize entity")]
    SerializationError(#[from] serde_json::Error),

    #[error("Failed to write file")]
    IoError(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum EntityPrivComponentLoadError {
    #[error("Failed to deserialize entity")]
    DeserializationError(#[from] serde_json::Error),

    #[error("Failed to read file")]
    IoError(#[from] std::io::Error),
}

#[derive(Error, Debug)]
#[error("Failed to decipher data")]
pub struct DecipherError;

#[derive(Error, Debug)]
#[error("Signature verification failed")]
pub struct SignatureVerificationError;

impl EntityPrivComponent {
    pub fn new(id: EntityId, role: Role) -> Self {
        let sig_skey = Sealable::Unsealed(sign::gen_keypair().1);
        let cipher_skey = Sealable::Unsealed(box_::gen_keypair().1);

        EntityPrivComponent {
            id,
            role,
            sig_skey,
            cipher_skey,
        }
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, EntityPrivComponentLoadError> {
        let encoded = fs::read_to_string(path)?;
        let entity = serde_json::from_str(&encoded)?;
        Ok(entity)
    }

    pub fn unlock(&mut self, password: &str) -> Result<(), SealableError> {
        self.sig_skey.unseal(password)?;
        self.cipher_skey.unseal(password)?;

        Ok(())
    }

    pub fn lock(&mut self, password: &str) -> Result<(), SealableError> {
        self.sig_skey.seal(password)?;
        self.cipher_skey.seal(password)?;

        Ok(())
    }

    pub fn is_locked(&self) -> bool {
        // checking just one is probably fine, but this is more general
        // if just one is sealed, unlocking will be a no-op for the already unsealed key
        self.sig_skey.is_sealed() || self.cipher_skey.is_sealed()
    }

    pub fn save_to_file<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<(), EntityPrivComponentSaveError> {
        let encoded = serde_json::to_string_pretty(&self)?;
        fs::write(path, encoded)?;
        Ok(())
    }

    pub fn pub_component(&self) -> EntityPubComponent {
        EntityPubComponent {
            id: self.id,
            role: self.role,
            sig_pubkey: self.sig_skey.get().public_key(),
            cipher_pubkey: self.cipher_skey.get().public_key(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        sign::sign_detached(message, self.sig_skey.get())
    }

    pub fn cipher(&self, partner: &EntityPubComponent, plaintext: &[u8]) -> (Vec<u8>, Nonce) {
        let nonce = box_::gen_nonce();

        let ciphertext = box_::seal(
            plaintext,
            &nonce,
            &partner.cipher_pubkey,
            self.cipher_skey.get(),
        );

        (ciphertext, nonce)
    }

    pub fn decipher(
        &self,
        partner: &EntityPubComponent,
        ciphertext: &[u8],
        nonce: &Nonce,
    ) -> Result<Vec<u8>, DecipherError> {
        box_::open(
            ciphertext,
            &nonce,
            &partner.cipher_pubkey,
            self.cipher_skey.get(),
        )
        .map_err(|_| DecipherError)
    }
}

impl EntityPubComponent {
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureVerificationError> {
        if sign::verify_detached(signature, message, &self.sig_pubkey) {
            Ok(())
        } else {
            Err(SignatureVerificationError)
        }
    }
}

impl fmt::Debug for EntityPrivComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const REDACTED: &str = "[REDACTED]";

        f.debug_struct("EntityPrivComponent")
            .field("id", &self.id)
            .field("role", &self.role)
            .field("sig_skey", &REDACTED)
            .field("sig_pkey", &REDACTED)
            .finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_save() {
        let tempfile = NamedTempFile::new().unwrap();

        let entity = EntityPrivComponent::new(42, Role::Server);
        entity.save_to_file(tempfile.path()).unwrap();

        let loaded_entity = EntityPrivComponent::load_from_file(tempfile.path()).unwrap();
        assert!(entity == loaded_entity);
    }

    #[test]
    fn priv_to_pub_equal() {
        crate::ensure_init();

        let entity_priv = EntityPrivComponent::new(1, Role::User);
        let entity_pub_manual = EntityPubComponent {
            id: 1,
            role: Role::User,
            sig_pubkey: entity_priv.sig_skey.get().public_key(),
            cipher_pubkey: entity_priv.cipher_skey.get().public_key(),
        };

        assert_eq!(entity_pub_manual, entity_priv.pub_component());
    }

    #[test]
    // smoke tests for sign/verify
    fn sign() {
        crate::ensure_init();
        let message = vec![1, 2, 3];
        let message_tampered = vec![3, 2, 1];
        let entity = EntityPrivComponent::new(1, Role::User);

        let signature = entity.sign(&message);
        assert!(
            entity
                .pub_component()
                .verify_signature(&message, &signature)
                .is_ok(),
            "signature with same entity/message should be valid"
        );
        assert!(
            entity
                .pub_component()
                .verify_signature(&message_tampered, &signature)
                .is_err(),
            "signature with different message should be invalid"
        );

        let other_entity = EntityPrivComponent::new(2, Role::User).pub_component();
        assert!(
            other_entity.verify_signature(&message, &signature).is_err(),
            "signature with different entity should be invalid"
        );
        assert!(
            other_entity
                .verify_signature(&message_tampered, &signature)
                .is_err(),
            "signature with different entity and message should be invalid"
        );
    }

    #[test]
    // smoke tests for cipher/decipher
    fn cipher() {
        crate::ensure_init();
        let entity1 = EntityPrivComponent::new(1, Role::User);
        let entity2 = EntityPrivComponent::new(2, Role::User);
        let message = vec![4, 2];

        let (ciphertext, nonce) = entity1.cipher(&entity2.pub_component(), &message);
        assert_eq!(
            entity2
                .decipher(&entity1.pub_component(), &ciphertext, &nonce)
                .unwrap(),
            message
        );
        assert_eq!(
            entity1
                .decipher(&entity2.pub_component(), &ciphertext, &nonce)
                .unwrap(),
            message
        );

        assert!(entity2
            .decipher(&entity2.pub_component(), &ciphertext, &nonce)
            .is_err());
        assert!(entity1
            .decipher(&entity1.pub_component(), &ciphertext, &nonce)
            .is_err());

        let mut bad_ciphertext = ciphertext.clone();
        bad_ciphertext[0] = bad_ciphertext[0].wrapping_add(1);

        let mut bad_nonce = nonce.to_owned();
        bad_nonce.0[0] = bad_nonce.0[0].wrapping_add(1);

        assert!(entity2
            .decipher(&entity1.pub_component(), &bad_ciphertext, &nonce)
            .is_err());
        assert!(entity2
            .decipher(&entity1.pub_component(), &ciphertext, &bad_nonce)
            .is_err());
    }
}

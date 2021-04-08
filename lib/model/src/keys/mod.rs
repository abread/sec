use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

mod key_base64_serialization;

mod user;
pub use user::{UserId, UserPrivComponent, UserPubComponent};
pub use user::{UserPrivComponentLoadError, UserPrivComponentSaveError};
use user::{NONCEBYTES, SIGNATUREBYTES};

use self::user::{DecipherError, SignatureVerificationError};

pub struct KeyStore {
    user_registry: HashMap<UserId, UserPubComponent>,
    me: UserPrivComponent,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Role {
    Server,
    User,
    HAClient,
}

#[derive(Error, Debug)]
pub enum KeyStoreSaveError {
    #[error("Failed to write user registry file")]
    UserRegistryIOError(#[from] std::io::Error),

    #[error("Failed to serialize user registry")]
    UserRegistrySerializationError(#[from] serde_json::Error),

    #[error("Failed to save current user")]
    MeSaveError(#[from] UserPrivComponentSaveError),
}

#[derive(Error, Debug)]
pub enum KeyStoreLoadError {
    #[error("Current user not consistent with registry")]
    ConsistencyError(#[from] KeyStoreConsistencyError),

    #[error("Failed to read user registry file")]
    UserRegistryIOError(#[from] std::io::Error),

    #[error("Failed to deserialize user registry")]
    UserRegistryDeserializationError(#[from] serde_json::Error),

    #[error("Failed to load current user")]
    MeLoadError(#[from] UserPrivComponentLoadError),
}

#[derive(Error, Debug)]
#[error("User registry already contains a (different) user with this ID")]
pub struct KeyStoreConsistencyError;

#[derive(Error, Debug)]
pub enum KeyStoreError {
    #[error("User {} does not exist in registry", .0)]
    UserNotFound(UserId),

    #[error("Could not decipher message (corrupted data)")]
    DecipherError(#[from] DecipherError),

    #[error("Signature verification failed")]
    SignatureVerificationError(#[from] SignatureVerificationError),
}

impl KeyStore {
    pub fn new(me: UserPrivComponent) -> Self {
        let mut user_registry = HashMap::new();
        user_registry.insert(me.id, me.pub_component());

        KeyStore { user_registry, me }
    }

    pub fn load_from_files<P1: AsRef<Path>, P2: AsRef<Path>>(
        registry_path: P1,
        me_path: P2,
    ) -> Result<Self, KeyStoreLoadError> {
        let user_registry_enc = fs::read_to_string(registry_path)?;
        let mut user_registry = serde_json::from_str(&user_registry_enc)?;

        let me = UserPrivComponent::load_from_file(me_path)?;

        // guarantee consistency
        assert_registry_consistent(&mut user_registry, &me)?;

        Ok(KeyStore { user_registry, me })
    }

    pub fn save_to_files<P1: AsRef<Path>, P2: AsRef<Path>>(
        &self,
        registry_path: P1,
        me_path: P2,
    ) -> Result<(), KeyStoreSaveError> {
        let user_registry = serde_json::to_string_pretty(&self.user_registry)?;
        fs::write(registry_path, user_registry)?;

        self.me.save_to_file(me_path)?;

        Ok(())
    }

    pub fn add_user(&mut self, user: UserPubComponent) -> Result<(), KeyStoreConsistencyError> {
        if !self
            .user_registry
            .get(&user.id)
            .map_or(true, |u| *u == user)
        {
            // a *different* user with this ID already exists
            return Err(KeyStoreConsistencyError);
        }

        self.user_registry.insert(user.id, user);

        Ok(())
    }

    pub fn set_me(&mut self, me: UserPrivComponent) -> Result<(), KeyStoreConsistencyError> {
        assert_registry_consistent(&mut self.user_registry, &me)?;
        self.me = me;

        Ok(())
    }

    pub fn role_of(&self, id: &UserId) -> Option<Role> {
        self.user_registry.get(id).map(|user| user.role)
    }

    pub fn my_id(&self) -> &UserId {
        &self.me.id
    }

    pub fn my_role(&self) -> Role {
        self.me.role
    }

    pub fn cipher(
        &self,
        partner_id: &UserId,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; NONCEBYTES]), KeyStoreError> {
        let partner = self
            .user_registry
            .get(partner_id)
            .ok_or_else(|| KeyStoreError::UserNotFound(partner_id.to_owned()))?;

        Ok(self.me.cipher(&partner, plaintext))
    }

    pub fn decipher(
        &self,
        partner_id: &UserId,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, KeyStoreError> {
        let partner = self
            .user_registry
            .get(partner_id)
            .ok_or_else(|| KeyStoreError::UserNotFound(partner_id.to_owned()))?;

        Ok(self.me.decipher(&partner, ciphertext, nonce)?)
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATUREBYTES] {
        self.me.sign(message)
    }

    pub fn verify_signature(
        &self,
        author_id: &UserId,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), KeyStoreError> {
        let author = self
            .user_registry
            .get(author_id)
            .ok_or_else(|| KeyStoreError::UserNotFound(author_id.to_owned()))?;

        Ok(author.verify_signature(message, signature)?)
    }
}

fn assert_registry_consistent(
    registry: &mut HashMap<UserId, UserPubComponent>,
    me: &UserPrivComponent,
) -> Result<(), KeyStoreConsistencyError> {
    let me_pub = registry.entry(me.id).or_insert_with(|| me.pub_component());

    if *me_pub == me.pub_component() {
        Ok(())
    } else {
        Err(KeyStoreConsistencyError)
    }
}

#[cfg(test)]
mod test_manipulation {
    use super::*;
    use tempdir::TempDir;

    #[test]
    fn test_load_save() {
        let tempdir = TempDir::new("keystore-loadsave").unwrap();
        let registry_path = tempdir.path().join("registry.json");
        let me_path = tempdir.path().join("me.json");

        let mut store = KeyStore::new(UserPrivComponent::new(100, Role::Server));
        store
            .add_user(UserPrivComponent::new(101, Role::HAClient).pub_component())
            .unwrap();
        for id in 0..42 {
            store
                .add_user(UserPrivComponent::new(id, Role::User).pub_component())
                .unwrap();
        }

        store.save_to_files(&registry_path, &me_path).unwrap();

        let loaded_store = KeyStore::load_from_files(registry_path, me_path).unwrap();
        assert!(store.me == loaded_store.me);
        assert_eq!(store.user_registry, loaded_store.user_registry);
    }

    #[test]
    fn test_load_save_consistency() {
        let tempdir = TempDir::new("keystore-loadsave").unwrap();
        let registry_path = tempdir.path().join("registry.json");
        let me_path = tempdir.path().join("me.json");

        let mut store = KeyStore::new(UserPrivComponent::new(100, Role::Server));
        store
            .add_user(UserPrivComponent::new(101, Role::HAClient).pub_component())
            .unwrap();
        for id in 0..42 {
            store
                .add_user(UserPrivComponent::new(id, Role::User).pub_component())
                .unwrap();
        }

        store.save_to_files(&registry_path, &me_path).unwrap();

        let mut loaded_store = KeyStore::load_from_files(&registry_path, &me_path).unwrap();

        // set new (different) me on both stores with same ID
        store.set_me(UserPrivComponent::new(200, Role::User)).unwrap();
        loaded_store.set_me(UserPrivComponent::new(200, Role::User)).unwrap();

        // now save both of them but put the loaded_store.me in another path
        let me_path2 = tempdir.path().join("otherme.json");
        store.save_to_files(&registry_path, &me_path).unwrap();
        loaded_store.save_to_files(&registry_path, &me_path2).unwrap();

        // registry.json and me.json now have two different users with the same ID
        assert!(KeyStore::load_from_files(&registry_path, &me_path).is_err());
    }

    #[test]
    fn test_accessors() {
        crate::ensure_init();

        let mut store = KeyStore::new(UserPrivComponent::new(0, Role::User));
        assert_eq!(store.role_of(&0), Some(Role::User));
        assert_eq!(store.role_of(&1), None);
        assert_eq!(store.role_of(&2), None);
        assert_eq!(store.my_role(), Role::User);
        assert_eq!(store.my_id(), &0);

        store
            .add_user(UserPrivComponent::new(1, Role::Server).pub_component())
            .unwrap();
        assert_eq!(store.role_of(&0), Some(Role::User));
        assert_eq!(store.role_of(&1), Some(Role::Server));
        assert_eq!(store.role_of(&2), None);
        assert_eq!(store.my_role(), Role::User);
        assert_eq!(store.my_id(), &0);

        let new_me = UserPrivComponent::new(2, Role::HAClient);
        store.set_me(new_me).unwrap();
        assert_eq!(store.role_of(&0), Some(Role::User));
        assert_eq!(store.role_of(&1), Some(Role::Server));
        assert_eq!(store.role_of(&2), Some(Role::HAClient));
        assert_eq!(store.my_role(), Role::HAClient);
        assert_eq!(store.my_id(), &2);
    }

    #[test]
    fn test_insert_consistency() {
        crate::ensure_init();

        let mut store = KeyStore::new(UserPrivComponent::new(0, Role::User));
        assert_eq!(store.role_of(&0), Some(Role::User));
        assert_eq!(store.role_of(&1), None);
        assert_eq!(store.role_of(&2), None);
        assert_eq!(store.my_role(), Role::User);
        assert_eq!(store.my_id(), &0);

        assert!(
            store
                .add_user(UserPrivComponent::new(0, Role::User).pub_component())
                .is_err(),
            "adding an user with an ID already associated with a different user is not fine"
        );
        assert_eq!(store.role_of(&0), Some(Role::User));
        assert_eq!(store.role_of(&1), None);
        assert_eq!(store.role_of(&2), None);
        assert_eq!(store.my_role(), Role::User);
        assert_eq!(store.my_id(), &0);

        assert!(
            store.add_user(store.me.pub_component()).is_ok(),
            "adding an existing user is fine"
        );
        assert_eq!(store.role_of(&0), Some(Role::User));
        assert_eq!(store.role_of(&1), None);
        assert_eq!(store.role_of(&2), None);
        assert_eq!(store.my_role(), Role::User);
        assert_eq!(store.my_id(), &0);
    }

    #[test]
    fn test_set_me_consistency() {
        crate::ensure_init();

        let mut store = KeyStore::new(UserPrivComponent::new(0, Role::User));
        store.add_user(UserPrivComponent::new(1, Role::Server).pub_component()).unwrap();
        assert_eq!(store.role_of(&0), Some(Role::User));
        assert_eq!(store.role_of(&1), Some(Role::Server));
        assert_eq!(store.role_of(&2), None);
        assert_eq!(store.my_role(), Role::User);
        assert_eq!(store.my_id(), &0);

        assert!(
            store
                .set_me(UserPrivComponent::new(0, Role::User))
                .is_err(),
            "setting me to an user with an ID already associated with a different user is not fine"
        );
        assert!(
            store
                .set_me(UserPrivComponent::new(1, Role::Server))
                .is_err(),
            "setting me to an user with an ID already associated with a different user is not fine"
        );
        assert_eq!(store.role_of(&0), Some(Role::User));
        assert_eq!(store.role_of(&1), Some(Role::Server));
        assert_eq!(store.role_of(&2), None);
        assert_eq!(store.my_role(), Role::User);
        assert_eq!(store.my_id(), &0);

        let same_me = UserPrivComponent {
            id: store.me.id.clone(),
            role: store.me.role,
            sig_skey: store.me.sig_skey.clone(),
            cipher_skey: store.me.cipher_skey.clone(),
        };
        assert!(
            store.set_me(same_me).is_ok(),
            "setting me to the same user is fine"
        );
        assert_eq!(store.role_of(&0), Some(Role::User));
        assert_eq!(store.role_of(&1), Some(Role::Server));
        assert_eq!(store.role_of(&2), None);
        assert_eq!(store.my_role(), Role::User);
        assert_eq!(store.my_id(), &0);

        assert!(
            store.set_me(UserPrivComponent::new(2, Role::Server)).is_ok(),
            "setting me to a new user is fine"
        );
        assert_eq!(store.role_of(&0), Some(Role::User));
        assert_eq!(store.role_of(&1), Some(Role::Server));
        assert_eq!(store.role_of(&2), Some(Role::Server));
        assert_eq!(store.my_role(), Role::Server);
        assert_eq!(store.my_id(), &2);
    }
}

#[cfg(test)]
mod test_crypto {
    use super::*;
    use lazy_static::lazy_static;

    lazy_static! {
        static ref STORES: [KeyStore; 3] = {
            crate::ensure_init();
            let user0 = UserPrivComponent::new(0, Role::User);
            let user1 = UserPrivComponent::new(1, Role::User);
            let user2 = UserPrivComponent::new(2, Role::User);
            let mut store0 = KeyStore::new(user0);
            let mut store1 = KeyStore::new(user1);
            let mut store2 = KeyStore::new(user2);

            store0.add_user(store1.me.pub_component()).unwrap();
            store0.add_user(store2.me.pub_component()).unwrap();
            store1.add_user(store0.me.pub_component()).unwrap();
            store1.add_user(store2.me.pub_component()).unwrap();
            store2.add_user(store0.me.pub_component()).unwrap();
            store2.add_user(store1.me.pub_component()).unwrap();

            [store0, store1, store2]
        };
    }

    #[test]
    // smoke tests for sign/verify
    fn sign() {
        let message = vec![1, 2, 3];
        let message_tampered = vec![3, 2, 1];

        let signature = STORES[0].sign(&message);
        for store in &*STORES {
            assert!(store.verify_signature(&0, &message, &signature).is_ok());
            assert!(store
                .verify_signature(&0, &message_tampered, &signature)
                .is_err());
        }
    }

    #[test]
    // smoke tests for cipher/decipher
    fn cipher() {
        let message = vec![4, 2];

        let (ciphertext, nonce) = STORES[0].cipher(&1, &message).unwrap();
        assert_eq!(
            STORES[1].decipher(&0, &ciphertext, &nonce).unwrap(),
            message
        );
        assert_eq!(
            STORES[0].decipher(&1, &ciphertext, &nonce).unwrap(),
            message
        );
        assert!(STORES[0].decipher(&2, &ciphertext, &nonce).is_err());
        assert!(STORES[1].decipher(&2, &ciphertext, &nonce).is_err());
        assert!(STORES[2].decipher(&0, &ciphertext, &nonce).is_err());
        assert!(STORES[2].decipher(&1, &ciphertext, &nonce).is_err());
    }
}

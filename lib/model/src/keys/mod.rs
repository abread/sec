use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

mod entity;
pub use entity::{EntityId, EntityPrivComponent, EntityPubComponent};
pub use entity::{EntityPrivComponentLoadError, EntityPrivComponentSaveError};
use entity::{NONCEBYTES, SIGNATUREBYTES};

use self::entity::{DecipherError, SignatureVerificationError};

pub struct KeyStore {
    registry: HashMap<EntityId, EntityPubComponent>,
    me: EntityPrivComponent,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Role {
    Server,
    User,
    HaClient,
}

#[derive(Error, Debug)]
pub enum KeyStoreSaveError {
    #[error("Failed to write entity registry file")]
    EntityRegistryIoError(#[from] std::io::Error),

    #[error("Failed to serialize entity registry")]
    EntityRegistrySerializationError(#[from] serde_json::Error),

    #[error("Failed to save current entity")]
    MeSaveError(#[from] EntityPrivComponentSaveError),
}

#[derive(Error, Debug)]
pub enum KeyStoreLoadError {
    #[error("Current entity not consistent with registry")]
    ConsistencyError(#[from] KeyStoreConsistencyError),

    #[error("Failed to read registry file")]
    RegistryIoError(#[from] std::io::Error),

    #[error("Failed to deserialize registry")]
    RegistryDeserializationError(#[from] serde_json::Error),

    #[error("Failed to load current entity")]
    MeLoadError(#[from] EntityPrivComponentLoadError),
}

#[derive(Error, Debug)]
#[error("Registry already contains a (different) entity with this ID")]
pub struct KeyStoreConsistencyError;

#[derive(Error, Debug)]
pub enum KeyStoreError {
    #[error("Entity {} does not exist in registry", .0)]
    EntityNotFound(EntityId),

    #[error("Could not decipher message (corrupted data)")]
    DecipherError(#[from] DecipherError),

    #[error("Signature verification failed")]
    SignatureVerificationError(#[from] SignatureVerificationError),
}

impl KeyStore {
    pub fn new(me: EntityPrivComponent) -> Self {
        let mut registry = HashMap::new();
        registry.insert(me.id, me.pub_component());

        KeyStore { registry, me }
    }

    pub fn load_from_files<P1: AsRef<Path>, P2: AsRef<Path>>(
        registry_path: P1,
        me_path: P2,
    ) -> Result<Self, KeyStoreLoadError> {
        let registry_enc = fs::read_to_string(registry_path)?;
        let mut registry = serde_json::from_str(&registry_enc)?;

        let me = EntityPrivComponent::load_from_file(me_path)?;

        // guarantee consistency
        assert_registry_consistent(&mut registry, &me)?;

        Ok(KeyStore { registry, me })
    }

    pub fn save_to_files<P1: AsRef<Path>, P2: AsRef<Path>>(
        &self,
        registry_path: P1,
        me_path: P2,
    ) -> Result<(), KeyStoreSaveError> {
        let registry = serde_json::to_string_pretty(&self.registry)?;
        fs::write(registry_path, registry)?;

        self.me.save_to_file(me_path)?;

        Ok(())
    }

    pub fn add_entity(
        &mut self,
        entity: EntityPubComponent,
    ) -> Result<(), KeyStoreConsistencyError> {
        if !self.registry.get(&entity.id).map_or(true, |u| *u == entity) {
            // a *different* entity with this ID already exists
            return Err(KeyStoreConsistencyError);
        }

        self.registry.insert(entity.id, entity);

        Ok(())
    }

    pub fn set_me(&mut self, me: EntityPrivComponent) -> Result<(), KeyStoreConsistencyError> {
        assert_registry_consistent(&mut self.registry, &me)?;
        self.me = me;

        Ok(())
    }

    pub fn role_of(&self, id: &EntityId) -> Option<Role> {
        self.registry.get(id).map(|entity| entity.role)
    }

    pub fn my_id(&self) -> &EntityId {
        &self.me.id
    }

    pub fn my_role(&self) -> Role {
        self.me.role
    }

    pub fn cipher(
        &self,
        partner_id: &EntityId,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; NONCEBYTES]), KeyStoreError> {
        let partner = self
            .registry
            .get(partner_id)
            .ok_or_else(|| KeyStoreError::EntityNotFound(partner_id.to_owned()))?;

        Ok(self.me.cipher(&partner, plaintext))
    }

    pub fn decipher(
        &self,
        partner_id: &EntityId,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, KeyStoreError> {
        let partner = self
            .registry
            .get(partner_id)
            .ok_or_else(|| KeyStoreError::EntityNotFound(partner_id.to_owned()))?;

        Ok(self.me.decipher(&partner, ciphertext, nonce)?)
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATUREBYTES] {
        self.me.sign(message)
    }

    pub fn verify_signature(
        &self,
        author_id: &EntityId,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), KeyStoreError> {
        let author = self
            .registry
            .get(author_id)
            .ok_or_else(|| KeyStoreError::EntityNotFound(author_id.to_owned()))?;

        Ok(author.verify_signature(message, signature)?)
    }
}

fn assert_registry_consistent(
    registry: &mut HashMap<EntityId, EntityPubComponent>,
    me: &EntityPrivComponent,
) -> Result<(), KeyStoreConsistencyError> {
    let me_pub = registry.entry(me.id).or_insert_with(|| me.pub_component());

    if *me_pub == me.pub_component() {
        Ok(())
    } else {
        Err(KeyStoreConsistencyError)
    }
}

#[cfg(test)]
pub mod test_data {
    use super::*;

    pub struct KeyStoreTestData {
        pub user1: KeyStore,
        pub user2: KeyStore,
        pub user3: KeyStore,
        pub server: KeyStore,
        pub haclient: KeyStore,
    }

    impl KeyStoreTestData {
        pub fn new() -> Self {
            use itertools::Itertools;
            use std::cell::RefCell;

            crate::ensure_init();
            let mut user1 = RefCell::new(KeyStore::new(EntityPrivComponent::new(1, Role::User)));
            let mut user2 = RefCell::new(KeyStore::new(EntityPrivComponent::new(2, Role::User)));
            let mut user3 = RefCell::new(KeyStore::new(EntityPrivComponent::new(3, Role::User)));
            let mut server =
                RefCell::new(KeyStore::new(EntityPrivComponent::new(100, Role::Server)));
            let mut haclient =
                RefCell::new(KeyStore::new(EntityPrivComponent::new(200, Role::HaClient)));

            for (a, b) in [
                &mut user1,
                &mut user2,
                &mut user3,
                &mut server,
                &mut haclient,
            ]
            .iter()
            .tuple_combinations()
            {
                a.borrow_mut()
                    .add_entity(b.borrow().me.pub_component())
                    .unwrap();
                b.borrow_mut()
                    .add_entity(a.borrow().me.pub_component())
                    .unwrap();
            }

            KeyStoreTestData {
                user1: user1.into_inner(),
                user2: user2.into_inner(),
                user3: user3.into_inner(),
                server: server.into_inner(),
                haclient: haclient.into_inner(),
            }
        }

        pub fn iter(&self) -> impl Iterator<Item = &KeyStore> {
            std::array::IntoIter::new([
                &self.user1,
                &self.user2,
                &self.user3,
                &self.server,
                &self.haclient,
            ])
        }
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

        let mut store = KeyStore::new(EntityPrivComponent::new(100, Role::Server));
        store
            .add_entity(EntityPrivComponent::new(101, Role::HaClient).pub_component())
            .unwrap();
        for id in 0..42 {
            store
                .add_entity(EntityPrivComponent::new(id, Role::User).pub_component())
                .unwrap();
        }

        store.save_to_files(&registry_path, &me_path).unwrap();

        let loaded_store = KeyStore::load_from_files(registry_path, me_path).unwrap();
        assert!(store.me == loaded_store.me);
        assert_eq!(store.registry, loaded_store.registry);
    }

    #[test]
    fn test_load_save_consistency() {
        let tempdir = TempDir::new("keystore-loadsave").unwrap();
        let registry_path = tempdir.path().join("registry.json");
        let me_path = tempdir.path().join("me.json");

        let mut store = KeyStore::new(EntityPrivComponent::new(100, Role::Server));
        store
            .add_entity(EntityPrivComponent::new(101, Role::HaClient).pub_component())
            .unwrap();
        for id in 0..42 {
            store
                .add_entity(EntityPrivComponent::new(id, Role::User).pub_component())
                .unwrap();
        }

        store.save_to_files(&registry_path, &me_path).unwrap();

        let mut loaded_store = KeyStore::load_from_files(&registry_path, &me_path).unwrap();

        // set new (different) me on both stores with same ID
        store
            .set_me(EntityPrivComponent::new(200, Role::User))
            .unwrap();
        loaded_store
            .set_me(EntityPrivComponent::new(200, Role::User))
            .unwrap();

        // now save both of them but put the loaded_store.me in another path
        let me_path2 = tempdir.path().join("otherme.json");
        store.save_to_files(&registry_path, &me_path).unwrap();
        loaded_store
            .save_to_files(&registry_path, &me_path2)
            .unwrap();

        // registry.json and me.json now have two different entities with the same ID
        assert!(KeyStore::load_from_files(&registry_path, &me_path).is_err());
    }

    #[test]
    fn test_accessors() {
        crate::ensure_init();

        let mut store = KeyStore::new(EntityPrivComponent::new(0, Role::User));
        assert_eq!(store.role_of(&0), Some(Role::User));
        assert_eq!(store.role_of(&1), None);
        assert_eq!(store.role_of(&2), None);
        assert_eq!(store.my_role(), Role::User);
        assert_eq!(store.my_id(), &0);

        store
            .add_entity(EntityPrivComponent::new(1, Role::Server).pub_component())
            .unwrap();
        assert_eq!(store.role_of(&0), Some(Role::User));
        assert_eq!(store.role_of(&1), Some(Role::Server));
        assert_eq!(store.role_of(&2), None);
        assert_eq!(store.my_role(), Role::User);
        assert_eq!(store.my_id(), &0);

        let new_me = EntityPrivComponent::new(2, Role::HaClient);
        store.set_me(new_me).unwrap();
        assert_eq!(store.role_of(&0), Some(Role::User));
        assert_eq!(store.role_of(&1), Some(Role::Server));
        assert_eq!(store.role_of(&2), Some(Role::HaClient));
        assert_eq!(store.my_role(), Role::HaClient);
        assert_eq!(store.my_id(), &2);
    }

    #[test]
    fn test_insert_consistency() {
        crate::ensure_init();

        let mut store = KeyStore::new(EntityPrivComponent::new(0, Role::User));
        assert_eq!(store.role_of(&0), Some(Role::User));
        assert_eq!(store.role_of(&1), None);
        assert_eq!(store.role_of(&2), None);
        assert_eq!(store.my_role(), Role::User);
        assert_eq!(store.my_id(), &0);

        assert!(
            store
                .add_entity(EntityPrivComponent::new(0, Role::User).pub_component())
                .is_err(),
            "adding an entity with an ID already associated with a different entity is not fine"
        );
        assert_eq!(store.role_of(&0), Some(Role::User));
        assert_eq!(store.role_of(&1), None);
        assert_eq!(store.role_of(&2), None);
        assert_eq!(store.my_role(), Role::User);
        assert_eq!(store.my_id(), &0);

        assert!(
            store.add_entity(store.me.pub_component()).is_ok(),
            "adding an existing entity is fine"
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

        let mut store = KeyStore::new(EntityPrivComponent::new(0, Role::User));
        store
            .add_entity(EntityPrivComponent::new(1, Role::Server).pub_component())
            .unwrap();
        assert_eq!(store.role_of(&0), Some(Role::User));
        assert_eq!(store.role_of(&1), Some(Role::Server));
        assert_eq!(store.role_of(&2), None);
        assert_eq!(store.my_role(), Role::User);
        assert_eq!(store.my_id(), &0);

        assert!(
            store.set_me(EntityPrivComponent::new(0, Role::User)).is_err(),
            "setting me to an entity with an ID already associated with a different entity is not fine"
        );
        assert!(
            store
                .set_me(EntityPrivComponent::new(1, Role::Server))
                .is_err(),
            "setting me to an entity with an ID already associated with a different entity is not fine"
        );
        assert_eq!(store.role_of(&0), Some(Role::User));
        assert_eq!(store.role_of(&1), Some(Role::Server));
        assert_eq!(store.role_of(&2), None);
        assert_eq!(store.my_role(), Role::User);
        assert_eq!(store.my_id(), &0);

        let same_me = EntityPrivComponent {
            id: store.me.id.clone(),
            role: store.me.role,
            sig_skey: store.me.sig_skey.clone(),
            cipher_skey: store.me.cipher_skey.clone(),
        };
        assert!(
            store.set_me(same_me).is_ok(),
            "setting me to the same entity is fine"
        );
        assert_eq!(store.role_of(&0), Some(Role::User));
        assert_eq!(store.role_of(&1), Some(Role::Server));
        assert_eq!(store.role_of(&2), None);
        assert_eq!(store.my_role(), Role::User);
        assert_eq!(store.my_id(), &0);

        assert!(
            store
                .set_me(EntityPrivComponent::new(2, Role::Server))
                .is_ok(),
            "setting me to a new entity is fine"
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
            let entity0 = EntityPrivComponent::new(0, Role::User);
            let entity1 = EntityPrivComponent::new(1, Role::User);
            let entity2 = EntityPrivComponent::new(2, Role::User);
            let mut store0 = KeyStore::new(entity0);
            let mut store1 = KeyStore::new(entity1);
            let mut store2 = KeyStore::new(entity2);

            store0.add_entity(store1.me.pub_component()).unwrap();
            store0.add_entity(store2.me.pub_component()).unwrap();
            store1.add_entity(store0.me.pub_component()).unwrap();
            store1.add_entity(store2.me.pub_component()).unwrap();
            store2.add_entity(store0.me.pub_component()).unwrap();
            store2.add_entity(store1.me.pub_component()).unwrap();

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

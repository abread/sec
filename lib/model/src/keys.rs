use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub struct KeyStore;

pub enum Role {
    Server,
    User,
    HAClient,
}

#[derive(Error, Debug, Serialize, Deserialize)]
#[error("key store error")]
pub struct KeyStoreError;

impl KeyStore {
    pub fn new(_my_privkey: Vec<u8>, _my_role: Role) -> Self {
        // TODO
        KeyStore
    }

    pub fn from_file<P1: AsRef<Path>, P2: AsRef<Path>>(
        _path: P1,
        _privkey_path: P2,
    ) -> Result<Self, KeyStoreError> {
        // TODO
        Ok(KeyStore)
    }

    pub fn add_pubkey(&mut self, _pubkey: Vec<u8>, _role: Role) {
        // TODO
    }

    pub fn set_me(
        &mut self,
        _pubkey: Vec<u8>,
        _privkey: Vec<u8>,
        _role: Role,
    ) -> Result<(), KeyStoreError> {
        // TODO
        Err(KeyStoreError)
    }

    pub fn role_of(&self, _pubkey: &[u8]) -> Option<Role> {
        // TODO
        None
    }

    pub fn my_role(&self) -> Role {
        // TODO
        Role::Server
    }

    pub fn my_private_key(&self) -> &[u8] {
        // TODO
        &[]
    }

    pub fn my_public_key(&self) -> &[u8] {
        // TODO
        &[]
    }
}

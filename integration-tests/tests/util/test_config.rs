use std::collections::HashMap;
use std::ops::Range;
use std::path::PathBuf;

use client::User;
use lazy_static::lazy_static;
use model::keys::{EntityId, EntityPrivComponent, EntityPubComponent, KeyStore, Role};
use more_asserts::*;
use server::Server;

pub const SERVER_RANGE: Range<EntityId> = 0..100;
pub const USER_RANGE: Range<EntityId> = 100..200;
pub const MALICIOUS_USER_RANGE: Range<EntityId> = 200..300;
pub const HA_CLIENT_RANGE: Range<EntityId> = 300..400;

lazy_static! {
    pub static ref PRIV_KEYS: HashMap<EntityId, EntityPrivComponent> = {
        model::ensure_init();
        let mut map = HashMap::new();

        for id in SERVER_RANGE {
            map.insert(id, EntityPrivComponent::new(0, Role::Server));
        }

        for id in USER_RANGE.chain(MALICIOUS_USER_RANGE) {
            map.insert(id, EntityPrivComponent::new(id, Role::User));
        }

        for id in HA_CLIENT_RANGE {
            map.insert(id, EntityPrivComponent::new(id, Role::HaClient));
        }

        map
    };
    pub static ref PUB_KEYS: HashMap<EntityId, EntityPubComponent> = {
        let mut map = HashMap::new();
        for (id, priv_comp) in PRIV_KEYS.iter() {
            map.insert(*id, priv_comp.pub_component());
        }
        map
    };
}
pub struct TestConfig {
    pub n_correct_users: usize,
    pub n_malicious_users: usize,
    pub n_ha_clients: usize,
    pub max_neigh_faults: usize,
    pub dims: (usize, usize),
}

impl TestConfig {
    pub fn assert_valid(&self) {
        assert_lt!(self.n_correct_users, USER_RANGE.len(), "too many users");
        assert_lt!(
            self.n_malicious_users,
            MALICIOUS_USER_RANGE.len(),
            "too many malicious users"
        );
        assert_lt!(
            self.n_ha_clients,
            HA_CLIENT_RANGE.len(),
            "too many ha clients"
        );
    }

    pub fn all_entity_ids(&self) -> impl Iterator<Item = EntityId> {
        self.server_ids()
            .chain(self.user_ids())
            .chain(self.malicious_user_ids())
            .chain(self.ha_client_ids())
    }

    #[inline(always)]
    pub fn server_ids(&self) -> impl Iterator<Item = EntityId> {
        entity_ids(SERVER_RANGE, 1)
    }

    #[inline(always)]
    pub fn user_ids(&self) -> impl Iterator<Item = EntityId> {
        entity_ids(USER_RANGE, self.n_correct_users as u32)
    }

    #[inline(always)]
    pub fn malicious_user_ids(&self) -> impl Iterator<Item = EntityId> {
        entity_ids(MALICIOUS_USER_RANGE, self.n_malicious_users as u32)
    }

    #[inline(always)]
    pub fn ha_client_ids(&self) -> impl Iterator<Item = EntityId> {
        entity_ids(HA_CLIENT_RANGE, self.n_ha_clients as u32)
    }

    pub fn keystore_paths(&self, tempdir: &tempfile::TempDir) -> HashMap<EntityId, (PathBuf, PathBuf)> {
        self.all_entity_ids()
            .map(|id| (id, gen_keystore(&self, id, &tempdir)))
            .collect()
    }

    pub fn keystore_path(&self, tempdir: &tempfile::TempDir, id: EntityId) -> (PathBuf, PathBuf) {
        let me_path = tempdir
            .path()
            .join(format!("ent_{}_keystore_priv.json", id));
        let reg_path = tempdir.path().join(format!("ent_{}_registry.json", id));

        (reg_path, me_path)
    }

    pub fn gen_driver_config(
        &self,
        servers: &[Server],
        users: &[User],
        malicious_users: &[User],
    ) -> driver::Conf {
        let mut id_to_uri = HashMap::new();
        for (i, server) in servers.iter().enumerate() {
            let id = self.server_ids().nth(i).unwrap();
            id_to_uri.insert(id, server.uri());
        }
        for (i, user) in users.iter().enumerate() {
            let id = self.user_ids().nth(i).unwrap();
            id_to_uri.insert(id, user.uri());
        }
        for (i, user) in malicious_users.iter().enumerate() {
            let id = self.malicious_user_ids().nth(i).unwrap();
            id_to_uri.insert(id, user.uri());
        }

        driver::Conf {
            dims: self.dims,
            correct_servers: self.server_ids().collect(),
            correct_users: self.user_ids().collect(),
            malicious_users: self.malicious_user_ids().map(|id| (id, 0)).collect(),
            id_to_uri,
            max_neighbourhood_faults: self.max_neigh_faults,
        }
    }
}

#[inline(always)]
fn entity_ids(range: Range<EntityId>, n: u32) -> impl Iterator<Item = EntityId> {
    range.start..range.start + n
}

fn gen_keystore(config: &TestConfig, id: EntityId, tempdir: &tempfile::TempDir) -> (PathBuf, PathBuf) {
    let (reg_path, me_path) = config.keystore_path(tempdir, id);

    let mut ks = KeyStore::new(PRIV_KEYS.get(&id).unwrap().clone());
    for id in config.all_entity_ids() {
        ks.add_entity(PUB_KEYS.get(&id).unwrap().clone()).unwrap();
    }

    ks.save_to_files(&reg_path, &me_path).unwrap();

    (reg_path, me_path)
}

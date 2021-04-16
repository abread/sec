use std::collections::HashMap;
use std::ops::Range;
use std::path::PathBuf;

use lazy_static::lazy_static;
use model::keys::{EntityId, EntityPrivComponent, EntityPubComponent, KeyStore, Role};
use more_asserts::*;
use tempdir::TempDir;

pub const USER_RANGE: Range<EntityId> = 100..200;
pub const MALICIOUS_USER_RANGE: Range<EntityId> = 200..300;
pub const HA_CLIENT_RANGE: Range<EntityId> = 300..400;

lazy_static! {
    pub static ref PRIV_KEYS: HashMap<EntityId, EntityPrivComponent> = {
        model::ensure_init();
        let mut map = HashMap::new();

        map.insert(0, EntityPrivComponent::new(0, Role::Server));

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
    pub n_users: usize,
    pub n_malicious_users: usize,
    pub n_ha_clients: usize,
    pub max_faults: usize,
}

impl TestConfig {
    pub fn assert_valid(&self) {
        assert_lt!(self.n_users, USER_RANGE.len(), "too many users");
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
        std::iter::once(0)
            .chain(self.user_ids())
            .chain(self.malicious_user_ids())
            .chain(self.ha_client_ids())
    }

    #[inline(always)]
    pub fn user_ids(&self) -> impl Iterator<Item = EntityId> {
        entity_ids(USER_RANGE, self.n_users as u32)
    }

    #[inline(always)]
    pub fn malicious_user_ids(&self) -> impl Iterator<Item = EntityId> {
        entity_ids(MALICIOUS_USER_RANGE, self.n_malicious_users as u32)
    }

    #[inline(always)]
    pub fn ha_client_ids(&self) -> impl Iterator<Item = EntityId> {
        entity_ids(HA_CLIENT_RANGE, self.n_ha_clients as u32)
    }

    pub fn keystore_paths(&self, tempdir: &TempDir) -> HashMap<EntityId, (PathBuf, PathBuf)> {
        self.all_entity_ids()
            .map(|id| (id, gen_keystore(&self, id, &tempdir)))
            .collect()
    }
}

#[inline(always)]
fn entity_ids(range: Range<EntityId>, n: u32) -> impl Iterator<Item = EntityId> {
    range.start..range.start + n
}

fn gen_keystore(config: &TestConfig, id: EntityId, tempdir: &TempDir) -> (PathBuf, PathBuf) {
    let me_path = tempdir
        .path()
        .join(format!("ent_{}_keystore_priv.json", id));
    let reg_path = tempdir.path().join(format!("ent_{}_registry.json", id));

    let mut ks = KeyStore::new(PRIV_KEYS.get(&id).unwrap().clone());
    for id in config.all_entity_ids() {
        ks.add_entity(PUB_KEYS.get(&id).unwrap().clone()).unwrap();
    }

    ks.save_to_files(&reg_path, &me_path).unwrap();

    (reg_path, me_path)
}

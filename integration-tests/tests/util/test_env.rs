use std::path::PathBuf;
use std::ops::Range;

use lazy_static::lazy_static;
use model::keys::{EntityId, EntityPrivComponent, EntityPubComponent, KeyStore, Role};
use std::collections::HashMap;
use tempdir::TempDir;

const USER_RANGE: Range<EntityId> = 100..200;
const MALICIOUS_USER_RANGE: Range<EntityId> = 200..300;
const HA_CLIENT_RANGE: Range<EntityId> = 300..400;

lazy_static! {
    static ref PRIV_KEYS: HashMap<EntityId, EntityPrivComponent> = {
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
    static ref PUB_KEYS: HashMap<EntityId, EntityPubComponent> = {
        let mut map = HashMap::new();
        for (id, priv_comp) in PRIV_KEYS.iter() {
            map.insert(id, priv_comp.pub_component());
        }
        map
    };
}

type Server = ();
type Client = ();

pub(crate) struct TestEnvironment {
    tempdir: TempDir,
    pub server: Server,
    pub users: Vec<Client>,
    pub malicious_users: Vec<Client>,
    pub ha_clients: Vec<Client>,
}

impl TestEnvironment {
    pub(crate) fn new(n_users: u32, n_malicious_users: u32, n_ha_clients: u32) -> Self {
        assert!(n_users < 100);
        assert!(n_malicious_users < 100);
        assert!(n_ha_clients < 100);

        let tempdir =
            TempDir::new("integration-tests").expect("failed to create temp dir for test");

        let all_ids = || all_entity_ids(n_users, n_malicious_users, n_ha_clients);
        let keystore_paths: HashMap<EntityId, (PathBuf, PathBuf)> = all_ids()
            .map(|id| (id, gen_keystore(id, &tempdir, all_ids())))
            .collect();

        let server = spawn_server(0, &tempdir, &keystore_paths);
        let users = entity_ids(USER_RANGE, n_users)
            .map(|id| spawn_user(id, &tempdir, &keystore_paths))
            .collect();
        let malicious_users = entity_ids(MALICIOUS_USER_RANGE, n_malicious_users)
            .map(|id| spawn_malicious_user(id, &tempdir, &keystore_paths))
            .collect();
        let ha_clients = entity_ids(HA_CLIENT_RANGE, n_ha_clients)
            .map(|id| spawn_ha_client(id, &tempdir, &keystore_paths))
            .collect();

        TestEnvironment {
            tempdir,
            server,
            users,
            malicious_users,
            ha_clients,
        }
    }

    pub(crate) fn server(&self, _i: u32) -> Server {
        self.server
    }

    pub(crate) fn server_id(&self, _i: u32) -> EntityId {
        0
    }

    pub(crate) fn server_key(&self, i: u32) -> &EntityPrivComponent {
        &PRIV_KEYS.get(&self.server_id(i)).unwrap()
    }

    pub(crate) fn user(&self, i: u32) -> Client {
        self.users[i as usize]
    }

    pub(crate) fn user_id(&self, i: u32) -> EntityId {
        USER_RANGE.start + i
    }

    pub(crate) fn user_key(&self, i: u32) -> &EntityPrivComponent {
        &PRIV_KEYS.get(&self.user_id(i)).unwrap()
    }

    pub(crate) fn malicious_user(&self, i: u32) -> Client {
        self.malicious_users[i as usize]
    }

    pub(crate) fn malicious_user_id(&self, i: u32) -> EntityId {
        MALICIOUS_USER_RANGE.start + i
    }

    pub(crate) fn malicious_user_key(&self, i: u32) -> &EntityPrivComponent {
        &PRIV_KEYS.get(&self.malicious_user_id(i)).unwrap()
    }

    pub(crate) fn ha_client(&self, i: u32) -> Client {
        self.ha_clients[i as usize]
    }

    pub(crate) fn ha_client_id(&self, i: u32) -> EntityId {
        HA_CLIENT_RANGE.start + i
    }

    pub(crate) fn ha_client_key(&self, i: u32) -> &EntityPrivComponent {
        &PRIV_KEYS.get(&self.ha_client_id(i)).unwrap()
    }

}

fn spawn_server(id: EntityId, tempdir: &TempDir, keystore_paths: &HashMap<EntityId, (PathBuf, PathBuf)>) -> Server {
    ()
}

fn spawn_user(id: EntityId, tempdir: &TempDir, keystore_paths: &HashMap<EntityId, (PathBuf, PathBuf)>) -> Client {
    ()
}

fn spawn_malicious_user(id: EntityId, tempdir: &TempDir, keystore_paths: &HashMap<EntityId, (PathBuf, PathBuf)>) -> Client {
    ()
}

fn spawn_ha_client(id: EntityId, tempdir: &TempDir, keystore_paths: &HashMap<EntityId, (PathBuf, PathBuf)>) -> Client {
    ()
}

fn gen_keystore(
    id: EntityId,
    tempdir: &TempDir,
    all_entity_ids: impl Iterator<Item = EntityId>,
) -> (PathBuf, PathBuf) {
    let me_path = tempdir
        .path()
        .join(format!("ent_{}_keystore_priv.json", id));
    let reg_path = tempdir.path().join(format!("ent_{}_registry.json", id));

    let mut ks = KeyStore::new(PRIV_KEYS.get(&id).unwrap().clone());
    for id in all_entity_ids {
        ks.add_entity(PUB_KEYS.get(&id).unwrap().clone()).unwrap();
    }

    ks.save_to_files(&reg_path, &me_path).unwrap();

    (reg_path, me_path)
}

#[inline(always)]
fn all_entity_ids(n_users: u32, n_malicious_users: u32, n_ha_clients: u32) -> impl Iterator<Item = EntityId> {
    std::iter::once(0)
        .chain(entity_ids(USER_RANGE, n_users))
        .chain(entity_ids(MALICIOUS_USER_RANGE, n_malicious_users))
        .chain(entity_ids(HA_CLIENT_RANGE, n_ha_clients))
}

#[inline(always)]
fn entity_ids(range: Range<EntityId>, n: u32) -> impl Iterator<Item = EntityId> {
    range.start..range.start+n
}
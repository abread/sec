use std::path::PathBuf;

use model::keys::EntityId;
use std::collections::HashMap;
use tempdir::TempDir;

use super::test_config::TestConfig;

use server::{Server, ServerBgTaskHandle};

type Client = ();

pub struct TestEnvironment {
    tempdir: TempDir,
    config: TestConfig,
    pub server: Server,
    pub users: Vec<Client>,
    pub malicious_users: Vec<Client>,
    pub ha_clients: Vec<Client>,
}

impl TestEnvironment {
    pub fn new(config: TestConfig) -> Self {
        config.assert_valid();

        let tempdir =
            TempDir::new("integration-tests").expect("failed to create temp dir for test");

        let keystore_paths = config.keystore_paths(&tempdir);

        let (server, _) = spawn_server(0, &tempdir, &keystore_paths, config.quorum_size);
        let users = config
            .user_ids()
            .map(|id| spawn_user(id, &tempdir, &keystore_paths))
            .collect();
        let malicious_users = config
            .malicious_user_ids()
            .map(|id| spawn_malicious_user(id, &tempdir, &keystore_paths))
            .collect();
        let ha_clients = config
            .ha_client_ids()
            .map(|id| spawn_ha_client(id, &tempdir, &keystore_paths))
            .collect();

        TestEnvironment {
            tempdir,
            config,
            server,
            users,
            malicious_users,
            ha_clients,
        }
    }

    pub fn server(&self, _i: u32) -> &Server {
        &self.server
    }

    pub fn user(&self, i: u32) -> &Client {
        &self.users[i as usize]
    }

    pub fn malicious_user(&self, i: u32) -> &Client {
        &self.malicious_users[i as usize]
    }

    pub fn ha_client(&self, i: u32) -> &Client {
        &self.ha_clients[i as usize]
    }
}

fn spawn_server(
    id: EntityId,
    tempdir: &TempDir,
    keystore_paths: &HashMap<EntityId, (PathBuf, PathBuf)>,
    quorum_size: usize,
) -> (Server, ServerBgTaskHandle) {
    use server::Options;

    let (entity_registry_path, skeys_path) = keystore_paths.get(&id).unwrap().clone();

    let options = Options {
        entity_registry_path,
        skeys_path,
        quorum_size,
        storage_path: tempdir.path().join(format!("server_storage_{}", id)),
        bind_addr: "[::1]:0".parse().unwrap(),
    };

    Server::new(&options).expect("failed to spawn server")
}

fn spawn_user(
    id: EntityId,
    tempdir: &TempDir,
    keystore_paths: &HashMap<EntityId, (PathBuf, PathBuf)>,
) -> Client {
    ()
}

fn spawn_malicious_user(
    id: EntityId,
    tempdir: &TempDir,
    keystore_paths: &HashMap<EntityId, (PathBuf, PathBuf)>,
) -> Client {
    ()
}

fn spawn_ha_client(
    id: EntityId,
    tempdir: &TempDir,
    keystore_paths: &HashMap<EntityId, (PathBuf, PathBuf)>,
) -> Client {
    ()
}

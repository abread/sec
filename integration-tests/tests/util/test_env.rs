use std::path::PathBuf;

use model::keys::EntityId;
use std::collections::HashMap;
use tempdir::TempDir;

use super::test_config::TestConfig;

use client::Client;
use server::{Server, Uri};

type BgTaskHandle = server::ServerBgTaskHandle;

pub struct TestEnvironment {
    tempdir: TempDir,
    config: TestConfig,
    pub server: Server,
    pub users: Vec<Client>,
    pub malicious_users: Vec<Client>,
    pub ha_clients: Vec<Client>,
    bg_tasks: Vec<BgTaskHandle>,
}

impl TestEnvironment {
    pub fn new(config: TestConfig) -> Self {
        config.assert_valid();

        let tempdir =
            TempDir::new("integration-tests").expect("failed to create temp dir for test");

        let keystore_paths = config.keystore_paths(&tempdir);

        let mut bg_tasks = Vec::new();

        let (server, server_bg_task) =
            spawn_server(0, &tempdir, &keystore_paths, config.quorum_size);
        bg_tasks.push(server_bg_task);

        let (users, mut user_bg_tasks) = config
            .user_ids()
            .map(|id| spawn_user(id, &tempdir, &keystore_paths, server.uri()))
            .unzip();
        bg_tasks.append(&mut user_bg_tasks);

        let (malicious_users, mut mu_bg_tasks) = config
            .malicious_user_ids()
            .map(|id| spawn_malicious_user(id, &tempdir, &keystore_paths, server.uri()))
            .unzip();
        bg_tasks.append(&mut mu_bg_tasks);

        let (ha_clients, mut hc_bg_tasks) = config
            .ha_client_ids()
            .map(|id| spawn_ha_client(id, &tempdir, &keystore_paths, server.uri()))
            .unzip();
        bg_tasks.append(&mut hc_bg_tasks);

        TestEnvironment {
            tempdir,
            config,
            server,
            users,
            malicious_users,
            ha_clients,
            bg_tasks,
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

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        for task in &self.bg_tasks {
            task.abort()
        }
    }
}

fn spawn_server(
    id: EntityId,
    tempdir: &TempDir,
    keystore_paths: &HashMap<EntityId, (PathBuf, PathBuf)>,
    quorum_size: usize,
) -> (Server, BgTaskHandle) {
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
    server_uri: Uri,
) -> (Client, BgTaskHandle) {
    use client::Options;

    let (entity_registry_path, skeys_path) = keystore_paths.get(&id).unwrap().clone();

    let options = Options {
        entity_registry_path,
        skeys_path,
        server_uri,
        malicious: false,
        bind_addr: "[::1]:0".parse().unwrap(),
    };

    Client::new(&options).expect("failed to spawn client")
}

fn spawn_malicious_user(
    id: EntityId,
    tempdir: &TempDir,
    keystore_paths: &HashMap<EntityId, (PathBuf, PathBuf)>,
    server_uri: Uri,
) -> (Client, BgTaskHandle) {
    todo!()
}

fn spawn_ha_client(
    id: EntityId,
    tempdir: &TempDir,
    keystore_paths: &HashMap<EntityId, (PathBuf, PathBuf)>,
    server_uri: Uri,
) -> (Client, BgTaskHandle) {
    todo!()
}

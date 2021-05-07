use std::{path::PathBuf, sync::Arc, time::Duration};

use driver::Driver;
use model::keys::{EntityId, KeyStore};
use std::collections::HashMap;

use super::test_config::TestConfig;

use client::HdltApiClient;
use client::User;
use server::{Server, Uri};

type BgTaskHandle = server::ServerBgTaskHandle;

pub struct TestEnv {
    _tempdir: tempfile::TempDir,
    config: TestConfig,
    pub driver: Driver,
    pub servers: Vec<Server>,
    pub users: Vec<User>,
    pub malicious_users: Vec<User>,
    bg_tasks: Vec<BgTaskHandle>,
}

impl TestEnv {
    pub async fn new(config: TestConfig) -> Self {
        config.assert_valid();

        let tempdir = tempfile::tempdir().expect("failed to create temp dir for test");

        let keystore_paths = config.keystore_paths(&tempdir);

        let mut bg_tasks = Vec::new();

        let mut servers = Vec::new();
        for fut in config
            .server_ids()
            .map(|id| spawn_server(id, &tempdir, &keystore_paths))
        {
            let (server, bg_task) = fut.await;
            servers.push(server);
            bg_tasks.push(bg_task);
        }

        let server = &servers[0];

        let mut users = Vec::new();
        for fut in config
            .user_ids()
            .map(|id| spawn_user(id, &keystore_paths, server.uri(), false))
        {
            let (user, bg_task) = fut.await;
            users.push(user);
            bg_tasks.push(bg_task);
        }

        let mut malicious_users = Vec::new();
        for fut in config
            .malicious_user_ids()
            .map(|id| spawn_user(id, &keystore_paths, server.uri(), true))
        {
            let (muser, bg_task) = fut.await;
            malicious_users.push(muser);
            bg_tasks.push(bg_task);
        }

        // wait a bit for all the servers to start up
        tokio::time::sleep(Duration::from_secs(2)).await;

        let driver_config = config.gen_driver_config(&servers, &users, &malicious_users);
        let driver = Driver::new(driver_config).await.unwrap();

        TestEnv {
            _tempdir: tempdir,
            config,
            driver,
            servers,
            users,
            malicious_users,
            bg_tasks,
        }
    }

    pub async fn tick(&self) {
        self.driver.tick().await.unwrap()
    }

    pub async fn current_epoch(&self) -> u64 {
        self.driver.current_epoch().await
    }

    pub fn server(&self, i: usize) -> &Server {
        &self.servers[i]
    }

    pub fn user(&self, i: usize) -> &User {
        &self.users[i]
    }

    pub fn user_id(&self, i: usize) -> EntityId {
        self.config.user_ids().nth(i).unwrap()
    }

    pub fn malicious_user(&self, i: usize) -> &User {
        &self.malicious_users[i]
    }

    pub async fn ha_client(&self, i: usize) -> HdltApiClient {
        let id = self.config.ha_client_ids().nth(i).unwrap();
        self.api_client_for_entity(id).await
    }

    pub async fn user_api_client(&self, i: usize) -> HdltApiClient {
        let id = self.user_id(i);
        self.api_client_for_entity(id).await
    }

    pub async fn api_client_for_entity(&self, id: EntityId) -> HdltApiClient {
        let keystore = self.keystore_for_entity(id);
        let current_epoch = self.current_epoch().await;
        HdltApiClient::new(self.server(0).uri(), Arc::new(keystore), current_epoch).unwrap()
    }

    fn keystore_for_entity(&self, id: EntityId) -> KeyStore {
        let (registry_path, me_path) = self.config.keystore_path(&self._tempdir, id);
        KeyStore::load_from_files(registry_path, me_path).unwrap()
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        for task in &self.bg_tasks {
            task.abort()
        }
    }
}

async fn spawn_server(
    id: EntityId,
    tempdir: &tempfile::TempDir,
    keystore_paths: &HashMap<EntityId, (PathBuf, PathBuf)>,
) -> (Server, BgTaskHandle) {
    use server::Options;

    let (entity_registry_path, skeys_path) = keystore_paths.get(&id).unwrap().clone();

    let options = Options {
        entity_registry_path,
        skeys_path,
        storage_path: tempdir.path().join(format!("server_storage_{}", id)),
        bind_addr: "[::1]:0".parse().unwrap(),
    };

    Server::new(&options).await.expect("failed to spawn server")
}

async fn spawn_user(
    id: EntityId,
    keystore_paths: &HashMap<EntityId, (PathBuf, PathBuf)>,
    server_uri: Uri,
    is_malicious: bool,
) -> (User, BgTaskHandle) {
    use client::UserOptions;

    let (entity_registry_path, skeys_path) = keystore_paths.get(&id).unwrap().clone();

    let options = UserOptions {
        entity_registry_path,
        skeys_path,
        server_uri,
        malicious: is_malicious,
        bind_addr: "[::1]:0".parse().unwrap(),
    };

    User::new(&options).await.expect("failed to spawn user")
}

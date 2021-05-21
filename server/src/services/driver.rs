use std::sync::Arc;

use model::keys::EntityId;
use protos::driver::correct_server_driver_server::CorrectServerDriver;
use protos::driver::{InitialConfigRequest, ServerConfigUpdate};
use protos::util::Empty;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tonic::{transport::Uri, Request, Response};

use tracing::*;
use tracing_utils::instrument_tonic_service;

#[derive(Default, Debug)]
pub struct Driver {
    state: Arc<RwLock<ServerConfig>>,
}

#[derive(Debug)]
pub struct ServerConfig {
    pub epoch: u64,

    /// f', maximum number of byzantine users in a region
    ///
    /// See [model::PositionProof] for more information.
    pub max_neigh_faults: u64,

    /// max number of server faults
    pub max_server_faults: u64,

    /// servers
    pub servers: Vec<EntityId>,

    /// Id to URI
    pub id_uri_map: HashMap<EntityId, Uri>,
}

impl Driver {
    pub fn state(&self) -> Arc<RwLock<ServerConfig>> {
        Arc::clone(&self.state)
    }

    pub async fn id_to_uri(&self, id: &EntityId) -> Uri {
        self.state.read().await.id_uri_map.get(id).unwrap().clone()
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            epoch: 0,
            max_neigh_faults: 0,
            max_server_faults: 0,
            servers: vec![],
            id_uri_map: HashMap::new(),
        }
    }
}

impl ServerConfig {
    pub fn n_servers(&self) -> u64 {
        (self.servers.len() + 1) as u64
    }
}

type GrpcResult<T> = Result<Response<T>, tonic::Status>;

#[instrument_tonic_service]
#[tonic::async_trait]
impl CorrectServerDriver for Driver {
    #[instrument(skip(self))]
    async fn update_config(&self, request: Request<ServerConfigUpdate>) -> GrpcResult<Empty> {
        let request = request.into_inner();

        let mut state = self.state.write().await;
        state.epoch = request.new_epoch;
        state.max_neigh_faults = request.neighbour_faults;
        state.max_server_faults = request.server_faults;

        info!(event = "New state received", ?state);

        Ok(Response::new(Empty {}))
    }

    async fn initial_config(&self, request: Request<InitialConfigRequest>) -> GrpcResult<Empty> {
        let request = request.into_inner();
        let mut state = self.state.write().await;
        state.epoch = 0;
        state.max_neigh_faults = 0;
        state.max_server_faults = 0;
        state.servers = request.servers;
        state.id_uri_map = request
            .id_uri_map
            .iter()
            .map(|(k, v)| (*k, v.parse::<Uri>().unwrap()))
            .collect();

        info!(event = "New config received", ?state);

        Ok(Response::new(Empty {}))
    }
}

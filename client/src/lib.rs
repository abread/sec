pub(crate) mod driver;
pub mod hdlt_api;
pub(crate) mod malicious_driver;
pub(crate) mod malicious_witness;
pub(crate) mod state;
pub(crate) mod witness;
mod witness_api;

use std::path::PathBuf;
use std::sync::Arc;
use std::{net::SocketAddr, ops::Deref};

use structopt::StructOpt;
use tokio::sync::RwLock;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Server, Uri};
use tracing::info;

use model::keys::KeyStore;
use protos::driver::driver_server::DriverServer;
use protos::driver::malicious_driver_server::MaliciousDriverServer;
use protos::witness::witness_server::WitnessServer;

use driver::DriverService;
use hdlt_api::HdltApiClient;
use malicious_driver::MaliciousDriverService;
use malicious_witness::MaliciousWitnessService;
use state::{CorrectClientState, MaliciousClientState};
use witness::WitnessService;

#[derive(StructOpt, Debug)]
pub struct Options {
    /// Server URI
    #[structopt(short = "s", long = "server")]
    pub server_uri: Uri,

    /// Whether the client is malicious
    #[structopt(short, long)]
    pub malicious: bool,

    /// Bind address
    pub bind_addr: std::net::SocketAddr,

    /// path to entity registry
    ///
    /// See [KeyStore] for more information.
    #[structopt(short = "e", long = "entities", env = "ENTITY_REGISTRY_PATH")]
    pub entity_registry_path: PathBuf,

    /// path to client secret keys
    ///
    /// See [KeyStore] for more information.
    #[structopt(short = "k", long = "secret-keys", env = "SECRET_KEYS_PATH")]
    pub skeys_path: PathBuf,
}

#[derive(Debug)]
pub struct Client {
    listen_addr: SocketAddr,
    api_client: HdltApiClient,
}

pub type ClientBgTaskHandle = tokio::task::JoinHandle<eyre::Result<()>>;
impl Client {
    pub fn new(options: &Options) -> eyre::Result<(Self, ClientBgTaskHandle)> {
        let keystore = Arc::new(KeyStore::load_from_files(
            options.entity_registry_path.clone(),
            options.skeys_path.clone(),
        )?);

        let (incoming, listen_addr) = create_tcp_incoming(&options.bind_addr)?;

        let is_malicious = options.malicious;
        let ks = Arc::clone(&keystore);
        let su = options.server_uri.clone();
        let client_bg_task = tokio::spawn(async move {
            if is_malicious {
                malicious_driver_server(incoming, listen_addr, ks, su).await
            } else {
                driver_server(incoming, listen_addr, ks, su).await
            }
        });

        let api_client = HdltApiClient::new(options.server_uri.clone(), keystore)?;

        let client = Client {
            listen_addr,
            api_client,
        };
        Ok((client, client_bg_task))
    }

    pub fn api_client(&self) -> &HdltApiClient {
        &self.api_client
    }

    pub fn listen_addr(&self) -> &SocketAddr {
        &self.listen_addr
    }

    /// Compute client's URI/endpoint for use by other clients/driver
    ///
    /// Assumes the address [Self::listen_addr] is accessible.
    pub fn uri(&self) -> Uri {
        let authority = format!("{}:{}", self.listen_addr.ip(), self.listen_addr.port());
        Uri::builder()
            .scheme("http")
            .authority(authority.as_str())
            .build()
            .unwrap()
    }
}

impl Deref for Client {
    type Target = HdltApiClient;

    fn deref(&self) -> &Self::Target {
        &self.api_client
    }
}

async fn ctrl_c() {
    use std::future;

    if tokio::signal::ctrl_c().await.is_err() {
        eprintln!("Failed to listen for Ctrl+C/SIGINT. Server will still exit after receiving them, just not gracefully.");
        future::pending().await // never completes
    }
}

async fn malicious_driver_server(
    incoming: TcpListenerStream,
    listen_addr: SocketAddr,
    keystore: Arc<KeyStore>,
    server_uri: Uri,
) -> eyre::Result<()> {
    let state = Arc::new(RwLock::new(MaliciousClientState::new()));
    let server = Server::builder()
        .add_service(MaliciousDriverServer::new(MaliciousDriverService::new(
            state.clone(),
            Arc::clone(&keystore),
            server_uri,
        )))
        .add_service(WitnessServer::new(MaliciousWitnessService::new(
            keystore, state,
        )))
        .serve_with_incoming_shutdown(incoming, ctrl_c());

    info!("Malicious Driver Server @{:?}: listening", listen_addr);
    server.await?;
    info!("Malicious Driver Server @{:?}: finished", listen_addr);
    Ok(())
}

async fn driver_server(
    incoming: TcpListenerStream,
    listen_addr: SocketAddr,
    keystore: Arc<KeyStore>,
    server_uri: Uri,
) -> eyre::Result<()> {
    let state = Arc::new(RwLock::new(CorrectClientState::new()));
    let server = Server::builder()
        .add_service(DriverServer::new(DriverService::new(
            state.clone(),
            Arc::clone(&keystore),
            server_uri,
        )))
        .add_service(WitnessServer::new(WitnessService::new(keystore, state)))
        .serve_with_incoming_shutdown(incoming, ctrl_c());
    info!("Driver Server @{:?}: listening", listen_addr);
    server.await?;
    info!("Driver Server @{:?}: finished", listen_addr);
    Ok(())
}

fn create_tcp_incoming(bind_addr: &SocketAddr) -> eyre::Result<(TcpListenerStream, SocketAddr)> {
    let listener = std::net::TcpListener::bind(bind_addr)?;
    let listen_addr = listener.local_addr()?;

    let listener = tokio::net::TcpListener::from_std(listener)?;
    Ok((TcpListenerStream::new(listener), listen_addr))
}

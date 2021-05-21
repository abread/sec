#![deny(unsafe_op_in_unsafe_fn)]

pub(crate) mod correct_driver;
pub(crate) mod correct_witness;
pub(crate) mod hdlt_api;
pub(crate) mod malicious_driver;
pub(crate) mod malicious_witness;
pub(crate) mod state;
mod witness_api;

pub use hdlt_api::{HdltApiClient, HdltError};

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use structopt::StructOpt;
use tokio::{net::TcpStream, sync::RwLock};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::{Stream, StreamExt};
use tonic::transport::{Server, Uri};
use tracing::*;

use model::keys::KeyStore;
use protos::driver::correct_user_driver_server::CorrectUserDriverServer;
use protos::driver::malicious_user_driver_server::MaliciousUserDriverServer;
use protos::witness::witness_server::WitnessServer;

use correct_driver::CorrectDriverService;
use correct_witness::CorrectWitnessService;
use malicious_driver::MaliciousDriverService;
use malicious_witness::MaliciousWitnessService;
use state::{CorrectUserState, MaliciousUserState};

#[derive(StructOpt, Debug)]
pub struct UserOptions {
    /// Server URI: THE ORDER MATTERS
    /// TODO: a more elegant solution for this
    #[structopt(short = "s", long = "servers")]
    pub server_uris: Vec<Uri>,

    /// Whether the user is malicious
    #[structopt(short, long)]
    pub malicious: bool,

    /// Bind address
    pub bind_addr: std::net::SocketAddr,

    /// path to entity registry
    ///
    /// See [KeyStore] for more information.
    #[structopt(short = "e", long = "entities", env = "ENTITY_REGISTRY_PATH")]
    pub entity_registry_path: PathBuf,

    /// path to user secret keys
    ///
    /// See [KeyStore] for more information.
    #[structopt(short = "k", long = "secret-keys", env = "SECRET_KEYS_PATH")]
    pub skeys_path: PathBuf,
}

#[derive(Debug)]
pub struct User {
    listen_addr: SocketAddr,
}

pub type UserBgTaskHandle = tokio::task::JoinHandle<eyre::Result<()>>;
macro_rules! IncomingType {
    () => { impl Stream<Item = Result<TcpStream, std::io::Error>> }
}

impl User {
    pub async fn new(options: &UserOptions) -> eyre::Result<(Self, UserBgTaskHandle)> {
        let keystore = Arc::new(KeyStore::load_from_files(
            options.entity_registry_path.clone(),
            options.skeys_path.clone(),
        )?);

        let (incoming, listen_addr) = create_tcp_incoming(&options.bind_addr).await?;

        let is_malicious = options.malicious;
        let ks = Arc::clone(&keystore);
        let su = options
            .server_uris
            .clone()
            .into_iter()
            .enumerate()
            .map(|(idx, uri)| (idx as u32, uri))
            .collect();
        let user_bg_task = tokio::spawn(async move {
            let res = if is_malicious {
                malicious_driver_server(incoming, ks, su).await
            } else {
                driver_server(incoming, ks, su).await
            };

            if let Err(err) = &res {
                error!(event = "Something crashed the user task", ?err);
            }

            res
        }.instrument(info_span!("user task", entity_id = keystore.my_id(), %listen_addr, is_malicious = options.malicious)));

        let user = User { listen_addr };
        Ok((user, user_bg_task))
    }

    pub fn listen_addr(&self) -> &SocketAddr {
        &self.listen_addr
    }

    /// Compute user's URI/endpoint for use by other users/driver
    ///
    /// Assumes the address [Self::listen_addr] is accessible.
    pub fn uri(&self) -> Uri {
        let authority = if self.listen_addr.is_ipv6() {
            format!("[{}]:{}", self.listen_addr.ip(), self.listen_addr.port())
        } else {
            format!("{}:{}", self.listen_addr.ip(), self.listen_addr.port())
        };

        Uri::builder()
            .scheme("http")
            .authority(authority.as_str())
            .path_and_query("/")
            .build()
            .unwrap()
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
    incoming: IncomingType!(),
    keystore: Arc<KeyStore>,
    server_uris: Vec<(u32, Uri)>,
) -> eyre::Result<()> {
    let state = Arc::new(RwLock::new(MaliciousUserState::new()));
    let server = Server::builder()
        .add_service(MaliciousUserDriverServer::new(MaliciousDriverService::new(
            state.clone(),
            Arc::clone(&keystore),
            server_uris,
        )))
        .add_service(WitnessServer::new(MaliciousWitnessService::new(
            keystore, state,
        )))
        .serve_with_incoming_shutdown(incoming, ctrl_c());

    info!("Malicious User Driver Server listening");
    server.await.map_err(eyre::Report::from)
}

async fn driver_server(
    incoming: IncomingType!(),
    keystore: Arc<KeyStore>,
    server_uris: Vec<(u32, Uri)>,
) -> eyre::Result<()> {
    let state = Arc::new(RwLock::new(CorrectUserState::new()));
    let server = Server::builder()
        .add_service(CorrectUserDriverServer::new(CorrectDriverService::new(
            state.clone(),
            Arc::clone(&keystore),
            server_uris,
        )))
        .add_service(WitnessServer::new(CorrectWitnessService::new(
            keystore, state,
        )))
        .serve_with_incoming_shutdown(incoming, ctrl_c());

    info!("Correct User Driver Server listening");
    server.await.map_err(eyre::Report::from)
}

async fn create_tcp_incoming(
    bind_addr: &SocketAddr,
) -> eyre::Result<(IncomingType!(), SocketAddr)> {
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    let listen_addr = listener.local_addr()?;

    let listener_stream = TcpListenerStream::new(listener).map(|res| {
        res.and_then(|socket| {
            socket.set_nodelay(true)?;
            Ok(socket)
        })
    });

    Ok((listener_stream, listen_addr))
}

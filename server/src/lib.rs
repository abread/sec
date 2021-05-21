#![deny(unsafe_op_in_unsafe_fn)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use model::keys::KeyStore;
use protos::{
    driver::correct_server_driver_server::CorrectServerDriverServer,
    hdlt::hdlt_api_server::HdltApiServer,
};
use structopt::StructOpt;
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::{Stream, StreamExt};
use tonic::transport::Server as TonicServer;

use eyre::eyre;
use tracing::*;

pub type ServerBgTaskHandle = tokio::task::JoinHandle<eyre::Result<()>>;
pub use tonic::transport::Uri;

use hdlt_store::HdltLocalStore;
use services::{Driver, HdltApiService};

pub mod group_by;
pub(crate) mod hdlt_store;
pub(crate) mod services;

#[derive(StructOpt)]
pub struct Options {
    /// Bind address.
    #[structopt()]
    pub bind_addr: SocketAddr,

    /// Path to entity registry.
    ///
    /// See [KeyStore] for more information.
    #[structopt(short = "e", long = "entities", env = "ENTITY_REGISTRY_PATH")]
    pub entity_registry_path: PathBuf,

    /// Path to server secret keys.
    ///
    /// See [KeyStore] for more information.
    #[structopt(short = "s", long = "secrets", env = "SECRET_KEYS_PATH")]
    pub skeys_path: PathBuf,

    /// Path to storage file.
    #[structopt(long = "storage", default_value = "server-data.json")]
    pub storage_path: PathBuf,

    /// Secret keys password.
    #[structopt(long, short = "p", env = "SECRET_KEYS_PASSWORD")]
    pub skeys_password: Option<String>,
}

/// A HDLT Server, which can be polled to serve requests.
///
/// Only exists to facilitate integration testing.
pub struct Server {
    store: Arc<HdltLocalStore>,
    listen_addr: SocketAddr,
}

impl Server {
    pub async fn new(options: &Options) -> eyre::Result<(Self, ServerBgTaskHandle)> {
        let keystore = open_keystore(options)?;

        let store = Arc::new(HdltLocalStore::open(&options.storage_path).await?);

        let (incoming, listen_addr) = create_tcp_incoming(&options.bind_addr).await?;

        let driver = Driver::default();

        let entity_id = keystore.my_id();
        let state = driver.state();
        let conf = state.read().await;
        let server_uris = conf
            .servers
            .iter()
            .filter(|&id| id != &entity_id)
            .map(|id| conf.id_uri_map[id].clone())
            .collect();

        let server_bg_task = TonicServer::builder()
            .add_service(HdltApiServer::new(HdltApiService::new(
                keystore,
                Arc::clone(&store),
                driver.state(),
                server_uris,
            )))
            .add_service(CorrectServerDriverServer::new(driver))
            .serve_with_incoming_shutdown(incoming, ctrl_c());
        let server_bg_task = tokio::spawn(
            async move {
                info!("Server listening");
                let res = server_bg_task.await.map_err(eyre::Report::from);
                info!("Server stopped");

                if let Err(err) = &res {
                    error!(event = "Error ocurred in server", ?err);
                }
                res
            }
            .instrument(info_span!("server task", entity_id, %listen_addr)),
        );

        let server = Server { store, listen_addr };
        Ok((server, server_bg_task))
    }

    /// The server's underlying data store.
    pub fn store(&self) -> Arc<HdltLocalStore> {
        Arc::clone(&self.store)
    }

    /// Address where the server is listening for requests.
    ///
    /// Equivalent to callig [`local_addr()`](std::net::TcpListener::local_addr) on the underlying socket.
    /// So it will show the actual bound port when :0 is used in options.
    pub fn listen_addr(&self) -> &SocketAddr {
        &self.listen_addr
    }

    /// Compute server's URI/endpoint for a client-to-be.
    ///
    /// Assumes the address [Self::listen_addr] is accessible to the client-to-be.
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

fn open_keystore(options: &Options) -> eyre::Result<Arc<KeyStore>> {
    let mut keystore = KeyStore::load_from_files(
        options.entity_registry_path.clone(),
        options.skeys_path.clone(),
    )?;

    if keystore.is_locked() {
        let password = options.skeys_password.as_ref().ok_or_else(|| {
            eyre!("Secret keys are password-protected. Please supply their password")
        })?;
        keystore.unlock(password)?;
    }

    Ok(Arc::new(keystore))
}

async fn create_tcp_incoming(
    bind_addr: &SocketAddr,
) -> eyre::Result<(
    impl Stream<Item = Result<TcpStream, std::io::Error>>,
    SocketAddr,
)> {
    let listener = TcpListener::bind(bind_addr).await?;
    let listen_addr = listener.local_addr()?;

    let listener_stream = TcpListenerStream::new(listener).map(|res| {
        res.and_then(|socket| {
            socket.set_nodelay(true)?;
            Ok(socket)
        })
    });

    Ok((listener_stream, listen_addr))
}

async fn ctrl_c() {
    use std::future;

    if tokio::signal::ctrl_c().await.is_err() {
        eprintln!("Failed to listen for Ctrl+C/SIGINT. Server will still exit after receiving them, just not gracefully.");
        future::pending().await // never completes
    }
}

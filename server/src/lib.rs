use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use model::keys::KeyStore;
use protos::hdlt::hdlt_api_server::HdltApiServer;
use structopt::StructOpt;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server as TonicServer;

pub type ServerBgTaskHandle = tokio::task::JoinHandle<eyre::Result<()>>;
pub use tonic::transport::Uri;

use hdlt_store::HdltLocalStore;
use services::HdltApiService;

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

    /// Path to client secret keys.
    ///
    /// See [KeyStore] for more information.
    #[structopt(short = "s", long = "secrets", env = "SECRET_KEYS_PATH")]
    pub skeys_path: PathBuf,

    /// Path to storage file.
    #[structopt(long = "storage", default_value = "server-data.json")]
    pub storage_path: PathBuf,

    /// f', maximum number of byzantine users in a region
    ///
    /// See [model::PositionProof] for more information.
    #[structopt(short, long)]
    pub max_faults: usize,
}

/// A HDLT Server, which can be polled to serve requests.
///
/// Only exists to facilitate integration testing.
pub struct Server {
    store: Arc<HdltLocalStore>,
    listen_addr: SocketAddr,
}

impl Server {
    pub fn new(options: &Options) -> eyre::Result<(Self, ServerBgTaskHandle)> {
        let keystore = Arc::new(KeyStore::load_from_files(
            &options.entity_registry_path,
            &options.skeys_path,
        )?);

        let store = Arc::new(HdltLocalStore::open(&options.storage_path)?);

        let (incoming, listen_addr) = create_tcp_incoming(&options.bind_addr)?;

        let server_bg_task = TonicServer::builder()
            .add_service(HdltApiServer::new(HdltApiService::new(
                keystore,
                Arc::clone(&store),
                options.max_faults,
            )))
            .serve_with_incoming_shutdown(incoming, ctrl_c());
        let server_bg_task =
            tokio::spawn(async move { server_bg_task.await.map_err(eyre::Report::from) });

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
        let authority = format!("{}:{}", self.listen_addr.ip(), self.listen_addr.port());
        Uri::builder()
            .scheme("http")
            .authority(authority.as_str())
            .build()
            .unwrap()
    }
}

fn create_tcp_incoming(bind_addr: &SocketAddr) -> eyre::Result<(TcpListenerStream, SocketAddr)> {
    let listener = std::net::TcpListener::bind(bind_addr)?;
    let listen_addr = listener.local_addr()?;

    let listener = tokio::net::TcpListener::from_std(listener)?;
    Ok((TcpListenerStream::new(listener), listen_addr))
}

async fn ctrl_c() {
    use std::future;

    if tokio::signal::ctrl_c().await.is_err() {
        eprintln!("Failed to listen for Ctrl+C/SIGINT. Server will still exit after receiving them, just not gracefully.");
        future::pending().await // never completes
    }
}

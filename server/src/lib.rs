use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::{
    future::Future,
    task::{Context, Poll},
};

use model::keys::KeyStore;
use protos::hdlt::hdlt_api_server::HdltApiServer;
use structopt::StructOpt;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server as TonicServer;

use hdlt_store::HdltLocalStore;
use services::HdltApiService;

pub(crate) mod hdlt_store;
pub(crate) mod services;

type TonicServerOutput = Result<(), tonic::transport::Error>;

/// A HDLT Server, which can be polled to serve requests.
///
/// Only exists to facilitate integration testing.
pub struct Server {
    keystore: Arc<KeyStore>,
    store: Arc<HdltLocalStore>,
    server: Pin<Box<dyn Future<Output = TonicServerOutput>>>,
    listen_addr: SocketAddr,
}

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

    /// Quorum size for position proofs.
    #[structopt(short, long)]
    pub quorum_size: usize,
}

impl Server {
    pub fn new(options: &Options) -> eyre::Result<Self> {
        let keystore = Arc::new(KeyStore::load_from_files(
            &options.entity_registry_path,
            &options.skeys_path,
        )?);

        let store = Arc::new(HdltLocalStore::open(&options.storage_path)?);

        let (incoming, listen_addr) = create_tcp_incoming(&options.bind_addr)?;

        let server = TonicServer::builder()
            .add_service(HdltApiServer::new(HdltApiService::new(
                Arc::clone(&keystore),
                Arc::clone(&store),
                options.quorum_size,
            )))
            .serve_with_incoming_shutdown(incoming, ctrl_c());
        let server = Box::pin(server);

        Ok(Server {
            keystore,
            store,
            server,
            listen_addr,
        })
    }

    /// The server's underlying keystore.
    pub fn keystore(&self) -> Arc<KeyStore> {
        Arc::clone(&self.keystore)
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
}

impl Future for Server {
    type Output = TonicServerOutput;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.as_mut().server.as_mut().poll(cx)
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

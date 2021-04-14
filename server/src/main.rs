use std::sync::Arc;
use std::{net::SocketAddr, path::PathBuf};

use structopt::StructOpt;
use tonic::transport::Server;

use eyre::Result;
use tracing::info;

use model::keys::KeyStore;
use protos::hdlt::hdlt_api_server::HdltApiServer;

mod services;
use services::HdltApiService;

#[derive(StructOpt)]
struct Options {
    /// bind address.
    #[structopt()]
    bind_addr: SocketAddr,

    /// path to entity registry.
    ///
    /// See [KeyStore] for more information.
    #[structopt(short = "e", long = "entities", env = "ENTITY_REGISTRY_PATH")]
    entity_registry_path: PathBuf,

    /// path to client secret keys
    ///
    /// See [KeyStore] for more information.
    #[structopt(short = "s", long = "secrets", env = "SECRET_KEYS_PATH")]
    skeys_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::from_args();

    // pretty-print panics
    color_eyre::install()?;

    // trace stuff: do not remove
    let _guard = tracing_utils::setup(env!("CARGO_PKG_NAME"))?;

    let keystore = Arc::new(KeyStore::load_from_files(
        options.entity_registry_path,
        options.skeys_path,
    )?);

    let server = Server::builder()
        .add_service(HdltApiServer::new(HdltApiService::new(keystore.clone())))
        .serve_with_shutdown(options.bind_addr, ctrl_c());

    info!("Server listening on {:?}", options.bind_addr);
    server.await?;
    info!("Bye!");

    Ok(())
}

async fn ctrl_c() {
    use std::future;

    if tokio::signal::ctrl_c().await.is_err() {
        eprintln!("Failed to listen for Ctrl+C/SIGINT. Server will still exit after receiving them, just not gracefully.");
        future::pending().await // never completes
    }
}

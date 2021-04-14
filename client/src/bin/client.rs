use std::{path::PathBuf, sync::Arc};

use model::keys::KeyStore;
use structopt::StructOpt;
use tonic::transport::Uri;
use tracing::*;

use client::driver::DriverService;
use client::hdlt_api::HdltApiClient;
use client::malicious_driver::MaliciousDriverService;
use protos::driver::driver_server::DriverServer;
use protos::driver::malicious_driver_server::MaliciousDriverServer;
use tonic::transport::Server;

#[derive(StructOpt)]
struct Options {
    /// Server URI
    #[structopt(short = "s", long = "server")]
    server_uri: Option<Uri>,

    /// Whether the client is malicious
    #[structopt(short, long)]
    malicious: bool,

    /// Bind address
    bind_addr: std::net::SocketAddr,

    /// path to entity registry.
    ///
    /// See [KeyStore] for more information.
    #[structopt(short = "e", long = "entities", env = "ENTITY_REGISTRY_PATH")]
    entity_registry_path: PathBuf,

    /// path to client secret keys
    ///
    /// See [KeyStore] for more information.
    #[structopt(short = "k", long = "secret-keys", env = "SECRET_KEYS_PATH")]
    skeys_path: PathBuf,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    // do not remove
    let _guard = tracing_utils::setup(env!("CARGO_PKG_NAME"))?;
    true_main().await
}

#[instrument]
async fn true_main() -> eyre::Result<()> {
    let options = Options::from_args();

    let keystore = Arc::new(KeyStore::load_from_files(
        options.entity_registry_path.clone(),
        options.skeys_path.clone(),
    )?);

    let driver_task = async {
        if options.malicious {
            malicious_driver_server(options.bind_addr.clone()).await
        } else {
            driver_server(options.bind_addr.clone()).await
        }
    };

    let main_task = async {
        if let Some(server_uri) = options.server_uri.clone() {
            let client = HdltApiClient::new(server_uri, keystore)?;
            let reply = client.obtain_location_report(0, 0).await?;
            info!(
                event = "We asked the server to do the thing and got a reply",
                ?reply
            );
        }

        Ok::<_, eyre::Report>(())
    };

    tokio::select! {
        Err(e) = driver_task => {
            error!("Driver aborted: {:#?}", e);
        }
        _ = main_task => (),
    }

    Ok(())
}

async fn ctrl_c() {
    use std::future;

    if tokio::signal::ctrl_c().await.is_err() {
        eprintln!("Failed to listen for Ctrl+C/SIGINT. Server will still exit after receiving them, just not gracefully.");
        future::pending().await // never completes
    }
}

async fn malicious_driver_server(bind_addr: std::net::SocketAddr) -> eyre::Result<()> {
    let server = Server::builder()
        .add_service(MaliciousDriverServer::new(MaliciousDriverService::new()))
        .serve_with_shutdown(bind_addr, ctrl_c());
    info!("Malicious Driver Server @{:?}: listening", bind_addr);
    server.await?;
    info!("Malicious Driver Server @{:?}: finished", bind_addr);
    Ok(())
}

async fn driver_server(bind_addr: std::net::SocketAddr) -> eyre::Result<()> {
    let server = Server::builder()
        .add_service(DriverServer::new(DriverService::new()))
        .serve_with_shutdown(bind_addr, ctrl_c());
    info!("Malicious Driver Server @{:?}: listening", bind_addr);
    server.await?;
    info!("Malicious Driver Server @{:?}: finished", bind_addr);
    Ok(())
}

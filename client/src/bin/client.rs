use std::{path::PathBuf, sync::Arc};

use model::keys::KeyStore;
use structopt::StructOpt;
use tonic::transport::Uri;
use tracing::*;

use client::driver::DriverService;
use client::hdlt_api::HdltApiClient;
use client::malicious_driver::MaliciousDriverService;
use client::malicious_witness::MaliciousWitnessService;
use client::state::{CorrectClientState, MaliciousClientState};
use client::witness::WitnessService;
use protos::driver::driver_server::DriverServer;
use protos::driver::malicious_driver_server::MaliciousDriverServer;
use protos::witness::witness_server::WitnessServer;
use tonic::transport::Server;

use tokio::sync::RwLock;

#[derive(StructOpt)]
struct Options {
    /// Server URI
    #[structopt(short = "s", long = "server")]
    server_uri: Uri,

    /// Whether the client is malicious
    #[structopt(short, long)]
    malicious: bool,

    /// Bind address
    bind_addr: std::net::SocketAddr,

    /// path to entity registry
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
    model::ensure_init();
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
            malicious_driver_server(
                options.bind_addr,
                keystore.clone(),
                options.server_uri.clone(),
            )
            .await
        } else {
            driver_server(
                options.bind_addr,
                keystore.clone(),
                options.server_uri.clone(),
            )
            .await
        }
    };

    let main_task = async {
        let client = HdltApiClient::new(options.server_uri.clone(), keystore.clone())?;
        let reply = client.obtain_position_report(0, 0).await?;
        info!(
            event = "We asked the server to do the thing and got a reply",
            ?reply
        );

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

async fn malicious_driver_server(
    bind_addr: std::net::SocketAddr,
    keystore: Arc<KeyStore>,
    server_uri: Uri,
) -> eyre::Result<()> {
    let state = Arc::new(RwLock::new(MaliciousClientState::new()));
    let server = Server::builder()
        .add_service(MaliciousDriverServer::new(MaliciousDriverService::new(
            state.clone(),
            keystore.clone(),
            server_uri,
        )))
        .add_service(WitnessServer::new(MaliciousWitnessService::new(
            keystore, state,
        )))
        .serve_with_shutdown(bind_addr, ctrl_c());
    info!("Malicious Driver Server @{:?}: listening", bind_addr);
    server.await?;
    info!("Malicious Driver Server @{:?}: finished", bind_addr);
    Ok(())
}

async fn driver_server(
    bind_addr: std::net::SocketAddr,
    keystore: Arc<KeyStore>,
    server_uri: Uri,
) -> eyre::Result<()> {
    let state = Arc::new(RwLock::new(CorrectClientState::new()));
    let server = Server::builder()
        .add_service(DriverServer::new(DriverService::new(
            state.clone(),
            keystore.clone(),
            server_uri,
        )))
        .add_service(WitnessServer::new(WitnessService::new(keystore, state)))
        .serve_with_shutdown(bind_addr, ctrl_c());
    info!("Driver Server @{:?}: listening", bind_addr);
    server.await?;
    info!("Driver Server @{:?}: finished", bind_addr);
    Ok(())
}

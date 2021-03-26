use std::net::SocketAddr;

use structopt::StructOpt;
use tonic::transport::Server;

use eyre::Result;
use tracing::info;

use protos::cenas_server::CenasServer;

mod services;
use services::CenasService;

#[derive(StructOpt)]
struct Options {
    /// bind address
    #[structopt()]
    bind_addr: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::from_args();

    // pretty-print panics
    color_eyre::install()?;

    // trace stuff
    let _guard = tracing_utils::setup(env!("CARGO_PKG_NAME"))?;

    let server = Server::builder()
        .add_service(CenasServer::new(CenasService::new()))
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

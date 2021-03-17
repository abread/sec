use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

use tonic::transport::{Server, ServerTlsConfig, Certificate, Identity};
use tracing::info;
use structopt::StructOpt;
use eyre::Result;

use protos::cenas_server::CenasServer;

mod services;
use services::CenasService;

#[derive(StructOpt)]
struct Options {
    /// bind address
    #[structopt()]
    bind_addr: SocketAddr,

    #[structopt(short="a", long="ca-cert")]
    ca_cert_path: PathBuf,

    #[structopt(short="c", long="cert")]
    cert_path: PathBuf,

    #[structopt(short="k", long="key")]
    key_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::from_args();

    color_eyre::install()?;
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stderr());
    let subscriber = tracing_subscriber::fmt().with_writer(non_blocking).finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Unable to set global default subscriber");

    let tls_config = {
        let cert = fs::read(options.cert_path)?;
        let key = fs::read(options.key_path)?;
        let ca_cert = fs::read(options.ca_cert_path)?;

        ServerTlsConfig::new()
            .identity(Identity::from_pem(cert, key))
            .client_ca_root(Certificate::from_pem(ca_cert))
    };

    let server = Server::builder()
        .tls_config(tls_config)?
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

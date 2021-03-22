use std::fs;
use std::path::PathBuf;

use eyre::Result;
use structopt::StructOpt;
use tonic::transport::{Certificate, ClientTlsConfig, Identity, Uri};
use tracing::*;

use client::CenasClient;

#[derive(StructOpt)]
struct Options {
    /// Server URI
    #[structopt(short = "s", long = "server")]
    server_uri: Uri,

    #[structopt(short = "a", long = "ca-cert")]
    ca_cert_path: PathBuf,

    #[structopt(short = "c", long = "cert")]
    cert_path: PathBuf,

    #[structopt(short = "k", long = "key")]
    key_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let _guard = tracing_utils::setup(env!("CARGO_PKG_NAME"))?;

    true_main().await
}

#[instrument]
async fn true_main() -> Result<()> {
    let options = Options::from_args();
    let tls_config = {
        let cert = fs::read(options.cert_path)?;
        let key = fs::read(options.key_path)?;
        let ca_cert = fs::read(options.ca_cert_path)?;

        ClientTlsConfig::new()
            .identity(Identity::from_pem(cert, key))
            .ca_certificate(Certificate::from_pem(ca_cert))
    };

    let client = CenasClient::new(options.server_uri, tls_config)?;

    let reply = client.dothething().await?;
    info!(
        event = "We asked the server to do the thing and got a reply",
        ?reply
    );

    Ok(())
}

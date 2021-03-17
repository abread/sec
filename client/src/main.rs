use std::fs;
use std::path::PathBuf;

use tonic::transport::{Uri, ClientTlsConfig, Identity, Certificate};
use tracing::info;
use structopt::StructOpt;
use eyre::Result;

mod lib;
use lib::CenasClient;

#[derive(StructOpt)]
struct Options {
    /// Server URI
    #[structopt(short="s", long="server")]
    server_uri: Uri,

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

        ClientTlsConfig::new()
            .identity(Identity::from_pem(cert, key))
            .ca_certificate(Certificate::from_pem(ca_cert))
    };

    let client = CenasClient::new(options.server_uri, tls_config)?;
    let reply = client.dothething().await?;

    info!("We asked the server to do the thing and got {:?}", reply);
    Ok(())
}

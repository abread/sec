use eyre::Result;
use structopt::StructOpt;
use tonic::transport::Uri;
use tracing::*;

use client::CenasClient;

#[derive(StructOpt)]
struct Options {
    /// Server URI
    #[structopt(short = "s", long = "server")]
    server_uri: Uri,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_utils::setup(env!("CARGO_PKG_NAME"))?;

    true_main().await
}

#[instrument]
async fn true_main() -> Result<()> {
    let options = Options::from_args();
    let client = CenasClient::new(options.server_uri)?;

    let reply = client.dothething().await?;
    info!(
        event = "We asked the server to do the thing and got a reply",
        ?reply
    );

    Ok(())
}

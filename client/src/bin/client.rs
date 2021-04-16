use client::{Client, Options};
use structopt::StructOpt;
use tracing::*;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    model::ensure_init();
    color_eyre::install()?;
    // do not remove
    let _guard = tracing_utils::setup(env!("CARGO_PKG_NAME"))?;

    let options = Options::from_args();
    let (client, _task_handle) = Client::new(&options)?;

    true_main(&client).await
}

#[instrument]
async fn true_main(client: &Client) -> eyre::Result<()> {
    let reply = client.obtain_position_report(0, 0).await?;
    info!(
        event = "We asked the server to do the thing and got a reply",
        ?reply
    );

    Ok(())
}

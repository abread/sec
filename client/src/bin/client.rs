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

    let (client, task_handle) = Client::new(&options).await?;
    let uri = client.uri();

    async move {
        task_handle.await??;
        info!("Client closing");
        Ok(())
    }
    .instrument(info_span!("client task", %uri))
    .await
}

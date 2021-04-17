use client::{User, UserOptions};
use structopt::StructOpt;
use tracing::*;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    model::ensure_init();
    color_eyre::install()?;
    // do not remove
    let _guard = tracing_utils::setup(env!("CARGO_PKG_NAME"))?;

    let options = UserOptions::from_args();

    let (user, task_handle) = User::new(&options).await?;
    let uri = user.uri();

    async move {
        task_handle.await??;
        info!("User dying");
        Ok(())
    }
    .instrument(info_span!("user task", %uri))
    .await
}

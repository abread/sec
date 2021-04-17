use client::{User, UserOptions};
use structopt::StructOpt;
use tracing::*;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    model::ensure_init();
    color_eyre::install()?;

    let options = UserOptions::from_args();

    // do not remove
    let id =
        model::keys::KeyStore::load_from_files(&options.entity_registry_path, &options.skeys_path)?
            .my_id()
            .to_string();
    let _guard = tracing_utils::setup(env!("CARGO_PKG_NAME"), vec![("id", id)])?;

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

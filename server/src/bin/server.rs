use tracing::info;

use server::{Options, Server};
use structopt::StructOpt;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    model::ensure_init();
    let options = Options::from_args();

    // pretty-print panics
    color_eyre::install()?;

    // trace stuff: do not remove
    let id =
        model::keys::KeyStore::load_from_files(&options.entity_registry_path, &options.skeys_path)?
            .my_id()
            .to_string();
    let _guard = tracing_utils::setup(env!("CARGO_PKG_NAME"), vec![("id", id)])?;

    let (_server, task_handle) = Server::new(&options).await?;

    task_handle.await??;
    info!("Bye!");

    Ok(())
}

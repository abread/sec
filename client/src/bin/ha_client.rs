use std::{path::PathBuf, sync::Arc};

use model::keys::{EntityId, KeyStore};
use model::Position;
use structopt::StructOpt;
use tonic::transport::Uri;
use tracing::*;

use client::hdlt_api::HdltApiClient;

#[derive(StructOpt)]
struct Options {
    /// Server URI
    #[structopt(short = "s", long = "server")]
    server_uri: Uri,

    /// path to entity registry
    ///
    /// See [KeyStore] for more information.
    #[structopt(short = "e", long = "entities", env = "ENTITY_REGISTRY_PATH")]
    entity_registry_path: PathBuf,

    /// path to client secret keys
    ///
    /// See [KeyStore] for more information.
    #[structopt(short = "k", long = "secret-keys", env = "SECRET_KEYS_PATH")]
    skeys_path: PathBuf,

    #[structopt(short, long)]
    current_epoch: u64,

    /// command to execute
    #[structopt(subcommand)]
    command: Command,
}

#[derive(StructOpt, Clone)]
enum Command {
    /// Locate a user at a given epoch
    LocateUser { user_id: EntityId, epoch: u64 },

    /// Identify which users were in a given position during a given epoch
    IdentifyPosition { x: u64, y: u64, epoch: u64 },
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    model::ensure_init();
    color_eyre::install()?;
    // do not remove
    let _guard = tracing_utils::setup(env!("CARGO_PKG_NAME"))?;

    true_main().await
}

#[instrument]
async fn true_main() -> eyre::Result<()> {
    let options = Options::from_args();

    let keystore = Arc::new(KeyStore::load_from_files(
        options.entity_registry_path.clone(),
        options.skeys_path.clone(),
    )?);

    let client = HdltApiClient::new(
        options.server_uri.clone(),
        keystore.clone(),
        options.current_epoch,
    )?;

    match options.command {
        Command::LocateUser { user_id, epoch } => {
            let position = client.obtain_position_report(user_id, epoch).await?;
            println!(
                "At epoch {} user {} was at position ({}, {})",
                epoch, user_id, position.0, position.1
            );
        }
        Command::IdentifyPosition { x, y, epoch } => {
            let position = Position(x, y);
            let ids = client.obtain_users_at_position(position, epoch).await?;
            println!(
                "At epoch {} at position ({}, {}) there were the following users:",
                epoch, position.0, position.1
            );
            for id in ids {
                println!("> {}", id);
            }
        }
    }

    Ok(())
}

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
    let _guard = tracing_utils::setup(env!("CARGO_PKG_NAME"))?;

    let server = Server::new(&options)?;

    info!("Server listening on {:?}", server.listen_addr());
    server.await?;
    info!("Bye!");

    Ok(())
}

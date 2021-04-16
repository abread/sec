use std::convert::TryFrom;
use std::fs;
use structopt::StructOpt;

use driver::{Conf, Driver};

const TICK_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(30);

#[derive(StructOpt)]
struct Options {
    /// Location of the configuration file
    conf: String,

    /// How many times to drive
    #[structopt(short, long)]
    count: Option<usize>,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    // do not remove
    let _guard = tracing_utils::setup(env!("CARGO_PKG_NAME"))?;

    let options = Options::from_args();
    let config: Conf = fs::read_to_string(&options.conf)
        .map_err(eyre::Report::from)
        .and_then(|conf| json::parse(&conf).map_err(eyre::Report::from))
        .and_then(|conf| Conf::try_from(&conf).map_err(eyre::Report::from))?;

    let driver = Driver::new(config).await?;

    if let Some(c) = options.count {
        for _ in 0..c {
            tokio::join!(driver.tick(), tokio::time::sleep(TICK_INTERVAL)).0?;
        }
    } else {
        loop {
            tokio::join!(driver.tick(), tokio::time::sleep(TICK_INTERVAL)).0?;
        }
    }

    Ok(())
}

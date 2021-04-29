use std::convert::TryFrom;
use std::fs;
use std::time::Duration;
use structopt::StructOpt;

use driver::{Conf, Driver};
use tracing::*;

#[derive(StructOpt)]
struct Options {
    /// Location of the configuration file
    conf: String,

    /// How many times to drive
    #[structopt(short, long)]
    count: Option<usize>,

    /// Tick interval (in seconds)
    #[structopt(short, long, parse(try_from_str = parse_duration_secs), default_value = "30")]
    interval: Duration,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    // do not remove
    let _guard = tracing_utils::setup::<&str, &str, _>(env!("CARGO_PKG_NAME"), vec![])?;

    let options = Options::from_args();
    let config: Conf = fs::read_to_string(&options.conf)
        .map_err(eyre::Report::from)
        .and_then(|conf| json::parse(&conf).map_err(eyre::Report::from))
        .and_then(|conf| Conf::try_from(&conf).map_err(eyre::Report::from))?;

    let driver = Driver::new(config).await?;

    if let Some(c) = options.count {
        for _ in 0..c {
            tick(&driver, options.interval).await?;
        }
    } else {
        loop {
            tick(&driver, options.interval).await?;
        }
    }

    Ok(())
}

async fn tick(driver: &Driver, interval: Duration) -> eyre::Result<()> {
    async fn tick_inner(driver: &Driver) -> eyre::Result<()> {
        info!("Tick");
        driver.tick().await?;

        info!("Asking users to prove their positions");
        if let Err(errs) = driver.prove_position_all().await {
            warn!("Some users could not prove their position: {:#?}", errs);
        }

        Ok(())
    }

    async fn with_sleep(driver: &Driver, interval: Duration) -> eyre::Result<()> {
        tokio::join!(tick_inner(driver), tokio::time::sleep(interval)).0
    }

    tokio::select! {
        res = with_sleep(driver, interval) => res,
        _ = ctrl_c() => {
            info!("Ctrl+C signal received, exiting");
            std::process::exit(0);
        }
    }
}

async fn ctrl_c() {
    use std::future;

    if tokio::signal::ctrl_c().await.is_err() {
        eprintln!("Failed to listen for Ctrl+C/SIGINT. Server will still exit after receiving them, just not gracefully, potentially.");
        future::pending().await // never completes
    }
}

fn parse_duration_secs(input: &str) -> Result<Duration, std::num::ParseIntError> {
    let secs = input.parse()?;
    Ok(Duration::from_secs(secs))
}

use std::fs;
use std::path::PathBuf;

use eyre::{Result, WrapErr};
use structopt::StructOpt;
use tonic::transport::{Certificate, ClientTlsConfig, Identity, Uri};
use tracing::*;

use client::CenasClient;

#[derive(StructOpt)]
struct Options {
    /// Server URI
    #[structopt(short = "s", long = "server")]
    server_uri: Uri,

    #[structopt(short = "a", long = "ca-cert")]
    ca_cert_path: PathBuf,

    #[structopt(short = "c", long = "cert")]
    cert_path: PathBuf,

    #[structopt(short = "k", long = "key")]
    key_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let _guard = setup_tracing()?;

    true_main().await
}

#[instrument]
async fn true_main() -> Result<()> {
    let options = Options::from_args();
    let tls_config = {
        let cert = fs::read(options.cert_path)?;
        let key = fs::read(options.key_path)?;
        let ca_cert = fs::read(options.ca_cert_path)?;

        ClientTlsConfig::new()
            .identity(Identity::from_pem(cert, key))
            .ca_certificate(Certificate::from_pem(ca_cert))
    };

    let client = CenasClient::new(options.server_uri, tls_config)?;

    let reply = client.dothething().await?;
    info!(
        event = "We asked the server to do the thing and got a reply",
        ?reply
    );

    Ok(())
}

use opentelemetry_jaeger::Uninstall as JaegerGuard;
use tracing_appender::non_blocking::WorkerGuard as AppenderGuard;
type TracingGuard = (AppenderGuard, JaegerGuard);

pub fn setup_tracing() -> eyre::Result<TracingGuard> {
    use opentelemetry::sdk::propagation::TraceContextPropagator;
    use opentelemetry_jaeger::PipelineBuilder as JaegerPipelineBuilder;
    use tracing_opentelemetry::OpenTelemetryLayer;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::{fmt, EnvFilter, Registry};

    let (console_writer, _guard_appender) = tracing_appender::non_blocking(std::io::stderr());
    let console_layer = fmt::Layer::new().with_writer(console_writer).pretty();

    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
    let (tracer, _guard_jaeger) = JaegerPipelineBuilder::default()
        .with_service_name(env!("CARGO_PKG_NAME"))
        .from_env()
        .install()?;
    let jaeger_layer = OpenTelemetryLayer::default().with_tracer(tracer);

    let collector = Registry::default()
        .with(EnvFilter::from_default_env())
        .with(console_layer)
        .with(jaeger_layer);

    tracing::subscriber::set_global_default(collector)
        .wrap_err("Unable to set global default subscriber")?;

    Ok((_guard_appender, _guard_jaeger))
}

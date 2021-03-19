use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

use structopt::StructOpt;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use eyre::Result;
use tracing::info;

use protos::cenas_server::CenasServer;

mod services;
use services::CenasService;

#[derive(StructOpt)]
struct Options {
    /// bind address
    #[structopt()]
    bind_addr: SocketAddr,

    #[structopt(short = "a", long = "ca-cert")]
    ca_cert_path: PathBuf,

    #[structopt(short = "c", long = "cert")]
    cert_path: PathBuf,

    #[structopt(short = "k", long = "key")]
    key_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::from_args();

    // pretty-print panics
    color_eyre::install()?;

    // trace stuff
    let _guard = trace_aid::setup_tracing()?;

    let tls_config = {
        let cert = fs::read(options.cert_path)?;
        let key = fs::read(options.key_path)?;
        let ca_cert = fs::read(options.ca_cert_path)?;

        ServerTlsConfig::new()
            .identity(Identity::from_pem(cert, key))
            .client_ca_root(Certificate::from_pem(ca_cert))
    };

    let server = Server::builder()
        .tls_config(tls_config)?
        .add_service(CenasServer::new(CenasService::new()))
        .serve_with_shutdown(options.bind_addr, ctrl_c());

    info!("Server listening on {:?}", options.bind_addr);
    server.await?;
    info!("Bye!");

    Ok(())
}

async fn ctrl_c() {
    use std::future;

    if tokio::signal::ctrl_c().await.is_err() {
        eprintln!("Failed to listen for Ctrl+C/SIGINT. Server will still exit after receiving them, just not gracefully.");
        future::pending().await // never completes
    }
}

mod trace_aid {
    use eyre::WrapErr;

    use opentelemetry::sdk::propagation::TraceContextPropagator;
    use opentelemetry_jaeger::PipelineBuilder as JaegerPipelineBuilder;
    use tracing_opentelemetry::OpenTelemetryLayer;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::{fmt, EnvFilter, Registry};

    use opentelemetry_jaeger::Uninstall as JaegerGuard;
    use tracing_appender::non_blocking::WorkerGuard as AppenderGuard;
    type TracingGuard = (AppenderGuard, JaegerGuard);

    pub fn setup_tracing() -> eyre::Result<TracingGuard> {
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
            .wrap_err("Unable to set global default collector")?;

        Ok((_guard_appender, _guard_jaeger))
    }
}

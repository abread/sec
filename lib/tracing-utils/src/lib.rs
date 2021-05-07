#![deny(unsafe_op_in_unsafe_fn)]

use thiserror::Error;

mod metadata_mappers;
pub use metadata_mappers::{
    inject_ctx_into_tonic_request_metadata, set_parent_ctx_from_tonic_request_metadata,
};

// Expose instrument_tonic_method attribute macro and its dependencies
pub use tracing::instrument as _macro_aux_tracing_instrument;
pub use tracing_utils_macros::instrument_tonic_service;

/// Extension method for tonic::Request
pub trait RequestExt {
    /// Injects current tracing context into the current request for distributed tracing
    fn with_trace_ctx(self) -> Self;
}

impl<T> RequestExt for tonic::Request<T> {
    fn with_trace_ctx(mut self) -> Self {
        inject_ctx_into_tonic_request_metadata(self.metadata_mut());
        self
    }
}

/// Creates a tonic::Request with the given message and with the current tracing context injected into it
/// equivalent to `Request::new(msg).with_trace_ctx()`
#[macro_export]
macro_rules! Request {
    ($msg:expr) => {
        tracing_utils::RequestExt::with_trace_ctx(tonic::Request::new($msg))
    };
}

struct TraceSetupGuard(
    tracing_appender::non_blocking::WorkerGuard,
    opentelemetry_jaeger::Uninstall,
);

// empty drop implementation just for `impl Drop` to work for this type
// We want to return `impl Drop` to not let the caller do weird stuff with the guards
impl Drop for TraceSetupGuard {
    fn drop(&mut self) {}
}

#[derive(Error, Debug)]
pub enum TraceSetupError {
    #[error("Error in tracer")]
    TraceError(#[from] opentelemetry::trace::TraceError),

    #[error("Could not set global default subscriber")]
    SetGlobalDefaultError(#[from] tracing::subscriber::SetGlobalDefaultError),
}

/// Setup tracing with console and Jaeger output
/// The returned guard must not be dropped until the end of the program.
pub fn setup<K, V, T>(service_name: &str, tags: T) -> Result<impl Drop, TraceSetupError>
where
    K: Into<opentelemetry::Key>,
    V: Into<opentelemetry::Value>,
    T: IntoIterator<Item = (K, V)>,
{
    use opentelemetry::sdk::propagation::TraceContextPropagator;
    use opentelemetry_jaeger::PipelineBuilder as JaegerPipelineBuilder;
    use tracing_opentelemetry::OpenTelemetryLayer;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::{fmt, EnvFilter, Registry};

    let (console_writer, _guard_appender) = tracing_appender::non_blocking(std::io::stderr());
    let console_layer = fmt::Layer::new().with_writer(console_writer).pretty();

    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
    let (tracer, _guard_jaeger) = JaegerPipelineBuilder::default()
        .with_service_name(service_name)
        .with_tags(
            tags.into_iter()
                .map(|(k, v)| opentelemetry::KeyValue::new(k, v)),
        )
        .from_env()
        .install()?;
    let jaeger_layer = OpenTelemetryLayer::default().with_tracer(tracer);

    let collector = Registry::default()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(console_layer)
        .with(jaeger_layer);

    tracing::subscriber::set_global_default(collector)?;

    Ok(TraceSetupGuard(_guard_appender, _guard_jaeger))
}

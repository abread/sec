use opentelemetry::propagation::Injector;
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub trait Instrumented {
    fn instrumented(self) -> Self;
}

impl<T> Instrumented for tonic::Request<T> {
    fn instrumented(mut self) -> Self {
        opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.inject_context(
                &tracing::Span::current().context(),
                &mut MetadataMap(self.metadata_mut()),
            )
        });

        self
    }
}

struct MetadataMap<'a>(&'a mut tonic::metadata::MetadataMap);

impl<'a> Injector for MetadataMap<'a> {
    /// Set a key and value in the MetadataMap.  Does nothing if the key or value are not valid inputs
    fn set(&mut self, key: &str, value: String) {
        use tonic::metadata::{MetadataKey, MetadataValue};

        if let Ok(key) = MetadataKey::from_bytes(key.as_bytes()) {
            if let Ok(val) = MetadataValue::from_str(&value) {
                self.0.insert(key, val);
            }
        }
    }
}

// Based on opentelemetry-rust tracing-grpc example
// https://github.com/open-telemetry/opentelemetry-rust/blob/main/examples/tracing-grpc/src/server.rs

use tonic::Request;
use opentelemetry::propagation::Extractor;
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub fn propagate_trace_ctx<T>(request: &Request<T>) {
    let parent_cx = opentelemetry::global::get_text_map_propagator(|prop| prop.extract(&MetadataMap(request.metadata())));
    tracing::Span::current().set_parent(parent_cx);
}

struct MetadataMap<'a>(&'a tonic::metadata::MetadataMap);

impl<'a> Extractor for MetadataMap<'a> {
    /// Get a value for a key from the MetadataMap.  If the value can't be converted to &str, returns None
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|metadata| metadata.to_str().ok())
    }

    /// Collect all the keys from the MetadataMap.
    fn keys(&self) -> Vec<&str> {
        self.0
            .keys()
            .map(|key| match key {
                tonic::metadata::KeyRef::Ascii(v) => v.as_str(),
                tonic::metadata::KeyRef::Binary(v) => v.as_str(),
            })
            .collect::<Vec<_>>()
    }
}

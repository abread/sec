use opentelemetry::propagation::{Extractor, Injector};
use tonic::metadata::{KeyRef, MetadataKey, MetadataValue};
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Sets parent context of current span from the metadata of a tonic request
pub fn set_parent_ctx_from_tonic_request_metadata(req_metadata: &tonic::metadata::MetadataMap) {
    use opentelemetry::global::get_text_map_propagator;
    use tracing::Span;

    let parent_ctx =
        get_text_map_propagator(|prop| prop.extract(&TonicMetadataExtractor(req_metadata)));
    Span::current().set_parent(parent_ctx);
}

/// Injects current tracing context into the metadata of a tonic request
pub fn inject_ctx_into_tonic_request_metadata(req_metadata: &mut tonic::metadata::MetadataMap) {
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject_context(
            &tracing::Span::current().context(),
            &mut TonicMetadataInjector(req_metadata),
        )
    });
}

struct TonicMetadataExtractor<'a>(&'a tonic::metadata::MetadataMap);
impl<'a> Extractor for TonicMetadataExtractor<'a> {
    /// Get a value for a key from the MetadataMap.  If the value can't be converted to &str, returns None
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|metadata| metadata.to_str().ok())
    }

    /// Collect all the keys from the MetadataMap.
    fn keys(&self) -> Vec<&str> {
        self.0
            .keys()
            .map(|key| match key {
                KeyRef::Ascii(v) => v.as_str(),
                KeyRef::Binary(v) => v.as_str(),
            })
            .collect::<Vec<_>>()
    }
}

struct TonicMetadataInjector<'a>(&'a mut tonic::metadata::MetadataMap);
impl<'a> Injector for TonicMetadataInjector<'a> {
    /// Set a key and value in the MetadataMap.  Does nothing if the key or value are not valid inputs
    fn set(&mut self, key: &str, value: String) {
        if let Ok(key) = MetadataKey::from_bytes(key.as_bytes()) {
            if let Ok(val) = MetadataValue::from_str(&value) {
                self.0.insert(key, val);
            }
        }
    }
}

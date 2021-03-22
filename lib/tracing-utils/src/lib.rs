// Expose instrument_tonic_method attribute macro and its dependencies
pub use macros::instrument_tonic_service;
pub use tracing::instrument as _macro_aux_tracing_instrument;

/// Sets parent context of current span from the given Tonic Request metadata
pub fn set_parent_ctx_from_tonic_request_metadata(req_metadata: &tonic::metadata::MetadataMap) {
    use opentelemetry::global::get_text_map_propagator;
    use tracing::Span;
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    let parent_ctx = get_text_map_propagator(|prop| prop.extract(&TonicMetadataMap(req_metadata)));
    Span::current().set_parent(parent_ctx);
}

struct TonicMetadataMap<'a>(&'a tonic::metadata::MetadataMap);

use opentelemetry::propagation::Extractor;
impl<'a> Extractor for TonicMetadataMap<'a> {
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

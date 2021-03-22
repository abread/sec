mod metadata_mappers;
pub use metadata_mappers::{
    inject_ctx_into_tonic_request_metadata, set_parent_ctx_from_tonic_request_metadata,
};

// Expose instrument_tonic_method attribute macro and its dependencies
pub use macros::instrument_tonic_service;
pub use tracing::instrument as _macro_aux_tracing_instrument;

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
    }
}

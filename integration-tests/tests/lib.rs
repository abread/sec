pub mod util;

pub mod maybe_tracing {
    pub use tracing::*;

    #[cfg(feature = "trace")]
    pub mod tracing_utils {
        pub use tracing_utils::*;
    }

    #[cfg(not(feature = "trace"))]
    pub mod tracing_utils {
        #[allow(clippy::result_unit_err)]
        pub fn setup(_a: &str) -> Result<(), ()> {
            Ok(())
        }
    }
}

mod happy;

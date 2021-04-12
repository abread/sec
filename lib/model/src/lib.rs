macro_rules! partial_eq_impl {
    ($T:ty, $U:ty ; $($field:ident),+) => {
        impl std::cmp::PartialEq<$U> for $T {
            fn eq(&self, other: &$U) -> bool {
                $(self.$field == other.$field)&&+
            }
        }
        impl std::cmp::PartialEq<$T> for $U {
            fn eq(&self, other: &$T) -> bool {
                $(self.$field == other.$field)&&+
            }
        }
    };
}

pub(crate) mod base64_serialization;
mod closeness_proof;
mod closeness_proof_request;
pub mod keys;
mod location_proof;

use serde::{Deserialize, Serialize};
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Location(f64, f64);

impl Location {
    pub fn to_bytes(&self) -> Vec<u8> {
        [self.0.to_be_bytes(), self.1.to_be_bytes()].concat()
    }
}

pub use closeness_proof::*;
pub use closeness_proof_request::*;
pub use location_proof::*;

use std::sync::atomic::{AtomicBool, Ordering};
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Must be called to guarantee cryptographic primitive initialization
pub fn ensure_init() {
    if !INITIALIZED.load(Ordering::Acquire) {
        sodiumoxide::init().expect("failed to initialize libsodium");
        INITIALIZED.store(true, Ordering::Release);
    }
}

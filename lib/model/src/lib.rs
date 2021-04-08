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
    // libsodium's sodium_init is ok to call more than once and from multiple threads
    // https://doc.libsodium.org/usage#__GITBOOK__ROOT__CLIENT__:~:text=sodium_init()%20initializes%20the%20library%20and%20should,subsequent%20calls%20won't%20have%20any%20effects.
    // so it's ok to just use an AtomicBool with relaxed ordering
    if !INITIALIZED.load(Ordering::Relaxed) {
        sodiumoxide::init().expect("failed to initialize libsodium");
        INITIALIZED.store(true, Ordering::Relaxed);
    }
}

macro_rules! partial_eq_impl {
    ($T:ident, $U:ident ; $($field:ident),+) => {
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

mod closeness_proof;
mod closeness_proof_request;
pub mod keys;
mod location_proof;

use serde::{Deserialize, Serialize};
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Location(f64, f64);

pub use closeness_proof::*;
pub use closeness_proof_request::*;
pub use location_proof::*;

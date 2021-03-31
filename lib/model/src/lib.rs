macro_rules! partial_eq_impl {
    ($T:ident, $U:ident : $($field:ident),+) => {
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

pub mod keys;
mod closeness_proof_request;
mod closeness_proof;
mod location_proof;


#[derive(Debug, PartialEq)]
pub struct Location(f64, f64);

pub use closeness_proof::*;
pub use closeness_proof_request::*;
pub use location_proof::*;

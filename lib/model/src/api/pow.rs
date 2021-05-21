use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::hash::sha256;

const POW_DIFFICULTY: usize = 1; // adjust as needed

type PoWTag = [u8; 32];

/// Message that must be sent with a proof-of-work
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PoWProtected<T> {
    inner: T,
    pow: PoWTag,
}

impl<T> PoWProtected<T>
where
    T: Serialize,
{
    pub fn new(inner: T) -> Self {
        let inner_bytes = inner_bytes(&inner);

        let mut pow = [0; 32];
        while !pow_is_valid(&inner_bytes, &pow) {
            // increment pow
            let mut i = 31;
            while i > 0 && pow[i] == 0xff {
                pow[i] = 0;
                i -= 1;
            }
            pow[i] += 1;
        }

        PoWProtected { inner, pow }
    }

    pub fn try_into_inner(self) -> Result<T, Self> {
        let inner_bytes = inner_bytes(&self.inner);

        if pow_is_valid(&inner_bytes, &self.pow) {
            Ok(self.inner)
        } else {
            Err(self)
        }
    }
}

fn inner_bytes<T: Serialize>(inner: &T) -> Vec<u8> {
    bincode::serialize(&inner).expect("could not serialize inner value for PoW computation")
}

fn pow_is_valid(inner_bytes: &[u8], pow_tag: &PoWTag) -> bool {
    let mut bytes = inner_bytes.to_owned();
    bytes.extend_from_slice(pow_tag);

    let sha256::Digest(digest) = sha256::hash(&bytes);

    digest.iter().take(POW_DIFFICULTY).all(|&byte| byte == 0)
}

use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::hash::sha256;

const POW_DIFFICULTY: usize = 1; // adjust as needed

type PoWTag = [u8; 32];

/// Object certified with a proof-of-work
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PoWCertified<T> {
    inner: T,
    pow: PoWTag,
}

impl<T> PoWCertified<T>
where
    T: Serialize,
{
    /// Wrap object, certifying it with a proof-of-work
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

        PoWCertified { inner, pow }
    }

    /// Validate the proof-of-work and obtain inner object
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

#[cfg(test)]
#[test]
fn test() {
    let v = [4, 2];

    let pow_protected = PoWCertified::new(v);

    let bad_pow = {
        let mut p = pow_protected.clone();
        p.pow[0] = p.pow[0].wrapping_add(1);
        p
    };

    assert!(bad_pow.try_into_inner().is_err());
    assert_eq!(pow_protected.try_into_inner(), Ok(v));
}

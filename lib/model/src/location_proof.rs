use thiserror::Error;
use itertools::Itertools;

use crate::{ClosenessProof, UnverifiedClosenessProof, ClosenessProofValidationError, keys::KeyStore};

#[derive(Error, Debug)]
pub enum LocationProofValidationError {
    #[error("Bad witness")]
    BadWitness(#[from] ClosenessProofValidationError),
}

pub struct LocationProof {
    witnesses: Vec<ClosenessProof>,
}

pub struct UnverifiedLocationProof {
    pub witnesses: Vec<UnverifiedClosenessProof>,
}

impl UnverifiedLocationProof {
    pub fn verify(self, keystore: &KeyStore) -> Result<LocationProof, LocationProofValidationError> {
        let witnesses = self.witnesses
            .into_iter()
            .map(|p| p.verify(keystore))
            .try_collect()?;

        Ok(LocationProof {
            witnesses,
        })
    }

    pub unsafe fn verify_unchecked(self) -> LocationProof {
        let witnesses = self.witnesses
            .into_iter()
            .map(|p| p.verify_unchecked())
            .collect();

        LocationProof {
            witnesses,
        }
    }
}

impl LocationProof {
    pub fn new(witnesses: Vec<ClosenessProof>) -> LocationProof {
        LocationProof {
            witnesses,
        }
    }

    pub fn witnesses(&self) -> &[ClosenessProof] {
        &self.witnesses
    }
}

partial_eq_impl!(LocationProof, UnverifiedLocationProof : witnesses);
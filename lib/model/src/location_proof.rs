use itertools::Itertools;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    keys::KeyStore, ClosenessProof, ClosenessProofValidationError, UnverifiedClosenessProof,
};

#[derive(Error, Debug)]
pub enum LocationProofValidationError {
    #[error("Bad witness")]
    BadWitness(#[from] ClosenessProofValidationError),
}

#[derive(Serialize, Debug, PartialEq)]
pub struct LocationProof {
    witnesses: Vec<ClosenessProof>,
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct UnverifiedLocationProof {
    pub witnesses: Vec<UnverifiedClosenessProof>,
}

impl UnverifiedLocationProof {
    pub fn verify(
        self,
        keystore: &KeyStore,
    ) -> Result<LocationProof, LocationProofValidationError> {
        let witnesses = self
            .witnesses
            .into_iter()
            .map(|p| p.verify(keystore))
            .try_collect()?;

        Ok(LocationProof { witnesses })
    }

    pub unsafe fn verify_unchecked(self) -> LocationProof {
        let witnesses = self
            .witnesses
            .into_iter()
            .map(|p| p.verify_unchecked())
            .collect();

        LocationProof { witnesses }
    }
}

impl LocationProof {
    pub fn new(witnesses: Vec<ClosenessProof>) -> LocationProof {
        LocationProof { witnesses }
    }

    pub fn witnesses(&self) -> &[ClosenessProof] {
        &self.witnesses
    }
}

partial_eq_impl!(LocationProof, UnverifiedLocationProof: witnesses);

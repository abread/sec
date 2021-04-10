use itertools::Itertools;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keys::{EntityId, KeyStore};
use crate::{
    ClosenessProof, ClosenessProofRequest, ClosenessProofValidationError, Location,
    UnverifiedClosenessProof,
};

#[derive(Error, Debug)]
pub enum LocationProofValidationError {
    #[error("Witnesses are for different requests")]
    InconsistentRequest(ClosenessProofRequest, ClosenessProof),

    #[error("Not enough witnesses for quorum (needs {}, has {})", .required, .available)]
    NotEnoughWitnesess { required: usize, available: usize },

    #[error("Invalid witness")]
    InvalidWitness(#[from] ClosenessProofValidationError),
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct LocationProof {
    witnesses: Vec<ClosenessProof>,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct UnverifiedLocationProof {
    pub witnesses: Vec<UnverifiedClosenessProof>,
}

impl UnverifiedLocationProof {
    pub fn verify(
        self,
        quorum_size: usize,
        keystore: &KeyStore,
    ) -> Result<LocationProof, LocationProofValidationError> {
        let witnesses = self
            .witnesses
            .into_iter()
            .map(|p| p.verify(keystore))
            .try_collect()?;

        LocationProof::new(witnesses, quorum_size)
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
    pub fn new(
        mut witnesses: Vec<ClosenessProof>,
        quorum_size: usize,
    ) -> Result<LocationProof, LocationProofValidationError> {
        // Remove duplicates
        witnesses.sort_unstable_by(|a, b| a.signature().cmp(b.signature()));
        witnesses.dedup();

        if witnesses.len() > 0 {
            // even if the above check fails, we will check the number of witnesses against the quorum size

            let req = witnesses[0].request();
            for witness in &witnesses[1..] {
                if witness.request() != req {
                    return Err(LocationProofValidationError::InconsistentRequest(
                        req.clone(),
                        witness.clone(),
                    ));
                }
            }
        }

        if witnesses.len() < quorum_size {
            return Err(LocationProofValidationError::NotEnoughWitnesess {
                required: quorum_size,
                available: witnesses.len(),
            });
        }

        Ok(LocationProof { witnesses })
    }

    pub fn witnesses(&self) -> &[ClosenessProof] {
        &self.witnesses
    }

    pub fn user_id(&self) -> &EntityId {
        self.witnesses[0].request().author_id()
    }

    pub fn location(&self) -> &Location {
        &self.witnesses[0].location()
    }

    pub fn epoch(&self) -> u64 {
        self.witnesses[0].epoch()
    }

    pub fn quorum_size(&self) -> usize {
        self.witnesses.len()
    }
}

partial_eq_impl!(LocationProof, UnverifiedLocationProof; witnesses);

impl From<LocationProof> for UnverifiedLocationProof {
    fn from(verified: LocationProof) -> Self {
        UnverifiedLocationProof {
            witnesses: verified.witnesses.into_iter().map_into().collect(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::keys::test_data::KeyStoreTestData;
    use crate::ClosenessProofRequest;
    use lazy_static::lazy_static;

    lazy_static! {
        static ref KEYSTORES: KeyStoreTestData = KeyStoreTestData::new();
        static ref CREQ1: ClosenessProofRequest =
            ClosenessProofRequest::new(1, Location(1.0, 1.0), &KEYSTORES.user1);
        static ref CREQ2: ClosenessProofRequest =
            ClosenessProofRequest::new(2, Location(2.0, 2.0), &KEYSTORES.user2);
        static ref CPROOF1_2: ClosenessProof =
            ClosenessProof::new(CREQ1.clone(), &KEYSTORES.user2).unwrap();
        static ref CPROOF1_3: ClosenessProof =
            ClosenessProof::new(CREQ1.clone(), &KEYSTORES.user3).unwrap();
        static ref CPROOF2_1: ClosenessProof =
            ClosenessProof::new(CREQ2.clone(), &KEYSTORES.user1).unwrap();
        static ref PROOF1: LocationProof =
            LocationProof::new(vec![CPROOF1_2.clone(), CPROOF1_3.clone()], 2).unwrap();
        static ref PROOF2: LocationProof = LocationProof::new(vec![CPROOF2_1.clone()], 1).unwrap();
    }

    #[test]
    fn accessors() {
        assert_eq!(PROOF1.user_id(), &1);
        assert_eq!(PROOF1.location(), &Location(1.0, 1.0));
        assert_eq!(PROOF1.epoch(), 1);
        assert_eq!(PROOF1.quorum_size(), 2);

        assert_eq!(PROOF2.user_id(), &2);
        assert_eq!(PROOF2.location(), &Location(2.0, 2.0));
        assert_eq!(PROOF2.epoch(), 2);
        assert_eq!(PROOF2.quorum_size(), 1);
    }

    #[test]
    fn verified_unverified_equality() {
        let unverified: UnverifiedLocationProof = PROOF2.clone().into();
        assert_eq!(&unverified, &*PROOF2);

        let verified_serialized = serde_json::to_string(&*PROOF2).unwrap();
        let unverified_deserialized: UnverifiedLocationProof = serde_json::from_str(
            &verified_serialized,
        )
        .expect("could not deserialize UnverifiedLocationProof from serialized LocationProof");

        assert_eq!(unverified, unverified_deserialized);
    }

    #[test]
    fn verify_ok() {
        let unverified1: UnverifiedLocationProof = PROOF1.clone().into();
        let unverified2: UnverifiedLocationProof = PROOF2.clone().into();
        KEYSTORES.iter().for_each(|keystore| {
            let verified1: LocationProof = unverified1.clone().verify(2, keystore).unwrap();
            let verified2: LocationProof = unverified2.clone().verify(1, keystore).unwrap();
            assert_eq!(verified1, *PROOF1);
            assert_eq!(verified2, *PROOF2);
        });
    }

    macro_rules! verify_bad_test {
        ($name:ident -> $error:pat , |$unverified:ident| $bad_stuff:expr) => {
            #[test]
            fn $name() {
                #[allow(unused_assignments)]
                let mut $unverified: UnverifiedLocationProof = PROOF1.clone().into();
                $bad_stuff;

                KEYSTORES.iter().for_each(|keystore| {
                    assert!(matches!(
                        $unverified.clone().verify(2, keystore),
                        Err($error)
                    ));
                });
            }
        };
    }

    verify_bad_test! {
        verify_bad_no_quorum -> LocationProofValidationError::NotEnoughWitnesess{..},
        |unverified| unverified.witnesses.remove(1)
    }

    verify_bad_test! {
        verify_bad_no_quorum_duplicate_witenesses -> LocationProofValidationError::NotEnoughWitnesess{..},
        |unverified| unverified.witnesses = vec![CPROOF1_2.clone().into(), CPROOF1_2.clone().into()]
    }

    verify_bad_test! {
        verify_bad_closeness_proof -> LocationProofValidationError::InvalidWitness(_),
        |unverified| unverified.witnesses[0].signature[0] = unverified.witnesses[0].signature[0].wrapping_add(1)
    }

    verify_bad_test! {
        verify_bad_witnesses_different_requests -> LocationProofValidationError::InconsistentRequest(..),
        |unverified| unverified.witnesses = vec![CPROOF1_2.clone().into(), CPROOF2_1.clone().into()]
    }

    #[test]
    fn create_bad_no_quorum() {
        assert!(matches!(
            LocationProof::new(vec![CPROOF1_2.clone().into()], 2).unwrap_err(),
            LocationProofValidationError::NotEnoughWitnesess {
                available: 1,
                required: 2
            }
        ));
        assert!(matches!(
            LocationProof::new(vec![], 10).unwrap_err(),
            LocationProofValidationError::NotEnoughWitnesess {
                available: 0,
                required: 10
            }
        ));
    }

    #[test]
    fn create_bad_no_quorum_duplicate_witnesses() {
        assert!(matches!(
            LocationProof::new(vec![CPROOF1_2.clone().into(), CPROOF1_2.clone().into()], 2)
                .unwrap_err(),
            LocationProofValidationError::NotEnoughWitnesess {
                available: 1,
                required: 2
            }
        ));
    }

    #[test]
    fn create_bad_different_requests() {
        assert!(matches!(
            LocationProof::new(vec![CPROOF1_2.clone().into(), CPROOF2_1.clone().into()], 2)
                .unwrap_err(),
            LocationProofValidationError::InconsistentRequest(..)
        ));
    }
}

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keys::{EntityId, KeyStore};
use crate::{
    Location, ProximityProof, ProximityProofRequest, ProximityProofValidationError,
    UnverifiedProximityProof,
};

#[derive(Error, Debug)]
pub enum LocationProofValidationError {
    #[error("Witnesses are for different requests")]
    InconsistentRequest(ProximityProofRequest, ProximityProof),

    #[error("Not enough witnesses for quorum (needs {}, has {})", .required, .available)]
    NotEnoughWitnesess { required: usize, available: usize },

    #[error("Invalid witness")]
    InvalidWitness(#[from] ProximityProofValidationError),
}

/// A proof that a user was in some location at some epoch, derived from a quorum
/// of other users that witnessed it.
///
/// A valid location proof is made up of a set (no duplicates) of [ProximityProof]s (witnesses),
/// that all share the same request. The number of witnesses is the size of the quorum,
/// which is a mandatory argument when constructing/verifying a [LocationProof].
///
/// Instances of this struct are guaranteed to be valid and therefore it implements [Serialize]
/// but not [Deserialize]. To deserialize a [LocationProof] see [UnverifiedLocationProof::verify].
/// A serialized [LocationProof] deserialized as an [UnverifiedLocationProof] is guaranteed to be equal to the original proof.
///
/// Keep in mind that the quorum size associated with a LocationProof may not be trivial. See [LocationProof::quorum_size].
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct LocationProof {
    /// Witness accounts of a user being in a location at an epoch. Guaranteed to be free of duplicates.
    witnesses: Vec<ProximityProof>,
}

/// A unverified/untrusted proof that a user was in some location at some epoch.
///
/// This type is meant to be used as a stepping stone to receive a [LocationProof] from an outside source.
/// For this it implements [Deserialize], and can be [verify](Self::verify)-ed into a [LocationProof].
/// A serialized [LocationProof] deserialized as an [UnverifiedLocationProof] is guaranteed to be equal to the original proof.
///
/// Keep in mind that the quorum size associated with a LocationProof may not be trivial. See [LocationProof::quorum_size].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UnverifiedLocationProof {
    /// Witness accounts of a user being in a location at an epoch.
    pub witnesses: Vec<UnverifiedProximityProof>,
}

impl UnverifiedLocationProof {
    /// Verifies a proof yielding a [LocationProof].
    ///
    /// As documented in [LocationProof], any valid instance must be a set of
    /// [ProximityProof]s that share the same request, in a number greater or equal
    /// to the selected `quorum_size`.
    ///
    /// Any duplicate proximity proofs are discarded in the process.
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

    /// Marks a location proof as verified without actually performing any checks.
    ///
    /// The caller (**you**) is responsible for ensuring that the resulting quorum is big enough for your purposes.
    /// Keep in mind that the quorum size associated with a LocationProof may not be trivial. See [LocationProof::quorum_size].
    ///
    /// # Safety
    /// All witnesses must share the same request, and [UnverifiedProximityProof::verify] must be safe to call on all of them.
    /// There may not be any duplicate witnesses.
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
    /// Construct a LocationProof from a set of witness accounts.
    ///
    /// The list of witness accounts may contain duplicates, they will be ignored.
    /// Will return an error if witnesses refer to different [ProximityProofRequest]s or
    /// if there are not enough witnesses to satisfy the given `quorum_size`.
    ///
    /// Will panic if passed an empty list of witnesess.
    pub fn new(
        mut witnesses: Vec<ProximityProof>,
        quorum_size: usize,
    ) -> Result<LocationProof, LocationProofValidationError> {
        assert!(
            !witnesses.is_empty(),
            "Cannot construct a LocationProof without witnesses"
        );

        let req = witnesses[0].request();
        for witness in &witnesses[1..] {
            if witness.request() != req {
                return Err(LocationProofValidationError::InconsistentRequest(
                    req.clone(),
                    witness.clone(),
                ));
            }
        }

        // Remove duplicates
        witnesses.sort_unstable_by_key(|w| *w.witness_id());
        witnesses.dedup_by_key(|w| *w.witness_id());

        let proof = LocationProof { witnesses };
        if proof.quorum_size() < quorum_size {
            return Err(LocationProofValidationError::NotEnoughWitnesess {
                required: quorum_size,
                available: proof.quorum_size(),
            });
        }

        Ok(proof)
    }

    /// Witness accounts of a user being in a location at an epoch.
    pub fn witnesses(&self) -> &[ProximityProof] {
        &self.witnesses
    }

    /// Identifier of the request creator (trying to prove they're in [location](Self::location)).
    ///
    /// Shortcut for [`proof.witnesses()[i].request().prover_id()`](ProximityProofRequest::prover_id)
    pub fn prover_id(&self) -> &EntityId {
        self.witnesses[0].request().prover_id()
    }

    /// Location as stated by the prover.
    ///
    /// Shortcut for [`proof.witnesses()[i].request().location()`](ProximityProofRequest::location)
    pub fn location(&self) -> &Location {
        &self.witnesses[0].location()
    }

    /// Epoch associated with this proof.
    ///
    /// Shortcut for [`proof.witnesses()[i].request().epoch()`](ProximityProofRequest::epoch)
    pub fn epoch(&self) -> u64 {
        self.witnesses[0].epoch()
    }

    /// Quorum size in this proof.
    ///
    /// Assuming there are N witnesses we have a quorum with size N+1, because the
    /// the user that created the original [ProximityProofRequest] also states that
    /// they were in that location at that epoch.
    pub fn quorum_size(&self) -> usize {
        self.witnesses.len() + 1
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
    use crate::ProximityProofRequest;
    use lazy_static::lazy_static;

    lazy_static! {
        static ref KEYSTORES: KeyStoreTestData = KeyStoreTestData::new();
        static ref CREQ1: ProximityProofRequest =
            ProximityProofRequest::new(1, Location(1.0, 1.0), &KEYSTORES.user1);
        static ref CREQ2: ProximityProofRequest =
            ProximityProofRequest::new(2, Location(2.0, 2.0), &KEYSTORES.user2);
        static ref CPROOF1_2: ProximityProof =
            ProximityProof::new(CREQ1.clone(), &KEYSTORES.user2).unwrap();
        static ref CPROOF1_3: ProximityProof =
            ProximityProof::new(CREQ1.clone(), &KEYSTORES.user3).unwrap();
        static ref CPROOF2_1: ProximityProof =
            ProximityProof::new(CREQ2.clone(), &KEYSTORES.user1).unwrap();
        static ref PROOF1: LocationProof =
            LocationProof::new(vec![CPROOF1_2.clone(), CPROOF1_3.clone()], 2).unwrap();
        static ref PROOF2: LocationProof = LocationProof::new(vec![CPROOF2_1.clone()], 1).unwrap();
    }

    #[test]
    fn accessors() {
        assert_eq!(PROOF1.prover_id(), &1);
        assert_eq!(PROOF1.location(), &Location(1.0, 1.0));
        assert_eq!(PROOF1.epoch(), 1);
        assert_eq!(PROOF1.quorum_size(), 3);

        assert_eq!(PROOF2.prover_id(), &2);
        assert_eq!(PROOF2.location(), &Location(2.0, 2.0));
        assert_eq!(PROOF2.epoch(), 2);
        assert_eq!(PROOF2.quorum_size(), 2);
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
            let verified1: LocationProof = unverified1.clone().verify(3, keystore).unwrap();
            let verified2: LocationProof = unverified2.clone().verify(2, keystore).unwrap();
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
                        $unverified.clone().verify(3, keystore),
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
        verify_bad_proximity_proof -> LocationProofValidationError::InvalidWitness(_),
        |unverified| unverified.witnesses[0].signature[0] = unverified.witnesses[0].signature[0].wrapping_add(1)
    }

    verify_bad_test! {
        verify_bad_witnesses_different_requests -> LocationProofValidationError::InconsistentRequest(..),
        |unverified| unverified.witnesses = vec![CPROOF1_2.clone().into(), CPROOF2_1.clone().into()]
    }

    #[test]
    fn create_bad_no_quorum() {
        assert!(matches!(
            LocationProof::new(vec![CPROOF1_2.clone().into()], 3).unwrap_err(),
            LocationProofValidationError::NotEnoughWitnesess {
                available: 2,
                required: 3
            }
        ));
    }

    #[test]
    #[should_panic(expected = "Cannot construct a LocationProof without witnesses")]
    fn create_bad_no_witnesses() {
        LocationProof::new(vec![], 0).unwrap_err();
    }

    #[test]
    fn create_bad_no_quorum_duplicate_witnesses() {
        assert!(matches!(
            LocationProof::new(vec![CPROOF1_2.clone().into(), CPROOF1_2.clone().into()], 3)
                .unwrap_err(),
            LocationProofValidationError::NotEnoughWitnesess {
                available: 2,
                required: 3
            }
        ));
    }

    #[test]
    fn create_bad_different_requests() {
        assert!(matches!(
            LocationProof::new(vec![CPROOF1_2.clone().into(), CPROOF2_1.clone().into()], 1)
                .unwrap_err(),
            LocationProofValidationError::InconsistentRequest(..)
        ));
    }
}

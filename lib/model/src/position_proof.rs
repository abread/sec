use itertools::Itertools;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keys::{EntityId, KeyStore};
use crate::{
    Position, ProximityProof, ProximityProofRequest, ProximityProofValidationError,
    UnverifiedProximityProof,
};

#[derive(Error, Debug)]
pub enum PositionProofValidationError {
    #[error("Witnesses are for different requests")]
    InconsistentRequest(ProximityProofRequest, ProximityProof),

    #[error("Not enough witnesses for quorum (needs {}, has {})", .required, .available)]
    NotEnoughWitnesess { required: usize, available: usize },

    #[error("Invalid witness")]
    InvalidWitness(#[from] ProximityProofValidationError),
}

/// A proof that a user was in some position at some epoch, derived from a quorum
/// of other users that witnessed it.
///
/// A valid position proof is made up of a set (no duplicates) of [ProximityProof]s (witnesses),
/// that all share the same request. The number of witnesses is the number of tolerated faults,
/// which is a mandatory argument when constructing/verifying a [PositionProof].
///
/// Instances of this struct are guaranteed to be valid and therefore it implements [Serialize]
/// but not [Deserialize]. To deserialize a [PositionProof] see [UnverifiedPositionProof::verify].
/// A serialized [PositionProof] deserialized as an [UnverifiedPositionProof] is guaranteed to be equal to the original proof.
#[derive(Clone, Debug, PartialEq)]
pub struct PositionProof {
    /// Witness accounts of a user being in a position at an epoch. Guaranteed to be free of duplicates.
    witnesses: Vec<ProximityProof>,
}

/// A unverified/untrusted proof that a user was in some position at some epoch.
///
/// This type is meant to be used as a stepping stone to receive a [PositionProof] from an outside source.
/// For this it implements [Deserialize], and can be [verify](Self::verify)-ed into a [PositionProof].
/// A serialized [PositionProof] deserialized as an [UnverifiedPositionProof] is guaranteed to be equal to the original proof.
///
/// Keep in mind that the number of tolerated faults associated with a PositionProof may not be trivial. See [PositionProof::max_faults].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UnverifiedPositionProof {
    /// Witness accounts of a user being in a position at an epoch.
    pub witnesses: Vec<UnverifiedProximityProof>,
}

impl UnverifiedPositionProof {
    /// Verifies a proof yielding a [PositionProof].
    ///
    /// As documented in [PositionProof], any valid instance must be a set of
    /// [ProximityProof]s that share the same request, in a number greater or equal
    /// to the selected `max_faults`.
    ///
    /// Any duplicate proximity proofs are discarded in the process.
    pub fn verify(
        self,
        max_faults: usize,
        keystore: &KeyStore,
    ) -> Result<PositionProof, PositionProofValidationError> {
        let witnesses = self
            .witnesses
            .into_iter()
            .map(|p| p.verify(keystore))
            .try_collect()?;

        PositionProof::new(witnesses, max_faults)
    }

    /// Marks a position proof as verified without actually performing any checks.
    ///
    /// The caller (**you**) is responsible for ensuring that the number of witnesses is big enough for your purposes.
    /// Keep in mind that the number of tolerated faults associated with a PositionProof may not be trivial. See [PositionProof::max_faults].
    ///
    /// # Safety
    /// All witnesses must share the same request, and [UnverifiedProximityProof::verify_unchecked] must be safe to call on all of them.
    /// There may not be any duplicate witnesses.
    /// This function is always memory-safe, even if the above above conditions don't apply.
    pub unsafe fn verify_unchecked(self) -> PositionProof {
        let witnesses = self
            .witnesses
            .into_iter()
            // Safety: guaranteed by caller, always memory-safe
            .map(|p| unsafe { p.verify_unchecked() })
            .collect();

        PositionProof { witnesses }
    }
}

impl PositionProof {
    /// Construct a PositionProof from a set of witness accounts.
    ///
    /// The list of witness accounts may contain duplicates, they will be ignored.
    /// Will return an error if witnesses refer to different [ProximityProofRequest]s or
    /// if there are not enough witnesses to satisfy the given `max_faults`.
    ///
    /// Will panic if passed an empty list of witnesess.
    pub fn new(
        mut witnesses: Vec<ProximityProof>,
        max_faults: usize,
    ) -> Result<PositionProof, PositionProofValidationError> {
        assert!(
            !witnesses.is_empty(),
            "Cannot construct a PositionProof without witnesses"
        );

        let req = witnesses[0].request();
        for witness in &witnesses[1..] {
            if witness.request() != req {
                return Err(PositionProofValidationError::InconsistentRequest(
                    req.clone(),
                    witness.clone(),
                ));
            }
        }

        // Remove duplicates
        witnesses.sort_unstable_by_key(|w| *w.witness_id());
        witnesses.dedup_by_key(|w| *w.witness_id());

        let proof = PositionProof { witnesses };
        if proof.max_faults() < max_faults {
            return Err(PositionProofValidationError::NotEnoughWitnesess {
                required: max_faults,
                available: proof.max_faults(),
            });
        }

        Ok(proof)
    }

    /// Witness accounts of a user being in a position at an epoch.
    pub fn witnesses(&self) -> &[ProximityProof] {
        &self.witnesses
    }

    /// Identifier of the request creator (trying to prove they're in [position](Self::position)).
    ///
    /// Shortcut for [`proof.witnesses()[i].request().prover_id()`](ProximityProofRequest::prover_id)
    pub fn prover_id(&self) -> &EntityId {
        self.witnesses[0].request().prover_id()
    }

    /// Position as stated by the prover.
    ///
    /// Shortcut for [`proof.witnesses()[i].request().position()`](ProximityProofRequest::position)
    pub fn position(&self) -> &Position {
        &self.witnesses[0].position()
    }

    /// Epoch associated with this proof.
    ///
    /// Shortcut for [`proof.witnesses()[i].request().epoch()`](ProximityProofRequest::epoch)
    pub fn epoch(&self) -> u64 {
        self.witnesses[0].epoch()
    }

    /// Number of byzantine users in the vicinity tolerated by this proof without impacting correctness.
    ///
    /// Assuming there are f' witnesses we have f'+1 users asserting the prover's position,
    /// because the prover, which created the original [ProximityProofRequest], also states that
    /// they were in that position at that epoch.
    pub fn max_faults(&self) -> usize {
        self.witnesses.len()
    }
}

partial_eq_impl!(PositionProof, UnverifiedPositionProof; witnesses);

impl From<PositionProof> for UnverifiedPositionProof {
    fn from(verified: PositionProof) -> Self {
        UnverifiedPositionProof {
            witnesses: verified.witnesses.into_iter().map_into().collect(),
        }
    }
}

impl Serialize for PositionProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        UnverifiedPositionProof::serialize(&self.clone().into(), serializer)
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
            ProximityProofRequest::new(1, Position(1, 1), &KEYSTORES.user1);
        static ref CREQ2: ProximityProofRequest =
            ProximityProofRequest::new(2, Position(2, 2), &KEYSTORES.user2);
        static ref CPROOF1_2: ProximityProof =
            ProximityProof::new(CREQ1.clone(), Position(3, 3), &KEYSTORES.user2).unwrap();
        static ref CPROOF1_3: ProximityProof =
            ProximityProof::new(CREQ1.clone(), Position(4, 4), &KEYSTORES.user3).unwrap();
        static ref CPROOF2_1: ProximityProof =
            ProximityProof::new(CREQ2.clone(), Position(5, 5), &KEYSTORES.user1).unwrap();
        static ref PROOF1: PositionProof =
            PositionProof::new(vec![CPROOF1_2.clone(), CPROOF1_3.clone()], 2).unwrap();
        static ref PROOF2: PositionProof = PositionProof::new(vec![CPROOF2_1.clone()], 1).unwrap();
    }

    #[test]
    fn accessors() {
        assert_eq!(PROOF1.prover_id(), &1);
        assert_eq!(PROOF1.position(), &Position(1, 1));
        assert_eq!(PROOF1.epoch(), 1);
        assert_eq!(PROOF1.max_faults(), 2);

        assert_eq!(PROOF2.prover_id(), &2);
        assert_eq!(PROOF2.position(), &Position(2, 2));
        assert_eq!(PROOF2.epoch(), 2);
        assert_eq!(PROOF2.max_faults(), 1);
    }

    #[test]
    fn verified_unverified_equality() {
        let unverified: UnverifiedPositionProof = PROOF2.clone().into();
        assert_eq!(&unverified, &*PROOF2);

        let verified_serialized = serde_json::to_string(&*PROOF2).unwrap();
        let unverified_deserialized: UnverifiedPositionProof = serde_json::from_str(
            &verified_serialized,
        )
        .expect("could not deserialize UnverifiedPositionProof from serialized PositionProof");

        assert_eq!(unverified, unverified_deserialized);
    }

    #[test]
    fn verify_ok() {
        let unverified1: UnverifiedPositionProof = PROOF1.clone().into();
        let unverified2: UnverifiedPositionProof = PROOF2.clone().into();
        KEYSTORES.iter().for_each(|keystore| {
            let verified1: PositionProof = unverified1.clone().verify(2, keystore).unwrap();
            let verified2: PositionProof = unverified2.clone().verify(1, keystore).unwrap();
            assert_eq!(verified1, *PROOF1);
            assert_eq!(verified2, *PROOF2);
        });
    }

    macro_rules! verify_bad_test {
        ($name:ident -> $error:pat , |$unverified:ident| $bad_stuff:expr) => {
            #[test]
            fn $name() {
                #[allow(unused_assignments)]
                let mut $unverified: UnverifiedPositionProof = PROOF1.clone().into();
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
        verify_bad_no_quorum -> PositionProofValidationError::NotEnoughWitnesess{..},
        |unverified| unverified.witnesses.remove(1)
    }

    verify_bad_test! {
        verify_bad_no_quorum_duplicate_witenesses -> PositionProofValidationError::NotEnoughWitnesess{..},
        |unverified| unverified.witnesses = vec![CPROOF1_2.clone().into(), CPROOF1_2.clone().into()]
    }

    verify_bad_test! {
        verify_bad_proximity_proof -> PositionProofValidationError::InvalidWitness(_),
        |unverified| unverified.witnesses[0].signature.0[0] = unverified.witnesses[0].signature.0[0].wrapping_add(1)
    }

    verify_bad_test! {
        verify_bad_witnesses_different_requests -> PositionProofValidationError::InconsistentRequest(..),
        |unverified| unverified.witnesses = vec![CPROOF1_2.clone().into(), CPROOF2_1.clone().into()]
    }

    #[test]
    fn create_bad_no_quorum() {
        assert!(matches!(
            PositionProof::new(vec![CPROOF1_2.clone()], 2).unwrap_err(),
            PositionProofValidationError::NotEnoughWitnesess {
                available: 1,
                required: 2
            }
        ));
    }

    #[test]
    #[should_panic(expected = "Cannot construct a PositionProof without witnesses")]
    fn create_bad_no_witnesses() {
        PositionProof::new(vec![], 0).unwrap_err();
    }

    #[test]
    fn create_bad_no_quorum_duplicate_witnesses() {
        assert!(matches!(
            PositionProof::new(vec![CPROOF1_2.clone(), CPROOF1_2.clone()], 2).unwrap_err(),
            PositionProofValidationError::NotEnoughWitnesess {
                available: 1,
                required: 2
            }
        ));
    }

    #[test]
    fn create_bad_different_requests() {
        assert!(matches!(
            PositionProof::new(vec![CPROOF1_2.clone(), CPROOF2_1.clone()], 1).unwrap_err(),
            PositionProofValidationError::InconsistentRequest(..)
        ));
    }
}

use crate::keys::EntityId;
use crate::{
    keys::KeyStore, ProximityProof, ProximityProofValidationError, UnverifiedProximityProof,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Proof that a user was not behaving correctly in an epoch.
///
/// Composed of two [ProximityProof]s that show a given user stating they're in
/// different locations in the same epoch. The user may be acting as a prover,
/// witness or a combination of both in each proof.
///
/// The serialization format of this struct is guaranteed to be compatible with
/// [UnverifiedMisbehaviorProof]. It is impossible to construct an invalid proof
/// in safe Rust.
///
/// Note: It is impossible to have a witness-prover [MisbehaviorProof]. When the two
/// roles are combined, the prover always precedes the witness.
#[derive(Clone, Debug, PartialEq)]
pub struct MisbehaviorProof {
    kind: MisbehaviorProofKind,
    user_id: EntityId,
    a: ProximityProof,
    b: ProximityProof,
}

/// An unverified proof that a user was not behaving correctly in an epoch.
///
/// You should only use this type as a stepping stone to accept misbehavior proofs
/// from the outside world. Use [UnverifiedMisbehaviorProof::verify] to convert it
/// into a fully-fledged [MisbehaviorProof].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct UnverifiedMisbehaviorProof {
    user_id: EntityId,
    a: UnverifiedProximityProof,
    b: UnverifiedProximityProof,
}

/// Describes the combination of user roles (prover, witness) in a [MisbehaviorProof].
///
/// Note: It is impossible to have a witness-prover [MisbehaviorProof]. When the two
/// roles are combined, the prover always precedes the witness.
#[derive(Debug, Clone, Copy, PartialEq)]
enum MisbehaviorProofKind {
    ProverProver,
    ProverWitness,
    WitnessWitness,
}

/// Error while trying to construct a misbehavior proof.
#[derive(Debug, Error)]
pub enum MisbehaviorProofValidationError {
    #[error("No inconsistency between proofs for given user")]
    NoMisbehaviorHere {
        user_id: EntityId,
        a: UnverifiedProximityProof,
        b: UnverifiedProximityProof,
    },

    #[error("Bad proximity proof")]
    InvalidProximityProof(#[from] ProximityProofValidationError),
}

impl UnverifiedMisbehaviorProof {
    /// Verifies this proof (including the underlying proximity proofs), converting it into a [MisbehaviorProof].
    pub fn verify(
        self,
        keystore: &KeyStore,
    ) -> Result<MisbehaviorProof, MisbehaviorProofValidationError> {
        let a = self.a.verify(&keystore)?;
        let b = self.b.verify(&keystore)?;
        MisbehaviorProof::new(self.user_id, a, b)
    }
}

impl MisbehaviorProof {
    /// Construct a misbehavior proof for a given user from two proximity proofs.
    ///
    /// Keep in mind that when trying to derive the proof from a user acting as
    /// a witness and prover, the proximity proof where they act as the prover must
    /// be passed first.
    pub fn new(
        user_id: EntityId,
        a: ProximityProof,
        b: ProximityProof,
    ) -> Result<Self, MisbehaviorProofValidationError> {
        if a.epoch() != b.epoch() {
            return Err(MisbehaviorProofValidationError::NoMisbehaviorHere {
                user_id,
                a: a.into(),
                b: b.into(),
            });
        }

        let kind = if a.prover_id() == b.prover_id()
            && a.prover_id() == user_id
            && a.position() != b.position()
        {
            MisbehaviorProofKind::ProverProver
        } else if a.prover_id() == b.witness_id()
            && a.prover_id() == user_id
            && a.position() != b.witness_position()
        {
            MisbehaviorProofKind::ProverWitness
        } else if a.witness_id() == b.witness_id()
            && a.witness_id() == user_id
            && a.witness_position() != b.witness_position()
        {
            MisbehaviorProofKind::WitnessWitness
        } else {
            return Err(MisbehaviorProofValidationError::NoMisbehaviorHere {
                user_id,
                a: a.into(),
                b: b.into(),
            });
        };

        Ok(MisbehaviorProof {
            kind,
            user_id,
            a,
            b,
        })
    }

    /// ID of the user proven to be misbehaving.
    pub fn user_id(&self) -> EntityId {
        self.user_id
    }

    pub fn a(&self) -> ProximityProof {
        self.a.clone()
    }

    pub fn b(&self) -> ProximityProof {
        self.b.clone()
    }
}

impl From<MisbehaviorProof> for UnverifiedMisbehaviorProof {
    fn from(p: MisbehaviorProof) -> Self {
        UnverifiedMisbehaviorProof {
            user_id: p.user_id,
            a: p.a.into(),
            b: p.b.into(),
        }
    }
}

impl Serialize for MisbehaviorProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        UnverifiedMisbehaviorProof::serialize(&self.clone().into(), serializer)
    }
}

partial_eq_impl!(MisbehaviorProof, UnverifiedMisbehaviorProof ; user_id, a, b);

#[cfg(test)]
mod test {
    use super::*;
    use crate::keys::test_data::KeyStoreTestData;
    use crate::{Position, ProximityProofRequest};
    use itertools::Itertools;
    use lazy_static::lazy_static;

    lazy_static! {
        static ref KEYSTORES: KeyStoreTestData = KeyStoreTestData::new();
    }

    const POS_A: Position = Position(1, 1);
    const POS_B: Position = Position(2, 2);

    #[test]
    fn prover_prover() {
        let req_a = ProximityProofRequest::new(1, POS_A, &KEYSTORES.user1);
        let proof_a = ProximityProof::new(req_a, POS_A, &KEYSTORES.user2).unwrap();

        let req_b = ProximityProofRequest::new(1, POS_B, &KEYSTORES.user1);
        let proof_b = ProximityProof::new(req_b, POS_A, &KEYSTORES.user2).unwrap();

        let mp = MisbehaviorProof::new(KEYSTORES.user1.my_id(), proof_a.clone(), proof_b.clone())
            .unwrap();
        assert_eq!(KEYSTORES.user1.my_id(), mp.user_id());
        assert_eq!(MisbehaviorProofKind::ProverProver, mp.kind);

        assert!(matches!(
            MisbehaviorProof::new(KEYSTORES.user2.my_id(), proof_a, proof_b),
            Err(MisbehaviorProofValidationError::NoMisbehaviorHere { .. })
        ));
    }

    #[test]
    fn prover_witness() {
        let req_a = ProximityProofRequest::new(1, POS_A, &KEYSTORES.user1);
        let proof_a = ProximityProof::new(req_a, POS_A, &KEYSTORES.user2).unwrap();

        let req_b = ProximityProofRequest::new(1, POS_A, &KEYSTORES.user2);
        let proof_b = ProximityProof::new(req_b, POS_B, &KEYSTORES.user1).unwrap();

        let mp = MisbehaviorProof::new(KEYSTORES.user1.my_id(), proof_a.clone(), proof_b.clone())
            .unwrap();
        assert_eq!(KEYSTORES.user1.my_id(), mp.user_id());
        assert_eq!(MisbehaviorProofKind::ProverWitness, mp.kind);

        assert!(matches!(
            MisbehaviorProof::new(KEYSTORES.user2.my_id(), proof_a, proof_b),
            Err(MisbehaviorProofValidationError::NoMisbehaviorHere { .. })
        ));
    }

    #[test]
    fn witness_witness() {
        let req_a = ProximityProofRequest::new(1, POS_A, &KEYSTORES.user1);
        let proof_a = ProximityProof::new(req_a, POS_A, &KEYSTORES.user2).unwrap();

        let req_b = ProximityProofRequest::new(1, POS_A, &KEYSTORES.user1);
        let proof_b = ProximityProof::new(req_b, POS_B, &KEYSTORES.user2).unwrap();

        let mp = MisbehaviorProof::new(KEYSTORES.user2.my_id(), proof_a.clone(), proof_b.clone())
            .unwrap();
        assert_eq!(KEYSTORES.user2.my_id(), mp.user_id());
        assert_eq!(MisbehaviorProofKind::WitnessWitness, mp.kind);

        assert!(matches!(
            MisbehaviorProof::new(KEYSTORES.user1.my_id(), proof_a, proof_b),
            Err(MisbehaviorProofValidationError::NoMisbehaviorHere { .. })
        ));
    }

    #[test]
    fn not_misbehavior() {
        let req_a = ProximityProofRequest::new(1, POS_A, &KEYSTORES.user1);
        let proof_a = ProximityProof::new(req_a, POS_B, &KEYSTORES.user2).unwrap();

        let req_b = ProximityProofRequest::new(1, POS_B, &KEYSTORES.user2);
        let proof_b = ProximityProof::new(req_b, POS_A, &KEYSTORES.user1).unwrap();

        let req_c = ProximityProofRequest::new(2, POS_B, &KEYSTORES.user1);
        let proof_c = ProximityProof::new(req_c, POS_A, &KEYSTORES.user2).unwrap();

        for (p1, p2) in [proof_a, proof_b, proof_c].iter().tuple_combinations() {
            for &uid in &[KEYSTORES.user1.my_id(), KEYSTORES.user2.my_id()] {
                assert!(matches!(
                    MisbehaviorProof::new(uid, p1.clone(), p2.clone()),
                    Err(MisbehaviorProofValidationError::NoMisbehaviorHere { .. })
                ));
            }
        }
    }
}

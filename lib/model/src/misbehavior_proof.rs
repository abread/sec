use crate::keys::EntityId;
use crate::{
    keys::KeyStore, ProximityProof, ProximityProofValidationError, UnverifiedProximityProof,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq)]
pub struct MisbehaviorProof {
    kind: MisbehaviorProofKind,
    user_id: EntityId,
    a: ProximityProof,
    b: ProximityProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnverifiedMisbehaviorProof {
    user_id: EntityId,
    a: UnverifiedProximityProof,
    b: UnverifiedProximityProof,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum MisbehaviorProofKind {
    ProverProver,
    ProverWitness,
    WitnessWitness,
}

#[derive(Debug, Error)]
pub enum InvalidMisbehaviorProof {
    #[error("no inconsistency between proofs for given user")]
    NoMisbehaviorHere {
        user_id: EntityId,
        a: UnverifiedProximityProof,
        b: UnverifiedProximityProof,
    },

    #[error("bad proximity proof")]
    InvalidProximityProof(#[from] ProximityProofValidationError),
}

impl UnverifiedMisbehaviorProof {
    pub fn verify(self, keystore: &KeyStore) -> Result<MisbehaviorProof, InvalidMisbehaviorProof> {
        let a = self.a.verify(&keystore)?;
        let b = self.b.verify(&keystore)?;
        MisbehaviorProof::new(self.user_id, a, b)
    }
}

impl MisbehaviorProof {
    pub fn new(
        user_id: EntityId,
        a: ProximityProof,
        b: ProximityProof,
    ) -> Result<Self, InvalidMisbehaviorProof> {
        if a.epoch() != b.epoch() {
            return Err(InvalidMisbehaviorProof::NoMisbehaviorHere {
                user_id,
                a: a.into(),
                b: b.into(),
            });
        }

        let kind = if a.prover_id() == b.prover_id()
            && *a.prover_id() == user_id
            && a.position() != b.position()
        {
            MisbehaviorProofKind::ProverProver
        } else if a.prover_id() == b.witness_id()
            && *a.prover_id() == user_id
            && a.position() != b.witness_position()
        {
            MisbehaviorProofKind::ProverWitness
        } else if a.witness_id() == b.witness_id()
            && *a.witness_id() == user_id
            && a.witness_position() != b.witness_position()
        {
            MisbehaviorProofKind::WitnessWitness
        } else {
            return Err(InvalidMisbehaviorProof::NoMisbehaviorHere {
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

    pub fn user_id(&self) -> EntityId {
        self.user_id
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

impl PartialEq<MisbehaviorProof> for UnverifiedMisbehaviorProof {
    fn eq(&self, other: &MisbehaviorProof) -> bool {
        self.user_id == other.user_id && self.a == other.a && self.b == other.b
    }
}

impl PartialEq<UnverifiedMisbehaviorProof> for MisbehaviorProof {
    fn eq(&self, other: &UnverifiedMisbehaviorProof) -> bool {
        other.eq(&self)
    }
}

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

        let mp = MisbehaviorProof::new(*KEYSTORES.user1.my_id(), proof_a.clone(), proof_b.clone())
            .unwrap();
        assert_eq!(*KEYSTORES.user1.my_id(), mp.user_id());
        assert_eq!(MisbehaviorProofKind::ProverProver, mp.kind);

        assert!(matches!(
            MisbehaviorProof::new(*KEYSTORES.user2.my_id(), proof_a, proof_b),
            Err(InvalidMisbehaviorProof::NoMisbehaviorHere { .. })
        ));
    }

    #[test]
    fn prover_witness() {
        let req_a = ProximityProofRequest::new(1, POS_A, &KEYSTORES.user1);
        let proof_a = ProximityProof::new(req_a, POS_A, &KEYSTORES.user2).unwrap();

        let req_b = ProximityProofRequest::new(1, POS_A, &KEYSTORES.user2);
        let proof_b = ProximityProof::new(req_b, POS_B, &KEYSTORES.user1).unwrap();

        let mp = MisbehaviorProof::new(*KEYSTORES.user1.my_id(), proof_a.clone(), proof_b.clone())
            .unwrap();
        assert_eq!(*KEYSTORES.user1.my_id(), mp.user_id());
        assert_eq!(MisbehaviorProofKind::ProverWitness, mp.kind);

        assert!(matches!(
            MisbehaviorProof::new(*KEYSTORES.user2.my_id(), proof_a, proof_b),
            Err(InvalidMisbehaviorProof::NoMisbehaviorHere { .. })
        ));
    }

    #[test]
    fn witness_witness() {
        let req_a = ProximityProofRequest::new(1, POS_A, &KEYSTORES.user1);
        let proof_a = ProximityProof::new(req_a, POS_A, &KEYSTORES.user2).unwrap();

        let req_b = ProximityProofRequest::new(1, POS_A, &KEYSTORES.user1);
        let proof_b = ProximityProof::new(req_b, POS_B, &KEYSTORES.user2).unwrap();

        let mp = MisbehaviorProof::new(*KEYSTORES.user2.my_id(), proof_a.clone(), proof_b.clone())
            .unwrap();
        assert_eq!(*KEYSTORES.user2.my_id(), mp.user_id());
        assert_eq!(MisbehaviorProofKind::WitnessWitness, mp.kind);

        assert!(matches!(
            MisbehaviorProof::new(*KEYSTORES.user1.my_id(), proof_a, proof_b),
            Err(InvalidMisbehaviorProof::NoMisbehaviorHere { .. })
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
            for &uid in [*KEYSTORES.user1.my_id(), *KEYSTORES.user2.my_id()].iter() {
                assert!(matches!(
                    MisbehaviorProof::new(uid, p1.clone(), p2.clone()),
                    Err(InvalidMisbehaviorProof::NoMisbehaviorHere { .. })
                ));
            }
        }
    }
}

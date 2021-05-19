use crate::keys::EntityId;
use crate::{
    keys::KeyStore, ProximityProof, ProximityProofValidationError, UnverifiedProximityProof,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq)]
pub struct MaliciousProof {
    kind: MaliciousProofKind,
    user_id: EntityId,
    a: ProximityProof,
    b: ProximityProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnverifiedMaliciousProof(EntityId, UnverifiedProximityProof, UnverifiedProximityProof);

#[derive(Debug, Clone, Copy, PartialEq)]
enum MaliciousProofKind {
    ProverProver,
    ProverWitness,
    WitnessWitness,
}

#[derive(Debug, Error)]
pub enum InvalidMaliciousProof {
    #[error("no inconsistency between proofs for user")]
    NotMalicious,

    #[error("bad proximity proof")]
    InvalidProximityProof(#[from] ProximityProofValidationError),
}

impl UnverifiedMaliciousProof {
    pub fn verify(self, keystore: &KeyStore) -> Result<MaliciousProof, InvalidMaliciousProof> {
        let a = self.1.verify(&keystore)?;
        let b = self.2.verify(&keystore)?;
        MaliciousProof::new(self.0, a, b)
    }
}

impl MaliciousProof {
    pub fn new(
        user_id: EntityId,
        a: ProximityProof,
        b: ProximityProof,
    ) -> Result<Self, InvalidMaliciousProof> {
        if a.epoch() != b.epoch() {
            return Err(InvalidMaliciousProof::NotMalicious);
        }

        let kind = if a.prover_id() == b.prover_id()
            && *a.prover_id() == user_id
            && a.position() != b.position()
        {
            MaliciousProofKind::ProverProver
        } else if a.prover_id() == b.witness_id()
            && *a.prover_id() == user_id
            && a.position() != b.witness_position()
        {
            MaliciousProofKind::ProverWitness
        } else if a.witness_id() == b.witness_id()
            && *a.witness_id() == user_id
            && a.witness_position() != b.witness_position()
        {
            MaliciousProofKind::WitnessWitness
        } else {
            return Err(InvalidMaliciousProof::NotMalicious);
        };

        Ok(MaliciousProof {
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

impl From<MaliciousProof> for UnverifiedMaliciousProof {
    fn from(p: MaliciousProof) -> Self {
        UnverifiedMaliciousProof(p.user_id, p.a.into(), p.b.into())
    }
}

impl Serialize for MaliciousProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        UnverifiedMaliciousProof::serialize(&self.clone().into(), serializer)
    }
}

impl PartialEq<MaliciousProof> for UnverifiedMaliciousProof {
    fn eq(&self, other: &MaliciousProof) -> bool {
        self.0 == other.user_id && self.1 == other.a && self.2 == other.b
    }
}

impl PartialEq<UnverifiedMaliciousProof> for MaliciousProof {
    fn eq(&self, other: &UnverifiedMaliciousProof) -> bool {
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

        let mp = MaliciousProof::new(*KEYSTORES.user1.my_id(), proof_a.clone(), proof_b.clone())
            .unwrap();
        assert_eq!(*KEYSTORES.user1.my_id(), mp.user_id());
        assert_eq!(MaliciousProofKind::ProverProver, mp.kind);

        assert!(matches!(
            MaliciousProof::new(*KEYSTORES.user2.my_id(), proof_a, proof_b),
            Err(InvalidMaliciousProof::NotMalicious)
        ));
    }

    #[test]
    fn prover_witness() {
        let req_a = ProximityProofRequest::new(1, POS_A, &KEYSTORES.user1);
        let proof_a = ProximityProof::new(req_a, POS_A, &KEYSTORES.user2).unwrap();

        let req_b = ProximityProofRequest::new(1, POS_A, &KEYSTORES.user2);
        let proof_b = ProximityProof::new(req_b, POS_B, &KEYSTORES.user1).unwrap();

        let mp = MaliciousProof::new(*KEYSTORES.user1.my_id(), proof_a.clone(), proof_b.clone())
            .unwrap();
        assert_eq!(*KEYSTORES.user1.my_id(), mp.user_id());
        assert_eq!(MaliciousProofKind::ProverWitness, mp.kind);

        assert!(matches!(
            MaliciousProof::new(*KEYSTORES.user2.my_id(), proof_a, proof_b),
            Err(InvalidMaliciousProof::NotMalicious)
        ));
    }

    #[test]
    fn witness_witness() {
        let req_a = ProximityProofRequest::new(1, POS_A, &KEYSTORES.user1);
        let proof_a = ProximityProof::new(req_a, POS_A, &KEYSTORES.user2).unwrap();

        let req_b = ProximityProofRequest::new(1, POS_A, &KEYSTORES.user1);
        let proof_b = ProximityProof::new(req_b, POS_B, &KEYSTORES.user2).unwrap();

        let mp = MaliciousProof::new(*KEYSTORES.user2.my_id(), proof_a.clone(), proof_b.clone())
            .unwrap();
        assert_eq!(*KEYSTORES.user2.my_id(), mp.user_id());
        assert_eq!(MaliciousProofKind::WitnessWitness, mp.kind);

        assert!(matches!(
            MaliciousProof::new(*KEYSTORES.user1.my_id(), proof_a, proof_b),
            Err(InvalidMaliciousProof::NotMalicious)
        ));
    }

    #[test]
    fn not_malicious() {
        let req_a = ProximityProofRequest::new(1, POS_A, &KEYSTORES.user1);
        let proof_a = ProximityProof::new(req_a, POS_B, &KEYSTORES.user2).unwrap();

        let req_b = ProximityProofRequest::new(1, POS_B, &KEYSTORES.user2);
        let proof_b = ProximityProof::new(req_b, POS_A, &KEYSTORES.user1).unwrap();

        let req_c = ProximityProofRequest::new(2, POS_B, &KEYSTORES.user1);
        let proof_c = ProximityProof::new(req_c, POS_A, &KEYSTORES.user2).unwrap();

        for (p1, p2) in [proof_a, proof_b, proof_c].iter().tuple_combinations() {
            for &uid in [*KEYSTORES.user1.my_id(), *KEYSTORES.user2.my_id()].iter() {
                assert!(matches!(
                    MaliciousProof::new(uid, p1.clone(), p2.clone()),
                    Err(InvalidMaliciousProof::NotMalicious)
                ));
            }
        }
    }
}

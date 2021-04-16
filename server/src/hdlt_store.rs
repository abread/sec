use model::{keys::EntityId, Position, PositionProof, UnverifiedPositionProof};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use thiserror::Error;

#[derive(Debug)]
pub struct HdltLocalStore(RwLock<HdltLocalStoreInner>);

#[derive(Error, Debug)]
pub enum HdltLocalStoreError {
    #[error("I/O Error")]
    IoError(#[from] std::io::Error),

    #[error("Error (de)serializating contents")]
    SerializationError(#[from] serde_json::Error),

    #[error("A different proof for the same (user_id, epoch) already exists")]
    ProofAlreadyExists,
}

impl HdltLocalStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, HdltLocalStoreError> {
        let store = HdltLocalStoreInner::open(path)?;
        Ok(HdltLocalStore(RwLock::new(store)))
    }

    pub fn add_proof(&self, proof: PositionProof) -> Result<(), HdltLocalStoreError> {
        self.0.write().expect("lock poisoned").add_proof(proof)
    }

    pub fn user_position_at_epoch(&self, user_id: EntityId, epoch: u64) -> Option<Position> {
        self.0
            .read()
            .expect("local storage lock poisoned")
            .user_position_at_epoch(user_id, epoch)
    }

    pub fn users_at_position_at_epoch(&self, position: Position, epoch: u64) -> Vec<EntityId> {
        self.0
            .read()
            .expect("local storage lock poisoned")
            .users_at_position_at_epoch(position, epoch)
    }

    #[cfg(test)]
    /// Clone like in [std::clone::Clone]. Restricted to test environments because
    /// this is not usually a good idea. Forget about persistence guarantees after calling it.
    pub(crate) fn clone(&self) -> Self {
        let store = self.0.read().expect("lock poisoned").clone();
        Self(RwLock::new(store))
    }
}

#[derive(Debug, Clone)]
struct HdltLocalStoreInner {
    file_path: PathBuf,
    proofs: Vec<PositionProof>,
}

impl HdltLocalStoreInner {
    fn open<P: AsRef<Path>>(path: P) -> Result<Self, HdltLocalStoreError> {
        let proofs = match File::open(path.as_ref()) {
            Ok(file) => {
                serde_json::from_reader::<_, Vec<UnverifiedPositionProof>>(BufReader::new(file))?
                    .into_iter()
                    // Safety: we saved valid position proofs, so they must be safe to read
                    .map(|unverified| unsafe { unverified.verify_unchecked() })
                    .collect()
            }
            Err(e) if e.kind() == tokio::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };

        Ok(HdltLocalStoreInner {
            file_path: path.as_ref().to_owned(),
            proofs,
        })
    }

    fn add_proof(&mut self, proof: PositionProof) -> Result<(), HdltLocalStoreError> {
        if self
            .proofs
            .iter()
            .any(|p| p.prover_id() == proof.prover_id() && p.epoch() == proof.epoch())
        {
            return Err(HdltLocalStoreError::ProofAlreadyExists);
        }

        self.proofs.push(proof);

        self.save()?;
        Ok(())
    }

    fn user_position_at_epoch(&self, user_id: EntityId, epoch: u64) -> Option<Position> {
        self.proofs
            .iter()
            .find(|p| *p.prover_id() == user_id && p.epoch() == epoch)
            .map(|p| *p.position())
    }

    fn users_at_position_at_epoch(&self, position: Position, epoch: u64) -> Vec<EntityId> {
        self.proofs
            .iter()
            .filter(|p| *p.position() == position && p.epoch() == epoch)
            .map(|p| *p.prover_id())
            .collect()
    }

    fn save(&mut self) -> Result<(), HdltLocalStoreError> {
        let file = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&self.file_path)?;

        serde_json::to_writer_pretty(BufWriter::new(file), &self.proofs)?;

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use lazy_static::lazy_static;
    use model::{
        keys::Signature, UnverifiedPositionProof, UnverifiedProximityProof,
        UnverifiedProximityProofRequest,
    };
    use tempdir::TempDir;

    fn sig(a: u8, b: u8) -> Signature {
        let mut s = [0u8; 64];
        s[0] = a;
        s[1] = b;

        Signature::from_slice(&s).unwrap()
    }

    lazy_static! {
        static ref REQS: Vec<UnverifiedProximityProofRequest> = vec![
            UnverifiedProximityProofRequest {
                prover_id: 0,
                epoch: 0,
                position: Position(0, 0),
                signature: sig(42, 43),
            },
            UnverifiedProximityProofRequest {
                prover_id: 1,
                epoch: 0,
                position: Position(1, 0),
                signature: sig(43, 42),
            },
            UnverifiedProximityProofRequest {
                prover_id: 0,
                epoch: 1,
                position: Position(0, 1),
                signature: sig(42, 43),
            },
            UnverifiedProximityProofRequest {
                prover_id: 1,
                epoch: 1,
                position: Position(0, 1),
                signature: sig(43, 43),
            },
        ];
        static ref PPROOFS: Vec<UnverifiedProximityProof> = vec![
            UnverifiedProximityProof {
                request: REQS[0].clone(),
                witness_id: 42,
                witness_position: Position(35, 32),
                signature: sig(42, 0),
            },
            UnverifiedProximityProof {
                request: REQS[1].clone(),
                witness_id: 43,
                witness_position: Position(35, 32),
                signature: sig(43, 0),
            },
            UnverifiedProximityProof {
                request: REQS[2].clone(),
                witness_id: 44,
                witness_position: Position(35, 32),
                signature: sig(44, 0),
            },
            UnverifiedProximityProof {
                request: REQS[3].clone(),
                witness_id: 45,
                witness_position: Position(35, 32),
                signature: sig(45, 0),
            },
        ];
        pub(crate) static ref PROOFS: Vec<PositionProof> = vec![
            UnverifiedPositionProof {
                witnesses: vec![PPROOFS[0].clone()]
            },
            UnverifiedPositionProof {
                witnesses: vec![PPROOFS[1].clone()]
            },
            UnverifiedPositionProof {
                witnesses: vec![PPROOFS[2].clone()]
            },
            UnverifiedPositionProof {
                witnesses: vec![PPROOFS[3].clone()]
            },
        ]
        .into_iter()
        // Safety: it's a storage/query test, we don't care about valid signatures or quorum sizes
        .map(|p| unsafe { p.verify_unchecked() })
        .collect();

        pub(crate) static ref STORE: HdltLocalStore = {
            // leak to not drop the TempDir (which deletes our stuff)
            let tempdir = Box::leak(Box::new(TempDir::new("hdltlocalstore").unwrap()));

            let store = HdltLocalStore::open(tempdir.path().join("store.json")).unwrap();
            for p in &*PROOFS {
                store.add_proof(p.clone()).unwrap();
            }

            store
        };
    }

    #[test]
    fn persistence() {
        let tempdir = TempDir::new("hdltlocalstore").unwrap();
        let store_path = tempdir.path().join("store.json");

        {
            let store = HdltLocalStore::open(&store_path).unwrap();
            store.add_proof(PROOFS[0].clone()).unwrap();
            store.add_proof(PROOFS[1].clone()).unwrap();
        }

        {
            let store = HdltLocalStore::open(&store_path).unwrap();
            let mut inner = store.0.into_inner().unwrap();
            assert_eq!(inner.proofs.len(), 2);

            if inner.proofs[0] != PROOFS[0] {
                // we don't need the order to be preserved
                // if they were swapped, swap them back for comparison
                inner.proofs.swap(0, 1);
            }

            assert_eq!(inner.proofs[0], PROOFS[0]);
            assert_eq!(inner.proofs[1], PROOFS[1]);
        }
    }

    #[test]
    fn query_user_position_at_epoch() {
        assert_eq!(Position(0, 0), STORE.user_position_at_epoch(0, 0).unwrap());
        assert_eq!(Position(1, 0), STORE.user_position_at_epoch(1, 0).unwrap());
        assert_eq!(Position(0, 1), STORE.user_position_at_epoch(0, 1).unwrap());
        assert_eq!(Position(0, 1), STORE.user_position_at_epoch(1, 1).unwrap());
        assert!(STORE.user_position_at_epoch(2, 2).is_none());
        assert!(STORE.user_position_at_epoch(0, 2).is_none());
        assert!(STORE.user_position_at_epoch(2, 0).is_none());
    }

    #[test]
    fn query_users_at_position_at_epoch() {
        let empty: Vec<EntityId> = vec![];

        assert_eq!(vec![0], STORE.users_at_position_at_epoch(Position(0, 0), 0));
        assert_eq!(vec![1], STORE.users_at_position_at_epoch(Position(1, 0), 0));
        assert_eq!(
            vec![0, 1],
            STORE.users_at_position_at_epoch(Position(0, 1), 1)
        );
        assert_eq!(empty, STORE.users_at_position_at_epoch(Position(2, 2), 2));
        assert_eq!(empty, STORE.users_at_position_at_epoch(Position(2, 2), 0));
        assert_eq!(empty, STORE.users_at_position_at_epoch(Position(0, 0), 2));
    }

    #[test]
    fn add_existing_proof() {
        let original_proofs = STORE.0.read().unwrap().proofs.clone();

        assert!(STORE.add_proof(PROOFS[0].clone()).is_err(), "should not be able to add a proof when another one with the same prover_id/epoch exists");
        assert_eq!(
            STORE.0.read().unwrap().proofs,
            original_proofs,
            "add_proof cannot modify internal state when failing"
        );

        let mut proof: UnverifiedPositionProof = PROOFS[0].clone().into();
        proof.witnesses[0].witness_id = 52345;
        proof.witnesses[0].signature = sig(189, 40);
        proof.witnesses[0].request.position = Position(189, 416);
        proof.witnesses[0].request.signature = sig(189, 48);

        // Safety: always memory-safe, test can have data with bad signatures
        let proof = unsafe { proof.verify_unchecked() };

        assert!(STORE.add_proof(proof).is_err(), "should not be able to add a proof when another one with the same prover_id/epoch exists");
        assert_eq!(
            STORE.0.read().unwrap().proofs,
            original_proofs,
            "add_proof cannot modify internal state when failing"
        );
    }
}

use itertools::Itertools;
use model::{keys::EntityId, Position, PositionProof, UnverifiedPositionProof};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::*;

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

    #[error("User {} is trying to be in two places at the same time", .0)]
    InconsistentUser(EntityId),
}

impl HdltLocalStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, HdltLocalStoreError> {
        let store = HdltLocalStoreInner::open(path)?;
        Ok(HdltLocalStore(RwLock::new(store)))
    }

    pub async fn add_proof(&self, proof: PositionProof) -> Result<(), HdltLocalStoreError> {
        self.0.write().await.add_proof(proof)
    }

    pub async fn user_position_at_epoch(&self, user_id: EntityId, epoch: u64) -> Option<Position> {
        self.0.read().await.user_position_at_epoch(user_id, epoch)
    }

    pub async fn users_at_position_at_epoch(
        &self,
        position: Position,
        epoch: u64,
    ) -> Vec<EntityId> {
        self.0
            .read()
            .await
            .users_at_position_at_epoch(position, epoch)
    }

    #[cfg(test)]
    /// Clone like in [std::clone::Clone]. Restricted to test environments because
    /// this is not usually a good idea. Forget about persistence guarantees after calling it.
    pub(crate) async fn clone(&self) -> Self {
        let store = self.0.read().await.clone();
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
                if file.metadata()?.len() == 0 {
                    Vec::new()
                } else {
                    let reader = BufReader::new(file);

                    serde_json::from_reader::<_, Vec<UnverifiedPositionProof>>(reader)?
                        .into_iter()
                        // Safety: we saved valid position proofs, so they must be safe to read
                        .map(|unverified| unsafe { unverified.verify_unchecked() })
                        .collect()
                }
            }
            Err(e) if e.kind() == tokio::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };

        Ok(HdltLocalStoreInner {
            file_path: path.as_ref().to_owned(),
            proofs,
        })
    }

    fn save(&mut self) -> Result<(), HdltLocalStoreError> {
        let mut tempfile = tempfile::NamedTempFile::new_in(
            self.file_path.parent().unwrap_or(&PathBuf::from("./")),
        )
        .unwrap();

        serde_json::to_writer_pretty(BufWriter::new(tempfile.as_file_mut()), &self.proofs)?;
        fs::rename(tempfile.path(), &self.file_path)?;

        Ok(())
    }

    #[instrument(skip(self))]
    fn add_proof(&mut self, proof: PositionProof) -> Result<(), HdltLocalStoreError> {
        if self
            .proofs
            .iter()
            .any(|p| p.prover_id() == proof.prover_id() && p.epoch() == proof.epoch())
        {
            debug!("Proof already exists");
            return Err(HdltLocalStoreError::ProofAlreadyExists);
        }

        let proof_positions: Vec<_> = proof_position_info(&proof).collect();
        if let Some(id) = self
            .proofs
            .iter()
            .filter(|p| p.epoch() == proof.epoch())
            .flat_map(proof_position_info)
            .cartesian_product(&proof_positions)
            .find(|((id, pos), (pid, ppos))| id == pid && pos != ppos)
            .map(|((id, _), _)| id)
        {
            debug!("Proof shows a user to be inconsistent");
            return Err(HdltLocalStoreError::InconsistentUser(id));
        }

        self.proofs.push(proof);
        debug!("Proof saved");

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
}

fn proof_position_info(proof: &PositionProof) -> impl Iterator<Item = (EntityId, Position)> + '_ {
    proof
        .witnesses()
        .iter()
        .map(|w| (*w.witness_id(), *w.witness_position()))
        .chain(std::iter::once((*proof.prover_id(), *proof.position())))
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use lazy_static::lazy_static;
    use model::{
        keys::Signature, UnverifiedPositionProof, UnverifiedProximityProof,
        UnverifiedProximityProofRequest,
    };
    use tempfile::NamedTempFile;

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

        pub(crate) static ref STORE_EMPTY: HdltLocalStore = {
            let store_file = NamedTempFile::new().unwrap();
            let store = HdltLocalStore::open(store_file.path()).unwrap();

            // do not drop the file, or it will be prematurely deleted
            // this does mean it will not be cleaned by us
            // TODO: check if it's ok to just delete the temporary file
            std::mem::forget(store_file);

            store
        };
    }

    pub async fn build_store() -> HdltLocalStore {
        let store = STORE_EMPTY.clone().await;

        for p in &*PROOFS {
            store.add_proof(p.clone()).await.unwrap();
        }

        store
    }

    #[tokio::test]
    async fn persistence() {
        let store_file = NamedTempFile::new().unwrap();

        {
            let store = HdltLocalStore::open(store_file.path()).unwrap();
            store.add_proof(PROOFS[0].clone()).await.unwrap();
            store.add_proof(PROOFS[1].clone()).await.unwrap();
        }

        {
            let store = HdltLocalStore::open(store_file.path()).unwrap();
            let mut inner = store.0.into_inner();
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

    #[tokio::test]
    async fn query_user_position_at_epoch() {
        let store = build_store().await;

        assert_eq!(
            Position(0, 0),
            store.user_position_at_epoch(0, 0).await.unwrap()
        );
        assert_eq!(
            Position(1, 0),
            store.user_position_at_epoch(1, 0).await.unwrap()
        );
        assert_eq!(
            Position(0, 1),
            store.user_position_at_epoch(0, 1).await.unwrap()
        );
        assert_eq!(
            Position(0, 1),
            store.user_position_at_epoch(1, 1).await.unwrap()
        );
        assert!(store.user_position_at_epoch(2, 2).await.is_none());
        assert!(store.user_position_at_epoch(0, 2).await.is_none());
        assert!(store.user_position_at_epoch(2, 0).await.is_none());
    }

    #[tokio::test]
    async fn query_users_at_position_at_epoch() {
        let store = build_store().await;
        let empty: Vec<EntityId> = vec![];

        assert_eq!(
            vec![0],
            store.users_at_position_at_epoch(Position(0, 0), 0).await
        );
        assert_eq!(
            vec![1],
            store.users_at_position_at_epoch(Position(1, 0), 0).await
        );
        assert_eq!(
            vec![0, 1],
            store.users_at_position_at_epoch(Position(0, 1), 1).await
        );
        assert_eq!(
            empty,
            store.users_at_position_at_epoch(Position(2, 2), 2).await
        );
        assert_eq!(
            empty,
            store.users_at_position_at_epoch(Position(2, 2), 0).await
        );
        assert_eq!(
            empty,
            store.users_at_position_at_epoch(Position(0, 0), 2).await
        );
    }

    #[tokio::test]
    async fn add_existing_proof() {
        let store = build_store().await;
        let original_proofs = store.0.read().await.proofs.clone();

        assert!(store.add_proof(PROOFS[0].clone()).await.is_err(), "should not be able to add a proof when another one with the same prover_id/epoch exists");
        assert_eq!(
            store.0.read().await.proofs,
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

        assert!(store.add_proof(proof).await.is_err(), "should not be able to add a proof when another one with the same prover_id/epoch exists");
        assert_eq!(
            store.0.read().await.proofs,
            original_proofs,
            "add_proof cannot modify internal state when failing"
        );
    }

    #[tokio::test]
    async fn inconsistent_user() {
        let store = STORE_EMPTY.clone().await;
        store.0.write().await.proofs.clear();

        let p1 = PROOFS[0].clone();
        store.add_proof(p1).await.unwrap();

        let p1_prover_id = *PROOFS[0].prover_id();
        let p1_witness_id = *PROOFS[0].witnesses()[0].witness_id();
        // correctness of the test itself
        assert_ne!(p1_prover_id, p1_witness_id);
        assert_eq!(p1_prover_id, 0);
        assert_eq!(p1_witness_id, 42);

        // Build a proof where the prover from p1 is stating to be somewhere else as a witness
        let mut p2: UnverifiedPositionProof = PROOFS[0].clone().into();
        p2.witnesses[0].request.prover_id = 1000;
        p2.witnesses[0].witness_id = p1_prover_id;
        p2.witnesses[0].witness_position = Position(1000, 1000);
        // Safety: always memory-sfe, test can have data with bad signatures
        let p2 = unsafe { p2.verify_unchecked() };
        assert!(matches!(
            store.add_proof(p2).await.unwrap_err(),
            HdltLocalStoreError::InconsistentUser(0)
        ));

        // Build a proof where a witness from p1 is stating to be somewhere else as a prover
        let mut p2: UnverifiedPositionProof = PROOFS[0].clone().into();
        p2.witnesses[0].request.prover_id = p1_witness_id;
        p2.witnesses[0].request.position = Position(1000, 1000);
        p2.witnesses[0].witness_id = 1000;
        // Safety: always memory-sfe, test can have data with bad signatures
        let p2 = unsafe { p2.verify_unchecked() };
        assert!(matches!(
            store.add_proof(p2).await.unwrap_err(),
            HdltLocalStoreError::InconsistentUser(42)
        ));

        // Build a proof where a witness from p1 is stating to be somewhere else as a witness
        let mut p3: UnverifiedPositionProof = PROOFS[0].clone().into();
        p3.witnesses[0].request.prover_id = 1000;
        p3.witnesses[0].witness_position = Position(404, 404);
        // Safety: always memory-sfe, test can have data with bad signatures
        let p3 = unsafe { p3.verify_unchecked() };
        assert!(matches!(
            store.add_proof(p3).await.unwrap_err(),
            HdltLocalStoreError::InconsistentUser(42)
        ));
    }
}

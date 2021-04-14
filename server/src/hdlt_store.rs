use model::{keys::EntityId, Location, LocationProof, UnverifiedLocationProof};
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

    pub fn add_proof(&self, proof: LocationProof) -> Result<(), HdltLocalStoreError> {
        self.0.write().expect("lock poisoned").add_proof(proof)
    }

    pub fn user_location_at_epoch(&self, user_id: EntityId, epoch: u64) -> Option<Location> {
        self.0
            .read()
            .expect("local storage lock poisoned")
            .user_location_at_epoch(user_id, epoch)
    }

    pub fn users_at_location_at_epoch(&self, location: Location, epoch: u64) -> Vec<EntityId> {
        self.0
            .read()
            .expect("local storage lock poisoned")
            .users_at_location_at_epoch(location, epoch)
    }
}

#[derive(Debug)]
struct HdltLocalStoreInner {
    file_path: PathBuf,
    proofs: Vec<LocationProof>,
}

impl HdltLocalStoreInner {
    fn open<P: AsRef<Path>>(path: P) -> Result<Self, HdltLocalStoreError> {
        let proofs = match File::open(path.as_ref()) {
            Ok(file) => {
                serde_json::from_reader::<_, Vec<UnverifiedLocationProof>>(BufReader::new(file))?
                    .into_iter()
                    // Safety: we saved valid location proofs, so they must be safe to read
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

    fn add_proof(&mut self, proof: LocationProof) -> Result<(), HdltLocalStoreError> {
        if self
            .proofs
            .iter()
            .find(|p| p.prover_id() == proof.prover_id() && p.epoch() == proof.epoch())
            .is_some()
        {
            return Err(HdltLocalStoreError::ProofAlreadyExists);
        }

        self.proofs.push(proof);

        self.save()?;
        Ok(())
    }

    fn user_location_at_epoch(&self, user_id: EntityId, epoch: u64) -> Option<Location> {
        self.proofs
            .iter()
            .find(|p| *p.prover_id() == user_id && p.epoch() == epoch)
            .map(|p| p.location().clone())
    }

    fn users_at_location_at_epoch(&self, location: Location, epoch: u64) -> Vec<EntityId> {
        self.proofs
            .iter()
            .filter(|p| *p.location() == location && p.epoch() == epoch)
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
        UnverifiedLocationProof, UnverifiedProximityProof, UnverifiedProximityProofRequest,
    };
    use tempdir::TempDir;

    lazy_static! {
        static ref REQS: Vec<UnverifiedProximityProofRequest> = vec![
            UnverifiedProximityProofRequest {
                prover_id: 0,
                epoch: 0,
                location: Location(0, 0),
                signature: vec![42, 43],
            },
            UnverifiedProximityProofRequest {
                prover_id: 1,
                epoch: 0,
                location: Location(1, 0),
                signature: vec![43, 42],
            },
            UnverifiedProximityProofRequest {
                prover_id: 0,
                epoch: 1,
                location: Location(0, 1),
                signature: vec![42, 43],
            },
            UnverifiedProximityProofRequest {
                prover_id: 1,
                epoch: 1,
                location: Location(0, 1),
                signature: vec![43, 43],
            },
        ];
        static ref PPROOFS: Vec<UnverifiedProximityProof> = vec![
            UnverifiedProximityProof {
                request: REQS[0].clone(),
                witness_id: 42,
                signature: vec![42],
            },
            UnverifiedProximityProof {
                request: REQS[1].clone(),
                witness_id: 43,
                signature: vec![43],
            },
            UnverifiedProximityProof {
                request: REQS[2].clone(),
                witness_id: 44,
                signature: vec![44],
            },
            UnverifiedProximityProof {
                request: REQS[3].clone(),
                witness_id: 45,
                signature: vec![45],
            },
        ];
        static ref PROOFS: Vec<LocationProof> = vec![
            UnverifiedLocationProof {
                witnesses: vec![PPROOFS[0].clone()]
            },
            UnverifiedLocationProof {
                witnesses: vec![PPROOFS[1].clone()]
            },
            UnverifiedLocationProof {
                witnesses: vec![PPROOFS[2].clone()]
            },
            UnverifiedLocationProof {
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
    fn query_user_location_at_epoch() {
        assert_eq!(Location(0, 0), STORE.user_location_at_epoch(0, 0).unwrap());
        assert_eq!(Location(1, 0), STORE.user_location_at_epoch(1, 0).unwrap());
        assert_eq!(Location(0, 1), STORE.user_location_at_epoch(0, 1).unwrap());
        assert_eq!(Location(0, 1), STORE.user_location_at_epoch(1, 1).unwrap());
        assert!(STORE.user_location_at_epoch(2, 2).is_none());
        assert!(STORE.user_location_at_epoch(0, 2).is_none());
        assert!(STORE.user_location_at_epoch(2, 0).is_none());
    }

    #[test]
    fn query_users_at_location_at_epoch() {
        let empty: Vec<EntityId> = vec![];

        assert_eq!(vec![0], STORE.users_at_location_at_epoch(Location(0, 0), 0));
        assert_eq!(vec![1], STORE.users_at_location_at_epoch(Location(1, 0), 0));
        assert_eq!(
            vec![0, 1],
            STORE.users_at_location_at_epoch(Location(0, 1), 1)
        );
        assert_eq!(empty, STORE.users_at_location_at_epoch(Location(2, 2), 2));
        assert_eq!(empty, STORE.users_at_location_at_epoch(Location(2, 2), 0));
        assert_eq!(empty, STORE.users_at_location_at_epoch(Location(0, 0), 2));
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

        let mut proof: UnverifiedLocationProof = PROOFS[0].clone().into();
        proof.witnesses[0].witness_id = 52345;
        proof.witnesses[0].signature = vec![189, 40, 9];
        proof.witnesses[0].request.location = Location(189, 416);
        proof.witnesses[0].request.signature = vec![189, 48, 2];

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

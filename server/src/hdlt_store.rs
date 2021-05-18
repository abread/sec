use model::{
    keys::{EntityId, Signature},
    Position, PositionProof, ProximityProof,
};
use std::path::Path;
use thiserror::Error;
use tracing::*;

#[derive(Debug, Clone)]
pub struct HdltLocalStore(sqlx::Pool<sqlx::Sqlite>);

#[derive(Error, Debug)]
pub enum HdltLocalStoreError {
    #[error("Database Error")]
    DbError(#[from] sqlx::Error),

    #[error("A different proof for the same (user_id, epoch) already exists")]
    ProofAlreadyExists,

    #[error("User {} is trying to be in two places at the same time", .0)]
    InconsistentUser(EntityId),
}

impl HdltLocalStore {
    pub async fn open<P: AsRef<Path>>(path: P) -> Result<Self, HdltLocalStoreError> {
        let path = path
            .as_ref()
            .to_str()
            .expect("bad string used as db path. stick to unicode chars");
        let conn_uri = format!("sqlite://{}?mode=rwc", path);
        let db = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(64)
            .connect(&conn_uri)
            .await;
        let db = db?;

        let r = HdltLocalStore::new(db).await;
        r
    }

    #[cfg(test)]
    pub async fn open_memory() -> Self {
        let db = sqlx::sqlite::SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        HdltLocalStore::new(db).await.unwrap()
    }

    pub async fn new(db: sqlx::Pool<sqlx::Sqlite>) -> Result<Self, HdltLocalStoreError> {
        sqlx::query(include_str!("hdlt_store_init.sql"))
            .execute(&db)
            .await?;

        Ok(HdltLocalStore(db))
    }

    pub async fn add_proof(&self, proof: PositionProof) -> Result<(), HdltLocalStoreError> {
        let mut tx = self.0.begin().await?;

        for prox_proof in proof.witnesses() {
            sqlx::query(
                "INSERT INTO proximity_proofs (
                    epoch,
                    prover_id,
                    prover_position_x,
                    prover_position_y,
                    request_signature,
                    witness_id,
                    witness_position_x,
                    witness_position_y,
                    signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
            )
            .bind(prox_proof.epoch() as i64)
            .bind(prox_proof.prover_id())
            .bind(prox_proof.request().position().0)
            .bind(prox_proof.request().position().1)
            .bind(prox_proof.request().signature().as_ref())
            .bind(prox_proof.witness_id())
            .bind(prox_proof.witness_position().0)
            .bind(prox_proof.witness_position().1)
            .bind(prox_proof.signature().as_ref())
            .execute(&mut tx)
            .await?;

            // failure detector trigger detects bad stuff from prover/witness
        }

        tx.commit().await.map_err(|e| e.into())
    }

    pub async fn query_epoch_prover(
        &self,
        epoch: u64,
        prover_id: EntityId,
    ) -> Result<Vec<ProximityProof>, HdltLocalStoreError> {
        let proofs = sqlx::query_as::<_, DbProximityProof>(
            "SELECT * FROM proximity_proofs WHERE epoch = ? AND prover_id = ?;",
        )
        .bind(epoch as i64)
        .bind(prover_id)
        .fetch_all(&self.0)
        .await?
        .into_iter()
        .map(|r| r.into())
        .collect();

        Ok(proofs)
    }

    pub async fn query_epoch_prover_position(
        &self,
        epoch: u64,
        prover_position: Position,
    ) -> Result<Vec<ProximityProof>, HdltLocalStoreError> {
        let proofs = sqlx::query_as::<_, DbProximityProof>(
            "SELECT * FROM proximity_proofs
            WHERE epoch = ? AND prover_position_x = ? AND prover_position_y = ?
            ORDER BY prover_id ASC;
        ",
        )
        .bind(epoch as i64)
        .bind(prover_position.0)
        .bind(prover_position.1)
        .fetch_all(&self.0)
        .await?
        .into_iter()
        .map(|r| r.into())
        .collect();

        Ok(proofs)
    }
}

#[derive(sqlx::FromRow)]
struct DbProximityProof {
    epoch: i64,
    prover_id: u32,
    prover_position_x: i64,
    prover_position_y: i64,
    request_signature: Vec<u8>,
    witness_id: u32,
    witness_position_x: i64,
    witness_position_y: i64,
    signature: Vec<u8>,
}

impl From<DbProximityProof> for ProximityProof {
    fn from(p: DbProximityProof) -> Self {
        use model::{UnverifiedProximityProof, UnverifiedProximityProofRequest};

        let request = UnverifiedProximityProofRequest {
            epoch: p.epoch as u64,
            prover_id: p.prover_id,
            position: Position(p.prover_position_x, p.prover_position_y),
            signature: Signature::from_slice(&p.request_signature)
                .expect("DB stored invalid signature"),
        };

        let proof = UnverifiedProximityProof {
            request,
            witness_id: p.witness_id,
            witness_position: Position(p.witness_position_x, p.witness_position_y),
            signature: Signature::from_slice(&p.signature).expect("DB stored invalid signature"),
        };

        // Safety: only previously-verified proximity proofs are inserted in the database
        unsafe { proof.verify_unchecked() }
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
    }

    pub async fn build_store() -> HdltLocalStore {
        let store = HdltLocalStore::open_memory().await;

        for p in &*PROOFS {
            store.add_proof(p.clone()).await.unwrap();
        }

        store
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn persistence() {
        let tmpdir = tempfile::tempdir().unwrap();
        let store_file_path = tmpdir.path().join("db");

        {
            let store = HdltLocalStore::open(&store_file_path).await.unwrap();
            store.add_proof(PROOFS[0].clone()).await.unwrap();
            store.add_proof(PROOFS[1].clone()).await.unwrap();
        }

        {
            let store = HdltLocalStore::open(&store_file_path).await.unwrap();

            assert_eq!(
                vec![PPROOFS[0].clone()],
                store.query_epoch_prover(0, 0).await.unwrap(),
            );
            assert_eq!(
                vec![PPROOFS[1].clone()],
                store.query_epoch_prover(0, 1).await.unwrap(),
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn query_user_position_at_epoch() {
        let store = build_store().await;

        assert_eq!(
            vec![PPROOFS[0].clone()],
            store.query_epoch_prover(0, 0).await.unwrap(),
        );
        assert_eq!(
            vec![PPROOFS[1].clone()],
            store.query_epoch_prover(0, 1).await.unwrap(),
        );
        assert_eq!(
            vec![PPROOFS[2].clone()],
            store.query_epoch_prover(1, 0).await.unwrap(),
        );
        assert_eq!(
            vec![PPROOFS[3].clone()],
            store.query_epoch_prover(1, 1).await.unwrap(),
        );
        assert!(store.query_epoch_prover(2, 2).await.unwrap().is_empty());
        assert!(store.query_epoch_prover(0, 2).await.unwrap().is_empty());
        assert!(store.query_epoch_prover(2, 0).await.unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn query_users_at_position_at_epoch() {
        let store = build_store().await;
        let empty: Vec<ProximityProof> = vec![];

        assert_eq!(
            vec![PPROOFS[0].clone()],
            store
                .query_epoch_prover_position(0, Position(0, 0))
                .await
                .unwrap()
        );
        assert_eq!(
            vec![PPROOFS[1].clone()],
            store
                .query_epoch_prover_position(0, Position(1, 0))
                .await
                .unwrap()
        );
        assert_eq!(
            vec![PPROOFS[2].clone(), PPROOFS[3].clone()],
            store
                .query_epoch_prover_position(1, Position(0, 1))
                .await
                .unwrap()
        );
        assert_eq!(
            empty,
            store
                .query_epoch_prover_position(2, Position(2, 2))
                .await
                .unwrap()
        );
        assert_eq!(
            empty,
            store
                .query_epoch_prover_position(0, Position(2, 2))
                .await
                .unwrap()
        );
        assert_eq!(
            empty,
            store
                .query_epoch_prover_position(2, Position(0, 0))
                .await
                .unwrap()
        );
    }
}

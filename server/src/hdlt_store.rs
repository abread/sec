use model::{
    keys::{EntityId, Signature},
    MaliciousProof, Position, PositionProof, ProximityProof,
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

    #[error("User {} is trying to be in two places at the same time", .0.user_id())]
    InconsistentUser(Box<MaliciousProof>),
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
                "INSERT OR IGNORE INTO proximity_proofs (
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
        // get all proximity proofs for so-far-non-malicious provers
        let proofs: Vec<_> = sqlx::query_as::<_, DbProximityProof>(
            "SELECT * FROM proximity_proofs AS p
            WHERE p.epoch = ? AND p.prover_id = ?
                AND p.prover_id NOT IN (
                    SELECT m.malicious_user_id FROM malicious_proofs AS m
                    WHERE m.epoch = p.epoch AND m.malicious_user_id = p.prover_id
                )
            ORDER BY p.prover_id ASC, p.witness_id ASC;",
        )
        .bind(epoch as i64)
        .bind(prover_id)
        .fetch_all(&self.0)
        .await?
        .into_iter()
        .map(|r| r.into())
        .collect();

        if proofs.is_empty() {
            // even if there is a concurrent write for this user,
            // this block will either still return nothing or a malicious user.
            // it is as if the user had no submissions or was malicious at the start, no matter what

            let malicious_proof = sqlx::query_as::<_, DbMaliciousProof>(
                "SELECT
                    m.malicious_user_id AS user_id,
                    a.epoch AS a_epoch,
                    a.prover_id AS a_prover_id,
                    a.prover_position_x AS a_prover_position_x,
                    a.prover_position_y AS a_prover_position_y,
                    a.request_signature AS a_request_signature,
                    a.witness_id AS a_witness_id,
                    a.witness_position_x AS a_witness_position_x,
                    a.witness_position_y AS a_witness_position_y,
                    a.signature AS a_signature,
                    b.epoch AS b_epoch,
                    b.prover_id AS b_prover_id,
                    b.prover_position_x AS b_prover_position_x,
                    b.prover_position_y AS b_prover_position_y,
                    b.request_signature AS b_request_signature,
                    b.witness_id AS b_witness_id,
                    b.witness_position_x AS b_witness_position_x,
                    b.witness_position_y AS b_witness_position_y,
                    b.signature AS b_signature
                FROM malicious_proofs AS m
                    JOIN proximity_proofs AS a ON m.proof_left_id = a.rowid
                    JOIN proximity_proofs AS b ON m.proof_right_id = b.rowid
                WHERE m.epoch = ? AND m.malicious_user_id = ?;",
            )
            .bind(epoch as i64)
            .bind(prover_id)
            .fetch_optional(&self.0)
            .await?;

            if let Some(mp) = malicious_proof {
                return Err(HdltLocalStoreError::InconsistentUser(Box::new(mp.into())));
            }
        }

        Ok(proofs)
    }

    pub async fn query_epoch_prover_position(
        &self,
        epoch: u64,
        prover_position: Position,
    ) -> Result<(Vec<ProximityProof>, Vec<MaliciousProof>), HdltLocalStoreError> {
        // get all proximity proofs for so-far-non-malicious provers
        let proofs = sqlx::query_as::<_, DbProximityProof>(
            "SELECT p.* FROM proximity_proofs AS p
            WHERE p.epoch = ? AND p.prover_position_x = ? AND p.prover_position_y = ?
                AND prover_id NOT IN (
                    SELECT m.malicious_user_id FROM malicious_proofs AS m
                    WHERE m.epoch = p.epoch AND m.malicious_user_id = p.prover_id
                )
            ORDER BY p.prover_id ASC, p.witness_id ASC;",
        )
        .bind(epoch as i64)
        .bind(prover_position.0)
        .bind(prover_position.1)
        .fetch_all(&self.0)
        .await?
        .into_iter()
        .map(|r| r.into())
        .collect();

        let malicious_proofs = sqlx::query_as::<_, DbMaliciousProof>(
            "SELECT
                m.malicious_user_id AS user_id,
                a.epoch AS a_epoch,
                a.prover_id AS a_prover_id,
                a.prover_position_x AS a_prover_position_x,
                a.prover_position_y AS a_prover_position_y,
                a.request_signature AS a_request_signature,
                a.witness_id AS a_witness_id,
                a.witness_position_x AS a_witness_position_x,
                a.witness_position_y AS a_witness_position_y,
                a.signature AS a_signature,
                b.epoch AS b_epoch,
                b.prover_id AS b_prover_id,
                b.prover_position_x AS b_prover_position_x,
                b.prover_position_y AS b_prover_position_y,
                b.request_signature AS b_request_signature,
                b.witness_id AS b_witness_id,
                b.witness_position_x AS b_witness_position_x,
                b.witness_position_y AS b_witness_position_y,
                b.signature AS b_signature
            FROM malicious_proofs AS m
                JOIN proximity_proofs AS a ON m.proof_left_id = a.rowid
                JOIN proximity_proofs AS b ON m.proof_right_id = b.rowid",
        )
        .fetch_all(&self.0)
        .await?
        .into_iter()
        .map(|r| r.into())
        .collect();

        Ok((proofs, malicious_proofs))
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

struct DbMaliciousProof {
    user_id: u32,
    a: DbProximityProof,
    b: DbProximityProof,
}

// ugh, derive does not do the thing I want
impl<'a, R: ::sqlx::Row> ::sqlx::FromRow<'a, R> for DbMaliciousProof
where
    &'a ::std::primitive::str: ::sqlx::ColumnIndex<R>,
    u32: ::sqlx::decode::Decode<'a, R::Database>,
    u32: ::sqlx::types::Type<R::Database>,
    i64: ::sqlx::decode::Decode<'a, R::Database>,
    i64: ::sqlx::types::Type<R::Database>,
    Vec<u8>: ::sqlx::decode::Decode<'a, R::Database>,
    Vec<u8>: ::sqlx::types::Type<R::Database>,
{
    fn from_row(row: &'a R) -> ::sqlx::Result<Self> {
        macro_rules! prox_proof {
            ($prefix:expr) => {{
                let epoch: i64 = row.try_get(concat!($prefix, "epoch"))?;
                let prover_id: u32 = row.try_get(concat!($prefix, "prover_id"))?;
                let prover_position_x: i64 = row.try_get(concat!($prefix, "prover_position_x"))?;
                let prover_position_y: i64 = row.try_get(concat!($prefix, "prover_position_y"))?;
                let request_signature: Vec<u8> =
                    row.try_get(concat!($prefix, "request_signature"))?;
                let witness_id: u32 = row.try_get(concat!($prefix, "witness_id"))?;
                let witness_position_x: i64 =
                    row.try_get(concat!($prefix, "witness_position_x"))?;
                let witness_position_y: i64 =
                    row.try_get(concat!($prefix, "witness_position_y"))?;
                let signature: Vec<u8> = row.try_get(concat!($prefix, "signature"))?;

                DbProximityProof {
                    epoch,
                    prover_id,
                    prover_position_x,
                    prover_position_y,
                    request_signature,
                    witness_id,
                    witness_position_x,
                    witness_position_y,
                    signature,
                }
            }};
        }

        let user_id: u32 = row.try_get("user_id")?;
        let a = prox_proof!("a_");
        let b = prox_proof!("b_");

        Ok(DbMaliciousProof { user_id, a, b })
    }
}

impl From<DbMaliciousProof> for MaliciousProof {
    fn from(p: DbMaliciousProof) -> Self {
        let a: ProximityProof = p.a.into();
        let b: ProximityProof = p.b.into();

        MaliciousProof::new(p.user_id, a, b).expect("DB saved an invalid malicious proof")
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
                .0
        );
        assert_eq!(
            vec![PPROOFS[1].clone()],
            store
                .query_epoch_prover_position(0, Position(1, 0))
                .await
                .unwrap()
                .0
        );
        assert_eq!(
            vec![PPROOFS[2].clone(), PPROOFS[3].clone()],
            store
                .query_epoch_prover_position(1, Position(0, 1))
                .await
                .unwrap()
                .0
        );
        assert_eq!(
            empty,
            store
                .query_epoch_prover_position(2, Position(2, 2))
                .await
                .unwrap()
                .0
        );
        assert_eq!(
            empty,
            store
                .query_epoch_prover_position(0, Position(2, 2))
                .await
                .unwrap()
                .0
        );
        assert_eq!(
            empty,
            store
                .query_epoch_prover_position(2, Position(0, 0))
                .await
                .unwrap()
                .0
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn inconsistent_user() {
        use crate::hdlt_store::test::PROOFS;
        let store = HdltLocalStore::open_memory().await;

        let p0 = PROOFS[0].clone();
        store.add_proof(p0).await.unwrap();

        let p0_prover_id = *PROOFS[0].prover_id();
        let p0_witness_id = *PROOFS[0].witnesses()[0].witness_id();
        // correctness of the test itself
        assert_ne!(p0_prover_id, p0_witness_id);
        assert_eq!(p0_prover_id, 0);
        assert_eq!(p0_witness_id, 42);

        // Build a proof where the prover from p1 is stating to be somewhere else as a witness
        let mut p1: UnverifiedPositionProof = PROOFS[0].clone().into();
        p1.witnesses[0].request.prover_id = 1000;
        p1.witnesses[0].witness_id = p0_prover_id;
        p1.witnesses[0].witness_position = Position(1000, 1000);
        // Safety: always memory-sfe, test can have data with bad signatures
        let p1 = unsafe { p1.verify_unchecked() };
        store.add_proof(p1).await.unwrap();

        assert!(matches!(
            dbg!(store.query_epoch_prover(PROOFS[0].epoch(), p0_prover_id).await.unwrap_err()),
            HdltLocalStoreError::InconsistentUser(mp) if mp.user_id() == p0_prover_id
        ));

        // Build a proof where a witness from p1 is stating to be somewhere else as a prover
        let mut p2: UnverifiedPositionProof = PROOFS[0].clone().into();
        p2.witnesses[0].request.prover_id = p0_witness_id;
        p2.witnesses[0].request.position = Position(1000, 1000);
        p2.witnesses[0].witness_id = 1000;
        // Safety: always memory-sfe, test can have data with bad signatures
        let p2 = unsafe { p2.verify_unchecked() };
        store.add_proof(p2).await.unwrap_err();
        assert!(matches!(
            store.query_epoch_prover(PROOFS[0].epoch(), p0_witness_id).await.unwrap_err(),
            HdltLocalStoreError::InconsistentUser(mp) if mp.user_id() == p0_witness_id
        ));

        // Build a proof where a witness from p1 is stating to be somewhere else as a witness
        let mut p3: UnverifiedPositionProof = PROOFS[0].clone().into();
        p3.witnesses[0].request.prover_id = 1000;
        p3.witnesses[0].witness_position = Position(404, 404);
        // Safety: always memory-sfe, test can have data with bad signatures
        let p3 = unsafe { p3.verify_unchecked() };
        store.add_proof(p3).await.unwrap_err();
        assert!(matches!(
            store.query_epoch_prover(PROOFS[0].epoch(), p0_witness_id).await.unwrap_err(),
            HdltLocalStoreError::InconsistentUser(mp) if mp.user_id() == p0_witness_id
        ));
    }
}

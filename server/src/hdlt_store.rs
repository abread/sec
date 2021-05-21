use model::{
    keys::{EntityId, Signature},
    MisbehaviorProof, Position, PositionProof, ProximityProof,
};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;
use tracing::*;

#[derive(Debug)]
pub struct HdltLocalStore {
    db_pool: sqlx::Pool<sqlx::Sqlite>,
}

#[derive(Error, Debug)]
pub enum HdltLocalStoreError {
    #[error("Database Error")]
    DbError(#[from] sqlx::Error),

    #[error("An equally or more recent position proof already exists for this user")]
    StaleProof,

    #[error("User {} is trying to be in two places at the same time", .0.user_id())]
    InconsistentUser(Box<MisbehaviorProof>),
}

impl HdltLocalStore {
    pub async fn open<P: AsRef<Path>>(path: P) -> Result<Self, HdltLocalStoreError> {
        let path = path
            .as_ref()
            .to_str()
            .expect("bad string used as db path. stick to unicode chars");
        let conn_uri = format!("sqlite://{}?mode=rwc", path);
        let db_pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(64)
            .connect(&conn_uri)
            .await?;

        let r = HdltLocalStore::new(db_pool).await;
        r
    }

    #[cfg(test)]
    pub async fn open_memory() -> Self {
        let db_pool = sqlx::sqlite::SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        HdltLocalStore::new(db_pool).await.unwrap()
    }

    pub async fn new(db_pool: sqlx::Pool<sqlx::Sqlite>) -> Result<Self, HdltLocalStoreError> {
        sqlx::query(include_str!("hdlt_store_init.sql"))
            .execute(&db_pool)
            .await?;

        Ok(HdltLocalStore { db_pool })
    }

    /// Add a proof iff it is more recent than the last proof
    pub async fn add_proof(&self, proof: PositionProof) -> Result<(), HdltLocalStoreError> {
        let mut tx = self.db_pool.begin().await?;

        if sqlx::query("SELECT signature FROM proximity_proofs WHERE epoch >= ? AND prover_id = ?")
            .bind(proof.epoch() as i64)
            .bind(proof.prover_id())
            .fetch_optional(&mut tx)
            .await?
            .is_some()
        {
            return Err(HdltLocalStoreError::StaleProof);
        }

        if sqlx::query("SELECT signature FROM proximity_proofs WHERE epoch >= ? AND prover_id = ?")
            .bind(proof.epoch() as i64)
            .bind(proof.prover_id())
            .fetch_optional(&mut tx)
            .await?
            .is_some()
        {
            return Err(HdltLocalStoreError::StaleProof);
        }

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

            // misbehavior_proofs view detects bad stuff from prover/witness
        }

        tx.commit().await.map_err(|e| e.into())
    }

    /// Add a proof iff it is more recent than the last proof
    pub async fn add_misbehaviour_proof(&self, proof: MisbehaviorProof) -> Result<(), HdltLocalStoreError> {
        let mut tx = self.db_pool.begin().await?;

        let prox_proof_a = proof.a();
        let prox_proof_b = proof.b();

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
        .bind(prox_proof_a.epoch() as i64)
        .bind(prox_proof_a.prover_id())
        .bind(prox_proof_a.request().position().0)
        .bind(prox_proof_a.request().position().1)
        .bind(prox_proof_a.request().signature().as_ref())
        .bind(prox_proof_a.witness_id())
        .bind(prox_proof_a.witness_position().0)
        .bind(prox_proof_a.witness_position().1)
        .bind(prox_proof_a.signature().as_ref())
        .execute(&mut tx)
        .await?;

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
        .bind(prox_proof_b.epoch() as i64)
        .bind(prox_proof_b.prover_id())
        .bind(prox_proof_b.request().position().0)
        .bind(prox_proof_b.request().position().1)
        .bind(prox_proof_b.request().signature().as_ref())
        .bind(prox_proof_b.witness_id())
        .bind(prox_proof_b.witness_position().0)
        .bind(prox_proof_b.witness_position().1)
        .bind(prox_proof_b.signature().as_ref())
        .execute(&mut tx)
        .await?;

        tx.commit().await.map_err(|e| e.into())
    }

    async fn verify_proofs(
        &self,
        epoch: u64,
        prover_id: EntityId,
        p: Vec<ProximityProof>,
    ) -> Result<Vec<ProximityProof>, HdltLocalStoreError> {
        if p.is_empty() {
            // even if there is a concurrent write for this user,
            // this block will either still return nothing or a misbehaving user.
            // it is as if the user had no submissions or was misbehaving at the start, no matter what
            // therefore atomicity is still guaranteed
            let misbehavior_proof = sqlx::query_as::<_, DbMisbehaviorProof>(
                "SELECT m.* FROM misbehavior_proofs AS m
                WHERE m.epoch = ? AND m.user_id = ?;",
            )
            .bind(epoch as i64)
            .bind(prover_id)
            .fetch_optional(&self.db_pool)
            .await?;

            if let Some(mp) = misbehavior_proof {
                Err(HdltLocalStoreError::InconsistentUser(Box::new(mp.into())))
            } else {
                Ok(p)
            }
        } else {
            Ok(p)
        }
    }

    pub async fn query_epoch_prover(
        &self,
        epoch: u64,
        prover_id: EntityId,
    ) -> Result<Vec<ProximityProof>, HdltLocalStoreError> {
        // get all proximity proofs for non-misbehaving provers (non-misbehaving in this epoch)
        let proofs: Vec<_> = sqlx::query_as::<_, DbProximityProof>(
            "SELECT p.* FROM proximity_proofs AS p
            WHERE p.epoch = ? AND p.prover_id = ?
                AND p.prover_id NOT IN (
                    SELECT m.user_id FROM misbehavior_proofs AS m
                    WHERE m.epoch = ? AND m.user_id = ?
                )
            ORDER BY p.witness_id ASC;",
        )
        .bind(epoch as i64)
        .bind(prover_id)
        .bind(epoch as i64)
        .bind(prover_id)
        .fetch_all(&self.db_pool)
        .await?
        .into_iter()
        .map(|r| r.into())
        .collect();

        self.verify_proofs(epoch, prover_id, proofs).await
    }

    pub async fn query_epoch_prover_range(
        &self,
        epoch_range: std::ops::Range<u64>,
        prover_id: EntityId,
    ) -> Result<Vec<(u64, Vec<ProximityProof>)>, HdltLocalStoreError> {
        // get all proximity proofs for non-misbehaving provers
        // (non-misbehaving in this epoch range)

        let mut proofs = HashMap::with_capacity((epoch_range.end - epoch_range.start) as usize);
        for prox_proof in sqlx::query_as::<_, DbProximityProof>(
            "SELECT p.* FROM proximity_proofs AS p
            WHERE p.epoch >= ? AND p.epoch < ? AND p.prover_id = ?
                AND p.prover_id NOT IN (
                    SELECT m.user_id FROM misbehavior_proofs AS m
                    WHERE m.epoch >= ? AND m.epoch < ? AND m.user_id = ?
                )
            ORDER BY p.witness_id ASC;",
        )
        .bind(epoch_range.start as i64)
        .bind(epoch_range.end as i64)
        .bind(prover_id)
        .bind(epoch_range.start as i64)
        .bind(epoch_range.end as i64)
        .bind(prover_id)
        .fetch_all(&self.db_pool)
        .await?
        .into_iter()
        {
            let p: ProximityProof = prox_proof.into();
            proofs.entry(p.epoch()).or_insert_with(Vec::new).push(p);
        }

        let mut result = Vec::with_capacity(proofs.len());
        for (epoch, p) in proofs.into_iter() {
            result.push((epoch, self.verify_proofs(epoch, prover_id, p).await?))
        }
        Ok(result)
    }

    pub async fn query_epoch_prover_position(
        &self,
        epoch: u64,
        prover_position: Position,
    ) -> Result<Vec<ProximityProof>, HdltLocalStoreError> {
        // get all proximity proofs for non-misbehaving provers (non-misbehaving in this epoch)
        let proofs = sqlx::query_as::<_, DbProximityProof>(
            "SELECT p.* FROM proximity_proofs AS p
            WHERE p.epoch = ? AND p.prover_position_x = ? AND p.prover_position_y = ?
                AND prover_id NOT IN (
                    SELECT m.user_id FROM misbehavior_proofs AS m
                    WHERE m.epoch = ? AND m.user_id = p.prover_id
                )
            ORDER BY p.prover_id ASC, p.witness_id ASC;",
        )
        .bind(epoch as i64)
        .bind(prover_position.0)
        .bind(prover_position.1)
        .bind(epoch as i64)
        .fetch_all(&self.db_pool)
        .await?
        .into_iter()
        .map(|r| r.into())
        .collect();

        Ok(proofs)
    }

    pub async fn query_misbehaved(
        &self,
        id: EntityId,
    ) -> Result<Option<MisbehaviorProof>, HdltLocalStoreError> {
        sqlx::query_as::<_, DbMisbehaviorProof>(
            "SELECT * FROM misbehavior_proofs WHERE user_id = ? LIMIT 1;",
        )
        .bind(id)
        .fetch_optional(&self.db_pool)
        .await
        .map(|r| r.map(|proof| proof.into()))
        .map_err(|e| e.into())
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

struct DbMisbehaviorProof {
    user_id: u32,
    a: DbProximityProof,
    b: DbProximityProof,
}

// ugh, derive does not do the thing I want
impl<'a, R: ::sqlx::Row> ::sqlx::FromRow<'a, R> for DbMisbehaviorProof
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
        let epoch: i64 = row.try_get("epoch")?;

        macro_rules! prox_proof {
            ($prefix:expr) => {{
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

        Ok(DbMisbehaviorProof { user_id, a, b })
    }
}

impl From<DbMisbehaviorProof> for MisbehaviorProof {
    fn from(p: DbMisbehaviorProof) -> Self {
        let a: ProximityProof = p.a.into();
        let b: ProximityProof = p.b.into();

        MisbehaviorProof::new(p.user_id, a, b).expect("DB saved an invalid misbehavior proof")
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use futures::stream::FuturesUnordered;
    use futures::StreamExt;
    use itertools::Itertools;
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

    macro_rules! pos_proof {
        ($epoch:expr, $prover_id:expr => ($prover_pos_x:expr, $prover_pos_y:expr) ; $($witness_id:expr => ($witness_pos_x:expr, $witness_pos_y:expr)),+) => {{
            use model::{keys::EntityId, UnverifiedProximityProofRequest, UnverifiedProximityProof, UnverifiedPositionProof};

            let epoch: u64 = $epoch;
            let prover_id: EntityId = $prover_id;

            let req = UnverifiedProximityProofRequest {
                epoch,
                prover_id,
                position: Position($prover_pos_x, $prover_pos_y),
                signature: sig(epoch as u8, prover_id as u8 * 2),
            };

            let witnesses = vec![
                $(
                    {
                        let witness_id = $witness_id;
                        UnverifiedProximityProof {
                            request: req.clone(),
                            witness_id,
                            witness_position: Position($witness_pos_x, $witness_pos_y),
                            signature: sig(epoch as u8, witness_id as u8 * 2 + 1),
                        }
                    }
                ),+
            ];

            // Safety: always memory-safe, bad signatures are ok for tests
            unsafe { UnverifiedPositionProof { witnesses }.verify_unchecked() }
        }};
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn inconsistent_user() {
        let store = HdltLocalStore::open_memory().await;

        let p0 = pos_proof! {
            0, 2 => (0, 0);
            0 => (1, 1),
            1 => (2, 2)
        };

        // next epoch they switch positions, all fine still
        let p1_1 = pos_proof! {
            1, 0 => (0, 0);
            1 => (1, 1),
            2 => (2, 2)
        };
        let p1_2 = pos_proof! {
            1, 2 => (2, 2);
            0 => (0, 0),
            1 => (1, 1)
        };

        // ...but this next proof means all of them are messed up
        // Conflicts:
        // user 1: witness-witness with p1_1 and p1_2 (converges to conflict with p1_1)
        // user 2: witness-witness with p1_1 and witness-prover with p1_2 (converges to conflict with p1_1)
        let p1_3 = pos_proof! {
            1, 3 => (100, 100);
            2 => (100, 100),
            1 => (100, 100)
        };

        store.add_proof(p0).await.unwrap();
        store.add_proof(p1_1.clone()).await.unwrap();
        store.add_proof(p1_2.clone()).await.unwrap();

        // no conflicts yet
        for &epoch in &[0u64, 1] {
            for &uid in &[0u32, 1, 2, 3] {
                assert!(matches!(store.query_epoch_prover(epoch, uid).await, Ok(_)));
            }
        }
        assert_eq!(
            2,
            store
                .query_epoch_prover_position(0, Position(0, 0))
                .await
                .unwrap()[0]
                .prover_id()
        );
        assert_eq!(
            0,
            store
                .query_epoch_prover_position(1, Position(0, 0))
                .await
                .unwrap()[0]
                .prover_id()
        );

        // now add conflicts
        store.add_proof(p1_3.clone()).await.unwrap();

        // epoch 0 should still be fine
        assert!(store.query_epoch_prover(0, 0).await.is_ok());

        // epoch 1 is full of conflicts
        for &uid in &[1, 2] {
            assert!(matches!(
                store.query_epoch_prover(1, uid).await,
                Err(HdltLocalStoreError::InconsistentUser(mp)) if mp.user_id() == uid
            ));
        }
        for &pos in &[Position(1, 1), Position(2, 2)] {
            // users 1 and 2 have conflicts and should not show up here
            assert!(store
                .query_epoch_prover_position(1, pos)
                .await
                .unwrap()
                .is_empty());
        }

        // check convergence
        // also ensures both prover-witness and witness-prover conflicts are reliably detected
        let ps = [&p1_1, &p1_2, &p1_3];
        let mps: FuturesUnordered<_> = ps
            .iter()
            .permutations(3)
            .map(|proofs| async move {
                let store = HdltLocalStore::open_memory().await;
                for &p in proofs {
                    store.add_proof(p.to_owned()).await.unwrap();
                }

                let mp1 = match store.query_epoch_prover(1, 1).await {
                    Err(HdltLocalStoreError::InconsistentUser(mp)) => mp,
                    _ => unreachable!(),
                };
                let mp2 = match store.query_epoch_prover(1, 2).await {
                    Err(HdltLocalStoreError::InconsistentUser(mp)) => mp,
                    _ => unreachable!(),
                };

                (mp1, mp2)
            })
            .collect();
        let (first_mps, mps) = mps.into_future().await;
        let first_mps = first_mps.unwrap();

        mps.for_each(|mps| {
            assert_eq!(first_mps, mps);
            std::future::ready(())
        })
        .await;
    }
}

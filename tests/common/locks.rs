//! Watching which table locks other sessions hold while a push or a migrate runs, and how long a
//! concurrent application query waits (IN-A, IN-C).

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tokio::task::JoinHandle;

/// A pool of `size` connections to the database `pool` reaches, for a session the test drives
/// apart from the engine's.
pub async fn side_pool(pool: &PgPool, size: u32) -> PgPool {
    PgPoolOptions::new()
        .max_connections(size)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .expect("open a side pool")
}

/// Every lock mode another backend held on a relation named in `tables`, sampled until stopped.
pub struct LockSampler {
    stop: Arc<AtomicBool>,
    task: JoinHandle<BTreeSet<(String, String)>>,
}

impl LockSampler {
    /// Samples every 5 ms, leaving out the sessions in `ignored` and its own.
    pub async fn start(pool: &PgPool, tables: &[&str], ignored: Vec<i32>) -> LockSampler {
        let side = side_pool(pool, 1).await;
        let stop = Arc::new(AtomicBool::new(false));
        let tables: Vec<String> = tables.iter().map(|t| t.to_string()).collect();
        let flag = stop.clone();
        let task = tokio::spawn(async move {
            let mut seen = BTreeSet::new();
            while !flag.load(Ordering::SeqCst) {
                let rows: Vec<(String, String)> = sqlx::query_as(
                    "SELECT c.relname::text, l.mode FROM pg_locks l
                       JOIN pg_class c ON c.oid = l.relation
                      WHERE l.granted AND c.relname = ANY($1)
                        AND l.pid <> pg_backend_pid() AND l.pid <> ALL($2)",
                )
                .bind(&tables)
                .bind(&ignored)
                .fetch_all(&side)
                .await
                .unwrap_or_default();
                seen.extend(rows);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            side.close().await;
            seen
        });
        LockSampler { stop, task }
    }

    /// `(table, mode)` for every lock seen.
    pub async fn finish(self) -> BTreeSet<(String, String)> {
        self.stop.store(true, Ordering::SeqCst);
        self.task.await.expect("the lock sampler ran")
    }
}

/// The modes that make an `INSERT`, `UPDATE` or `DELETE` wait.
pub const BLOCKS_WRITES: &[&str] = &[
    "ShareLock",
    "ShareRowExclusiveLock",
    "ExclusiveLock",
    "AccessExclusiveLock",
];

/// An application running `statements` one after another in a loop, recording the longest any
/// one of them took.
pub struct App {
    stop: Arc<AtomicBool>,
    task: JoinHandle<(Duration, usize)>,
    pub pid: i32,
}

impl App {
    pub async fn start(pool: &PgPool, statements: &[&str]) -> App {
        let side = side_pool(pool, 1).await;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&side)
            .await
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let statements: Vec<String> = statements.iter().map(|s| s.to_string()).collect();
        let flag = stop.clone();
        let task = tokio::spawn(async move {
            let mut longest = Duration::ZERO;
            let mut ran = 0;
            while !flag.load(Ordering::SeqCst) {
                for sql in &statements {
                    let started = Instant::now();
                    sqlx::raw_sql(sql)
                        .execute(&side)
                        .await
                        .unwrap_or_else(|e| panic!("the application's {sql} failed: {e}"));
                    longest = longest.max(started.elapsed());
                    ran += 1;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            side.close().await;
            (longest, ran)
        });
        App { stop, task, pid }
    }

    /// The longest one statement took, and how many ran.
    pub async fn finish(self) -> (Duration, usize) {
        self.stop.store(true, Ordering::SeqCst);
        self.task.await.expect("the application ran")
    }
}

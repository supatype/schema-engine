//! Pushing to a database an application is using (IN-C).
//!
//! A push's transaction waits for each table lock it needs, and while it waits every query on that
//! table queues behind it: Postgres's lock queue. So each attempt waits at most
//! [`PUSH_LOCK_TIMEOUT`], rolls back whole on `lock_not_available`, and tries again after a jittered
//! pause, [`PUSH_ATTEMPTS`] times in all; the last failure names the table and the session holding
//! it ([`LockNotAvailable`]). The engine's own lock is held for the whole of it, at session level,
//! so a second push is refused at once with `engine_busy` between attempts too (ENG-CONC).
//!
//! Once the transaction has committed, what it left to run online runs on the same session: the
//! keys and checks it added `NOT VALID` are validated, and the indexes it left are built with
//! `CREATE INDEX CONCURRENTLY` ([`crate::generator::sql::online`]). Each is recorded in the ledger
//! once it is in place.

mod after_commit;
mod broken_rows;
mod index_drops;
mod not_null;
mod sizes;

pub use after_commit::{finished, run_after_commit, AfterCommitFailed, Unfinished};
pub use broken_rows::refuse_broken_rows;
pub use index_drops::{concurrent_drops, drop_concurrently};
pub use sizes::{online_tables, table_sizes, TableSize};

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::pool::PoolConnection;
use sqlx::{Connection, PgConnection, PgPool, Postgres, Transaction};

/// How long one attempt of a push waits for a table lock. Short, so the queue of application
/// queries behind a waiting `ALTER TABLE` lasts seconds.
pub const PUSH_LOCK_TIMEOUT: &str = "3s";
/// How many times a push tries before it gives up on a lock.
pub const PUSH_ATTEMPTS: u32 = 4;
/// The pause after the first failed attempt, doubled after each, then jittered by half either way:
/// with [`PUSH_LOCK_TIMEOUT`] the whole push gives up within about 25 seconds.
const FIRST_PAUSE: Duration = Duration::from_millis(1_000);

/// The engine's own lock, held by one pooled session for a whole push: every attempt of its
/// transaction and what runs after it commits. Released when the push ends; a session dropped
/// without that (a cancelled request) is closed, which releases it.
pub struct EngineSession {
    conn: Option<PoolConnection<Postgres>>,
    pid: i32,
}

impl EngineSession {
    /// The session, or [`crate::push::EngineBusy::Running`] when another writer holds the lock.
    pub async fn open(pool: &PgPool) -> Result<EngineSession> {
        let mut conn = pool.acquire().await.context("acquire the push's session")?;
        let (taken, pid): (bool, i32) =
            sqlx::query_as("SELECT pg_try_advisory_lock($1, $2), pg_backend_pid()")
                .bind(crate::push::PUSH_LOCK_CLASS)
                .bind(crate::push::ENGINE_LOCK_ID)
                .fetch_one(&mut *conn)
                .await
                .context("try the engine's advisory lock")?;
        if !taken {
            return Err(crate::push::EngineBusy::Running.into());
        }
        Ok(EngineSession {
            conn: Some(conn),
            pid,
        })
    }

    pub fn pid(&self) -> i32 {
        self.pid
    }

    pub fn conn(&mut self) -> &mut PgConnection {
        self.conn
            .as_mut()
            .expect("the session is open until closed")
    }

    /// A writer's transaction on this session, waiting at most `lock_timeout` for each lock.
    pub async fn begin(&mut self, lock_timeout: &str) -> Result<Transaction<'_, Postgres>> {
        let mut tx = self
            .conn()
            .begin()
            .await
            .context("begin the writer's transaction")?;
        crate::push::bound_writer(&mut tx, lock_timeout).await?;
        crate::push::take_engine_lock(&mut tx).await?;
        crate::push::take_push_lock(&mut tx).await?;
        Ok(tx)
    }

    /// Releases the lock. A session that cannot say so is closed instead, which releases it.
    pub async fn close(mut self) {
        let Some(mut conn) = self.conn.take() else {
            return;
        };
        let released = sqlx::query("SELECT pg_advisory_unlock($1, $2)")
            .bind(crate::push::PUSH_LOCK_CLASS)
            .bind(crate::push::ENGINE_LOCK_ID)
            .execute(&mut *conn)
            .await;
        if released.is_err() {
            let _ = conn.detach().close().await;
        }
    }
}

impl Drop for EngineSession {
    fn drop(&mut self) {
        // Not closed: the push was cancelled or panicked. The connection must not go back to the
        // pool holding the engine's lock, so it is dropped, which closes it.
        if let Some(conn) = self.conn.take() {
            drop(conn.detach());
        }
    }
}

/// Whether `e` is Postgres giving up on a lock (`lock_not_available`).
pub fn lock_timed_out(e: &anyhow::Error) -> bool {
    e.chain()
        .filter_map(|cause| cause.downcast_ref::<sqlx::Error>())
        .any(|cause| crate::state::migration_history::sql_state(cause).as_deref() == Some("55P03"))
}

/// The pause after failed attempt `attempt` (1-based): doubled each time, jittered by half.
pub fn pause(attempt: u32) -> Duration {
    let base = FIRST_PAUSE * 2u32.pow(attempt.saturating_sub(1));
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let jitter = 0.5 + f64::from(nanos % 1_000) / 1_000.0;
    base.mul_f64(jitter)
}

/// A session another one waited on: never its query, which may hold data.
#[derive(Debug, Clone, PartialEq)]
pub struct Holder {
    pub pid: i32,
    pub state: String,
    /// How long its transaction (or, outside one, its session) has been running.
    pub running_for: Duration,
}

/// What a push was waiting for when it last gave up on a lock.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LockWait {
    pub table: String,
    pub mode: String,
    pub holders: Vec<Holder>,
}

/// A writer that could not take a lock: a push or the bootstrap in [`PUSH_ATTEMPTS`] attempts, or
/// adopt, a rebaseline or a rollback in one, since a person is waiting on it (LK1). Nothing was
/// applied.
#[derive(Debug)]
pub struct LockNotAvailable {
    /// What gave up: `push`, `bootstrap`, `adopt`, `rebaseline`, `rollback`, `migrate --record`.
    pub what: &'static str,
    pub attempts: u32,
    /// What the last attempt waited on, when the writer saw it.
    pub wait: Option<LockWait>,
}

/// The stable name a caller matches a [`LockNotAvailable`] refusal on (LK6).
pub const LOCK_UNAVAILABLE: &str = "lock_unavailable";

impl LockNotAvailable {
    /// How long it waited: "in 4 attempts, each waiting 3s", or "waiting 3s" for one.
    fn waited(&self) -> String {
        match self.attempts {
            1 => format!("waiting {PUSH_LOCK_TIMEOUT}"),
            n => format!("in {n} attempts, each waiting {PUSH_LOCK_TIMEOUT}"),
        }
    }

    /// What to do once the lock is free.
    fn again(&self) -> String {
        match self.what {
            "push" => "push again".to_string(),
            what => format!("run the {what} again"),
        }
    }
}

impl std::fmt::Display for LockNotAvailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(wait) = &self.wait else {
            return write!(
                f,
                "The {} could not take a table lock {}, and nothing was applied. Another session \
                 is using a table it changes; {} once it is done.",
                self.what,
                self.waited(),
                self.again()
            );
        };
        let holders: Vec<String> = wait
            .holders
            .iter()
            .map(|h| {
                format!(
                    "pid {} ({}, running for {}s)",
                    h.pid,
                    h.state,
                    h.running_for.as_secs()
                )
            })
            .collect();
        write!(
            f,
            "The {} could not take {} on {} {}, and nothing was applied. It is held by {}. End \
             that session, or wait for it to finish, then {}.",
            self.what,
            wait.mode,
            wait.table,
            self.waited(),
            holders.join(", "),
            self.again()
        )
    }
}

impl std::error::Error for LockNotAvailable {}

/// The backend `conn` runs on, for [`fail_fast`] to watch.
pub async fn backend_pid(conn: &mut PgConnection) -> Result<i32> {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(conn)
        .await
        .context("read the writer's backend")
}

/// Runs `work`, a writer's transaction on backend `pid`, watching what it waits for. One that gives
/// up on a lock is said as [`LockNotAvailable`] naming the table and the session holding it,
/// without trying again: the writers a person runs at a prompt (adopt, a rebaseline, a rollback)
/// tell them at once (LK1).
pub async fn fail_fast<T>(
    pool: &PgPool,
    pid: i32,
    what: &'static str,
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    let watch = WaitWatch::start(pool, pid);
    let result = work.await;
    let wait = watch.finish().await;
    result.map_err(|e| {
        if retryable(&e) {
            LockNotAvailable {
                what,
                attempts: 1,
                wait,
            }
            .into()
        } else {
            e
        }
    })
}

/// Runs `once` until it does not give up on a lock, [`PUSH_ATTEMPTS`] times at most with a
/// [`pause`] between, as a push's attempts run: for a writer no person waits on (the bootstrap a
/// push or `dev` runs). The last failure names what it waited for when `once` said so
/// ([`fail_fast`]).
pub async fn retrying<T, F, Fut>(what: &'static str, mut once: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    for tried in 1..=PUSH_ATTEMPTS {
        let e = match once().await {
            Ok(out) => return Ok(out),
            Err(e) => e,
        };
        let gave_up = e.downcast_ref::<LockNotAvailable>().is_some() || retryable(&e);
        if !gave_up {
            return Err(e);
        }
        if tried == PUSH_ATTEMPTS {
            let wait = e
                .downcast::<LockNotAvailable>()
                .ok()
                .and_then(|failed| failed.wait);
            return Err(LockNotAvailable {
                what,
                attempts: tried,
                wait,
            }
            .into());
        }
        tracing::warn!("{what} attempt {tried} gave up on a lock; trying again");
        tokio::time::sleep(pause(tried)).await;
    }
    unreachable!("the last attempt returns")
}

/// Watches one backend while it runs a statement, keeping the last relation lock it was seen
/// waiting for and the sessions it waited behind.
pub struct WaitWatch {
    stop: Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<Option<LockWait>>,
}

type WaitRow = (String, String, i32, String, f64);

impl WaitWatch {
    pub fn start(pool: &PgPool, pid: i32) -> WaitWatch {
        let stop = Arc::new(tokio::sync::Notify::new());
        let stopped = stop.clone();
        let pool = pool.clone();
        let task = tokio::spawn(async move {
            let mut seen = None;
            loop {
                // Woken at once when told to stop, so a writer that took every lock it needed is
                // not held up by the watch's own pause.
                tokio::select! {
                    _ = stopped.notified() => return seen,
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                }
                if let Ok(Some(wait)) = waiting(&pool, pid).await {
                    seen = Some(wait);
                }
            }
        });
        WaitWatch { stop, task }
    }

    pub async fn finish(self) -> Option<LockWait> {
        // `notify_one` keeps the wake-up for a watch between two of its polls.
        self.stop.notify_one();
        self.task.await.ok().flatten()
    }
}

/// The relation lock `pid` is waiting for, and who holds it, if it is waiting.
async fn waiting(pool: &PgPool, pid: i32) -> Result<Option<LockWait>> {
    let rows: Vec<WaitRow> = sqlx::query_as(
        "SELECT l.relation::regclass::text, l.mode, b.pid, COALESCE(b.state, 'unknown'),
                EXTRACT(EPOCH FROM now() - COALESCE(b.xact_start, b.backend_start))::float8
           FROM pg_locks l
          CROSS JOIN LATERAL unnest(pg_blocking_pids(l.pid)) AS bp(pid)
           JOIN pg_stat_activity b ON b.pid = bp.pid
          WHERE l.pid = $1 AND NOT l.granted AND l.locktype = 'relation'
          ORDER BY b.pid",
    )
    .bind(pid)
    .fetch_all(pool)
    .await?;
    let Some((table, mode, ..)) = rows.first().cloned() else {
        return Ok(None);
    };
    let holders = rows
        .into_iter()
        .map(|(_, _, pid, state, secs)| Holder {
            pid,
            state,
            running_for: Duration::from_secs_f64(secs.max(0.0)),
        })
        .collect();
    Ok(Some(LockWait {
        table,
        mode,
        holders,
    }))
}

/// A future one attempt of a push's transaction runs, borrowing the transaction.
pub type Running<'t, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send + 't>>;

/// What a push does inside one transaction, run again whole when it gives up on a lock.
pub trait Attempt {
    type Out: Send;
    fn run<'t>(&'t self, tx: &'t mut PgConnection) -> Running<'t, Self::Out>;
}

/// Whether an attempt gave up on a lock and may be tried again.
fn retryable(e: &anyhow::Error) -> bool {
    lock_timed_out(e) || e.downcast_ref::<crate::push::LockTimeout>().is_some()
}

/// Runs `attempt` in a transaction on `session` that waits at most [`PUSH_LOCK_TIMEOUT`] for each
/// lock, committing it when it succeeds. One that gives up on a lock is rolled back whole and run
/// again after [`pause`], up to [`PUSH_ATTEMPTS`] times; the last failure says what it waited for
/// ([`LockNotAvailable`]). Any other failure is rolled back and returned as it came.
pub async fn with_retries<A: Attempt + Sync>(
    pool: &PgPool,
    session: &mut EngineSession,
    attempt: &A,
) -> Result<A::Out> {
    for tried in 1..=PUSH_ATTEMPTS {
        let (e, wait) = match once(pool, session, attempt).await {
            Ok(out) => return Ok(out),
            Err(failed) => failed,
        };
        if !retryable(&e) {
            return Err(e);
        }
        if tried == PUSH_ATTEMPTS {
            return Err(LockNotAvailable {
                what: "push",
                attempts: tried,
                wait,
            }
            .into());
        }
        tracing::warn!("push attempt {tried} gave up on a lock; trying again");
        tokio::time::sleep(pause(tried)).await;
    }
    unreachable!("the last attempt returns")
}

/// One attempt, committed when it succeeds and rolled back when it fails, with what it was seen
/// waiting for.
async fn once<A: Attempt + Sync>(
    pool: &PgPool,
    session: &mut EngineSession,
    attempt: &A,
) -> std::result::Result<A::Out, (anyhow::Error, Option<LockWait>)> {
    let pid = session.pid();
    let mut tx = session
        .begin(PUSH_LOCK_TIMEOUT)
        .await
        .map_err(|e| (e, None))?;
    let watch = WaitWatch::start(pool, pid);
    let result = attempt.run(&mut tx).await;
    let wait = watch.finish().await;
    match result {
        Ok(out) => match tx.commit().await {
            Ok(()) => Ok(out),
            Err(e) => Err((anyhow::Error::from(e).context("commit the push"), wait)),
        },
        Err(e) => {
            let _ = tx.rollback().await;
            Err((e, wait))
        }
    }
}

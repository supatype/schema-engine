//! Connecting to a project's database, the one way every command that reads or writes its schema
//! connects.
//!
//! A writer holds the engine's lock keys and its table locks for one transaction, so the server
//! has to notice a client that is gone. Postgres learns that a TCP peer died only when it sends
//! something, and with the operating system's defaults (keepalive after 2 hours) a dropped
//! network kept both keys held for 15 minutes to over 2 hours (E33). Server-side keepalives are
//! per session and settable by any role, so every connection asks for them when it opens; they are
//! ignored on a Unix socket, where a dead peer is seen at once. The writer's own transaction adds
//! the timeouts that cover a client that is alive but silent (`push::begin_writer`).

use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use anyhow::{Context, Result};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Executor, PgPool};

/// Probe an idle peer after 30 s, every 10 s, and give up after 3 unanswered probes: a dead
/// client is noticed in about a minute.
const KEEPALIVES: &str = "SELECT set_config('tcp_keepalives_idle', '30', false), \
                                 set_config('tcp_keepalives_interval', '10', false), \
                                 set_config('tcp_keepalives_count', '3', false)";

/// How long a preview's read (`diff`, `doctor`) waits for a lock. A preview takes none
/// of the engine's locks, so a lock it meets is a writer's: better to say so in seconds than to
/// wait as long as the writer runs (A4-N1). A writer's own transaction sets its own, longer,
/// timeout with `SET LOCAL`, which wins over this one.
const PREVIEW_LOCK_TIMEOUT: &str = "5s";

/// A pool on `url` whose every connection runs with [`KEEPALIVES`].
pub async fn connect(url: &str) -> Result<PgPool> {
    pool(url, KEEPALIVES.to_string()).await
}

/// [`connect`], with [`PREVIEW_LOCK_TIMEOUT`] on every connection.
pub async fn connect_for_preview(url: &str) -> Result<PgPool> {
    let session =
        format!("{KEEPALIVES}, set_config('lock_timeout', '{PREVIEW_LOCK_TIMEOUT}', false)");
    pool(url, session).await
}

/// A pool on `url` that runs `session` on each connection as it opens.
async fn pool(url: &str, session: String) -> Result<PgPool> {
    PgPoolOptions::new()
        .after_connect(move |conn, _meta| {
            let session = session.clone();
            Box::pin(async move {
                conn.execute(session.as_str()).await?;
                Ok(())
            })
        })
        .connect(url)
        .await
        .context("Failed to connect to database")
}

/// Whether `relation` (a qualified, quoted name) exists, asked of the catalog. Asking rather than
/// reading it and catching the error matters inside a transaction: a failed read aborts it.
pub async fn relation_exists(conn: &mut sqlx::PgConnection, relation: &str) -> Result<bool> {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(relation)
        .fetch_one(&mut *conn)
        .await
        .with_context(|| format!("Failed to look up {relation}"))
}

/// What each pool's server said when asked whether it can check its client (see
/// [`checks_clients`]), keyed by the pool's connect options. A pool keeps the same options for its
/// whole life, and the [`Weak`] keeps their allocation, so a later pool can never be mistaken for
/// one that has gone; the entries of pools that have gone are dropped as new ones are added.
static CLIENT_CHECKS: Mutex<Vec<(Weak<PgConnectOptions>, bool)>> = Mutex::new(Vec::new());

/// Whether the server behind `pool` runs Postgres 14 or later and accepts a non-zero
/// `client_connection_check_interval`. Postgres refuses any value but 0 with
/// `invalid_parameter_value` on a platform that cannot tell a closed socket from an idle one
/// (Windows among them), and a refusal inside a writer's transaction would abort it. The server is
/// asked rather than the platform guessed, since the engine and the database need not run on the
/// same one, and the answer never changes for a server, so each pool asks once and every writer
/// on it reuses the answer (`push::bound_writer`).
pub(crate) async fn checks_clients(pool: &PgPool) -> Result<bool> {
    remembered(&pool.connect_options(), ask_checks_clients(pool)).await
}

/// The answer remembered for `options`, or `ask`'s, remembered from then on.
async fn remembered(
    options: &Arc<PgConnectOptions>,
    ask: impl Future<Output = Result<bool>>,
) -> Result<bool> {
    let known = |checks: &[(Weak<PgConnectOptions>, bool)]| {
        checks
            .iter()
            .find(|(seen, _)| std::ptr::eq(seen.as_ptr(), Arc::as_ptr(options)))
            .map(|(_, answer)| *answer)
    };
    if let Some(answer) = known(&client_checks()) {
        return Ok(answer);
    }
    let answer = ask.await?;
    let mut checks = client_checks();
    checks.retain(|(seen, _)| seen.strong_count() > 0);
    if known(&checks).is_none() {
        checks.push((Arc::downgrade(options), answer));
    }
    Ok(answer)
}

/// [`CLIENT_CHECKS`], whose entries stay whole even if a thread panicked holding it.
fn client_checks() -> MutexGuard<'static, Vec<(Weak<PgConnectOptions>, bool)>> {
    CLIENT_CHECKS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Asks the server with a `set_config` local to the statement's own transaction, so the setting
/// ends with it and a refusal aborts nothing else.
async fn ask_checks_clients(pool: &PgPool) -> Result<bool> {
    let asked = sqlx::query_scalar(
        "SELECT CASE WHEN current_setting('server_version_num')::int >= 140000
                     THEN set_config('client_connection_check_interval', $1, true) IS NOT NULL
                     ELSE false END",
    )
    .bind(crate::push::WRITER_CLIENT_CHECK)
    .fetch_one(pool)
    .await;
    match asked {
        Ok(checks) => Ok(checks),
        Err(e) if crate::state::migration_history::sql_state(&e).as_deref() == Some("22023") => {
            Ok(false)
        }
        Err(e) => Err(e).context("ask whether the server can check its client"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counts how often the server would be asked, and answers `answer`.
    async fn ask(asked: &AtomicUsize, answer: bool) -> Result<bool> {
        asked.fetch_add(1, Ordering::SeqCst);
        Ok(answer)
    }

    #[tokio::test]
    async fn each_pools_server_is_asked_once_whatever_it_answers() {
        let asked = AtomicUsize::new(0);
        let accepts = Arc::new(PgConnectOptions::new());
        let refuses = Arc::new(PgConnectOptions::new());
        for _ in 0..3 {
            assert!(remembered(&accepts, ask(&asked, true)).await.unwrap());
            assert!(!remembered(&refuses, ask(&asked, false)).await.unwrap());
        }
        assert_eq!(asked.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_failed_question_is_not_remembered() {
        let options = Arc::new(PgConnectOptions::new());
        let failed = remembered(&options, async { anyhow::bail!("connection refused") }).await;
        assert!(failed.is_err());
        let asked = AtomicUsize::new(0);
        assert!(remembered(&options, ask(&asked, true)).await.unwrap());
        assert_eq!(asked.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_gone_pools_answer_is_dropped_and_never_reused() {
        let gone = Arc::new(PgConnectOptions::new());
        let asked = AtomicUsize::new(0);
        remembered(&gone, ask(&asked, true)).await.unwrap();
        let gone_at = Arc::as_ptr(&gone);
        drop(gone);
        let next = Arc::new(PgConnectOptions::new());
        assert!(!remembered(&next, ask(&asked, false)).await.unwrap());
        assert_eq!(asked.load(Ordering::SeqCst), 2);
        assert!(!client_checks()
            .iter()
            .any(|(seen, _)| std::ptr::eq(seen.as_ptr(), gone_at)));
    }
}

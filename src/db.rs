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

use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
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

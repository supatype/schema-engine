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

/// A pool on `url` whose every connection runs with [`KEEPALIVES`].
pub async fn connect(url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                conn.execute(KEEPALIVES).await?;
                Ok(())
            })
        })
        .connect(url)
        .await
        .context("Failed to connect to database")
}

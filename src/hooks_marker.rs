//! The marker that tells the server's change-log listener to run no after-hooks for a transaction.
//!
//! After-hooks run from the change log, for every committed write. A seed loads data and a push's
//! migration converts or moves rows; neither is a change anyone's hooks should act on, so their
//! transactions open with this marker and the listener skips them.
//!
//! Transactional, so it is decoded inside the transaction it describes and vanishes if that rolls
//! back. Works at any `wal_level`, `replica` included: Postgres writes the record either way and
//! only logical decoding ever reads it. The listener honours it only in a transaction with no
//! `supatype.actor` marker, so an API request cannot use it to skip its own hooks.

use sqlx::PgConnection;

/// The statement that writes the marker.
pub const SKIP_HOOKS_SQL: &str = "SELECT pg_logical_emit_message(true, 'supatype.hooks', 'skip')";

/// Writes the marker in the transaction `conn` is in. Run it first, before the transaction's
/// writes, and once.
pub async fn skip_hooks(conn: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query(SKIP_HOOKS_SQL).execute(conn).await.map(|_| ())
}

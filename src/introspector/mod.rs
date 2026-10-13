pub mod catalog;
pub mod constraints;
pub mod dependents;
pub mod enums;
pub mod extensions;
pub mod fingerprint;
pub mod indexes;
pub mod postgres;
pub mod rls;
pub mod tables;
pub mod triggers;

use crate::state::database_state::DatabaseState;
use anyhow::Result;
use sqlx::{PgConnection, PgPool};

/// The session setting naming, by oid, the relations another session holds exclusively, whose
/// deparsed parts a read leaves out rather than wait on (IN-B): `pg_get_expr`, the deparsers of
/// keys, indexes and views, and a column's default all take a lock on the relation. Unset for
/// every read but doctor's, so every other reader waits as it always has.
pub const UNREADABLE: &str = "supatype.unreadable";

/// SQL that is true when the relation `relid` (an oid expression) is not one of [`UNREADABLE`].
pub fn readable(relid: &str) -> String {
    format!(
        "NOT ({relid}::text = ANY (string_to_array(COALESCE(current_setting({}, true), ''), ',')))",
        crate::sql_quote::quote_literal(UNREADABLE)
    )
}

/// The differ's view of `schema`, read under the session's own `search_path`.
///
/// Deliberately not pinned ([`pin_search_path`]): nothing read here is fingerprinted, and it is
/// what `POST /introspect` and the `introspect` command return, so its deparsed defaults and
/// expressions read as the caller's session writes them rather than schema-qualified. A push does
/// not read through here; its live read is pinned, so the ledger's fingerprints never depend on
/// whose session read them.
pub async fn introspect(pool: &PgPool, schema: &str) -> Result<DatabaseState> {
    let mut conn = pool.acquire().await?;
    introspect_connection(&mut conn, schema).await
}

/// Introspect using an existing Postgres connection (e.g. inside a transaction).
pub async fn introspect_connection(conn: &mut PgConnection, schema: &str) -> Result<DatabaseState> {
    postgres::introspect(conn, schema).await
}

/// Everything [`introspect`] leaves out. See [`catalog::CatalogState`] for why it is read apart.
/// Read under a pinned `search_path` ([`pin_search_path`]), as a push reads it.
pub async fn introspect_catalog(pool: &PgPool, schema: &str) -> Result<catalog::CatalogState> {
    let mut conn = pool.acquire().await?;
    let saved = pin_search_path(&mut conn).await?;
    let read = catalog::read(&mut conn, schema).await;
    let restored = restore_search_path(&mut conn, &saved).await;
    let catalog = read?;
    restored?;
    Ok(catalog)
}

/// The `search_path` every read that feeds a fingerprint runs under.
///
/// Deparsed text (`pg_get_expr`, `pg_get_constraintdef`, `pg_get_indexdef`,
/// `pg_get_functiondef`, `format_type`) leaves a name bare when its schema is on the session's
/// `search_path` and qualifies it otherwise, so the same object fingerprinted from two sessions
/// with different paths (the CLI's and the server's, a role with its own `search_path`) read as
/// two different objects. With only `pg_catalog` on the path every other name is qualified, the
/// same way every time.
pub const PINNED_SEARCH_PATH: &str = "pg_catalog";

/// Set the session's `search_path` to [`PINNED_SEARCH_PATH`] and return what it was, for
/// [`restore_search_path`]. A session setting rather than `SET LOCAL`, so it holds outside a
/// transaction too; the caller restores it, because the connection goes back to a pool.
pub async fn pin_search_path(conn: &mut PgConnection) -> Result<String> {
    let saved: String = sqlx::query_scalar("SELECT current_setting('search_path')")
        .fetch_one(&mut *conn)
        .await?;
    sqlx::query("SELECT set_config('search_path', $1, false)")
        .bind(PINNED_SEARCH_PATH)
        .execute(&mut *conn)
        .await?;
    Ok(saved)
}

/// Put back the `search_path` [`pin_search_path`] returned.
pub async fn restore_search_path(conn: &mut PgConnection, saved: &str) -> Result<()> {
    sqlx::query("SELECT set_config('search_path', $1, false)")
        .bind(saved)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

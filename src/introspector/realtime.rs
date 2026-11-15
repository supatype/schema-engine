//! The bodies of the realtime channel functions as the database holds them now, for the drift
//! check: `pg_proc.prosrc` keeps a function's body verbatim, so a hand edit is a difference in text.

use crate::generator::sql::realtime::FUNCTION_NAMES;
use crate::generator::sql::versions::HELPER_SCHEMA;
use anyhow::Result;
use sqlx::PgConnection;
use std::collections::BTreeMap;

/// Each realtime function that exists, by name, with its body. A function a push has not made yet
/// is absent, which is not drift.
pub async fn read_function_sources(conn: &mut PgConnection) -> Result<BTreeMap<String, String>> {
    let names: Vec<String> = FUNCTION_NAMES.iter().map(|n| (*n).to_string()).collect();
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT p.proname::text, p.prosrc \
         FROM pg_catalog.pg_proc p \
         JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
         WHERE n.nspname = $1 AND p.proname = ANY($2)",
    )
    .bind(HELPER_SCHEMA)
    .bind(&names)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.into_iter().collect())
}

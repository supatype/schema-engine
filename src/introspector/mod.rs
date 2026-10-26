pub mod catalog;
pub mod constraints;
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

pub async fn introspect(pool: &PgPool, schema: &str) -> Result<DatabaseState> {
    let mut conn = pool.acquire().await?;
    introspect_connection(&mut conn, schema).await
}

/// Introspect using an existing Postgres connection (e.g. inside a transaction).
pub async fn introspect_connection(conn: &mut PgConnection, schema: &str) -> Result<DatabaseState> {
    postgres::introspect(conn, schema).await
}

/// Everything [`introspect`] leaves out. See [`catalog::CatalogState`] for why it is read apart.
pub async fn introspect_catalog(pool: &PgPool, schema: &str) -> Result<catalog::CatalogState> {
    let mut conn = pool.acquire().await?;
    catalog::read(&mut conn, schema).await
}

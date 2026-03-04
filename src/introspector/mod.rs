pub mod postgres;
pub mod tables;
pub mod indexes;
pub mod constraints;
pub mod rls;
pub mod triggers;
pub mod extensions;

use anyhow::Result;
use sqlx::PgPool;
use crate::state::database_state::DatabaseState;

pub async fn introspect(pool: &PgPool, schema: &str) -> Result<DatabaseState> {
    postgres::introspect(pool, schema).await
}

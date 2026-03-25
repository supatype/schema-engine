pub mod constraints;
pub mod enums;
pub mod extensions;
pub mod indexes;
pub mod postgres;
pub mod rls;
pub mod tables;
pub mod triggers;

use crate::state::database_state::DatabaseState;
use anyhow::Result;
use sqlx::PgPool;

pub async fn introspect(pool: &PgPool, schema: &str) -> Result<DatabaseState> {
    postgres::introspect(pool, schema).await
}

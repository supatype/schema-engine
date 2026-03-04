use anyhow::Result;
use sqlx::PgPool;
use crate::state::database_state::DatabaseState;
use super::{tables, indexes, constraints, rls, triggers, extensions};

pub async fn introspect(pool: &PgPool, schema: &str) -> Result<DatabaseState> {
    let db_tables = tables::read(pool, schema).await?;
    let db_indexes = indexes::read(pool, schema).await?;
    let db_constraints = constraints::read(pool, schema).await?;
    let db_rls = rls::read(pool, schema).await?;
    let db_triggers = triggers::read(pool, schema).await?;
    let db_extensions = extensions::read(pool).await?;

    Ok(DatabaseState {
        schema: schema.to_string(),
        tables: db_tables,
        indexes: db_indexes,
        constraints: db_constraints,
        rls_policies: db_rls,
        triggers: db_triggers,
        extensions: db_extensions,
    })
}

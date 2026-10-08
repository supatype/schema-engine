use super::{constraints, enums, extensions, indexes, rls, tables, triggers};
use crate::state::database_state::DatabaseState;
use anyhow::Result;
use sqlx::PgConnection;

pub async fn introspect(conn: &mut PgConnection, schema: &str) -> Result<DatabaseState> {
    let db_tables = tables::read(conn, schema).await?;
    let db_indexes = indexes::read(conn, schema).await?;
    let db_constraints = constraints::read(conn, schema).await?;
    let db_rls = rls::read(conn, schema).await?;
    let db_rls_enabled = rls::read_rls_enabled_tables(conn, schema).await?;
    let db_triggers = triggers::read(conn, schema).await?;
    let db_extensions = extensions::read(conn).await?;
    let db_enums = enums::read(conn, schema).await?;

    Ok(DatabaseState {
        schema: schema.to_string(),
        tables: db_tables,
        indexes: db_indexes,
        constraints: db_constraints,
        rls_policies: db_rls,
        triggers: db_triggers,
        extensions: db_extensions,
        enums: db_enums,
        rls_enabled_tables: db_rls_enabled,
        // The ledger's, filled by whoever reads it.
        table_ownership: Default::default(),
        owned_policies: Default::default(),
        column_ownership: Default::default(),
    })
}

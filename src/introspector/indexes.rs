use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbIndex {
    pub table: String,
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
    pub method: String,
    pub is_primary: bool,
    /// Postgres `COMMENT ON INDEX` text, when set.
    #[serde(default)]
    pub comment: Option<String>,
}

type IndexRow = (
    String,
    String,
    Vec<String>,
    bool,
    String,
    bool,
    Option<String>,
);

pub async fn read(conn: &mut PgConnection, schema: &str) -> Result<Vec<DbIndex>> {
    let rows: Vec<IndexRow> = sqlx::query_as(
        "SELECT t.relname, i.relname,
                array_agg(a.attname ORDER BY array_position(ix.indkey, a.attnum)),
                ix.indisunique, am.amname, ix.indisprimary,
                pg_catalog.obj_description(i.oid, 'pg_class')
         FROM pg_class t
         JOIN pg_index ix ON t.oid = ix.indrelid
         JOIN pg_class i ON i.oid = ix.indexrelid
         JOIN pg_am am ON am.oid = i.relam
         JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
         JOIN pg_namespace n ON n.oid = t.relnamespace
         WHERE n.nspname = $1
         GROUP BY t.relname, i.relname, ix.indisunique, am.amname, ix.indisprimary, i.oid",
    )
    .bind(schema)
    .fetch_all(&mut *conn)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(table, name, columns, unique, method, is_primary, comment)| DbIndex {
                table,
                name,
                columns,
                unique,
                method,
                is_primary,
                comment,
            },
        )
        .collect())
}

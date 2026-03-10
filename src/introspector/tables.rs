use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbTable {
    pub schema: String,
    pub name: String,
    pub columns: Vec<DbColumn>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbColumn {
    pub name: String,
    pub data_type: String,
    pub udt_name: String,
    pub nullable: bool,
    pub default: Option<String>,
    pub ordinal_position: i32,
}

pub async fn read(pool: &PgPool, schema: &str) -> Result<Vec<DbTable>> {
    let table_rows: Vec<(String,)> = sqlx::query_as(
        "SELECT table_name FROM information_schema.tables
         WHERE table_schema = $1 AND table_type = 'BASE TABLE'
           AND table_name NOT LIKE '\\_platform%'
         ORDER BY table_name",
    )
    .bind(schema)
    .fetch_all(pool)
    .await?;

    let mut tables = Vec::new();
    for (name,) in table_rows {
        let columns = read_columns(pool, schema, &name).await?;
        tables.push(DbTable {
            schema: schema.to_string(),
            name,
            columns,
        });
    }
    Ok(tables)
}

async fn read_columns(pool: &PgPool, schema: &str, table: &str) -> Result<Vec<DbColumn>> {
    let rows: Vec<(String, String, String, String, Option<String>, i32)> = sqlx::query_as(
        "SELECT column_name, data_type, udt_name, is_nullable, column_default, ordinal_position
         FROM information_schema.columns
         WHERE table_schema = $1 AND table_name = $2
         ORDER BY ordinal_position",
    )
    .bind(schema)
    .bind(table)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(name, data_type, udt_name, is_nullable, default, ordinal_position)| DbColumn {
                name,
                data_type,
                udt_name,
                nullable: is_nullable == "YES",
                default,
                ordinal_position,
            },
        )
        .collect())
}

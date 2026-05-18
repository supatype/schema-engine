use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

const TABLES_QUERY: &str = "SELECT t.table_name
         FROM information_schema.tables t
         JOIN pg_catalog.pg_namespace n
           ON n.nspname = t.table_schema
         JOIN pg_catalog.pg_class c
           ON c.relname = t.table_name
          AND c.relnamespace = n.oid
          AND c.relkind = 'r'
         LEFT JOIN pg_catalog.pg_depend d
           ON d.classid = 'pg_class'::regclass
          AND d.objid = c.oid
          AND d.deptype = 'e'
         WHERE t.table_schema = $1
           AND t.table_type = 'BASE TABLE'
           AND t.table_name NOT LIKE '\\_platform%'
           AND d.objid IS NULL
         ORDER BY t.table_name";

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

pub async fn read(conn: &mut PgConnection, schema: &str) -> Result<Vec<DbTable>> {
    let table_rows: Vec<(String,)> = sqlx::query_as(TABLES_QUERY)
        .bind(schema)
        .fetch_all(&mut *conn)
        .await?;

    let mut tables = Vec::new();
    for (name,) in table_rows {
        let columns = read_columns(conn, schema, &name).await?;
        tables.push(DbTable {
            schema: schema.to_string(),
            name,
            columns,
        });
    }
    Ok(tables)
}

async fn read_columns(conn: &mut PgConnection, schema: &str, table: &str) -> Result<Vec<DbColumn>> {
    let rows: Vec<(String, String, String, String, Option<String>, i32)> = sqlx::query_as(
        "SELECT column_name, data_type, udt_name, is_nullable, column_default, ordinal_position
         FROM information_schema.columns
         WHERE table_schema = $1 AND table_name = $2
         ORDER BY ordinal_position",
    )
    .bind(schema)
    .bind(table)
    .fetch_all(&mut *conn)
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

#[cfg(test)]
mod tests {
    use super::TABLES_QUERY;

    #[test]
    fn table_query_excludes_extension_owned_tables() {
        assert!(TABLES_QUERY.contains("LEFT JOIN pg_catalog.pg_depend d"));
        assert!(TABLES_QUERY.contains("d.deptype = 'e'"));
        assert!(TABLES_QUERY.contains("d.objid IS NULL"));
    }
}

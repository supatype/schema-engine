use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbRlsPolicy {
    pub table: String,
    pub name: String,
    pub command: String,   // SELECT, INSERT, UPDATE, DELETE, ALL
    pub permissive: bool,
    pub using_expr: Option<String>,
    pub check_expr: Option<String>,
}

pub async fn read(pool: &PgPool, schema: &str) -> Result<Vec<DbRlsPolicy>> {
    let rows: Vec<(String, String, String, bool, Option<String>, Option<String>)> =
        sqlx::query_as(
            "SELECT c.relname, p.polname, p.polcmd::text,
                    p.polpermissive,
                    pg_get_expr(p.polqual, p.polrelid),
                    pg_get_expr(p.polwithcheck, p.polrelid)
             FROM pg_policy p
             JOIN pg_class c ON c.oid = p.polrelid
             JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = $1",
        )
        .bind(schema)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .into_iter()
        .map(|(table, name, command, permissive, using_expr, check_expr)| DbRlsPolicy {
            table,
            name,
            command,
            permissive,
            using_expr,
            check_expr,
        })
        .collect())
}

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbTrigger {
    pub table: String,
    pub name: String,
    pub event: String,
    pub timing: String,
    pub function_name: String,
}

pub async fn read(pool: &PgPool, schema: &str) -> Result<Vec<DbTrigger>> {
    let rows: Vec<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT event_object_table, trigger_name, event_manipulation,
                action_timing, action_statement
         FROM information_schema.triggers
         WHERE trigger_schema = $1
         ORDER BY event_object_table, trigger_name",
    )
    .bind(schema)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(table, name, event, timing, function_name)| DbTrigger {
            table,
            name,
            event,
            timing,
            function_name,
        })
        .collect())
}

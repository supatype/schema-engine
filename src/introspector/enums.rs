use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// A Postgres enum type discovered in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbEnum {
    /// The enum type name, e.g. "post_status".
    pub name: String,
    /// Values in creation order (which determines Postgres enum ordering).
    pub values: Vec<String>,
}

/// Read all user-defined enum types in the given schema.
pub async fn read(pool: &PgPool, schema: &str) -> Result<Vec<DbEnum>> {
    // pg_type + pg_enum gives us enum values in sort order (enumsortorder).
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT t.typname AS enum_name, e.enumlabel AS enum_value
         FROM pg_type t
         JOIN pg_enum e ON e.enumtypid = t.oid
         JOIN pg_namespace n ON n.oid = t.typnamespace
         WHERE n.nspname = $1
         ORDER BY t.typname, e.enumsortorder",
    )
    .bind(schema)
    .fetch_all(pool)
    .await?;

    // Group rows by enum name, preserving order.
    let mut enums: Vec<DbEnum> = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_values: Vec<String> = Vec::new();

    for (name, value) in rows {
        if current_name.as_deref() != Some(&name) {
            if let Some(prev_name) = current_name.take() {
                enums.push(DbEnum {
                    name: prev_name,
                    values: std::mem::take(&mut current_values),
                });
            }
            current_name = Some(name);
        }
        current_values.push(value);
    }
    if let Some(name) = current_name {
        enums.push(DbEnum {
            name,
            values: current_values,
        });
    }

    Ok(enums)
}

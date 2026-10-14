use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

/// One installed extension: where its objects live, and whether `ALTER EXTENSION ... SET SCHEMA`
/// can move them (`pg_extension.extrelocatable`; PostGIS, for one, cannot be moved).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledExtension {
    pub name: String,
    pub schema: String,
    pub relocatable: bool,
}

pub async fn read(conn: &mut PgConnection) -> Result<Vec<InstalledExtension>> {
    let rows: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT e.extname::text, n.nspname::text, e.extrelocatable
         FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
         ORDER BY e.extname",
    )
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(name, schema, relocatable)| InstalledExtension {
            name,
            schema,
            relocatable,
        })
        .collect())
}

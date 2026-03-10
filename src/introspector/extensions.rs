use anyhow::Result;
use sqlx::PgPool;

pub async fn read(pool: &PgPool) -> Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT extname FROM pg_extension ORDER BY extname")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|(name,)| name).collect())
}

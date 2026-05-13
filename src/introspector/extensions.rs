use anyhow::Result;
use sqlx::PgConnection;

pub async fn read(conn: &mut PgConnection) -> Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT extname FROM pg_extension ORDER BY extname")
        .fetch_all(&mut *conn)
        .await?;
    Ok(rows.into_iter().map(|(name,)| name).collect())
}

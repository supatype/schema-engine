use super::{DiffOutput, Operation};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationReport {
    pub safe_to_apply: bool,
    pub checks: Vec<ValidationCheck>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationCheck {
    pub operation: String,
    pub passed: bool,
    pub message: String,
}

/// Run pre-flight checks against production data before applying a migration.
pub async fn validate(diff: &DiffOutput, pool: &PgPool) -> Result<ValidationReport> {
    let mut checks = Vec::new();

    for op in &diff.operations {
        if let Operation::AddUniqueConstraint {
            table,
            column,
            constraint,
            ..
        } = op
        {
            let op_label = format!("AddUniqueConstraint {table}.{column}");
            let (total, distinct): (i64, i64) = sqlx::query_as(&format!(
                "SELECT COUNT(*)::bigint, COUNT(DISTINCT \"{column}\")::bigint \
                 FROM \"{table}\" WHERE \"{column}\" IS NOT NULL"
            ))
            .fetch_one(pool)
            .await?;

            let passed = total == distinct;
            let message = if passed {
                format!("No duplicate values in {table}.{column}")
            } else {
                let dupes = total - distinct;
                format!(
                    "{dupes} duplicate value(s) in {table}.{column} — cannot add constraint {constraint}"
                )
            };
            checks.push(ValidationCheck {
                operation: op_label,
                passed,
                message,
            });
        }
    }

    let safe_to_apply = checks.iter().all(|c| c.passed);
    Ok(ValidationReport {
        safe_to_apply,
        checks,
    })
}

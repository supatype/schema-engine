use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use super::DiffOutput;

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
pub async fn validate(_diff: &DiffOutput, _pool: &PgPool) -> Result<ValidationReport> {
    let checks = Vec::new();

    // TODO: Phase 1 — check for NULL values before SET NOT NULL,
    // check for duplicates before ADD UNIQUE, etc.

    let safe_to_apply = checks.iter().all(|c: &ValidationCheck| c.passed);
    Ok(ValidationReport { safe_to_apply, checks })
}

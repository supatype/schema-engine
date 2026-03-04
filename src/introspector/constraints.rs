use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbConstraint {
    pub table: String,
    pub name: String,
    pub constraint_type: DbConstraintType,
    pub columns: Vec<String>,
    pub foreign_table: Option<String>,
    pub foreign_columns: Option<Vec<String>>,
    pub check_expression: Option<String>,
    pub on_delete: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DbConstraintType {
    PrimaryKey,
    Unique,
    ForeignKey,
    Check,
}

pub async fn read(_pool: &PgPool, _schema: &str) -> Result<Vec<DbConstraint>> {
    // TODO: full constraint introspection
    Ok(vec![])
}

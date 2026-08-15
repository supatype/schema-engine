//! Supatype-managed object metadata (Postgres comments + naming conventions).

pub const MANAGED_PREFIX: &str = "supatype:managed";

/// Returns true when a Postgres object comment marks it as Supatype-managed.
pub fn is_managed_comment(comment: Option<&str>) -> bool {
    comment
        .map(|c| c.starts_with(MANAGED_PREFIX))
        .unwrap_or(false)
}

/// Build a `COMMENT ON` value for a managed constraint or index.
pub fn managed_comment(kind: &str, table: &str, fields: &[&str]) -> String {
    format!(
        "{MANAGED_PREFIX};kind={kind};table={table};fields={};v=1",
        fields.join(",")
    )
}

/// Postgres default name for a single-column UNIQUE constraint.
pub fn expected_unique_constraint_name(table: &str, column: &str) -> String {
    format!("{table}_{column}_key")
}

/// Default name for a model-level index (`indexes` in schema meta).
pub fn expected_model_index_name(table: &str, fields: &[String]) -> String {
    format!("{table}_{}_idx", fields.join("_"))
}

/// SQL to stamp a constraint comment (escaped single quotes in comment).
pub fn comment_on_constraint_sql(
    table: &str,
    constraint: &str,
    comment: &str,
    schema: &str,
) -> String {
    let escaped = comment.replace('\'', "''");
    format!("COMMENT ON CONSTRAINT \"{constraint}\" ON \"{schema}\".\"{table}\" IS '{escaped}';")
}

/// SQL to stamp a table comment.
///
/// The stamp is what the ownership gate reads, so adoption and creation must produce the same
/// marker — `migration.rs` writes exactly this on `CREATE TABLE`. A table adopted with a different
/// shape would stay undroppable forever, and the differ could never converge.
pub fn comment_on_table_sql(table: &str, comment: &str, schema: &str) -> String {
    let escaped = comment.replace('\'', "''");
    format!("COMMENT ON TABLE \"{schema}\".\"{table}\" IS '{escaped}';")
}

/// SQL to stamp an index comment.
pub fn comment_on_index_sql(index_name: &str, comment: &str, schema: &str) -> String {
    let escaped = comment.replace('\'', "''");
    format!("COMMENT ON INDEX \"{schema}\".\"{index_name}\" IS '{escaped}';")
}

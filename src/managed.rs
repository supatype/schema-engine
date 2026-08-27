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

/// Name for the constraint holding a column's declared bounds.
///
/// Deliberately not Postgres's own `{table}_{column}_check`: an inline `CHECK` written by anything
/// else already claims that name, and a bound Supatype manages has to be distinguishable from one it
/// merely found, or `doctor` and `adopt` cannot tell them apart.
pub fn expected_check_constraint_name(table: &str, column: &str) -> String {
    format!("{table}_{column}_bounds")
}

/// `COMMENT ON` value for a check constraint: which columns it covers, and a fingerprint of it.
///
/// `columns` is the columns the rule reads, matching what `fields=` means on an index or a unique
/// constraint. A model-level rule can name several, and one that named none would be a rule about
/// nothing.
///
/// The fingerprint is the whole point. Postgres rewrites a check expression on read-back
/// (`pg_get_constraintdef` re-quotes identifiers, re-parenthesises, moves casts), so comparing the
/// SQL text to decide whether a bound changed produces a spurious difference on every push. The
/// access-rule work needed three separate normaliser fixes for exactly that. A hash of what *we*
/// generated is not rewritten by anyone, so equality means equality.
pub fn managed_check_comment(table: &str, columns: &[&str], expression: &str) -> String {
    format!(
        "{};bounds={}",
        managed_comment("check", table, columns),
        check_fingerprint(expression)
    )
}

/// Short, stable digest of a check expression.
pub fn check_fingerprint(expression: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(expression.as_bytes());
    // 16 hex characters: collision-free at any schema size a person will write, and short enough
    // that the comment stays readable when someone runs `\d+` on the table.
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// The fingerprint recorded in a managed check comment, if it carries one.
pub fn fingerprint_of(comment: Option<&str>) -> Option<&str> {
    comment?
        .split(';')
        .find_map(|part| part.strip_prefix("bounds="))
}

/// Name for a model-level constraint, by its position in the declared list.
///
/// Positional because the rule itself has no name: the author writes an expression, not an
/// identifier. Reordering `constraints` therefore renames them, which the differ handles as a drop
/// and an add of the same expression, and the fingerprint in the comment keeps that from churning
/// when nothing actually changed.
pub fn expected_model_constraint_name(table: &str, index: usize) -> String {
    format!("{table}_check_{}", index + 1)
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

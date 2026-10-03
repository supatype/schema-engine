//! The `CHECK` expressions a field type carries, as distinct from a declared bound.
//!
//! One source for the generator, which writes them inline on the column, and for the desired
//! object set, which has to know what a push creates. Two copies of a regex drift; one does not.

/// What an `Email` column must match.
pub fn email_check_expr(column: &str) -> String {
    format!("\"{column}\" ~* '^[^@]+@[^@]+\\.[^@]+$'")
}

/// What a `URL` column must start with.
pub fn url_check_expr(column: &str) -> String {
    format!("\"{column}\" ~* '^https?://'")
}

/// The `IN` list a TEXT enum column is held to.
pub fn enum_check_expr(column: &str, values: &[String]) -> String {
    let vals = values
        .iter()
        .map(|v| format!("'{v}'"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("\"{column}\" IN ({vals})")
}

/// The states a `Publishable` model's `status` column may hold.
pub fn publishable_status_check_expr() -> &'static str {
    "\"status\" IN ('draft', 'published', 'scheduled', 'archived')"
}

/// The states a versions table's `status` column may hold.
pub fn versions_status_check_expr() -> &'static str {
    "\"status\" IN ('draft', 'published')"
}

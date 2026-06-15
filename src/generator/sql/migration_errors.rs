//! User-facing messages for common migration apply failures.

/// Turn raw Postgres / driver errors into actionable guidance when possible.
pub fn enrich_migration_error(raw: &str) -> String {
    if let Some((column, table)) = parse_null_violation(raw) {
        return format!(
            "Cannot apply required field \"{column}\" on table \"{table}\": existing rows have no value for this column.\n\n\
             What you can do:\n\
             • Make the field optional in your schema:  Optional<YourType>\n\
             • Or give it a default:  Default<YourType, value>  or  RichText<\"…\">\n\
             • Or backfill existing rows in seed/SQL, then push again\n\
             • Dev reset (drops local data):  supatype self-host compose down -v\n\n\
             Database error: {raw}"
        );
    }
    raw.to_string()
}

fn parse_null_violation(raw: &str) -> Option<(&str, &str)> {
    if let Some((col, tail)) = raw.split("column \"").nth(1)?.split_once("\" of relation \"") {
        let table = tail.split('"').next()?;
        return Some((col, table));
    }

    // Engine guard from alter_column_sql (types without automatic backfill).
    if let Some(tail) = raw.strip_prefix("Cannot set NOT NULL on ") {
        if let Some((table_col, _)) = tail.split_once(':') {
            if let Some((table, column)) = table_col.rsplit_once('.') {
                return Some((column, table));
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enriches_postgres_null_violation() {
        let raw = r#"column "someField" of relation "_global_homepage" contains null values"#;
        let msg = enrich_migration_error(raw);
        assert!(msg.contains("someField"));
        assert!(msg.contains("_global_homepage"));
        assert!(msg.contains("Optional<YourType>"));
    }

    #[test]
    fn passes_through_unknown_errors() {
        let raw = "permission denied for table foo";
        assert_eq!(enrich_migration_error(raw), raw);
    }
}

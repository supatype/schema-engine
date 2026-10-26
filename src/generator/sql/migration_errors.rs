//! User-facing messages for common migration apply failures.

use crate::differ::{DiffOutput, Operation};

/// A check constraint the push is adding or replacing, for naming the rows that breach it.
/// Built by the push from the reconcile's actions, which is where checks live now.
pub struct CheckSite<'a> {
    pub table: &'a str,
    pub constraint: &'a str,
    pub expression: &'a str,
}

/// Turn raw Postgres / driver errors into actionable guidance when possible.
///
/// `diff` lets a message name the column at fault. Postgres reports an impossible column conversion
/// as bare `cannot cast type integer to uuid`: no table, no column, no hint that a schema field is
/// what asked for it, and the diff is the only place that correspondence exists. `checks` does the
/// same for a check constraint the rows breach.
pub fn enrich_migration_error(
    raw: &str,
    diff: Option<&DiffOutput>,
    checks: &[CheckSite<'_>],
) -> String {
    if let Some((from, to)) = parse_impossible_cast(raw) {
        let site = diff.and_then(|d| find_type_change(d, from, to));
        let what = match &site {
            Some((table, column)) => format!("column \"{table}\".\"{column}\""),
            None => "a column".to_string(),
        };
        let field_hint = match &site {
            Some((table, column)) => format!(
                "• Change the field's type in your schema so it matches the column: {table}.{column} \
                 is {from} in the database\n"
            ),
            None => String::new(),
        };
        return format!(
            "Cannot convert {what} from {from} to {to}: Postgres has no cast between these types.\n\n\
             Nothing was applied: the migration runs in one transaction and rolled back.\n\n\
             What you can do:\n\
             {field_hint}\
             • Or migrate the data by hand: add a new column of the target type, backfill it, drop the \
             old one, then rename\n\
             • Or, if the column holds nothing you need, drop it in your schema, push, then re-add it \
             with the new type\n\n\
             Database error: {raw}"
        );
    }

    if let Some(constraint) = parse_check_violation(raw) {
        // Naming the table and handing over a query that finds the offending rows is the
        // difference between "your push failed" and "here is what to fix".
        let site = checks.iter().find(|c| c.constraint == constraint);
        let (what, find_them) = match site {
            Some(c) => (
                format!("\"{}\".\"{}\"", c.table, c.constraint),
                // A query the reader copies and runs, so the table is quoted as SQL quotes it.
                format!(
                    "• Find the rows that breach it:\n    SELECT * FROM {} WHERE NOT ({});\n",
                    crate::sql_quote::quote_ident(c.table),
                    c.expression
                ),
            ),
            None => (format!("the column behind \"{constraint}\""), String::new()),
        };
        return format!(
            "Cannot apply the bound on {what}: rows already in the table breach it.\n\n\
             Nothing was applied. The migration runs in one transaction and rolled back, so every \
             row is exactly as it was.\n\n\
             What you can do:\n\
             {find_them}\
             • Correct or delete those rows, then push again\n\
             • Or loosen the bound in your schema so it admits the data you already have\n\n\
             Database error: {raw}"
        );
    }

    identity_column_message(raw)
        .or_else(|| null_violation_message(raw))
        .unwrap_or_else(|| raw.to_string())
}

/// Postgres refusing a change to a column because it is an identity column (`DROP NOT NULL` on
/// one): the column's definition is at fault, never the rows, so nothing about the data is said.
fn identity_column_message(raw: &str) -> Option<String> {
    let (column, table) = column_of_relation(raw, "is an identity column")?;
    Some(format!(
        "Cannot change column \"{table}\".\"{column}\": Postgres refused the change while it is an \
         identity column. The rows are not at fault and need nothing.\n\n\
         Nothing was applied: the migration runs in one transaction and rolled back.\n\n\
         Database error: {raw}"
    ))
}

fn null_violation_message(raw: &str) -> Option<String> {
    let (column, table) = parse_null_violation(raw)?;
    Some(format!(
        "Cannot apply required field \"{column}\" on table \"{table}\": existing rows have no value for this column.\n\n\
         What you can do:\n\
         • Make the field optional in your schema:  Optional<YourType>\n\
         • Or give it a default:  Default<YourType, value>  or  RichText<\"…\">\n\
         • Or backfill existing rows in seed/SQL, then push again\n\
         • Dev reset (drops local data):  supatype self-host compose down -v\n\n\
         Database error: {raw}"
    ))
}

/// `column "c" of relation "t" <what>` → `("c", "t")`, for the error Postgres words that way.
fn column_of_relation<'a>(raw: &'a str, what: &str) -> Option<(&'a str, &'a str)> {
    let (column, tail) = raw
        .split("column \"")
        .nth(1)?
        .split_once("\" of relation \"")?;
    let (table, rest) = tail.split_once('"')?;
    rest.trim_start()
        .starts_with(what)
        .then_some((column, table))
}

/// `cannot cast type integer to uuid` → `("integer", "uuid")`.
fn parse_impossible_cast(raw: &str) -> Option<(&str, &str)> {
    let tail = raw.split("cannot cast type ").nth(1)?;
    let (from, rest) = tail.split_once(" to ")?;
    // The type name ends at the first delimiter Postgres adds after it.
    let to = rest.split(['\n', '"', ',']).next()?.trim();
    if from.is_empty() || to.is_empty() {
        return None;
    }
    Some((from.trim(), to))
}

/// The table and column whose declared conversion matches this cast failure.
///
/// Matched on the type pair rather than by parsing SQL: the migration is applied as one batch, so
/// there is no statement-level error to attribute. Two columns converting between the same pair in
/// one push are indistinguishable; the first is named, which is still incomparably better than
/// naming none.
fn find_type_change<'a>(diff: &'a DiffOutput, from: &str, to: &str) -> Option<(&'a str, &'a str)> {
    diff.operations.iter().find_map(|op| {
        let (table, column, changes) = match op {
            Operation::AlterColumn {
                table,
                column,
                changes,
                ..
            }
            | Operation::RecreateColumn {
                table,
                column,
                changes,
                ..
            } => (table, column, changes),
            _ => return None,
        };
        let type_change = changes.get("type")?;
        let from_udt = type_change.get("from_udt").and_then(|v| v.as_str())?;
        let to_pg = type_change.get("to_pg").and_then(|v| v.as_str())?;
        // `from_udt` is a pg_type name (`int4`); the error says `integer`. Compare loosely at both
        // ends so either spelling matches.
        let matches_from = same_type(from_udt, from);
        let matches_to = same_type(to_pg, to);
        (matches_from && matches_to).then_some((table.as_str(), column.as_str()))
    })
}

/// True when two Postgres type spellings name the same type.
fn same_type(a: &str, b: &str) -> bool {
    let norm = |t: &str| {
        let t = t.trim().to_ascii_lowercase();
        // Strip any modifier: `character varying(255)` and `varchar` are the same type here.
        let base = t.split('(').next().unwrap_or(&t).trim().to_string();
        match base.as_str() {
            "int4" | "integer" | "int" => "int4".to_string(),
            "int8" | "bigint" => "int8".to_string(),
            "int2" | "smallint" => "int2".to_string(),
            "bool" | "boolean" => "bool".to_string(),
            "float8" | "double precision" => "float8".to_string(),
            "float4" | "real" => "float4".to_string(),
            "varchar" | "character varying" => "varchar".to_string(),
            "bpchar" | "character" => "bpchar".to_string(),
            "timestamptz" | "timestamp with time zone" => "timestamptz".to_string(),
            "timestamp" | "timestamp without time zone" => "timestamp".to_string(),
            "numeric" | "decimal" => "numeric".to_string(),
            other => other.to_string(),
        }
    };
    norm(a) == norm(b)
}

/// The constraint named in a `check_violation`.
///
/// Postgres phrases it as `check constraint "posts_excerpt_bounds" is violated by some row` when
/// adding one, and `new row for relation "posts" violates check constraint "..."` when inserting.
/// Only the first can happen during a migration, but matching both costs nothing and stops the
/// message regressing to raw if the wording is met elsewhere.
fn parse_check_violation(raw: &str) -> Option<&str> {
    let marker = "check constraint \"";
    let start = raw.find(marker)? + marker.len();
    let rest = &raw[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// The column and table of a NULL violation: Postgres's `column "c" of relation "t" contains null
/// values`, or the engine's own guard before a `SET NOT NULL` (`Cannot set NOT NULL on t.c: ...`).
/// Nothing else that names a column of a relation is one.
fn parse_null_violation(raw: &str) -> Option<(&str, &str)> {
    if let Some(found) = column_of_relation(raw, "contains null values") {
        return Some(found);
    }
    let tail = raw.split("Cannot set NOT NULL on ").nth(1)?;
    let (table_col, _) = tail.split_once(':')?;
    let (table, column) = table_col.rsplit_once('.')?;
    Some((column, table))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_the_column_behind_an_impossible_cast() {
        // Postgres says only `cannot cast type integer to uuid`: no table, no column, no hint that a
        // schema field asked for it. On a database with tables Supatype did not create, that is
        // exactly when you need to know which one.
        let diff = DiffOutput {
            operations: vec![Operation::AlterColumn {
                table: "post".into(),
                column: "id".into(),
                field: Box::new(crate::parser::ast::FieldAst::Uuid(
                    crate::parser::ast::ScalarFieldAst {
                        pg_type: "UUID".into(),
                        ..Default::default()
                    },
                )),
                changes: serde_json::json!({ "type": { "from_udt": "int4", "to_pg": "UUID" } }),
                dependencies: Vec::new(),
                risk: crate::differ::Risk::Destructive,
                warning: None,
            }],
            summary: crate::differ::DiffSummary {
                safe: 0,
                cautious: 0,
                destructive: 1,
                is_destructive: true,
            },
            warnings: vec![],
            unmanaged_model_tables: vec![],
            field_masking: crate::differ::FieldMaskingTier::None,
            field_view_plan: Vec::new(),
            rename_candidates: Vec::new(),
            rewrites: Vec::new(),
        };

        let msg = enrich_migration_error("cannot cast type integer to uuid", Some(&diff), &[]);
        assert!(
            msg.contains("\"post\".\"id\""),
            "the column is not named: {msg}"
        );
        assert!(
            msg.contains("integer") && msg.contains("uuid"),
            "the types are not named: {msg}"
        );
        assert!(
            msg.contains("rolled back"),
            "the message must say nothing was applied: {msg}"
        );
        assert!(
            msg.contains("post.id"),
            "the remedy must name the field to change: {msg}"
        );
    }

    #[test]
    fn matches_type_spellings_across_the_pg_catalog_and_the_error_text() {
        // `from_udt` is a pg_type name (`int4`); the error says `integer`. Either spelling must match,
        // or the column silently goes unnamed.
        assert!(same_type("int4", "integer"));
        assert!(same_type("timestamptz", "timestamp with time zone"));
        assert!(same_type("character varying(255)", "varchar"));
        assert!(!same_type("int4", "uuid"));
    }

    #[test]
    fn falls_back_to_the_raw_error_when_no_operation_matches() {
        // Better a vaguer message than a wrong column.
        let msg = enrich_migration_error("cannot cast type integer to uuid", None, &[]);
        assert!(msg.contains("a column"), "{msg}");
        assert!(msg.contains("cannot cast type integer to uuid"), "{msg}");
    }

    #[test]
    fn enriches_postgres_null_violation() {
        let raw = r#"column "someField" of relation "_global_homepage" contains null values"#;
        let msg = enrich_migration_error(raw, None, &[]);
        assert!(msg.contains("someField"));
        assert!(msg.contains("_global_homepage"));
        assert!(msg.contains("Optional<YourType>"));
    }

    /// Postgres refuses `DROP NOT NULL` on an identity column with an error that names the column
    /// and its table the way a NULL violation does. Read as one, it sent the user to backfill rows
    /// that were fine.
    #[test]
    fn an_identity_column_error_is_not_read_as_missing_values() {
        let raw = r#"column "seq" of relation "lines" is an identity column"#;
        let msg = enrich_migration_error(raw, None, &[]);
        assert!(!msg.contains("no value"), "{msg}");
        assert!(!msg.contains("backfill"), "{msg}");
        assert!(msg.contains("\"lines\".\"seq\""), "{msg}");
        assert!(msg.contains("identity column"), "{msg}");
        assert!(msg.contains("rolled back"), "{msg}");
    }

    /// The engine's own guard before a `SET NOT NULL` names no `column "..."`, and is still read.
    #[test]
    fn enriches_the_engines_not_null_guard() {
        let raw = "Cannot set NOT NULL on posts.title: NULL values exist.";
        let msg = enrich_migration_error(raw, None, &[]);
        assert!(
            msg.contains("required field \"title\" on table \"posts\""),
            "{msg}"
        );
    }

    /// Only Postgres's own NULL violation wording is read as one.
    #[test]
    fn other_errors_naming_a_column_are_not_read_as_missing_values() {
        let raw = r#"column "seq" of relation "lines" already exists"#;
        assert_eq!(enrich_migration_error(raw, None, &[]), raw);
    }

    #[test]
    fn passes_through_unknown_errors() {
        let raw = "permission denied for table foo";
        assert_eq!(enrich_migration_error(raw, None, &[]), raw);
    }

    #[test]
    fn names_the_rows_that_block_a_tightened_bound() {
        let checks = [CheckSite {
            table: "posts",
            constraint: "posts_excerpt_bounds",
            expression: "char_length(\"excerpt\") <= 80",
        }];
        let raw = "ERROR: check constraint \"posts_excerpt_bounds\" of relation \"posts\" is violated by some row";

        let message = enrich_migration_error(raw, None, &checks);

        // The table, not just a generated constraint name.
        assert!(
            message.contains("\"posts\".\"posts_excerpt_bounds\""),
            "{message}"
        );
        // A query they can run, with the actual bound in it.
        assert!(
            message.contains("SELECT * FROM \"posts\" WHERE NOT (char_length(\"excerpt\") <= 80);"),
            "{message}"
        );
        // And the reassurance that matters most on a failed migration.
        assert!(message.contains("rolled back"), "{message}");
    }

    #[test]
    fn falls_back_gracefully_when_the_constraint_is_not_ours() {
        let raw = "ERROR: check constraint \"legacy_manual_check\" of relation \"posts\" is violated by some row";
        let message = enrich_migration_error(raw, None, &[]);
        assert!(message.contains("legacy_manual_check"), "{message}");
        // No fabricated query, because we do not know the expression.
        assert!(!message.contains("SELECT * FROM"), "{message}");
    }
}

//! A column's DEFAULT, converged on a table that already exists.
//!
//! The default a field declares is rendered as `CREATE TABLE` renders it and compared with the one
//! the database deparses. Postgres writes the same default back in its own spelling (`'a'::text`
//! for `'a'`, `now()` for `NOW()`, `'-1'::integer` for `-1`), so both sides are reduced to a
//! comparable form first. Only the field kinds whose default `CREATE TABLE` writes through the one
//! renderer are compared; a serial, identity or generated column's default is the database's, and a
//! rich text or localized default is written by an expression the comparison could not settle.

use crate::generator::sql::migration::render_default;
use crate::introspector::tables::DbColumn;
use crate::parser::ast::{scalar_of, FieldAst};
use crate::sql_quote::quote_literal;
use serde_json::{json, Value};

/// The `default` change for `field` against `db_col`, when the two differ.
///
/// `{"from": <the database's default or null>, "to": <the declared default or null>}`: `to` is what
/// the migration sets (null drops it), `from` what a rollback puts back.
pub(crate) fn default_change(field: &FieldAst, db_col: &DbColumn) -> Option<Value> {
    let declared = declared_default(field)?;
    let live = db_col.default.as_deref();
    if live.is_some_and(|d| d.to_ascii_lowercase().starts_with("nextval(")) {
        return None;
    }
    let same = match (declared.as_deref(), live) {
        (None, None) => true,
        (Some(a), Some(b)) => comparable(a) == comparable(b),
        _ => false,
    };
    (!same).then(|| json!({ "from": live, "to": declared }))
}

/// `Some(default)` for a field whose default is compared (`Some(None)` when it declares none),
/// `None` for a field whose default is the database's or not comparable.
fn declared_default(field: &FieldAst) -> Option<Option<String>> {
    if let FieldAst::Enum(f) = field {
        return Some(f.default.as_deref().map(quote_literal));
    }
    if matches!(
        field,
        FieldAst::Serial(_) | FieldAst::BigSerial(_) | FieldAst::RichText(_)
    ) {
        return None;
    }
    let scalar = scalar_of(field)?;
    let filled = scalar.identity.is_some() || scalar.auto_increment || scalar.generated.is_some();
    if filled || scalar.localized {
        return None;
    }
    Some(scalar.default.as_ref().map(render_default))
}

/// `sql` without casts, whitespace, case, quotes around a number or wrapping parentheses.
fn comparable(sql: &str) -> String {
    let mut out: String = strip_casts(&sql.to_ascii_lowercase())
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    while out.starts_with('(') && out.ends_with(')') && balanced(&out[1..out.len() - 1]) {
        out = out[1..out.len() - 1].to_string();
    }
    let unquoted = out.trim_matches('\'');
    if out.starts_with('\'') && unquoted.parse::<f64>().is_ok() {
        return unquoted.to_string();
    }
    out
}

/// `sql` with every `::type` cast removed, multi-word, quoted, sized and array types included.
fn strip_casts(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut rest = sql;
    while let Some(at) = rest.find("::") {
        out.push_str(&rest[..at]);
        rest = &rest[at + 2..];
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || " _.\"[](),".contains(c)))
            .unwrap_or(rest.len());
        rest = &rest[cast_len(&rest[..end])..];
    }
    out.push_str(rest);
    out
}

/// How much of `tail` is the type name: up to a `)` or `,` that is not part of a size.
fn cast_len(tail: &str) -> usize {
    let mut depth = 0i32;
    for (i, c) in tail.char_indices() {
        match c {
            '(' => depth += 1,
            ')' if depth == 0 => return i,
            ')' => depth -= 1,
            ',' if depth == 0 => return i,
            _ => {}
        }
    }
    tail.len()
}

/// Whether every parenthesis in `s` closes, so stripping a pair around it keeps it whole.
fn balanced(s: &str) -> bool {
    let mut depth = 0i32;
    for c in s.chars() {
        depth += match c {
            '(' => 1,
            ')' => -1,
            _ => 0,
        };
        if depth < 0 {
            return false;
        }
    }
    depth == 0
}

#[cfg(test)]
mod tests {
    use super::comparable;

    #[test]
    fn postgres_spellings_compare_equal_to_the_declared_ones() {
        let pairs = [
            ("'hello'", "'hello'::text"),
            ("NOW()", "now()"),
            ("-1", "'-1'::integer"),
            ("0", "'0'::double precision"),
            ("upper('x')", "upper('x'::text)"),
            ("_supatype.jwt_uid()", "_supatype.jwt_uid()"),
            ("'draft'", "'draft'::character varying(20)"),
            ("'{}'", "'{}'::text[]"),
        ];
        for (declared, live) in pairs {
            assert_eq!(
                comparable(declared),
                comparable(live),
                "{declared} vs {live}"
            );
        }
        assert_ne!(comparable("'hello'"), comparable("'bye'::text"));
    }
}

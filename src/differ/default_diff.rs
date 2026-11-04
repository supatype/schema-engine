//! A column's DEFAULT, converged on a table that already exists.
//!
//! The default a field declares is rendered as `CREATE TABLE` renders it and compared with the one
//! the database deparses. Postgres writes the same default back in its own spelling (`'a'::text`
//! for `'a'`, `now()` for `NOW()`, `'-1'::integer` for `-1`, `jsonb` with its keys reordered), so
//! both sides are reduced to a comparable form first. Only the field kinds whose default
//! `CREATE TABLE` writes through the one renderer are compared; a serial, identity or generated
//! column's default is the database's, and a rich text or localized default is written by an
//! expression the comparison could not settle. A geography default is written as an
//! `ST_GeogFromText` call so that it reads back as written: a geography literal would read back in
//! its binary form, which no spelling of the declared text matches.

use crate::generator::sql::extensions::EXTENSIONS_SCHEMA;
use crate::generator::sql::migration::declared_default_sql;
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
        (Some(a), Some(b)) => comparable(a) == comparable(b) || same_jsonb(a, b),
        _ => false,
    };
    (!same).then(|| json!({ "from": live, "to": declared }))
}

/// `Some(default)` for a field whose default is compared (`Some(None)` when it declares none),
/// `None` for a field whose default is the database's or not comparable.
fn declared_default(field: &FieldAst) -> Option<Option<String>> {
    match field {
        FieldAst::Enum(f) => Some(f.default.as_deref().map(quote_literal)),
        FieldAst::Serial(_) | FieldAst::BigSerial(_) | FieldAst::RichText(_) => None,
        FieldAst::Json(f) | FieldAst::Button(f) if f.localized => None,
        FieldAst::Json(_)
        | FieldAst::Button(_)
        | FieldAst::Decimal(_)
        | FieldAst::Array(_)
        | FieldAst::Vector(_)
        | FieldAst::Geo(_) => Some(declared_default_sql(field)),
        other => {
            let scalar = scalar_of(other)?;
            let filled =
                scalar.identity.is_some() || scalar.auto_increment || scalar.generated.is_some();
            if filled || scalar.localized {
                return None;
            }
            Some(declared_default_sql(other))
        }
    }
}

/// Whether two defaults are the same `jsonb` value, however each spells it: Postgres stores a
/// `jsonb` object with its keys sorted and spaced, which [`comparable`] cannot see past.
fn same_jsonb(declared: &str, live: &str) -> bool {
    match (jsonb_literal(declared), jsonb_literal(live)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// The value of a `'<json text>'::jsonb` literal, or None for any other SQL.
fn jsonb_literal(sql: &str) -> Option<Value> {
    let quoted = sql.trim().strip_suffix("::jsonb")?;
    let text = quoted.strip_prefix('\'')?.strip_suffix('\'')?;
    serde_json::from_str(&text.replace("''", "'")).ok()
}

/// `sql` without casts, whitespace, case, quotes around a number, wrapping parentheses or the
/// extensions schema. Generated SQL never names that schema (`generator::sql::extensions`), and
/// Postgres names it when it reads back a call to an extension's function, such as
/// `extensions.st_geogfromtext(...)`, from outside the push's search path.
fn comparable(sql: &str) -> String {
    let unqualified = without_extensions_schema(&sql.to_ascii_lowercase());
    let mut out: String = strip_casts(&unqualified)
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

/// `sql` without the extensions schema where it qualifies a name (`extensions.st_geogfromtext`).
/// A string literal is the value itself, so one that mentions the schema keeps it, and so does a
/// name that only ends in it (`myextensions.f`).
fn without_extensions_schema(sql: &str) -> String {
    let qualifier = format!("{EXTENSIONS_SCHEMA}.");
    let mut out = String::with_capacity(sql.len());
    let mut in_literal = false;
    let mut rest = sql;
    while let Some(c) = rest.chars().next() {
        let starts_name = !out.ends_with(|p: char| p.is_ascii_alphanumeric() || "_.\"".contains(p));
        if !in_literal && starts_name && rest.starts_with(&qualifier) {
            rest = &rest[qualifier.len()..];
            continue;
        }
        // A doubled quote inside a literal toggles twice, so it stays inside.
        in_literal ^= c == '\'';
        out.push(c);
        rest = &rest[c.len_utf8()..];
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
            (
                "ST_GeogFromText('SRID=4326;POINT(1 2)')",
                "extensions.st_geogfromtext('SRID=4326;POINT(1 2)'::text)",
            ),
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

    /// The extensions schema is dropped only where it qualifies a name, never from inside a
    /// string, where it is the value itself.
    #[test]
    fn a_string_naming_the_extensions_schema_keeps_it() {
        assert_ne!(
            comparable("'see extensions.foo'"),
            comparable("'see foo'::text")
        );
        assert_eq!(
            comparable("'see extensions.foo'"),
            comparable("'see extensions.foo'::text")
        );
        assert_ne!(
            comparable("myextensions.f()"),
            comparable("myf()"),
            "only the schema itself is a qualifier"
        );
    }
}

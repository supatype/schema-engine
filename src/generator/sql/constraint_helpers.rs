//! Immutable helper functions that column `CHECK` constraints call.
//!
//! Two constraint shapes cannot be written as a bare expression:
//!
//! * **Rich text.** The column is a lexical document in JSONB, so "at most 320 characters" means
//!   the length of its plain text, which needs an extractor.
//! * **Localized columns.** These are JSONB keyed by locale, so a bound applies per locale. A
//!   `CHECK` may not contain a subquery, but it may call a function, and a function may iterate its
//!   own argument. That distinction is the whole reason localized fields could not be constrained
//!   before, and it is not a property of localization.
//!
//! Every function is `IMMUTABLE PARALLEL SAFE STRICT` and takes **one** bound. Two-sided helpers
//! were rejected: `STRICT` means a `NULL` argument yields `NULL`, so a one-sided bound passed
//! through a two-sided helper returns `NULL`, and a `CHECK` that evaluates to `NULL` passes. A
//! silently disabled constraint is the failure this whole area already had once.
//!
//! `STRICT` is load-bearing in the other direction too: a `NULL` column is absent, not out of
//! bounds, which is how a bare `char_length(col) <= n` behaves and therefore what callers expect.

/// Schema holding the helpers. Every call site is schema-qualified, so a restore that runs with an
/// empty `search_path` still resolves them.
pub const HELPER_SCHEMA: &str = "_supatype";

/// `CREATE OR REPLACE` for every helper, safe to run on each push.
///
/// Emitted **before** table DDL, unlike triggers: a `CHECK` that calls a function is validated at
/// `CREATE TABLE` time, so the function has to exist first.
pub fn generate() -> String {
    format!(
        "-- Constraint helper functions (idempotent)\n\
         CREATE SCHEMA IF NOT EXISTS {HELPER_SCHEMA};\n\n\
         {richtext}\n\n\
         {localized}\n",
        richtext = richtext_text(),
        localized = localized_helpers(),
    )
}

/// Plain text of a lexical document, for bounding rich text by what a reader actually sees.
///
/// `jsonb_path_query` walks to every `text` member at any depth, which is what makes this one
/// expression rather than a recursive plpgsql walk, and lets the function stay `IMMUTABLE` and
/// therefore legal inside a `CHECK` and usable in an expression index.
fn richtext_text() -> String {
    format!(
        "CREATE OR REPLACE FUNCTION {HELPER_SCHEMA}.richtext_text(v jsonb)\n\
         RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT AS $fn$\n\
         \x20 SELECT coalesce(string_agg(t, ''), '')\n\
         \x20 FROM jsonb_path_query(v, 'strict $.**.text ? (@.type() == \"string\")') AS q(j),\n\
         \x20      LATERAL (SELECT j #>> '{{}}') AS s(t)\n\
         $fn$;"
    )
}

/// One function per (measure, direction). Generated rather than hand-written so a new measure
/// cannot arrive with only one of its two directions.
fn localized_helpers() -> String {
    const MEASURES: [(&str, &str, &str); 5] = [
        // (name, argument type, expression over each locale's value)
        ("length", "integer", "char_length(value)"),
        ("richtext_length", "integer", "char_length({schema}.richtext_text(value::jsonb))"),
        ("items", "integer", "jsonb_array_length(value::jsonb)"),
        ("number", "numeric", "value::numeric"),
        // A localized temporal value is one ISO string per locale. Comparing through `timestamptz`
        // keeps this to a single helper for every date and time column: a date string widens
        // cleanly, and the bound was already validated as ISO-8601 at push time.
        ("temporal", "text", "value::timestamptz"),
    ];

    let mut out = Vec::new();
    for (name, arg_type, measure) in MEASURES {
        for (direction, comparison) in [("max", "<="), ("min", ">=")] {
            let expr = measure.replace("{schema}", HELPER_SCHEMA);
            // The temporal helper takes its bound as text so one function serves every date and
            // time column; it casts both sides rather than trusting the argument's declared type.
            let rhs = if name == "temporal" { "n::timestamptz" } else { "n" };
            out.push(format!(
                "CREATE OR REPLACE FUNCTION {HELPER_SCHEMA}.localized_{name}_{direction}(v jsonb, n {arg_type})\n\
                 RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT AS $fn$\n\
                 \x20 SELECT bool_and({expr} {comparison} {rhs}) FROM jsonb_each_text(v)\n\
                 $fn$;"
            ));
        }
    }
    out.join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_helper_is_immutable_and_strict() {
        let sql = generate();
        let count = sql.matches("CREATE OR REPLACE FUNCTION").count();
        assert_eq!(
            count,
            sql.matches("IMMUTABLE PARALLEL SAFE STRICT").count(),
            "a helper that is not IMMUTABLE cannot be called from a CHECK, and one that is not \
             STRICT would treat a NULL column as out of bounds:\n{sql}"
        );
        // richtext_text plus five measures in two directions.
        assert_eq!(count, 11, "unexpected helper count:\n{sql}");
    }

    #[test]
    fn every_helper_is_schema_qualified() {
        let sql = generate();
        for line in sql.lines().filter(|l| l.contains("CREATE OR REPLACE FUNCTION")) {
            assert!(
                line.contains(&format!("FUNCTION {HELPER_SCHEMA}.")),
                "an unqualified helper stops resolving when search_path is empty, which is what a \
                 restore does: {line}"
            );
        }
    }

    #[test]
    fn both_directions_exist_for_every_measure() {
        let sql = generate();
        for measure in ["length", "richtext_length", "items", "number", "temporal"] {
            for direction in ["max", "min"] {
                assert!(
                    sql.contains(&format!("localized_{measure}_{direction}(")),
                    "missing localized_{measure}_{direction}"
                );
            }
        }
    }
}

//! A function's key, built from its declared signature the way the catalog builds it live.
//!
//! The live side (`DbFunction::identity_types`) writes each input argument's type with built-ins
//! as `format_type` writes them and everything else schema-qualified, no argument names, no
//! defaults: `text, timestamp with time zone, public.posts`. This produces the same string from
//! the argument list the generator wrote, so a desired function and a live one meet on one key
//! with no database in between. `tests/statement_attribution_tests.rs` proves it for every
//! function every pushable fixture creates; a type this module spells differently from Postgres
//! fails there by name.

/// `name(type, type)` for a function declared as `name(declared_args)`.
///
/// `default_schema` qualifies a user type written bare. The generator always qualifies the row
/// types it passes, so this is a safety net rather than a path it takes.
pub fn function_key(default_schema: &str, name: &str, declared_args: &str) -> String {
    let types: Vec<String> = split_top_level(declared_args)
        .iter()
        .filter_map(|arg| argument_type(default_schema, arg))
        .collect();
    format!("{name}({})", types.join(", "))
}

/// Split on commas outside parentheses and double quotes.
fn split_top_level(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut quoted = false;
    let mut current = String::new();
    for c in s.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                current.push(c);
            }
            '(' if !quoted => {
                depth += 1;
                current.push(c);
            }
            ')' if !quoted => {
                depth = depth.saturating_sub(1);
                current.push(c);
            }
            ',' if !quoted && depth == 0 => {
                out.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

/// Whitespace-separated tokens, where a double-quoted identifier is one token.
fn tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                current.push(c);
            }
            c if c.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// The first word of each multi-word built-in type. An argument whose first token is one of
/// these has no name; anything else in first position with more tokens after it is the name.
const MULTI_WORD_TYPE_HEADS: &[&str] = &["timestamp", "time", "double", "character", "bit"];

/// The canonical type of one declared argument, or `None` for an `OUT` argument, which is not
/// part of the identity.
fn argument_type(default_schema: &str, arg: &str) -> Option<String> {
    let mut toks = tokens(arg);
    // Everything from `DEFAULT` or `=` on is the default value, which the identity leaves out.
    if let Some(i) = toks
        .iter()
        .position(|t| t.eq_ignore_ascii_case("DEFAULT") || t == "=")
    {
        toks.truncate(i);
    }
    let mode = toks
        .first()
        .map(|t| t.to_ascii_uppercase())
        .filter(|t| matches!(t.as_str(), "IN" | "OUT" | "INOUT" | "VARIADIC"));
    if let Some(mode) = mode {
        toks.remove(0);
        if mode == "OUT" {
            return None;
        }
    }
    if toks.len() > 1 && !MULTI_WORD_TYPE_HEADS.contains(&toks[0].to_ascii_lowercase().as_str()) {
        toks.remove(0);
    }
    if toks.is_empty() {
        return None;
    }
    Some(canonical_type(default_schema, &toks.join(" ")))
}

/// `format_type`'s spelling of a type the generator may write.
fn canonical_type(default_schema: &str, declared: &str) -> String {
    let mut text = declared.trim().to_string();
    let mut dims = 0usize;
    while let Some(stripped) = text.strip_suffix("[]") {
        text = stripped.trim_end().to_string();
        dims += 1;
    }
    // A type modifier (`varchar(32)`, `numeric(10, 2)`) is not part of the identity.
    if let Some(i) = text.find('(') {
        text.truncate(i);
        text = text.trim_end().to_string();
    }
    let parts: Vec<String> = split_identifier(&text);
    let base = match parts.as_slice() {
        [one] => {
            let lower = one.to_ascii_lowercase();
            match builtin(&lower) {
                Some(canonical) => canonical.to_string(),
                None => format!(
                    "{}.{}",
                    quote_if_needed(default_schema),
                    quote_if_needed(one)
                ),
            }
        }
        [schema, name] => format!("{}.{}", quote_if_needed(schema), quote_if_needed(name)),
        _ => text,
    };
    format!("{base}{}", "[]".repeat(dims))
}

/// `"a"."b"`, `a.b`, `"a"` or `a` into its unquoted parts. A bare multi-word built-in
/// (`timestamp with time zone`) is one part.
fn split_identifier(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '"' => quoted = !quoted,
            '.' if !quoted => parts.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    parts.push(current);
    parts
}

fn quote_if_needed(ident: &str) -> String {
    let simple = !ident.is_empty()
        && ident
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && !ident.chars().next().is_some_and(|c| c.is_ascii_digit());
    if simple {
        ident.to_string()
    } else {
        format!("\"{}\"", ident.replace('"', "\"\""))
    }
}

/// The `pg_catalog` types by every spelling the generator uses, to `format_type`'s spelling.
/// A name not listed here is a user type.
fn builtin(lower: &str) -> Option<&'static str> {
    Some(match lower {
        "text" => "text",
        "jsonb" => "jsonb",
        "json" => "json",
        "uuid" => "uuid",
        "boolean" | "bool" => "boolean",
        "integer" | "int" | "int4" => "integer",
        "bigint" | "int8" => "bigint",
        "smallint" | "int2" => "smallint",
        "numeric" | "decimal" => "numeric",
        "real" | "float4" => "real",
        "double precision" | "float8" => "double precision",
        "timestamptz" | "timestamp with time zone" => "timestamp with time zone",
        "timestamp" | "timestamp without time zone" => "timestamp without time zone",
        "timetz" | "time with time zone" => "time with time zone",
        "time" | "time without time zone" => "time without time zone",
        "date" => "date",
        "interval" => "interval",
        "bytea" => "bytea",
        "inet" => "inet",
        "character varying" | "varchar" => "character varying",
        "character" | "char" | "bpchar" => "character",
        "name" => "name",
        "oid" => "oid",
        "regclass" => "regclass",
        "regprocedure" => "regprocedure",
        "tsvector" => "tsvector",
        "tsquery" => "tsquery",
        "anyelement" => "anyelement",
        "anyarray" => "anyarray",
        "record" => "record",
        "void" => "void",
        "trigger" => "trigger",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_arguments_lose_their_names_and_aliases_become_format_type_spellings() {
        assert_eq!(
            function_key(
                "public",
                "schedule_publish",
                "text, text, timestamptz, integer, text[]"
            ),
            "schedule_publish(text, text, timestamp with time zone, integer, text[])"
        );
        assert_eq!(
            function_key("public", "localized_length_max", "v jsonb, n integer"),
            "localized_length_max(jsonb, integer)"
        );
        assert_eq!(
            function_key("public", "preview_epoch", ""),
            "preview_epoch()"
        );
        assert_eq!(
            function_key(
                "public",
                "h",
                "n int, tags VARCHAR(32)[], at timestamp with time zone DEFAULT now()"
            ),
            "h(integer, character varying[], timestamp with time zone)"
        );
    }

    #[test]
    fn row_types_are_schema_qualified_and_out_arguments_are_not_identity() {
        assert_eq!(
            function_key("public", "can_read_page", "\"page\" \"public\".\"page\""),
            "can_read_page(public.page)"
        );
        assert_eq!(
            function_key("public", "f", "p things, OUT total integer, INOUT n bigint"),
            "f(public.things, bigint)"
        );
        assert_eq!(
            function_key("public", "g", "x \"Mixed\".\"Case\""),
            "g(\"Mixed\".\"Case\")"
        );
    }
}

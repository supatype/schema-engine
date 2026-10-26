//! A function's key, built from its declared signature the way the catalog builds it live.
//!
//! The live side (`DbFunction::identity_types`) writes each input argument's type with
//! `pg_catalog` types as `format_type` writes them and everything else schema-qualified, no
//! argument names, no defaults: `text, timestamp with time zone, public.posts`. This produces the
//! same string from the argument list the generator wrote, so a desired function and a live one
//! meet on one key with no database in between.
//!
//! The rule is closed, not an enumeration of types. The generator writes `pg_catalog` types bare
//! and qualifies every other type it passes (a model's row type is `"public"."posts"`), so a bare
//! name is a built-in and passes through unchanged except for the few spellings `format_type`
//! rewrites (`int` to `integer`, `timestamptz` to `timestamp with time zone`), and a qualified name
//! is kept qualified. `tests/statement_attribution_tests.rs` proves the result against the catalog
//! for every function every pushable fixture creates.

/// `name(type, type)` for a function declared as `name(declared_args)`.
pub fn function_key(name: &str, declared_args: &str) -> String {
    let types: Vec<String> = split_outside_quotes(declared_args, |c, depth| c == ',' && depth == 0)
        .iter()
        .filter_map(|arg| argument_type(arg))
        .collect();
    format!("{name}({})", types.join(", "))
}

/// Split `s` wherever `is_separator(char, paren_depth)` holds outside double quotes, dropping
/// empty pieces. Serves both the comma between arguments and the whitespace between tokens.
fn split_outside_quotes(s: &str, is_separator: impl Fn(char, usize) -> bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    let mut quoted = false;
    for c in s.chars() {
        if c == '"' {
            quoted = !quoted;
        } else if !quoted {
            match c {
                '(' => depth += 1,
                ')' => depth = depth.saturating_sub(1),
                _ if is_separator(c, depth) => {
                    if !current.trim().is_empty() {
                        out.push(std::mem::take(&mut current));
                    }
                    continue;
                }
                _ => {}
            }
        }
        current.push(c);
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

/// The first word of each multi-word built-in type. An argument whose first token is one of
/// these has no name; anything else in first position with more tokens after it is the name.
const MULTI_WORD_TYPE_HEADS: &[&str] = &["timestamp", "time", "double", "character", "bit"];

/// The canonical type of one declared argument, or `None` for an `OUT` argument, which is not
/// part of the identity.
fn argument_type(arg: &str) -> Option<String> {
    let mut toks = split_outside_quotes(arg, |c, _| c.is_whitespace());
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
    Some(canonical_type(&toks.join(" ")))
}

/// `format_type`'s spelling of a declared type.
fn canonical_type(declared: &str) -> String {
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
    let parts = split_identifier(&text);
    let base = match parts.as_slice() {
        [bare] => {
            let lower = bare.to_ascii_lowercase();
            format_type_spelling(&lower).unwrap_or(&lower).to_string()
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

/// `quote_ident`'s rule: bare when the name is a plain lowercase identifier, quoted otherwise.
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

/// The spellings `format_type` rewrites: the SQL-standard names and their aliases. Every other
/// `pg_catalog` type name is already its own `format_type` spelling.
fn format_type_spelling(lower: &str) -> Option<&'static str> {
    Some(match lower {
        "bool" => "boolean",
        "int" | "int4" => "integer",
        "int8" => "bigint",
        "int2" => "smallint",
        "decimal" => "numeric",
        "float4" => "real",
        "float8" => "double precision",
        "timestamptz" => "timestamp with time zone",
        "timestamp" => "timestamp without time zone",
        "timetz" => "time with time zone",
        "time" => "time without time zone",
        "varchar" => "character varying",
        "char" | "bpchar" => "character",
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
                "schedule_publish",
                "text, text, timestamptz, integer, text[]"
            ),
            "schedule_publish(text, text, timestamp with time zone, integer, text[])"
        );
        assert_eq!(
            function_key("localized_length_max", "v jsonb, n integer"),
            "localized_length_max(jsonb, integer)"
        );
        assert_eq!(function_key("preview_epoch", ""), "preview_epoch()");
        assert_eq!(
            function_key(
                "h",
                "n int, tags VARCHAR(32)[], at timestamp with time zone DEFAULT now()"
            ),
            "h(integer, character varying[], timestamp with time zone)"
        );
    }

    #[test]
    fn a_bare_name_passes_through_as_a_built_in_and_a_qualified_one_stays_qualified() {
        // Not in any alias table, and must not be: `format_type` writes these as they are.
        assert_eq!(
            function_key("f", "r int4range, w tstzrange, p point"),
            "f(int4range, tstzrange, point)"
        );
        assert_eq!(
            function_key("can_read_page", "\"page\" \"public\".\"page\""),
            "can_read_page(public.page)"
        );
        assert_eq!(
            function_key("f", "p public.things, OUT total integer, INOUT n bigint"),
            "f(public.things, bigint)"
        );
        assert_eq!(
            function_key("g", "x \"Mixed\".\"Case\""),
            "g(\"Mixed\".\"Case\")"
        );
    }
}

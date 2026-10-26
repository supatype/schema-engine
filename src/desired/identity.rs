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
    // Whitespace inside a modifier (`numeric(10, 2)`) does not separate tokens.
    let mut toks = split_outside_quotes(arg, |c, depth| c.is_whitespace() && depth == 0);
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
    // `timestamp(3) with time zone`: the head is compared without its modifier.
    let head = toks
        .first()
        .map(|t| t.split('(').next().unwrap_or_default().to_ascii_lowercase());
    if toks.len() > 1 && !head.is_some_and(|h| MULTI_WORD_TYPE_HEADS.contains(&h.as_str())) {
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
    // A type modifier (`varchar(32)`, `numeric(10, 2)`, the `(3)` of `timestamp(3) with time
    // zone`) is not part of the identity, but the words after it are. `float(p)` is the one
    // modifier that picks the type: `real` up to 24 bits, `double precision` above.
    let (unmodified, modifier) = without_modifiers(&text);
    let parts = split_identifier(&unmodified);
    let base = match parts.as_slice() {
        [bare] => {
            let lower = bare.split_whitespace().collect::<Vec<_>>().join(" ");
            let lower = lower.to_ascii_lowercase();
            if lower == "float" && modifier.is_some_and(|p| p <= 24) {
                "real".to_string()
            } else {
                format_type_spelling(&lower).unwrap_or(&lower).to_string()
            }
        }
        [schema, name] => format!("{}.{}", quote_if_needed(schema), quote_if_needed(name)),
        _ => unmodified,
    };
    format!("{base}{}", "[]".repeat(dims))
}

/// `declared` with every parenthesised modifier outside double quotes taken out, and the first
/// modifier's leading number (the `p` of `float(p)`), if it has one.
fn without_modifiers(declared: &str) -> (String, Option<u32>) {
    let mut out = String::new();
    let mut first: Option<String> = None;
    let mut current = String::new();
    let mut depth = 0usize;
    let mut quoted = false;
    for c in declared.chars() {
        match c {
            '"' if depth == 0 => {
                quoted = !quoted;
                out.push(c);
            }
            '(' if !quoted => {
                depth += 1;
            }
            ')' if !quoted && depth > 0 => {
                depth -= 1;
                if depth == 0 && first.is_none() {
                    first = Some(std::mem::take(&mut current));
                }
            }
            _ if depth > 0 => current.push(c),
            _ => out.push(c),
        }
    }
    let modifier = first.and_then(|m| m.split(',').next()?.trim().parse().ok());
    (out.trim().to_string(), modifier)
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

/// Every keyword `quote_ident` quotes: the ones Postgres does not class as unreserved
/// (`select word from pg_get_keywords() where catcode <> 'U'` on Postgres 17), sorted for
/// binary search.
///
/// This list is Postgres 17's, the baseline `supatype/postgres` image. Postgres adds keywords
/// between majors, and a function keyed on a type named by a new one would no longer match the
/// catalog's `identity_types`: re-run that query and update this list whenever the baseline
/// Postgres version moves.
const QUOTED_KEYWORDS: &[&str] = &[
    "all",
    "analyse",
    "analyze",
    "and",
    "any",
    "array",
    "as",
    "asc",
    "asymmetric",
    "authorization",
    "between",
    "bigint",
    "binary",
    "bit",
    "boolean",
    "both",
    "case",
    "cast",
    "char",
    "character",
    "check",
    "coalesce",
    "collate",
    "collation",
    "column",
    "concurrently",
    "constraint",
    "create",
    "cross",
    "current_catalog",
    "current_date",
    "current_role",
    "current_schema",
    "current_time",
    "current_timestamp",
    "current_user",
    "dec",
    "decimal",
    "default",
    "deferrable",
    "desc",
    "distinct",
    "do",
    "else",
    "end",
    "except",
    "exists",
    "extract",
    "false",
    "fetch",
    "float",
    "for",
    "foreign",
    "freeze",
    "from",
    "full",
    "grant",
    "greatest",
    "group",
    "grouping",
    "having",
    "ilike",
    "in",
    "initially",
    "inner",
    "inout",
    "int",
    "integer",
    "intersect",
    "interval",
    "into",
    "is",
    "isnull",
    "join",
    "json",
    "json_array",
    "json_arrayagg",
    "json_exists",
    "json_object",
    "json_objectagg",
    "json_query",
    "json_scalar",
    "json_serialize",
    "json_table",
    "json_value",
    "lateral",
    "leading",
    "least",
    "left",
    "like",
    "limit",
    "localtime",
    "localtimestamp",
    "merge_action",
    "national",
    "natural",
    "nchar",
    "none",
    "normalize",
    "not",
    "notnull",
    "null",
    "nullif",
    "numeric",
    "offset",
    "on",
    "only",
    "or",
    "order",
    "out",
    "outer",
    "overlaps",
    "overlay",
    "placing",
    "position",
    "precision",
    "primary",
    "real",
    "references",
    "returning",
    "right",
    "row",
    "select",
    "session_user",
    "setof",
    "similar",
    "smallint",
    "some",
    "substring",
    "symmetric",
    "system_user",
    "table",
    "tablesample",
    "then",
    "time",
    "timestamp",
    "to",
    "trailing",
    "treat",
    "trim",
    "true",
    "union",
    "unique",
    "user",
    "using",
    "values",
    "varchar",
    "variadic",
    "verbose",
    "when",
    "where",
    "window",
    "with",
    "xmlattributes",
    "xmlconcat",
    "xmlelement",
    "xmlexists",
    "xmlforest",
    "xmlnamespaces",
    "xmlparse",
    "xmlpi",
    "xmlroot",
    "xmlserialize",
    "xmltable",
];

/// Postgres's own `quote_ident` rule, which is how the catalog spells a name: bare when the name is
/// a plain lowercase identifier that is not a quoted keyword, quoted by
/// [`crate::sql_quote::quote_ident`] otherwise. Leaving keywords bare keyed `public.user` against
/// the catalog's `public."user"`.
pub(crate) fn quote_if_needed(ident: &str) -> String {
    let simple = !ident.is_empty()
        && ident
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && !ident.chars().next().is_some_and(|c| c.is_ascii_digit())
        && QUOTED_KEYWORDS.binary_search(&ident).is_err();
    if simple {
        ident.to_string()
    } else {
        crate::sql_quote::quote_ident(ident)
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
        "decimal" | "dec" => "numeric",
        "float" => "double precision",
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

    /// A modifier is dropped and the words after it kept: cutting at the first `(` turned
    /// `timestamp(3) with time zone` into `timestamp`, and so `timestamp without time zone`.
    #[test]
    fn a_type_modifier_goes_and_the_rest_of_the_type_stays() {
        assert_eq!(
            function_key(
                "f",
                "a timestamp(3) with time zone, b time(0) with time zone, c timestamp(6)"
            ),
            "f(timestamp with time zone, time with time zone, timestamp without time zone)"
        );
        // Unnamed, and with whitespace inside the modifier.
        assert_eq!(
            function_key(
                "g",
                "timestamp(3) with time zone, numeric(10, 2), character varying(32)"
            ),
            "g(timestamp with time zone, numeric, character varying)"
        );
        assert_eq!(
            function_key("h", "n numeric(10, 2)[], v varchar(5)"),
            "h(numeric[], character varying)"
        );
    }

    #[test]
    fn float_and_dec_take_their_format_type_spelling() {
        assert_eq!(
            function_key(
                "f",
                "a float, b float(24), c float(53), d dec, e dec(4, 1), f float8"
            ),
            "f(double precision, real, double precision, numeric, numeric, double precision)"
        );
    }

    /// An array of a type outside `pg_catalog` is its element type, qualified, with brackets: what
    /// the catalog reader now reports in place of the array type's own name (`public._things`).
    #[test]
    fn an_array_of_a_qualified_type_keeps_its_brackets() {
        assert_eq!(
            function_key("f", "rows \"public\".\"things\"[], tags text[]"),
            "f(public.things[], text[])"
        );
    }

    /// `quote_ident` quotes a keyword Postgres does not leave unreserved, so a model whose table is
    /// `user` has a row type the catalog writes `public."user"`. Keyed bare, the push could not find
    /// the `can_*` function it had just created and refused (the blog example).
    #[test]
    fn a_type_named_after_a_reserved_word_is_quoted_as_the_catalog_quotes_it() {
        assert_eq!(
            function_key("can_create_user", "\"user\" \"public\".\"user\""),
            "can_create_user(public.\"user\")"
        );
        // Column-name and type-function keywords are quoted too; an unreserved one is not.
        assert_eq!(quote_if_needed("between"), "\"between\"");
        assert_eq!(quote_if_needed("join"), "\"join\"");
        assert_eq!(quote_if_needed("comment"), "comment");
        // The lookup is a binary search, which is only right over a sorted list.
        assert!(QUOTED_KEYWORDS.windows(2).all(|w| w[0] < w[1]));
    }
}

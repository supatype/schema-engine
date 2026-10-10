//! Quoting for every name and value the engine writes into SQL.
//!
//! Names reach generated statements from two places the engine does not control: the live catalog
//! (an index, constraint, policy or function someone created by hand) and the schema (a table, a
//! column, a role named in an access rule). Either can hold a quote character. Pasting one between
//! quotes without doubling it ends the identifier or literal early, so `my"idx` breaks a push with a
//! syntax error, and a role named `x' OR true OR 'a'='a` turns a policy into one every caller
//! passes. Every name and value goes through these functions instead; `tests/sql_quote_lint.rs`
//! fails the build on a format string that quotes a placeholder by hand.

/// A double-quoted identifier, with every `"` doubled: Postgres's `quote_ident`, always quoting.
///
/// Always quoting keeps the case the schema declared and makes a keyword safe, and the normaliser
/// the differ compares with strips the quotes again, so nothing is recreated for it.
pub fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// `"schema"."name"`, each part quoted by [`quote_ident`].
pub fn quote_qualified(schema: &str, name: &str) -> String {
    format!("{}.{}", quote_ident(schema), quote_ident(name))
}

/// A single-quoted string literal with every `'` doubled.
///
/// Backslashes are left as they are: the engine's statements are written for
/// `standard_conforming_strings = on`, Postgres's default since 9.1, under which a backslash is an
/// ordinary character. Doubling them into an `E'...'` literal would also change how a regular
/// expression in a check constraint is written, and the differ would then see every such check as
/// changed.
pub fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// The message of a PL/pgSQL `RAISE`, as a literal: quoted by [`quote_literal`], with every `%`
/// doubled, because `RAISE` reads its message as a format string and a lone `%` in a name would
/// ask for a parameter that is not there.
pub fn raise_message(text: &str) -> String {
    quote_literal(&text.replace('%', "%%"))
}

/// Text for a `--` comment line: a line break in a name would end the comment and leave the rest of
/// the name to run as SQL, so each one becomes a space.
pub fn comment_text(text: &str) -> String {
    text.replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identifier_doubles_its_quotes() {
        assert_eq!(quote_ident("posts"), "\"posts\"");
        assert_eq!(quote_ident("my\"idx"), "\"my\"\"idx\"");
        assert_eq!(
            quote_ident("x\"; DROP TABLE t; --"),
            "\"x\"\"; DROP TABLE t; --\""
        );
    }

    #[test]
    fn a_qualified_name_quotes_both_parts() {
        assert_eq!(quote_qualified("public", "a\"b"), "\"public\".\"a\"\"b\"");
    }

    #[test]
    fn a_literal_doubles_its_quotes() {
        assert_eq!(quote_literal("o'brien"), "'o''brien'");
        assert_eq!(
            quote_literal("x' OR true OR 'a'='a"),
            "'x'' OR true OR ''a''=''a'"
        );
    }

    #[test]
    fn a_literal_keeps_its_backslashes() {
        assert_eq!(quote_literal("^\\d+$"), "'^\\d+$'");
    }

    #[test]
    fn a_raise_message_is_a_literal_with_no_placeholders() {
        assert_eq!(raise_message("50% of o'brien"), "'50%% of o''brien'");
    }

    #[test]
    fn a_comment_cannot_be_ended_by_a_name() {
        assert_eq!(comment_text("a\nDROP TABLE t;\r\n"), "a DROP TABLE t;  ");
    }
}

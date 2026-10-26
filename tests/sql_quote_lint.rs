//! No SQL is written with a name quoted by hand.
//!
//! A format string such as `"DROP INDEX \"{name}\""` or `"rolname = '{role}'"` pastes a name between
//! quotes without doubling the quote character, so a name that holds one ends the identifier or the
//! literal early and the rest of it runs as SQL. Every name goes through `sql_quote::quote_ident` or
//! `sql_quote::quote_literal` instead. This test reads the engine's source and fails on any string
//! literal that looks like SQL and has a `format!` placeholder inside a quoted identifier or a quoted
//! literal, so the pattern cannot come back unnoticed.
//!
//! A placeholder written in capitals names a constant the engine defines, which cannot hold a name
//! from outside, so it is allowed. Anything else that is deliberate goes in [`ALLOWED`] with the
//! reason.

use std::fs;
use std::path::{Path, PathBuf};

/// Literals the scan flags that are safe, as `(file, text the literal contains, why)`.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "src/generator/sql/rls.rs",
        "'{n} column rule(s) in this schema would not be enforced.'",
        "`n` is a count",
    ),
    (
        "src/generator/sql/rls.rs",
        "GRANT USAGE ON SCHEMA {CLAIMS_SCHEMA} TO {roles};'",
        "`roles` is the `API_ROLES` constant, in a hint for the reader",
    ),
    (
        "src/differ/field_access_diff.rs",
        "is not in the introspected state, so a BEFORE INSERT trigger",
        "a warning for the reader, not SQL",
    ),
    (
        "src/main.rs",
        "Re-run {} to apply the DROP + CREATE.",
        "terminal output, not SQL",
    ),
];

/// Words that mark a literal as SQL rather than a message. Matched as whole upper-case words, so
/// prose such as "Table" or "drop" does not count.
const SQL_WORDS: &[&str] = &[
    "ALTER", "COMMENT", "CREATE", "DELETE", "DROP", "EXECUTE", "FROM", "GRANT", "INSERT", "INTO",
    "LABEL", "POLICY", "REVOKE", "SELECT", "SET", "UPDATE", "VALUES", "WHERE",
];

#[test]
fn no_sql_quotes_a_placeholder_by_hand() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    for file in rust_files(&root.join("src")) {
        let rel = file
            .strip_prefix(root)
            .expect("under the crate root")
            .to_string_lossy()
            .replace('\\', "/");
        let source = fs::read_to_string(&file).expect("source reads");
        for (line, literal) in format_strings(&source) {
            if let Some(placeholder) = hand_quoted_placeholder(&literal) {
                if !allowed(&rel, &literal) {
                    found.push(format!("{rel}:{line}: {placeholder} in {literal:?}"));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "SQL quotes a placeholder by hand; use sql_quote::quote_ident or quote_literal:\n{}",
        found.join("\n")
    );
}

/// The scan itself: each shape it exists to catch is caught, and the safe ones are not.
#[test]
fn the_scan_tells_a_hand_quoted_name_from_a_safe_one() {
    let flagged = [
        "DROP INDEX IF EXISTS \"{name}\";",
        "ALTER TABLE \"{}\".\"{}\" DROP COLUMN x",
        "SELECT 1 FROM pg_roles WHERE rolname = '{role}'",
        "    EXECUTE 'DROP VIEW IF EXISTS {}.{}';",
        "CREATE POLICY \"{table}_{suffix}\" ON t",
    ];
    for literal in flagged {
        assert!(
            hand_quoted_placeholder(literal).is_some(),
            "not flagged: {literal}"
        );
    }
    let safe = [
        "DROP INDEX IF EXISTS {};",
        "SELECT 1 FROM pg_extension WHERE extname = '{MASK_EXTENSION}'",
        "Table \"{table}\" is not managed by Supatype",
        "SELECT '{{}}'::jsonb FROM {t}",
        "-- the model's \"{x}\" in a comment\nSELECT {y}",
    ];
    for literal in safe {
        assert_eq!(hand_quoted_placeholder(literal), None, "flagged: {literal}");
    }
}

fn allowed(file: &str, literal: &str) -> bool {
    ALLOWED
        .iter()
        .any(|(f, text, _)| *f == file && literal.contains(text))
}

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).expect("source directory reads") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            out.extend(rust_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// The first placeholder in `literal` that sits inside a quoted identifier or a quoted literal, when
/// `literal` reads as SQL.
fn hand_quoted_placeholder(literal: &str) -> Option<String> {
    if !looks_like_sql(literal) {
        return None;
    }
    let mut quote: Option<char> = None;
    for line in literal.lines() {
        let code = line.split("--").next().unwrap_or("");
        let mut chars = code.char_indices().peekable();
        while let Some((i, c)) = chars.next() {
            match c {
                '"' | '\'' if quote == Some(c) => quote = None,
                '"' | '\'' if quote.is_none() => quote = Some(c),
                '{' if chars.peek().is_some_and(|(_, n)| *n == '{') => {
                    chars.next();
                }
                '{' => {
                    let name = placeholder_name(&code[i + 1..]);
                    if quote.is_some() && !is_constant(name) {
                        return Some(format!("{{{name}}}"));
                    }
                }
                _ => {}
            }
        }
    }
    None
}

fn looks_like_sql(literal: &str) -> bool {
    literal
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|word| SQL_WORDS.contains(&word))
}

fn placeholder_name(after_brace: &str) -> &str {
    let end = after_brace.find(['}', ':']).unwrap_or(after_brace.len());
    &after_brace[..end]
}

fn is_constant(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// The format strings of `source`'s non-test code (the literal straight after a macro's `!(`), with
/// the line each starts on. A plain literal has no placeholders, whatever braces it holds, and the
/// unit tests at the foot of a file build their fixtures by hand on purpose.
fn format_strings(source: &str) -> Vec<(usize, String)> {
    let code = source
        .find("\n#[cfg(test)]")
        .map_or(source, |end| &source[..end]);
    string_literals(code)
        .into_iter()
        .filter(|(at, _)| code[..*at].trim_end().ends_with("!("))
        .map(|(at, text)| (line_of(code, at), text))
        .collect()
}

/// Every string literal in `source`, with the byte it starts at, decoded as the compiler reads it.
/// Comments and character literals are skipped, so a `'"'` or a quote in a doc comment does not
/// start a string.
fn string_literals(source: &str) -> Vec<(usize, String)> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                i = source[i..].find('\n').map_or(bytes.len(), |n| i + n);
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i = source[i + 2..]
                    .find("*/")
                    .map_or(bytes.len(), |n| i + n + 4);
            }
            b'\'' => i = skip_char_literal(bytes, i),
            b'r' if is_raw_start(bytes, i) => {
                let (text, end) = raw_string(source, i);
                out.push((i, text));
                i = end;
            }
            b'"' => {
                let (text, end) = cooked_string(source, i);
                out.push((i, text));
                i = end;
            }
            _ => i += 1,
        }
    }
    out
}

fn line_of(source: &str, at: usize) -> usize {
    source[..at].matches('\n').count() + 1
}

/// Past a character literal or a lifetime starting at `i`.
fn skip_char_literal(bytes: &[u8], i: usize) -> usize {
    if bytes.get(i + 1) == Some(&b'\\') {
        let mut j = i + 2;
        while j < bytes.len() && bytes[j] != b'\'' {
            j += 1;
        }
        return j + 1;
    }
    let width = bytes.get(i + 1).map_or(1, |b| {
        if *b >= 0xF0 {
            4
        } else if *b >= 0xE0 {
            3
        } else if *b >= 0xC0 {
            2
        } else {
            1
        }
    });
    if bytes.get(i + 1 + width) == Some(&b'\'') {
        i + 2 + width
    } else {
        i + 1
    }
}

/// `r"`, `r#"` and so on, not the `r` at the end of an identifier.
fn is_raw_start(bytes: &[u8], i: usize) -> bool {
    let prev_is_ident = i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
    let mut j = i + 1;
    while bytes.get(j) == Some(&b'#') {
        j += 1;
    }
    !prev_is_ident && bytes.get(j) == Some(&b'"')
}

fn raw_string(source: &str, i: usize) -> (String, usize) {
    let bytes = source.as_bytes();
    let mut j = i + 1;
    while bytes[j] == b'#' {
        j += 1;
    }
    let hashes = j - i - 1;
    let close = format!("\"{}", "#".repeat(hashes));
    let start = j + 1;
    let end = source[start..]
        .find(&close)
        .map_or(source.len(), |n| start + n);
    (source[start..end].to_string(), end + close.len())
}

/// A `"..."` literal starting at `i`, with its escapes decoded and its line continuations joined.
fn cooked_string(source: &str, i: usize) -> (String, usize) {
    let mut text = String::new();
    let mut chars = source[i + 1..].char_indices();
    while let Some((n, c)) = chars.next() {
        match c {
            '"' => return (text, i + 1 + n + 1),
            '\\' => match chars.next().map(|(_, e)| e) {
                Some('n') => text.push('\n'),
                Some('t') => text.push('\t'),
                Some('r') => text.push('\r'),
                Some('0') => text.push('\0'),
                Some('u') => {
                    // `\u{...}`: the character itself does not matter to the scan.
                    for (_, u) in chars.by_ref() {
                        if u == '}' {
                            break;
                        }
                    }
                    text.push('?');
                }
                // A line continuation, with either line ending.
                Some('\n' | '\r') => {
                    let rest = chars.as_str();
                    let skip = rest.len() - rest.trim_start().len();
                    for _ in 0..rest[..skip].chars().count() {
                        chars.next();
                    }
                }
                Some(other) => text.push(other),
                None => break,
            },
            other => text.push(other),
        }
    }
    (text, source.len())
}

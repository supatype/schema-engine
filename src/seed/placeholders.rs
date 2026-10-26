//! How many parameters a raw statement uses.
//!
//! Postgres reports a statement given too few parameters, but one given too many is
//! silently accepted and the extras ignored, so a `$sql` whose params drifted from its text
//! would run with the wrong values in the wrong places. Counting here lets validation say
//! so, for both directions, before anything runs.
//!
//! The count is the highest `$n` outside string literals, quoted names, comments and
//! dollar-quoted bodies, which is how Postgres numbers a statement's parameters.

/// The highest `$n` placeholder in `text`, or 0 when it uses none.
pub fn placeholder_count(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut highest = 0;
    let mut at = 0;
    while at < bytes.len() {
        at = match bytes[at] {
            b'\'' => skip_string(bytes, at),
            b'"' => skip_quoted(bytes, at + 1, b'"'),
            b'-' if bytes.get(at + 1) == Some(&b'-') => skip_line_comment(bytes, at),
            b'/' if bytes.get(at + 1) == Some(&b'*') => skip_block_comment(bytes, at),
            b'$' => skip_dollar(bytes, at, &mut highest),
            _ => at + 1,
        };
    }
    highest
}

/// A byte that can continue an identifier, `$` included, as Postgres lexes one.
fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' || byte >= 0x80
}

/// A byte that can start a dollar-quote tag. Never a digit, which is what keeps a tag apart
/// from a placeholder.
fn is_tag_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte >= 0x80
}

/// Past a `'...'` literal, honouring backslash escapes when it is an `E'...'` string.
fn skip_string(bytes: &[u8], at: usize) -> usize {
    let escaped = at >= 1
        && matches!(bytes[at - 1], b'e' | b'E')
        && (at < 2 || !is_ident_byte(bytes[at - 2]));
    if !escaped {
        return skip_quoted(bytes, at + 1, b'\'');
    }
    let mut cursor = at + 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => cursor += 2,
            b'\'' if bytes.get(cursor + 1) == Some(&b'\'') => cursor += 2,
            b'\'' => return cursor + 1,
            _ => cursor += 1,
        }
    }
    bytes.len()
}

/// Past a body closed by `quote`, where a doubled `quote` stands for itself.
fn skip_quoted(bytes: &[u8], from: usize, quote: u8) -> usize {
    let mut cursor = from;
    while cursor < bytes.len() {
        if bytes[cursor] == quote {
            if bytes.get(cursor + 1) != Some(&quote) {
                return cursor + 1;
            }
            cursor += 1;
        }
        cursor += 1;
    }
    bytes.len()
}

fn skip_line_comment(bytes: &[u8], at: usize) -> usize {
    bytes[at..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(bytes.len(), |offset| at + offset + 1)
}

/// Past a `/* ... */` comment, which Postgres lets nest.
fn skip_block_comment(bytes: &[u8], at: usize) -> usize {
    let mut depth = 0usize;
    let mut cursor = at;
    while cursor + 1 < bytes.len() {
        match (bytes[cursor], bytes[cursor + 1]) {
            (b'/', b'*') => depth += 1,
            (b'*', b'/') => depth -= 1,
            _ => {
                cursor += 1;
                continue;
            }
        }
        cursor += 2;
        if depth == 0 {
            return cursor;
        }
    }
    bytes.len()
}

/// A `$` is a placeholder, a dollar-quote, or part of a name; step past whichever it is.
fn skip_dollar(bytes: &[u8], at: usize, highest: &mut usize) -> usize {
    if at > 0 && is_ident_byte(bytes[at - 1]) {
        return at + 1;
    }
    let digits = bytes[at + 1..]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    if digits > 0 {
        let end = at + 1 + digits;
        let number = std::str::from_utf8(&bytes[at + 1..end])
            .ok()
            .and_then(|n| n.parse::<usize>().ok())
            .unwrap_or(0);
        *highest = (*highest).max(number);
        return end;
    }
    skip_dollar_quote(bytes, at)
}

/// Past a `$tag$ ... $tag$` body, or one byte when `at` does not open one.
fn skip_dollar_quote(bytes: &[u8], at: usize) -> usize {
    let tag_length = bytes[at + 1..]
        .iter()
        .enumerate()
        .take_while(|&(i, &b)| {
            if i == 0 {
                is_tag_start(b)
            } else {
                b != b'$' && is_ident_byte(b)
            }
        })
        .count();
    let close = at + 1 + tag_length;
    if bytes.get(close) != Some(&b'$') {
        return at + 1;
    }
    let tag = &bytes[at..=close];
    bytes[close + 1..]
        .windows(tag.len())
        .position(|window| window == tag)
        .map_or(bytes.len(), |offset| close + 1 + offset + tag.len())
}

#[cfg(test)]
mod tests {
    use super::placeholder_count;

    #[test]
    fn counts_the_highest_placeholder() {
        assert_eq!(placeholder_count("select $1, $2"), 2);
        assert_eq!(placeholder_count("select $2, $1, $2"), 2);
        assert_eq!(
            placeholder_count("select $3"),
            3,
            "a gap still needs $1 and $2"
        );
        assert_eq!(placeholder_count("insert into t values (1)"), 0);
        assert_eq!(placeholder_count("select $10 + 1"), 10);
    }

    #[test]
    fn ignores_placeholders_inside_literals_and_names() {
        assert_eq!(placeholder_count("select '$1', $1"), 1);
        assert_eq!(placeholder_count("select 'it''s $2', $1"), 1);
        assert_eq!(placeholder_count(r"select E'\' $2', $1"), 1);
        assert_eq!(placeholder_count(r#"select "a$2", $1"#), 1);
        assert_eq!(placeholder_count("select price$1 from t"), 0);
    }

    #[test]
    fn ignores_placeholders_inside_comments() {
        assert_eq!(placeholder_count("select $1 -- and $2\n"), 1);
        assert_eq!(placeholder_count("select /* $3 /* $4 */ $5 */ $1"), 1);
        assert_eq!(placeholder_count("select $1 /* unterminated $2"), 1);
    }

    #[test]
    fn ignores_placeholders_inside_dollar_quotes() {
        assert_eq!(placeholder_count("do $$ begin perform $1; end $$"), 0);
        assert_eq!(placeholder_count("select $fn$ $2 $fn$, $1"), 1);
        assert_eq!(placeholder_count("select $a$ $$ $2 $a$ || $1"), 1);
    }

    #[test]
    fn does_not_panic_on_a_trailing_dollar() {
        assert_eq!(placeholder_count("select $"), 0);
        assert_eq!(placeholder_count("$"), 0);
        assert_eq!(placeholder_count("select $$"), 0);
    }
}

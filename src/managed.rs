//! Naming conventions for the objects Supatype creates, and the one thing left of its comment stamps:
//! recognising and removing an older engine's `supatype:managed` stamp (plan section 7). Since Phase
//! 6 nothing writes one; ownership is the ledger's.

pub const MANAGED_PREFIX: &str = "supatype:managed";

/// Returns true when a Postgres object comment marks it as Supatype-managed.
pub fn is_managed_comment(comment: Option<&str>) -> bool {
    comment
        .map(|c| c.starts_with(MANAGED_PREFIX))
        .unwrap_or(false)
}

/// `comment` with the stamp line taken out: `None` when the comment was only the stamp, the
/// remaining lines otherwise. Once an object is in the ledger its comment is the user's (plan
/// section 6), so whatever they wrote beside the stamp stays.
pub fn comment_without_stamp(comment: Option<&str>) -> Option<String> {
    let rest: Vec<&str> = comment?
        .lines()
        .filter(|line| !line.starts_with(MANAGED_PREFIX))
        .collect();
    let rest = rest.join("\n");
    (!rest.trim().is_empty()).then_some(rest)
}

/// Postgres's identifier limit: `NAMEDATALEN - 1` bytes.
pub const MAX_IDENTIFIER_BYTES: usize = 63;

/// `base` followed by `suffix`, trimmed to fit Postgres's identifier limit by shortening `base`.
///
/// Every generated name goes through this, for the reason Prisma does the same: Postgres silently
/// truncates a long identifier to 63 bytes, so a `{table}_{column}_key` built in full here and
/// truncated there is a name nothing can find again. Trimming before the suffix keeps the part
/// that says what the object is. The cut lands on a character boundary, so a multibyte identifier
/// cannot be split mid-character.
pub fn truncate_identifier(base: &str, suffix: &str) -> String {
    if base.len() + suffix.len() <= MAX_IDENTIFIER_BYTES {
        return format!("{base}{suffix}");
    }
    let mut cut = MAX_IDENTIFIER_BYTES.saturating_sub(suffix.len());
    while cut > 0 && !base.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{suffix}", &base[..cut])
}

/// Postgres's own default name for a table's primary key.
pub fn primary_key_name(table: &str) -> String {
    truncate_identifier(table, "_pkey")
}

/// Postgres's own default name for a single-column foreign key.
pub fn foreign_key_name(table: &str, column: &str) -> String {
    truncate_identifier(&format!("{table}_{column}"), "_fkey")
}

/// Postgres's own default name for the check a field type carries (an `Email` regex, a `URL`
/// prefix, a TEXT enum's `IN` list, a `Publishable` status), as distinct from a declared bound.
pub fn type_check_name(table: &str, column: &str) -> String {
    truncate_identifier(&format!("{table}_{column}"), "_check")
}

/// Name for the constraint holding a column's declared bounds.
///
/// Deliberately not Postgres's own `{table}_{column}_check`: an inline `CHECK` written by anything
/// else already claims that name, and a bound Supatype manages has to be distinguishable from one it
/// merely found, or `doctor` and `adopt` cannot tell them apart.
pub fn expected_check_constraint_name(table: &str, column: &str) -> String {
    truncate_identifier(&format!("{table}_{column}"), "_bounds")
}

/// Name for a model-level constraint, by its position in the declared list.
///
/// Positional because the rule itself has no name: the author writes an expression, not an
/// identifier. Reordering `constraints` therefore renames them, which the differ handles as a drop
/// and an add of the same expression, and the fingerprint in the comment keeps that from churning
/// when nothing actually changed.
pub fn expected_model_constraint_name(table: &str, index: usize) -> String {
    truncate_identifier(table, &format!("_check_{}", index + 1))
}

/// Postgres default name for a single-column UNIQUE constraint.
pub fn expected_unique_constraint_name(table: &str, column: &str) -> String {
    truncate_identifier(&format!("{table}_{column}"), "_key")
}

/// Default name for a model-level index (`indexes` in schema meta).
pub fn expected_model_index_name(table: &str, fields: &[String]) -> String {
    truncate_identifier(&format!("{table}_{}", fields.join("_")), "_idx")
}

/// The value side of a `COMMENT ON ... IS`: a quoted literal, or `NULL` to clear it, for the ledger
/// putting back what a user wrote beside a stamp it removes.
pub fn comment_value(text: Option<&str>) -> String {
    match text {
        Some(t) => format!("'{}'", t.replace('\'', "''")),
        None => "NULL".to_string(),
    }
}

/// `COMMENT ON CONSTRAINT`, with `None` clearing the comment.
pub fn comment_on_constraint(
    schema: &str,
    table: &str,
    constraint: &str,
    text: Option<&str>,
) -> String {
    format!(
        "COMMENT ON CONSTRAINT \"{constraint}\" ON \"{schema}\".\"{table}\" IS {};",
        comment_value(text)
    )
}

/// `COMMENT ON TABLE`, with `None` clearing the comment.
pub fn comment_on_table(schema: &str, table: &str, text: Option<&str>) -> String {
    format!(
        "COMMENT ON TABLE \"{schema}\".\"{table}\" IS {};",
        comment_value(text)
    )
}

/// `COMMENT ON INDEX`, with `None` clearing the comment.
pub fn comment_on_index(schema: &str, index: &str, text: Option<&str>) -> String {
    format!(
        "COMMENT ON INDEX \"{schema}\".\"{index}\" IS {};",
        comment_value(text)
    )
}

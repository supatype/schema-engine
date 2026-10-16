//! Names for model-level constraints, read off what each rule checks (CK1).
//!
//! A rule is an expression with no identifier of its own, and these were once named by their
//! place in the list (`chat_message_check_1`), so the error a writer saw named nothing. Each is
//! now named for the columns it reads and what it asks of them: `Gte<Length<"body">, Literal<2>>`
//! is `chat_message_body_min_length`, `Lte<"starts_at", "ends_at">` is
//! `talk_starts_at_lte_ends_at`. Literal values never appear, so tightening a bound keeps the
//! name and the push replaces the constraint under it rather than renaming it.
//!
//! A name past Postgres's 63-byte limit is cut to 54 bytes on a character boundary and given
//! `_` and the first 8 hex characters of the SHA-256 of the whole name, so two long names that
//! share a prefix still differ, and the same rule always gets the same name. Two rules on one
//! table that want the same name are told apart by [`crate::managed::ObjectNames`].

use sha2::{Digest, Sha256};

use crate::managed::MAX_IDENTIFIER_BYTES;
use crate::parser::ast::{AccessRule, CompareOp, Operand};

/// The bytes of a hashed name kept from the name itself: the rest is `_` and 8 hex characters.
const HASHED_PREFIX_BYTES: usize = MAX_IDENTIFIER_BYTES - 9;

/// What a rule checks, as the part of its name after the table: `body_min_length`.
pub fn rule_descriptor(rule: &AccessRule) -> String {
    match rule {
        AccessRule::Compare { left, op, right } => compare_descriptor(left, *op, right),
        AccessRule::NullCheck { operand, is_null } => null_descriptor(operand, *is_null),
        AccessRule::Matches { column, .. } => format!("{column}_format"),
        AccessRule::Not { rule } => match rule.as_ref() {
            AccessRule::NullCheck { operand, is_null } => null_descriptor(operand, !is_null),
            inner => format!("not_{}", rule_descriptor(inner)),
        },
        AccessRule::All { rules } => joined(rules, "_and_"),
        AccessRule::Any { rules } => joined(rules, "_or_"),
        // A rule a CHECK cannot hold fails the push in the generator; it still needs a name.
        _ => "check".to_string(),
    }
}

/// The name of the model constraint on `table` that checks `descriptor`, the `pass`-th to want it:
/// `{table}_{descriptor}` for the first, with `_2`, `_3`, ... after it for the others, fitted to
/// the identifier limit.
pub fn rule_constraint_name(table: &str, descriptor: &str, pass: usize) -> String {
    let full = match pass {
        0 => format!("{table}_{descriptor}"),
        n => format!("{table}_{descriptor}_{}", n + 1),
    };
    fit(full)
}

/// `name` as it stands when it fits, and otherwise its first 54 bytes (cut back to a character
/// boundary) with a hash of the whole.
fn fit(name: String) -> String {
    if name.len() <= MAX_IDENTIFIER_BYTES {
        return name;
    }
    let digest = Sha256::digest(name.as_bytes());
    let hash: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();
    let mut cut = HASHED_PREFIX_BYTES;
    while !name.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}_{hash}", &name[..cut])
}

fn joined(rules: &[AccessRule], joiner: &str) -> String {
    if rules.is_empty() {
        return "check".to_string();
    }
    rules
        .iter()
        .map(rule_descriptor)
        .collect::<Vec<_>>()
        .join(joiner)
}

fn null_descriptor(operand: &Operand, is_null: bool) -> String {
    let what = operand_word(operand);
    if is_null {
        format!("{what}_null")
    } else {
        format!("{what}_not_null")
    }
}

/// A comparison with a literal reads as a bound on the other side (`body_min_length`,
/// `price_max`, `status_eq`); any other reads as the two sides and the operator
/// (`starts_at_lte_ends_at`).
fn compare_descriptor(left: &Operand, op: CompareOp, right: &Operand) -> String {
    match (left, right) {
        (subject, Operand::Literal { .. }) if !is_literal(subject) => bound(subject, op),
        (Operand::Literal { .. }, subject) if !is_literal(subject) => bound(subject, mirrored(op)),
        _ => format!(
            "{}_{}_{}",
            operand_word(left),
            op_word(op),
            operand_word(right)
        ),
    }
}

fn is_literal(operand: &Operand) -> bool {
    matches!(operand, Operand::Literal { .. })
}

/// `subject op literal`: a lower or upper bound, or the operator.
fn bound(subject: &Operand, op: CompareOp) -> String {
    let (column, measure) = match subject {
        Operand::Length { column, .. } => (column.as_str(), Some("length")),
        Operand::ItemCount { column, .. } => (column.as_str(), Some("items")),
        other => return bound_on(&operand_word(other), op),
    };
    match (op, measure) {
        (CompareOp::Gt | CompareOp::Gte, Some(measure)) => format!("{column}_min_{measure}"),
        (CompareOp::Lt | CompareOp::Lte, Some(measure)) => format!("{column}_max_{measure}"),
        (_, Some(measure)) => format!("{column}_{measure}_{}", op_word(op)),
        (_, None) => bound_on(column, op),
    }
}

fn bound_on(what: &str, op: CompareOp) -> String {
    match op {
        CompareOp::Gt | CompareOp::Gte => format!("{what}_min"),
        CompareOp::Lt | CompareOp::Lte => format!("{what}_max"),
        other => format!("{what}_{}", op_word(other)),
    }
}

/// The operator that says the same with its sides swapped.
fn mirrored(op: CompareOp) -> CompareOp {
    match op {
        CompareOp::Gt => CompareOp::Lt,
        CompareOp::Gte => CompareOp::Lte,
        CompareOp::Lt => CompareOp::Gt,
        CompareOp::Lte => CompareOp::Gte,
        other => other,
    }
}

fn op_word(op: CompareOp) -> &'static str {
    match op {
        CompareOp::Eq => "eq",
        CompareOp::Neq => "ne",
        CompareOp::Gt => "gt",
        CompareOp::Gte => "gte",
        CompareOp::Lt => "lt",
        CompareOp::Lte => "lte",
        CompareOp::Like => "like",
    }
}

/// One operand as it reads in a name. Only columns, measures and literals reach a CHECK; the
/// caller and clock operands are refused by the generator, and named for what they are.
fn operand_word(operand: &Operand) -> String {
    match operand {
        Operand::Column { name } => name.clone(),
        Operand::Length { column, .. } => format!("{column}_length"),
        Operand::ItemCount { column, .. } => format!("{column}_items"),
        Operand::Literal { .. } => "value".to_string(),
        Operand::AuthUid => "uid".to_string(),
        Operand::AuthRole => "role".to_string(),
        Operand::Claim { .. } => "claim".to_string(),
        Operand::Now
        | Operand::StartOf { .. }
        | Operand::Ago { .. }
        | Operand::FromNow { .. }
        | Operand::After { .. }
        | Operand::Before { .. } => "time".to_string(),
    }
}

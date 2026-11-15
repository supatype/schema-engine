//! Realtime channel declarations: the checks the engine makes again after the CLI, the pattern
//! grammar, and the two splits of a rule the SQL generator needs (content nodes, and the tables
//! a rule reads).
//!
//! The CLI's extractor refuses a bad declaration first. These checks exist anyway because what
//! passes them is compiled into SQL that runs as the caller: a pattern that two declarations can
//! both match would make the access function return two rows, and a rule that names a parameter
//! the pattern does not bind would fail at push time, inside Postgres, with a message about a
//! column rather than about the channel.

use super::ast::{AccessRule, ChannelAst, ChannelParamType, MembershipSource, Operand, SchemaAst};
use anyhow::{bail, Result};
use std::collections::BTreeSet;

/// One `:`-separated piece of a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    Literal(String),
    Param(String),
    /// A final `*`: one or more remaining segments.
    Wildcard,
}

/// A topic may not start with either: `realtime:` is the server's own namespace and `_supatype`
/// is this platform's, so a declaration could otherwise grant access to internal channels.
const RESERVED_PREFIXES: [&str; 2] = ["realtime:", "_supatype"];

/// What a literal segment may hold. Narrow on purpose: a literal is escaped into a regular
/// expression and a quoted SQL string, and every character outside this set is one more thing
/// that has to be proven harmless in both.
fn literal_is_plain(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.@=+~!,;/".contains(c))
}

fn param_name_is_plain(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Splits a pattern into its segments, refusing one that is malformed.
pub fn parse_pattern(channel: &str, pattern: &str) -> Result<Vec<Segment>> {
    if RESERVED_PREFIXES.iter().any(|p| pattern.starts_with(p)) {
        bail!(
            "Channel '{channel}': the pattern \"{pattern}\" starts with a reserved prefix \
             (`realtime:` and `_supatype` belong to the platform)"
        );
    }
    let parts: Vec<&str> = pattern.split(':').collect();
    let last = parts.len() - 1;
    let mut segments = Vec::with_capacity(parts.len());
    for (i, part) in parts.iter().enumerate() {
        segments.push(parse_segment(channel, pattern, part, i == last)?);
    }
    Ok(segments)
}

fn parse_segment(channel: &str, pattern: &str, part: &str, is_last: bool) -> Result<Segment> {
    if part == "*" {
        if !is_last {
            bail!(
                "Channel '{channel}': the pattern \"{pattern}\" has a `*` before its last \
                 segment; a wildcard may only end a pattern"
            );
        }
        return Ok(Segment::Wildcard);
    }
    if let Some(name) = part.strip_prefix('{').and_then(|p| p.strip_suffix('}')) {
        if !param_name_is_plain(name) {
            bail!(
                "Channel '{channel}': \"{part}\" in \"{pattern}\" is not a parameter name \
                 (letters, digits and `_`, not starting with a digit)"
            );
        }
        return Ok(Segment::Param(name.to_string()));
    }
    if !literal_is_plain(part) {
        bail!(
            "Channel '{channel}': the segment \"{part}\" of \"{pattern}\" is empty or holds a \
             character a literal segment may not (letters, digits and `_ - . @ = + ~ ! , ; /`)"
        );
    }
    Ok(Segment::Literal(part.to_string()))
}

/// Refuses a schema's channel declarations that cannot be compiled safely.
pub fn validate(ast: &SchemaAst) -> Result<()> {
    let mut parsed: Vec<(&ChannelAst, Vec<Segment>)> = Vec::new();
    for channel in &ast.channels {
        validate_name(channel, &parsed)?;
        let segments = parse_pattern(&channel.name, &channel.pattern)?;
        validate_params(channel, &segments)?;
        validate_access(channel)?;
        parsed.push((channel, segments));
    }
    refuse_overlaps(&parsed)?;
    refuse_param_outside_channels(ast)
}

fn validate_name(channel: &ChannelAst, earlier: &[(&ChannelAst, Vec<Segment>)]) -> Result<()> {
    if channel.name.is_empty() {
        bail!("A channel declaration has an empty name");
    }
    if earlier.iter().any(|(c, _)| c.name == channel.name) {
        bail!("Channel '{}' is declared twice", channel.name);
    }
    Ok(())
}

fn validate_params(channel: &ChannelAst, segments: &[Segment]) -> Result<()> {
    let in_pattern: Vec<&str> = segments
        .iter()
        .filter_map(|s| match s {
            Segment::Param(name) => Some(name.as_str()),
            _ => None,
        })
        .collect();
    let mut seen = BTreeSet::new();
    for param in &channel.params {
        if !seen.insert(param.name.as_str()) {
            bail!(
                "Channel '{}': parameter '{}' is declared twice",
                channel.name,
                param.name
            );
        }
        if !in_pattern.contains(&param.name.as_str()) {
            bail!(
                "Channel '{}': parameter '{}' is declared but \"{}\" has no {{{}}} segment",
                channel.name,
                param.name,
                channel.pattern,
                param.name
            );
        }
    }
    for name in &in_pattern {
        if !seen.contains(name) {
            bail!(
                "Channel '{}': \"{}\" has a {{{name}}} segment but no parameter '{name}' is \
                 declared with a type",
                channel.name,
                channel.pattern
            );
        }
    }
    let distinct: BTreeSet<&&str> = in_pattern.iter().collect();
    if distinct.len() != in_pattern.len() {
        bail!(
            "Channel '{}': \"{}\" binds the same parameter twice",
            channel.name,
            channel.pattern
        );
    }
    Ok(())
}

fn validate_access(channel: &ChannelAst) -> Result<()> {
    let access = &channel.access;
    let names: BTreeSet<&str> = channel.params.iter().map(|p| p.name.as_str()).collect();
    for (op, rule) in [("join", &access.join), ("track", &access.track)] {
        if let Some(rule) = rule {
            if has_content(rule) {
                bail!(
                    "Channel '{}': the {op} rule uses `Event` or `Payload`, which describe a \
                     broadcast and are valid only in `send`",
                    channel.name
                );
            }
            validate_rule(channel, op, rule, &names)?;
        }
    }
    if let Some(rule) = &access.send {
        let (sql_rule, _) = split_send_rule(&channel.name, rule)?;
        validate_rule(channel, "send", &sql_rule, &names)?;
    }
    Ok(())
}

/// Refuses what a channel rule cannot mean: nodes with no row to read (`Owner`, `Matches`, a
/// measure), a bare column that is not a parameter, and a `Param` the pattern does not bind.
fn validate_rule(
    channel: &ChannelAst,
    op: &str,
    rule: &AccessRule,
    params: &BTreeSet<&str>,
) -> Result<()> {
    let fail =
        |what: String| -> Result<()> { bail!("Channel '{}': the {op} rule {what}", channel.name) };
    match rule {
        AccessRule::Owner { .. } => fail("uses `Owner`, and a channel has no row to own".into()),
        AccessRule::Matches { .. } => fail("uses `Matches`, which is for constraints".into()),
        AccessRule::Any { rules } | AccessRule::All { rules } => rules
            .iter()
            .try_for_each(|r| validate_rule(channel, op, r, params)),
        AccessRule::Not { rule } => validate_rule(channel, op, rule, params),
        AccessRule::Compare { left, right, .. } => {
            validate_operand(channel, op, left, params, true)?;
            validate_operand(channel, op, right, params, true)
        }
        AccessRule::NullCheck { operand, .. } => {
            validate_operand(channel, op, operand, params, true)
        }
        AccessRule::In { column, source } => {
            if !params.contains(column.as_str()) {
                return fail(format!(
                    "tests \"{column}\", which is not a parameter of \"{}\" (parameters: {})",
                    channel.pattern,
                    list(params)
                ));
            }
            validate_source(channel, op, source, params)
        }
        AccessRule::Exists { source } => validate_source(channel, op, source, params),
        _ => Ok(()),
    }
}

fn validate_source(
    channel: &ChannelAst,
    op: &str,
    source: &MembershipSource,
    params: &BTreeSet<&str>,
) -> Result<()> {
    let MembershipSource::Rows {
        filter: Some(filter),
        ..
    } = source
    else {
        return Ok(());
    };
    // Inside a `Rows` filter a bare column belongs to the source table, so only `Param`s are
    // checked there.
    check_filter(channel, op, filter, params)
}

fn check_filter(
    channel: &ChannelAst,
    op: &str,
    rule: &AccessRule,
    params: &BTreeSet<&str>,
) -> Result<()> {
    match rule {
        AccessRule::Any { rules } | AccessRule::All { rules } => rules
            .iter()
            .try_for_each(|r| check_filter(channel, op, r, params)),
        AccessRule::Not { rule } => check_filter(channel, op, rule, params),
        AccessRule::Compare { left, right, .. } => {
            validate_operand(channel, op, left, params, false)?;
            validate_operand(channel, op, right, params, false)
        }
        AccessRule::NullCheck { operand, .. } => {
            validate_operand(channel, op, operand, params, false)
        }
        AccessRule::In { source, .. } | AccessRule::Exists { source } => {
            validate_source(channel, op, source, params)
        }
        AccessRule::Owner { .. } | AccessRule::Matches { .. } => Ok(()),
        _ => Ok(()),
    }
}

fn validate_operand(
    channel: &ChannelAst,
    op: &str,
    operand: &Operand,
    params: &BTreeSet<&str>,
    top_level: bool,
) -> Result<()> {
    let problem = match operand {
        Operand::Param { name } if !params.contains(name.as_str()) => Some(format!(
            "uses Param<\"{name}\">, which \"{}\" does not bind (parameters: {})",
            channel.pattern,
            list(params)
        )),
        Operand::Column { name } if top_level && !params.contains(name.as_str()) => Some(format!(
            "tests \"{name}\", which is not a parameter of \"{}\" (parameters: {})",
            channel.pattern,
            list(params)
        )),
        Operand::Length { .. } | Operand::ItemCount { .. } => {
            Some("uses a measure, which is for constraints".to_string())
        }
        _ => None,
    };
    match problem {
        Some(what) => bail!("Channel '{}': the {op} rule {what}", channel.name),
        None => Ok(()),
    }
}

fn list(params: &BTreeSet<&str>) -> String {
    if params.is_empty() {
        return "none".to_string();
    }
    params.iter().copied().collect::<Vec<_>>().join(", ")
}

// ---------------------------------------------------------------------------------------------
// Overlap
// ---------------------------------------------------------------------------------------------

/// Whether some topic fits both patterns. Two declarations that can match one topic would make
/// the access function return two rows for it, and which row a caller was judged by would depend
/// on declaration order: refused rather than ranked (P3).
fn refuse_overlaps(parsed: &[(&ChannelAst, Vec<Segment>)]) -> Result<()> {
    for (i, (a, sa)) in parsed.iter().enumerate() {
        for (b, sb) in &parsed[i + 1..] {
            if patterns_overlap(a, sa, b, sb) {
                bail!(
                    "Channels '{}' (\"{}\") and '{}' (\"{}\") can both match one topic. Declare \
                     one channel for them, or make the patterns disjoint",
                    a.name,
                    a.pattern,
                    b.name,
                    b.pattern
                );
            }
        }
    }
    Ok(())
}

fn patterns_overlap(a: &ChannelAst, sa: &[Segment], b: &ChannelAst, sb: &[Segment]) -> bool {
    match (sa.first(), sb.first()) {
        (None, None) => true,
        (None, _) | (_, None) => false,
        // A trailing `*` takes this segment and everything after it, so it meets any non-empty
        // remainder.
        (Some(Segment::Wildcard), Some(_)) | (Some(_), Some(Segment::Wildcard)) => true,
        (Some(x), Some(y)) => {
            segments_meet(a, x, b, y) && patterns_overlap(a, &sa[1..], b, &sb[1..])
        }
    }
}

fn segments_meet(a: &ChannelAst, x: &Segment, b: &ChannelAst, y: &Segment) -> bool {
    match (x, y) {
        (Segment::Literal(l), Segment::Literal(m)) => l == m,
        (Segment::Literal(l), Segment::Param(p)) => fits(l, param_type(b, p)),
        (Segment::Param(p), Segment::Literal(l)) => fits(l, param_type(a, p)),
        (Segment::Param(p), Segment::Param(q)) => types_meet(param_type(a, p), param_type(b, q)),
        _ => true,
    }
}

fn param_type(channel: &ChannelAst, name: &str) -> ChannelParamType {
    channel
        .params
        .iter()
        .find(|p| p.name == name)
        .map_or(ChannelParamType::String, |p| p.kind)
}

/// Whether a literal segment is a value of the type, by the same shape the SQL checks.
fn fits(literal: &str, kind: ChannelParamType) -> bool {
    match kind {
        ChannelParamType::String => true,
        ChannelParamType::Integer => is_integer_shape(literal),
        ChannelParamType::Uuid => is_uuid_shape(literal),
    }
}

fn types_meet(x: ChannelParamType, y: ChannelParamType) -> bool {
    use ChannelParamType::String;
    x == y || x == String || y == String
}

/// Non-negative, at most 18 digits so it always fits a `bigint`.
pub fn is_integer_shape(text: &str) -> bool {
    (1..=18).contains(&text.len()) && text.chars().all(|c| c.is_ascii_digit())
}

pub fn is_uuid_shape(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && g.chars().all(|c| c.is_ascii_hexdigit()))
}

// ---------------------------------------------------------------------------------------------
// Param outside channels
// ---------------------------------------------------------------------------------------------

/// `Param` names a channel parameter, so in a model's or bucket's rule it names nothing. Rendered
/// it would be a reference to a column of a derived table that is not there, so it is refused
/// where it enters.
fn refuse_param_outside_channels(ast: &SchemaAst) -> Result<()> {
    for model in &ast.models {
        let access = &model.annotations.platform.access;
        let mut rules: Vec<&AccessRule> = [
            &access.read,
            &access.create,
            &access.update,
            &access.update_check,
            &access.delete,
        ]
        .into_iter()
        .flatten()
        .collect();
        for field in access.fields.values() {
            rules.extend(field.read.iter().chain(field.write.iter()));
        }
        for rule in rules {
            if let Some(what) = misplaced_node(rule) {
                bail!(
                    "Model '{}': a rule uses {what}, which belongs to a channel rule",
                    model.name
                );
            }
        }
    }
    Ok(())
}

/// The first `Param`, `Event` or `Payload` in a rule, named for an error.
fn misplaced_node(rule: &AccessRule) -> Option<&'static str> {
    match rule {
        AccessRule::Event { .. } => Some("`Event`"),
        AccessRule::Payload { .. } => Some("`Payload`"),
        AccessRule::Any { rules } | AccessRule::All { rules } => {
            rules.iter().find_map(misplaced_node)
        }
        AccessRule::Not { rule } => misplaced_node(rule),
        AccessRule::Compare { left, right, .. } => {
            [left, right].into_iter().find_map(misplaced_operand)
        }
        AccessRule::NullCheck { operand, .. } => misplaced_operand(operand),
        AccessRule::In { source, .. } | AccessRule::Exists { source } => match source {
            MembershipSource::Rows {
                filter: Some(f), ..
            } => misplaced_node(f),
            _ => None,
        },
        _ => None,
    }
}

fn misplaced_operand(operand: &Operand) -> Option<&'static str> {
    match operand {
        Operand::Param { .. } => Some("`Param`"),
        Operand::After { base, .. } | Operand::Before { base, .. } => misplaced_operand(base),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------
// Content rules
// ---------------------------------------------------------------------------------------------

/// Whether every leaf of the rule is an `Event` or a `Payload`: a rule the realtime server can
/// decide from the message alone.
pub fn is_content(rule: &AccessRule) -> bool {
    match rule {
        AccessRule::Event { .. } | AccessRule::Payload { .. } => true,
        AccessRule::Any { rules } | AccessRule::All { rules } => {
            !rules.is_empty() && rules.iter().all(is_content)
        }
        AccessRule::Not { rule } => is_content(rule),
        _ => false,
    }
}

/// Whether any node of the rule is an `Event` or a `Payload`.
pub fn has_content(rule: &AccessRule) -> bool {
    match rule {
        AccessRule::Event { .. } | AccessRule::Payload { .. } => true,
        AccessRule::Any { rules } | AccessRule::All { rules } => rules.iter().any(has_content),
        AccessRule::Not { rule } => has_content(rule),
        _ => false,
    }
}

/// A `send` rule, divided into what the database decides and what the server decides.
///
/// `Event` and `Payload` render as `TRUE` in SQL, which is only sound where they can be taken out
/// of the rule without changing what is left: the whole rule, or a direct child of the top-level
/// `All`. Under an `Any` or a `Not` mixed with table or caller tests, taking them out would
/// widen the rule (`Any[All[Event a, Role admin], Event b]` would let a non-admin send `a`), so a
/// send rule that does that is refused and the author splits it into two channels or one rule.
///
/// Returns the SQL half (`Public` when nothing is left) and the content half the server
/// evaluates, `None` when the rule has no content node.
pub fn split_send_rule(
    channel: &str,
    rule: &AccessRule,
) -> Result<(AccessRule, Option<AccessRule>)> {
    if is_content(rule) {
        return Ok((AccessRule::Public, Some(rule.clone())));
    }
    let AccessRule::All { rules } = rule else {
        return if has_content(rule) {
            Err(mixed_content(channel))
        } else {
            Ok((rule.clone(), None))
        };
    };
    let mut flat = Vec::new();
    flatten_all(rules, &mut flat);
    let (content, rest): (Vec<AccessRule>, Vec<AccessRule>) =
        flat.into_iter().partition(is_content);
    if rest.iter().any(has_content) {
        return Err(mixed_content(channel));
    }
    Ok((all_of(rest, AccessRule::Public), none_if_empty(content)))
}

fn mixed_content(channel: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "Channel '{channel}': the send rule mixes `Event` or `Payload` with caller or table \
         tests under an `Any` or a `Not`, which cannot be split between the database and the \
         realtime server without widening it. Put the event and payload checks in the \
         top-level `All`, beside the other tests"
    )
}

fn flatten_all(rules: &[AccessRule], out: &mut Vec<AccessRule>) {
    for rule in rules {
        match rule {
            AccessRule::All { rules: inner } if has_content(rule) => flatten_all(inner, out),
            other => out.push(other.clone()),
        }
    }
}

fn all_of(mut rules: Vec<AccessRule>, empty: AccessRule) -> AccessRule {
    match rules.len() {
        0 => empty,
        1 => rules.remove(0),
        _ => AccessRule::All { rules },
    }
}

fn none_if_empty(mut rules: Vec<AccessRule>) -> Option<AccessRule> {
    match rules.len() {
        0 => None,
        1 => Some(rules.remove(0)),
        _ => Some(AccessRule::All { rules }),
    }
}

// ---------------------------------------------------------------------------------------------
// Dependencies
// ---------------------------------------------------------------------------------------------

/// The tables a channel's rules read, for the realtime server to re-check a held channel when
/// one changes (stage J). Sorted and de-duplicated, so the function body is stable.
pub fn tables_read(channel: &ChannelAst) -> BTreeSet<String> {
    let access = &channel.access;
    let mut tables = BTreeSet::new();
    for rule in [&access.join, &access.send, &access.track]
        .into_iter()
        .flatten()
    {
        collect_tables(rule, &mut tables);
    }
    tables
}

fn collect_tables(rule: &AccessRule, out: &mut BTreeSet<String>) {
    match rule {
        AccessRule::Any { rules } | AccessRule::All { rules } => {
            rules.iter().for_each(|r| collect_tables(r, out))
        }
        AccessRule::Not { rule } => collect_tables(rule, out),
        AccessRule::In { source, .. } | AccessRule::Exists { source } => {
            if let MembershipSource::Rows { table, filter, .. } = source {
                out.insert(table.clone());
                if let Some(filter) = filter {
                    collect_tables(filter, out);
                }
            }
        }
        _ => {}
    }
}

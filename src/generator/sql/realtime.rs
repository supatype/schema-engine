//! Private realtime channels, compiled to SQL.
//!
//! A schema's `Channel<>` declarations become functions in `_supatype` that the realtime server
//! (and `realtime_send`) ask as the caller. All of it is re-asserted on every push, like the
//! `can_*` affordance functions: the functions hold every declaration, so removing one removes
//! its branch with no ledger bookkeeping, and a hand edit is overwritten.
//!
//! What is emitted:
//!
//! - `realtime_channel_access(topic)`: which declaration a topic matches and what the caller may do
//!   on it. `SECURITY INVOKER`, so a `Rows<>` subquery sees only the rows the caller can read,
//!   exactly as in a table policy.
//! - `realtime_channel_mode()`: `open` or `declared`.
//! - `realtime_channel_send_checks()`: the `Event` and `Payload` nodes of each `send` rule, for the
//!   server to evaluate per message.
//! - `realtime_channel_dependencies()`: the tables each channel's rules read.
//! - `realtime_outbox` and `realtime_send(topic, event, payload)`: broadcast from SQL.
//!
//! **Every function pins `search_path` to empty** and every name in a body is schema-qualified (or
//! lives in `pg_catalog`, which is always searched). A body that resolved a name through the
//! caller's `search_path` would let a caller who can create objects in a schema they control
//! substitute their own function or table for one the rule reads.

use crate::generator::sql::auth_functions::API_ROLES;
use crate::generator::sql::rls::access_rule_to_expr;
use crate::generator::sql::versions::HELPER_SCHEMA;
use crate::parser::ast::{
    AccessRule, ChannelAst, ChannelParamType, ModelAst, PayloadCheck, RealtimeAst, SchemaAst,
};
use crate::parser::channels::{parse_pattern, split_send_rule, tables_read, Segment};
use crate::sql_quote::{do_block, dollar_quote, quote_ident, quote_literal, quote_qualified};
use indexmap::IndexMap;

/// The alias of the one-row derived table a channel's parameters are read from. A constant rather
/// than the channel's name, so `Operand::Param` can render with no context: it is qualified by this
/// alias wherever it sits, including inside a `Rows<>` filter where a bare column would belong to
/// the source table. Chosen not to collide with a table a rule reads.
pub const PARAM_ALIAS: &str = "_realtime_channel";

pub const OUTBOX: &str = "realtime_outbox";

/// The dollar tag of the blocks that make the outbox's policies, which statement attribution reads.
pub const POLICY_TAG: &str = "rt_policy";

/// The dollar tag of the block that makes the outbox's delete-after-insert trigger.
pub const TRIGGER_TAG: &str = "rt_trigger";

/// The outbox's trigger, and the function it runs (one name for both).
pub const OUTBOX_TRIGGER: &str = "realtime_outbox_delete_row";

/// `[0-9a-fA-F]{8}-...`: the canonical form only. Postgres's own `uuid` input also accepts braces
/// and unhyphenated forms, which would let one channel have several topic spellings.
const UUID_RE: &str = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";
/// At most 18 digits, so the cast to `bigint` cannot overflow.
const INTEGER_RE: &str = "[0-9]{1,18}";
const STRING_RE: &str = "[^:]+";

/// One emitted function: everything `CREATE OR REPLACE FUNCTION` needs, and the body kept apart so
/// the drift check can compare it with `pg_proc.prosrc`, which holds the body verbatim.
#[derive(Debug, Clone)]
pub struct RealtimeFunction {
    pub name: &'static str,
    /// The declared argument list, as written.
    pub args: &'static str,
    /// What follows `RETURNS`.
    pub returns: &'static str,
    /// `LANGUAGE ... SET search_path`, the part between the return type and `AS`.
    pub attributes: &'static str,
    pub body: String,
    /// The roles that may call it. Everyone else, `PUBLIC` included, may not.
    pub callers: Vec<&'static str>,
}

impl RealtimeFunction {
    fn qualified(&self) -> String {
        quote_qualified(HELPER_SCHEMA, self.name)
    }

    /// The `CREATE OR REPLACE`, then the privileges.
    ///
    /// `REVOKE ... FROM PUBLIC` first: `_supatype` grants `EXECUTE` on every function in it to
    /// `PUBLIC` by default, so a function that is meant for some roles has to take it away.
    pub fn create_sql(&self) -> String {
        let signature = format!("{}({})", self.qualified(), self.arg_types());
        format!(
            "CREATE OR REPLACE FUNCTION {}({})\n  RETURNS {} {} AS {};\n\
             REVOKE ALL ON FUNCTION {signature} FROM PUBLIC;\n\
             GRANT EXECUTE ON FUNCTION {signature} TO {};\n",
            self.qualified(),
            self.args,
            self.returns,
            self.attributes,
            dollar_quote(&self.body, "rt"),
            self.callers.join(", ")
        )
    }

    /// The argument types alone, for a `GRANT`/`REVOKE` signature: `text, text, jsonb`.
    fn arg_types(&self) -> String {
        self.args
            .split(',')
            .filter_map(|arg| arg.split_whitespace().nth(1))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The access function's callers: every role the API connects as.
fn api_callers() -> Vec<&'static str> {
    API_ROLES.to_vec()
}

/// The functions a push re-asserts, in the order they are created. Every one is named in
/// [`FUNCTION_NAMES`], which the drift check reads.
pub fn functions(ast: &SchemaAst, schema: &str) -> Vec<RealtimeFunction> {
    vec![
        access_function(ast, schema),
        mode_function(ast.realtime.as_ref()),
        send_checks_function(ast),
        dependencies_function(ast, schema),
        content_function(ast),
        refusal_function(),
        send_function(),
        outbox_trigger_function(),
    ]
}

/// The names of [`functions`], for the drift check to read the live bodies of.
pub const FUNCTION_NAMES: [&str; 8] = [
    "realtime_channel_access",
    "realtime_channel_mode",
    "realtime_channel_send_checks",
    "realtime_channel_dependencies",
    "realtime_channel_content_ok",
    "realtime_send_refusal",
    "realtime_send",
    "realtime_outbox_delete_row",
];

/// Everything a push re-asserts for realtime, as one script: the outbox, then the functions, then
/// the outbox's policies (which call a function).
pub fn generate(ast: &SchemaAst, schema: &str) -> String {
    let mut out = outbox_table_sql();
    for function in functions(ast, schema) {
        out.push_str(&function.create_sql());
    }
    out.push_str(&outbox_policies_sql());
    out.push_str(&outbox_trigger_sql());
    out
}

// ---------------------------------------------------------------------------------------------
// Pattern to regular expression
// ---------------------------------------------------------------------------------------------

/// A pattern as a POSIX regular expression, with each parameter's group in `params` order.
///
/// `typed` decides what a parameter segment must look like: its declared type's shape (and a
/// capture group, to read it back) or any one segment. The typed form says whether a topic fits;
/// the shape form says whether it is trying to, which is how a topic that has the right prefix and
/// the wrong parameter is told apart from one that matches nothing.
fn pattern_regex(channel: &ChannelAst, segments: &[Segment], typed: bool) -> String {
    let mut out = String::from("^");
    for (i, segment) in segments.iter().enumerate() {
        out.push_str(&segment_regex(channel, segment, typed, i == 0));
    }
    out.push('$');
    out
}

fn segment_regex(channel: &ChannelAst, segment: &Segment, typed: bool, first: bool) -> String {
    let separator = if first { "" } else { ":" };
    match segment {
        Segment::Literal(text) => format!("{separator}{}", escape_literal(text)),
        Segment::Param(name) if typed => {
            format!("{separator}({})", param_regex(param_kind(channel, name)))
        }
        Segment::Param(_) => format!("{separator}{STRING_RE}"),
        // One or more remaining segments. Written with its own separator because it may be the
        // whole pattern.
        Segment::Wildcard if first => "[^:]+(:[^:]+)*".to_string(),
        Segment::Wildcard => "(:[^:]+)+".to_string(),
    }
}

/// Each character of a literal segment, made literal. The set a literal may hold is already
/// narrow (`parser::channels`); of it, `.` and `+` are regular expression syntax, so they go in a
/// bracket expression, where they are plain.
fn escape_literal(text: &str) -> String {
    text.chars()
        .map(|c| {
            if ".+".contains(c) {
                format!("[{c}]")
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn param_kind(channel: &ChannelAst, name: &str) -> ChannelParamType {
    channel
        .params
        .iter()
        .find(|p| p.name == name)
        .map_or(ChannelParamType::String, |p| p.kind)
}

fn param_regex(kind: ChannelParamType) -> &'static str {
    match kind {
        ChannelParamType::Uuid => UUID_RE,
        ChannelParamType::Integer => INTEGER_RE,
        ChannelParamType::String => STRING_RE,
    }
}

fn param_cast(kind: ChannelParamType) -> &'static str {
    match kind {
        ChannelParamType::Uuid => "uuid",
        ChannelParamType::Integer => "bigint",
        ChannelParamType::String => "text",
    }
}

// ---------------------------------------------------------------------------------------------
// realtime_channel_access
// ---------------------------------------------------------------------------------------------

/// The synthetic model a channel's rules render against: no fields, and the parameter alias as its
/// table, which is the name `In<>` qualifies a bare column with.
fn channel_model(channel: &ChannelAst) -> ModelAst {
    let mut model = ModelAst {
        name: channel.name.clone(),
        fields: IndexMap::new(),
        options: Default::default(),
        annotations: Default::default(),
    };
    model.annotations.db.table_name = PARAM_ALIAS.to_string();
    model
}

/// One operation's verdict as an expression, in three states: `NULL` when the declaration has no
/// rule for it (denied to every caller but the service role, which the server tells apart from a
/// denial), `FALSE` when a rule denies, `TRUE` when it admits. A rule that answers unknown is
/// `FALSE` (`COALESCE`), so a `NULL` from a rule can never be read as a grant or as "no rule".
fn verdict_sql(
    ast: &SchemaAst,
    model: &ModelAst,
    rule: Option<&AccessRule>,
    schema: &str,
) -> String {
    match rule {
        None => "NULL::boolean".to_string(),
        Some(rule) => format!(
            "COALESCE(({}), FALSE)",
            access_rule_to_expr(ast, model, rule, schema)
        ),
    }
}

/// The `send` rule with its content nodes taken out, which is the half the database decides.
fn send_sql_half(channel: &ChannelAst) -> Option<AccessRule> {
    // Validated by `parser::channels`; a rule that fails to split was refused there.
    channel
        .access
        .send
        .as_ref()
        .and_then(|rule| split_send_rule(&channel.name, rule).ok())
        .map(|(sql, _)| sql)
}

/// The three verdict columns of a channel's row.
fn verdicts(ast: &SchemaAst, channel: &ChannelAst, schema: &str) -> String {
    let model = channel_model(channel);
    let send = send_sql_half(channel);
    [
        verdict_sql(ast, &model, channel.access.join.as_ref(), schema),
        verdict_sql(ast, &model, send.as_ref(), schema),
        verdict_sql(ast, &model, channel.access.track.as_ref(), schema),
    ]
    .join(", ")
}

/// The three verdict columns when the caller may not read something a rule needs: every operation
/// that has a rule is denied, and one without a rule stays "no rule".
fn denied_verdicts(channel: &ChannelAst) -> String {
    let denied = |has_rule: bool| if has_rule { "FALSE" } else { "NULL::boolean" };
    [
        denied(channel.access.join.is_some()),
        denied(channel.access.send.is_some()),
        denied(channel.access.track.is_some()),
    ]
    .join(", ")
}

/// The parameters as a one-row derived table, each read from the topic only when the topic fits.
///
/// **The cast sits inside a `CASE` guarded by the typed shape**, and the branch that reads it runs
/// only after the typed shape matched, so a topic that does not fit never reaches `::uuid`. The
/// capture is read with the same typed expression, so it is a value of the type or `NULL`.
fn params_table(channel: &ChannelAst, segments: &[Segment], typed_regex: &str) -> String {
    let guard = quote_literal(typed_regex);
    let columns: Vec<String> = segments
        .iter()
        .filter_map(|s| match s {
            Segment::Param(name) => Some(name),
            _ => None,
        })
        .enumerate()
        .map(|(i, name)| {
            format!(
                "CASE WHEN $1 ~ {guard} THEN (pg_catalog.regexp_match($1, {guard}))[{}]::{} END AS {}",
                i + 1,
                param_cast(param_kind(channel, name)),
                quote_ident(name)
            )
        })
        .collect();
    format!(
        "FROM (SELECT {}) AS {}",
        columns.join(", "),
        quote_ident(PARAM_ALIAS)
    )
}

/// The first columns of every row: the declaration's name and pattern as literals.
fn identity_columns(channel: &ChannelAst) -> String {
    format!(
        "{}::text, {}::text",
        quote_literal(&channel.name),
        quote_literal(&channel.pattern)
    )
}

/// The block a topic that fits the channel answers with, and returns from.
///
/// **A rule that reads a table the caller has no privilege on raises `42501`**, since the function
/// is `SECURITY INVOKER`. That is a denial, not an error: each branch catches
/// `insufficient_privilege` and answers with the operations denied. Only that class is caught, so
/// a real fault (a bad cast, a missing table) still surfaces rather than reading as "denied".
fn fitting_branch(
    ast: &SchemaAst,
    channel: &ChannelAst,
    segments: &[Segment],
    schema: &str,
) -> String {
    let typed = pattern_regex(channel, segments, true);
    let has_params = segments.iter().any(|s| matches!(s, Segment::Param(_)));
    let from = if has_params {
        format!(" {}", params_table(channel, segments, &typed))
    } else {
        String::new()
    };
    let is_literal = segments.iter().all(|s| matches!(s, Segment::Literal(_)));
    let matches_topic = if is_literal {
        format!("$1 = {}", quote_literal(&channel.pattern))
    } else {
        format!("$1 ~ {}", quote_literal(&typed))
    };
    let id = identity_columns(channel);
    format!(
        "  -- {name}: {pattern}\n  IF {matches_topic} THEN\n    BEGIN\n      \
         RETURN QUERY SELECT {id}, TRUE, NULL::text, {verdicts}{from};\n    \
         EXCEPTION WHEN insufficient_privilege THEN\n      \
         RETURN QUERY SELECT {id}, TRUE, NULL::text, {denied};\n    END;\n    RETURN;\n  END IF;",
        name = channel.name.replace(['\n', '\r'], " "),
        pattern = channel.pattern.replace(['\n', '\r'], " "),
        verdicts = verdicts(ast, channel, schema),
        denied = denied_verdicts(channel),
    )
}

/// The shape of a pattern with each parameter captured as one segment, for reading back which
/// parameter a topic got wrong.
fn shape_capture_regex(channel: &ChannelAst, segments: &[Segment]) -> String {
    let mut out = String::from("^");
    for (i, segment) in segments.iter().enumerate() {
        match segment {
            Segment::Param(_) => {
                out.push_str(&format!("{}({STRING_RE})", if i == 0 { "" } else { ":" }))
            }
            other => out.push_str(&segment_regex(channel, other, false, i == 0)),
        }
    }
    out.push('$');
    out
}

/// "id must be a UUID": the first typed parameter whose segment is not a value of its type, as a
/// `CASE` over the captured segments.
fn param_error_sql(channel: &ChannelAst, segments: &[Segment]) -> String {
    let capture = quote_literal(&shape_capture_regex(channel, segments));
    let arms: Vec<String> = segments
        .iter()
        .filter_map(|s| match s {
            Segment::Param(name) => Some(name),
            _ => None,
        })
        .enumerate()
        .filter_map(|(i, name)| {
            let (kind, words) = match param_kind(channel, name) {
                ChannelParamType::Uuid => (ChannelParamType::Uuid, "a UUID"),
                ChannelParamType::Integer => (ChannelParamType::Integer, "an integer"),
                ChannelParamType::String => return None,
            };
            Some(format!(
                "WHEN m[{}] !~ {} THEN {}",
                i + 1,
                quote_literal(&format!("^{}$", param_regex(kind))),
                quote_literal(&format!("{name} must be {words}"))
            ))
        })
        .collect();
    format!(
        "(SELECT CASE {} END FROM (SELECT pg_catalog.regexp_match($1, {capture}) AS m) AS shape)",
        arms.join(" ")
    )
}

/// The block a topic that has the channel's shape but not a parameter's type answers with: it does
/// not fit, says why, and may do nothing. Only a channel with a typed parameter can have one.
fn misfit_branch(channel: &ChannelAst, segments: &[Segment]) -> Option<String> {
    if channel
        .params
        .iter()
        .all(|p| p.kind == ChannelParamType::String)
    {
        return None;
    }
    Some(format!(
        "  -- {name}: {pattern}, a topic of this shape whose parameters do not fit\n  \
         IF $1 ~ {shape} AND $1 !~ {typed} THEN\n    \
         RETURN QUERY SELECT {id}, FALSE, {error}, {denied};\n    RETURN;\n  END IF;",
        name = channel.name.replace(['\n', '\r'], " "),
        pattern = channel.pattern.replace(['\n', '\r'], " "),
        id = identity_columns(channel),
        error = param_error_sql(channel, segments),
        denied = denied_verdicts(channel),
        shape = quote_literal(&pattern_regex(channel, segments, false)),
        typed = quote_literal(&pattern_regex(channel, segments, true)),
    ))
}

/// The longest topic that is looked at. Anything longer answers no row before a regular
/// expression runs on it, so a hostile topic cannot cost more than a length test.
const MAX_TOPIC_CHARS: usize = 255;

fn access_body(ast: &SchemaAst, schema: &str) -> String {
    let mut blocks = Vec::new();
    for channel in &ast.channels {
        // Validated at parse; an AST that skipped it contributes no branch rather than a wrong one.
        let Ok(segments) = parse_pattern(&channel.name, &channel.pattern) else {
            continue;
        };
        blocks.push(fitting_branch(ast, channel, &segments, schema));
        blocks.extend(misfit_branch(channel, &segments));
    }
    format!(
        "\n#variable_conflict use_column\nBEGIN\n  IF pg_catalog.char_length($1) > {MAX_TOPIC_CHARS} THEN\n    RETURN;\n  END IF;\n{}\n  RETURN;\nEND;\n",
        blocks.join("\n")
    )
}

fn access_function(ast: &SchemaAst, schema: &str) -> RealtimeFunction {
    RealtimeFunction {
        name: "realtime_channel_access",
        args: "topic text",
        returns: "TABLE (channel text, pattern text, fits boolean, param_error text, can_join boolean, can_send boolean, can_track boolean)",
        // INVOKER: the rules run as the caller, so a `Rows<>` subquery is bound by the caller's
        // row level security, as in a table policy. DEFINER would answer as the owner, who reads
        // every row, and grant what the caller cannot see. plpgsql rather than sql so each branch
        // can turn a privilege error into a denial.
        attributes: "LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = ''",
        body: access_body(ast, schema),
        callers: api_callers(),
    }
}

// ---------------------------------------------------------------------------------------------
// Mode, send checks, dependencies
// ---------------------------------------------------------------------------------------------

fn mode_function(realtime: Option<&RealtimeAst>) -> RealtimeFunction {
    let mode = realtime.map_or("open", |r| r.channels.as_str());
    RealtimeFunction {
        name: "realtime_channel_mode",
        args: "",
        returns: "text",
        attributes: "LANGUAGE sql STABLE SET search_path = ''",
        body: format!(" SELECT {}::text ", quote_literal(mode)),
        callers: api_callers(),
    }
}

/// `VALUES` rows as a table, or the empty table of the same shape.
fn rows_or_empty(rows: &[String], columns: &str, empty: &str) -> String {
    if rows.is_empty() {
        return format!("\n  SELECT {empty}\n  WHERE FALSE\n");
    }
    format!(
        "\n  SELECT * FROM (VALUES\n{}\n  ) AS v({columns})\n",
        rows.join(",\n")
    )
}

/// The content half of each `send` rule that has one, as the AST's own JSON (`{"type":"all",
/// "rules":[{"type":"event",...}]}`), which the server evaluates against each message. A channel
/// whose `send` rule has no `Event` or `Payload` has no row.
fn send_checks_function(ast: &SchemaAst) -> RealtimeFunction {
    let rows: Vec<String> = ast
        .channels
        .iter()
        .filter_map(|c| content_half(c).map(|rule| (c, rule)))
        .filter_map(|(c, rule)| serde_json::to_string(&rule).ok().map(|json| (c, json)))
        .map(|(c, json)| {
            format!(
                "    ({}::text, {}::jsonb)",
                quote_literal(&c.name),
                quote_literal(&json)
            )
        })
        .collect();
    RealtimeFunction {
        name: "realtime_channel_send_checks",
        args: "",
        returns: "TABLE (channel text, checks jsonb)",
        attributes: "LANGUAGE sql STABLE SET search_path = ''",
        body: rows_or_empty(&rows, "channel, checks", "NULL::text, NULL::jsonb"),
        callers: api_callers(),
    }
}

fn content_half(channel: &ChannelAst) -> Option<AccessRule> {
    let rule = channel.access.send.as_ref()?;
    split_send_rule(&channel.name, rule).ok()?.1
}

/// Every table a channel's rules read, in the managed schema, for stage J's re-check on change.
fn dependencies_function(ast: &SchemaAst, schema: &str) -> RealtimeFunction {
    let rows: Vec<String> = ast
        .channels
        .iter()
        .flat_map(|c| tables_read(c).into_iter().map(move |t| (c, t)))
        .map(|(c, table)| {
            format!(
                "    ({}::text, {}::text, {}::text)",
                quote_literal(&c.name),
                quote_literal(schema),
                quote_literal(&table)
            )
        })
        .collect();
    RealtimeFunction {
        name: "realtime_channel_dependencies",
        args: "",
        returns: "TABLE (channel text, table_schema text, table_name text)",
        attributes: "LANGUAGE sql STABLE SET search_path = ''",
        body: rows_or_empty(
            &rows,
            "channel, table_schema, table_name",
            "NULL::text, NULL::text, NULL::text",
        ),
        callers: api_callers(),
    }
}

// ---------------------------------------------------------------------------------------------
// Content rules in SQL (for realtime_send)
// ---------------------------------------------------------------------------------------------

/// A content rule as a boolean expression over the event (`$2`) and the payload (`$3`).
///
/// The same semantics the realtime server applies, and **failing closed**: a field that is absent
/// or of another type fails every kind except `Required`. A numeric test is a `CASE` on the type,
/// so a string in the field is "no", not a cast error.
fn content_sql(rule: &AccessRule) -> String {
    match rule {
        AccessRule::Event { name } => format!("$2 = {}", quote_literal(name)),
        AccessRule::Payload { field, check } => payload_sql(field, check),
        AccessRule::Any { rules } => join_content(rules, " OR "),
        AccessRule::All { rules } => join_content(rules, " AND "),
        AccessRule::Not { rule } => format!("NOT ({})", content_sql(rule)),
        // Not content: `split_send_rule` leaves these out of the content half.
        _ => "FALSE".to_string(),
    }
}

fn join_content(rules: &[AccessRule], joiner: &str) -> String {
    rules
        .iter()
        .map(|r| format!("({})", content_sql(r)))
        .collect::<Vec<_>>()
        .join(joiner)
}

fn payload_sql(field: &str, check: &PayloadCheck) -> String {
    let value = format!("($3 -> {})", quote_literal(field));
    let kind = format!("pg_catalog.jsonb_typeof({value})");
    let text = format!("({value} #>> '{{}}')");
    match check {
        PayloadCheck::Required => format!("{value} IS NOT NULL AND {kind} <> 'null'"),
        PayloadCheck::Boolean => format!("{kind} = 'boolean'"),
        PayloadCheck::String { max_length } => {
            let limit = max_length.map_or(String::new(), |n| {
                format!(" AND pg_catalog.char_length({text}) <= {n}")
            });
            format!("{kind} = 'string'{limit}")
        }
        PayloadCheck::Number { min, max } => {
            let bounds: Vec<String> = [(">=", min), ("<=", max)]
                .into_iter()
                .filter_map(|(op, bound)| bound.map(|b| format!("{text}::numeric {op} {b}")))
                .collect();
            let bounds = if bounds.is_empty() {
                "TRUE".to_string()
            } else {
                bounds.join(" AND ")
            };
            format!("CASE WHEN {kind} = 'number' THEN {bounds} ELSE FALSE END")
        }
    }
}

fn content_function(ast: &SchemaAst) -> RealtimeFunction {
    let arms: Vec<String> = ast
        .channels
        .iter()
        .filter_map(|c| content_half(c).map(|rule| (c, rule)))
        .map(|(c, rule)| {
            format!(
                "    WHEN {} THEN COALESCE(({}), FALSE)",
                quote_literal(&c.name),
                content_sql(&rule)
            )
        })
        .collect();
    let body = if arms.is_empty() {
        " SELECT TRUE ".to_string()
    } else {
        format!(
            "\n  SELECT CASE $1\n{}\n    ELSE TRUE\n  END\n",
            arms.join("\n")
        )
    };
    RealtimeFunction {
        name: "realtime_channel_content_ok",
        args: "channel text, event text, payload jsonb",
        returns: "boolean",
        attributes: "LANGUAGE sql STABLE SET search_path = ''",
        body,
        callers: vec!["authenticated", "service_role"],
    }
}

// ---------------------------------------------------------------------------------------------
// realtime_send
// ---------------------------------------------------------------------------------------------

/// Why a send is refused, or `NULL` when it is allowed. One function answers for both
/// `realtime_send` (which raises it) and the outbox's insert policy (which requires `NULL`), so a
/// direct insert into the outbox is judged exactly as a call is.
///
/// The wording is section 7's. A `NULL` `can_send` is "no send rule", a `FALSE` a denial.
fn refusal_function() -> RealtimeFunction {
    let body = format!(
        "\n  SELECT CASE\n\
         \x20     WHEN {SERVICE} THEN NULL\n\
         \x20     WHEN a.channel IS NULL THEN\n\
         \x20       CASE WHEN {S}.realtime_channel_mode() = 'declared' THEN\n\
         \x20         $1 || ' matches no declared channel, and this project refuses broadcast and presence on undeclared channels (realtime.channels is \"declared\")'\n\
         \x20       END\n\
         \x20     WHEN NOT a.fits THEN $1 || ' does not fit ' || a.pattern || ': ' || a.param_error\n\
         \x20     WHEN a.can_send IS NULL THEN a.channel || ' declares no send rule, so only the service role may broadcast on ' || $1\n\
         \x20     WHEN NOT a.can_send THEN 'not allowed to broadcast on ' || $1 || ': the send rule of ' || a.channel || ' denied it'\n\
         \x20     WHEN NOT {S}.realtime_channel_content_ok(a.channel, $2, $3) THEN\n\
         \x20       'not allowed to broadcast ' || $2 || ' on ' || $1 || ': the send rule of ' || a.channel || ' refused the payload'\n\
         \x20   END\n\
         \x20   FROM (SELECT 1) AS one\n\
         \x20   LEFT JOIN {S}.realtime_channel_access($1) AS a ON TRUE\n  ",
        S = quote_ident(HELPER_SCHEMA),
        SERVICE = SERVICE_CALLER,
    );
    RealtimeFunction {
        name: "realtime_send_refusal",
        args: "topic text, event text, payload jsonb",
        returns: "text",
        // INVOKER, as the access function it calls: the caller is judged, not the owner.
        attributes: "LANGUAGE sql STABLE SECURITY INVOKER SET search_path = ''",
        body,
        callers: vec!["authenticated", "service_role"],
    }
}

/// Whether the caller is the service role, or a superuser (a migration, `pg_cron`, an operator in
/// `psql`), which has no row security to be judged by. Read from `current_user`, which only
/// `SET ROLE` can change, and `SET ROLE` is checked against role membership: unlike a setting or
/// a claim, a caller cannot claim to be the service role.
const SERVICE_CALLER: &str = "(current_user = 'service_role' OR COALESCE((SELECT r.rolsuper FROM pg_catalog.pg_roles AS r WHERE r.rolname = current_user), FALSE))";

/// `realtime_send(topic, event, payload)`: broadcast from SQL.
///
/// **`SECURITY INVOKER`, not `DEFINER`.** The send rule has to be judged as the caller, because a
/// `Rows<>` in it reads tables under the caller's row level security. A `SECURITY DEFINER`
/// function cannot do that: Postgres refuses `SET ROLE` inside one (`cannot set parameter "role"
/// within security-definer function`), and calling the access function from inside it runs it as
/// the owner, who reads every row. So the check runs here as the caller, and the write is made
/// under the outbox's own row level security (see [`outbox_policies_sql`]), whose insert policy
/// asks the same [`refusal_function`]. Calling `realtime_send` or inserting directly is judged by
/// one function either way.
///
/// The row is deleted by the outbox's own trigger ([`outbox_trigger_function`]) as it is inserted,
/// exactly as a direct insert is: the insert reaches the replication slot the realtime server
/// reads, and the table never accumulates. This function carries no delete of its own, so there
/// is one place that guarantees it.
fn send_function() -> RealtimeFunction {
    let body = format!(
        "\nDECLARE\n  refusal text := {S}.realtime_send_refusal(topic, event, payload);\nBEGIN\n  \
         IF refusal IS NOT NULL THEN\n    RAISE EXCEPTION '%', refusal USING ERRCODE = '42501';\n  END IF;\n  \
         INSERT INTO {S}.{OUTBOX} (topic, event, payload, sender)\n    \
         VALUES (topic, event, payload, {S}.jwt_uid());\nEND;\n",
        S = quote_ident(HELPER_SCHEMA),
        OUTBOX = quote_ident(OUTBOX),
    );
    RealtimeFunction {
        name: "realtime_send",
        args: "topic text, event text, payload jsonb DEFAULT '{}'::jsonb",
        returns: "void",
        attributes: "LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = ''",
        body,
        callers: vec!["authenticated", "service_role"],
    }
}

/// The trigger function that empties the outbox: deletes the row just inserted, by its id.
///
/// **`SECURITY INVOKER`**, the narrowest privilege that always deletes. The caller of a direct
/// insert can delete exactly the row they were let insert: the insert policy requires `sender` to
/// be them and the delete policy admits their own rows. `service_role` has a policy for every
/// row, and a superuser meets none. A `SECURITY DEFINER` body would run as the owner and skip
/// every policy, and buys nothing. It is an `AFTER` trigger, so the row is written and logged
/// before it is deleted: the realtime server still reads the insert from the replication slot.
fn outbox_trigger_function() -> RealtimeFunction {
    let body = format!(
        "\nBEGIN\n  DELETE FROM {S}.{OUTBOX} WHERE id = NEW.id;\n  RETURN NULL;\nEND;\n",
        S = quote_ident(HELPER_SCHEMA),
        OUTBOX = quote_ident(OUTBOX),
    );
    RealtimeFunction {
        name: OUTBOX_TRIGGER,
        args: "",
        returns: "trigger",
        attributes: "LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = ''",
        body,
        callers: vec!["authenticated", "service_role"],
    }
}

/// The trigger itself: made when absent or not as wanted (changed, or disabled), and left alone
/// otherwise, because replacing a trigger locks the table and a push that changed nothing has no
/// reason to. `ENABLE ALWAYS`, so it also fires under `session_replication_role = replica`, which
/// would otherwise let a row stay. `tgtype = 5` is row-level (1) and `AFTER` (0) and `INSERT` (4).
fn outbox_trigger_sql() -> String {
    let table = quote_qualified(HELPER_SCHEMA, OUTBOX);
    let function = quote_qualified(HELPER_SCHEMA, OUTBOX_TRIGGER);
    let name = quote_ident(OUTBOX_TRIGGER);
    do_block(
        TRIGGER_TAG,
        &format!(
            "\nBEGIN\n  IF NOT EXISTS (\n    SELECT 1 FROM pg_catalog.pg_trigger\n    WHERE tgrelid = {rel}::regclass AND tgname = {name_literal}\n      AND tgfoid = {func}::regproc AND tgenabled = 'A' AND tgtype = 5\n  ) THEN\n    CREATE OR REPLACE TRIGGER {name} AFTER INSERT ON {table}\n      FOR EACH ROW EXECUTE FUNCTION {function}();\n    ALTER TABLE {table} ENABLE ALWAYS TRIGGER {name};\n  END IF;\nEND;\n",
            rel = quote_literal(&table),
            name_literal = quote_literal(OUTBOX_TRIGGER),
            func = quote_literal(&function),
        ),
    ) + "\n"
}

// ---------------------------------------------------------------------------------------------
// The outbox
// ---------------------------------------------------------------------------------------------

/// The outbox table, its privileges and its row level security.
///
/// The key is an identity column, not the contract's `bigserial`: the two are the same type and
/// default, but a caller inserting into a `bigserial` needs `USAGE` on its sequence, which would
/// be a second grant to `authenticated`, and an identity column needs none.
///
/// A row is deleted by a trigger as it is written ([`outbox_trigger_function`]), so the realtime
/// server sees the insert on its replication slot and nothing is left behind, whoever inserted. `authenticated` holds `INSERT`, `SELECT` and
/// `DELETE` on it, and each is bounded by a policy: a caller can insert only what
/// [`refusal_function`] allows, as itself, and see or delete only its own rows. `anon` holds
/// nothing, so a call without a login is refused before any policy is read.
fn outbox_table_sql() -> String {
    let table = quote_qualified(HELPER_SCHEMA, OUTBOX);
    format!(
        "CREATE TABLE IF NOT EXISTS {table} (\n  \
         id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,\n  \
         topic text NOT NULL,\n  \
         event text NOT NULL,\n  \
         payload jsonb NOT NULL DEFAULT '{{}}'::jsonb,\n  \
         sender uuid,\n  \
         created_at timestamptz NOT NULL DEFAULT now()\n);\n\
         ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;\n\
         REVOKE ALL ON {table} FROM PUBLIC, anon;\n\
         GRANT INSERT, SELECT, DELETE ON {table} TO authenticated;\n\
         GRANT ALL ON {table} TO service_role;\n"
    )
}

fn outbox_policies_sql() -> String {
    let table = quote_qualified(HELPER_SCHEMA, OUTBOX);
    let s = quote_ident(HELPER_SCHEMA);
    // Wrapped in a SELECT so the planner evaluates the caller once per query, not once per row.
    let own = format!("sender IS NOT DISTINCT FROM (SELECT {s}.jwt_uid())");
    let policy = |name: &str, command: &str, to: &str, clause: &str, expr: &str| {
        // Made if absent, altered if present, never dropped: a drop and create would leave the
        // outbox with no policy between the two statements, and a push is not the place to
        // learn what that does to a send in flight. `ALTER POLICY` cannot change the command, and
        // the command of each is fixed here.
        let name = quote_ident(name);
        let alter_clause = format!("{clause} ({expr})");
        let policy_name = quote_literal(&name.replace('"', ""));
        do_block(
            POLICY_TAG,
            &format!(
                "\nBEGIN\n  IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy WHERE polrelid = {rel}::regclass AND polname = {policy_name}) THEN\n    ALTER POLICY {name} ON {table} TO {to} {alter_clause};\n  ELSE\n    CREATE POLICY {name} ON {table} AS PERMISSIVE FOR {command} TO {to} {clause} ({expr});\n  END IF;\nEND;\n",
                rel = quote_literal(&table),
            ),
        ) + "\n"
    };
    [
        policy(
            "realtime_outbox_insert",
            "INSERT",
            "authenticated",
            "WITH CHECK",
            &format!("{s}.realtime_send_refusal(topic, event, payload) IS NULL AND {own}"),
        ),
        policy(
            "realtime_outbox_select",
            "SELECT",
            "authenticated",
            "USING",
            &own,
        ),
        policy(
            "realtime_outbox_delete",
            "DELETE",
            "authenticated",
            "USING",
            &own,
        ),
        policy(
            "realtime_outbox_service",
            "ALL",
            "service_role",
            "USING",
            "TRUE",
        ),
    ]
    .concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ast::{ChannelAccessAst, ChannelParamAst};

    fn channel(pattern: &str, params: &[(&str, ChannelParamType)]) -> ChannelAst {
        ChannelAst {
            name: "Ch".into(),
            pattern: pattern.into(),
            params: params
                .iter()
                .map(|(name, kind)| ChannelParamAst {
                    name: (*name).into(),
                    kind: *kind,
                })
                .collect(),
            access: ChannelAccessAst::default(),
        }
    }

    fn regex(c: &ChannelAst, typed: bool) -> String {
        pattern_regex(c, &parse_pattern("Ch", &c.pattern).unwrap(), typed)
    }

    #[test]
    fn a_literal_pattern_is_anchored_and_escaped() {
        let c = channel("v1.2:lobby+", &[]);
        assert_eq!(regex(&c, true), "^v1[.]2:lobby[+]$");
    }

    #[test]
    fn a_uuid_parameter_is_typed_in_one_form_and_any_segment_in_the_other() {
        let c = channel("lot:{id}", &[("id", ChannelParamType::Uuid)]);
        assert_eq!(regex(&c, true), format!("^lot:({UUID_RE})$"));
        assert_eq!(regex(&c, false), "^lot:[^:]+$");
    }

    #[test]
    fn a_trailing_wildcard_takes_one_or_more_segments_and_never_none() {
        assert_eq!(regex(&channel("org:*", &[]), true), "^org(:[^:]+)+$");
        assert_eq!(regex(&channel("*", &[]), true), "^[^:]+(:[^:]+)*$");
    }

    #[test]
    fn the_payload_number_check_casts_only_after_the_type_test() {
        let sql = payload_sql(
            "amount",
            &PayloadCheck::Number {
                min: Some(1.0),
                max: None,
            },
        );
        assert!(
            sql.starts_with("CASE WHEN pg_catalog.jsonb_typeof"),
            "{sql}"
        );
        assert!(sql.contains("::numeric >= 1"), "{sql}");
        assert!(sql.ends_with("ELSE FALSE END"), "{sql}");
    }
}

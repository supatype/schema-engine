use super::{Operation, Risk};
use crate::generator::sql::rls::access_rule_to_expr;
use crate::parser::ast::{AccessAst, AccessRule, SchemaAst};
use crate::state::database_state::DatabaseState;
use anyhow::Result;

/// Policy naming convention; must match generator/sql/rls.rs.
/// `polcmd` column from pg_policy: r=SELECT, a=INSERT, w=UPDATE, d=DELETE, *=ALL.
pub(crate) fn expected_policies(access: &AccessAst) -> Vec<(String, Option<&AccessRule>)> {
    vec![
        ("select".to_string(), access.read.as_ref()),
        ("insert".to_string(), access.create.as_ref()),
        ("update".to_string(), access.update.as_ref()),
        ("delete".to_string(), access.delete.as_ref()),
    ]
    .into_iter()
    .filter_map(|(suffix, rule)| rule.map(|r| (suffix, Some(r))))
    .collect()
}

/// Canonicalise an RLS expression for comparison.
///
/// Postgres rewrites expressions when it stores a policy: it wraps them in
/// parentheses, drops the `auth.` schema prefix (since `auth` is in the search
/// path), and may quote identifiers. A naive string compare against the engine's
/// generated SQL therefore always differs, so every policy looks "changed" and is
/// needlessly dropped/recreated on every push. We strip those incidental
/// differences (schema prefix, parentheses, quotes, whitespace) so an unchanged
/// policy compares equal and is left untouched. The same transform is applied to
/// both sides, so it only ever collapses incidental formatting, never semantics.
/// Postgres also qualifies columns on the policy's own table (`photo.album_id` vs
/// `album_id` in generated SQL). Strip only that table prefix so subquery refs
/// like `album.owner_id` are preserved.
///
/// Two more rewrites Postgres applies, each of which otherwise made every policy
/// look changed on every push:
///   * boolean literals are stored lowercase: generated `FALSE` vs stored `false`
///     (Private/Public rules produce nothing but these, so they never converged);
///   * literals gain an explicit cast: generated `'admin'` vs stored `'admin'::text`;
///   * a scalar subquery gains an output alias: generated `(SELECT auth.uid())` vs
///     stored `( SELECT auth.uid() AS uid)`. Auth calls are wrapped in exactly that
///     shape so the planner evaluates them once per query, so without this every
///     policy would look changed on every push.
fn normalise(s: &str, table: &str) -> String {
    // First, while the `INTERVAL` keyword and the `::interval` cast are both still
    // present to mark which literals are intervals. Both are removed further down.
    let mut out = canonicalise_interval_literals(s).replace("auth.", "");
    // Parens become spaces rather than vanishing. Deleting them welded tokens
    // together on one side only: generated `ANY(ARRAY[…])` collapsed to
    // `ANYARRAY[…]` while Postgres stores `ANY (ARRAY[…])`, which survives as
    // `ANY ARRAY[…]`, so every multi-role policy was dropped and recreated on
    // every push. The trailing whitespace collapse makes the substitution free.
    out = out
        .chars()
        .map(|c| if c == '(' || c == ')' { ' ' } else { c })
        .filter(|c| *c != '"')
        .collect();
    // Postgres drops a schema qualification when the schema is in the search path,
    // so stored `FROM posts` has to match generated `FROM "public"."posts"`.
    // Membership sources are generated schema-qualified so a `can_*` function's
    // derived table cannot shadow the real one; without this, every policy with a
    // membership test would look changed on every push. Stripped after the quotes
    // are gone, since the generated form is `"public".` rather than `public.`.
    out = out.replace("public.", "");

    let table_prefix = format!("{table}.");
    out = out.replace(&table_prefix, "");
    out = canonicalise_keywords_and_casts(&out);
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Postgres's internal interval representation: months, days and microseconds, kept
/// apart because it never folds one into another. `30 days` is stored as 30 days, not
/// as one month, so collapsing them here would make two different intervals compare
/// equal.
#[derive(Clone, Copy, PartialEq, Eq)]
struct IntervalParts {
    months: i64,
    days: i64,
    micros: i64,
}

/// `HH:MM:SS[.ffffff]`, optionally negative, as Postgres prints the time component.
/// Hours are not bounded by 24.
fn parse_interval_clock(token: &str) -> Option<i64> {
    let (negative, body) = match token.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, token),
    };
    let mut fields = body.split(':');
    let hours: i64 = fields.next()?.parse().ok()?;
    let minutes: i64 = fields.next()?.parse().ok()?;
    let seconds_field = fields.next()?;
    if fields.next().is_some() {
        return None;
    }
    let (seconds, micros) = match seconds_field.split_once('.') {
        Some((whole, fraction)) => {
            if fraction.is_empty()
                || fraction.len() > 6
                || !fraction.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            let mut padded = fraction.to_string();
            while padded.len() < 6 {
                padded.push('0');
            }
            (whole.parse::<i64>().ok()?, padded.parse::<i64>().ok()?)
        }
        None => (seconds_field.parse::<i64>().ok()?, 0),
    };
    if hours < 0 || minutes < 0 || seconds < 0 {
        return None;
    }
    let total = hours
        .checked_mul(3_600_000_000)?
        .checked_add(minutes.checked_mul(60_000_000)?)?
        .checked_add(seconds.checked_mul(1_000_000)?)?
        .checked_add(micros)?;
    Some(if negative { -total } else { total })
}

/// Unit words Postgres accepts on input or prints on output. Single letters are
/// deliberately absent: `m` is ambiguous between months and minutes, and neither the
/// generator nor Postgres emits it, so accepting it could only ever guess wrong.
fn add_interval_unit(parts: &mut IntervalParts, amount: i64, unit: &str) -> Option<()> {
    match unit.to_ascii_lowercase().as_str() {
        "year" | "years" | "yr" | "yrs" => {
            parts.months = parts.months.checked_add(amount.checked_mul(12)?)?
        }
        "mon" | "mons" | "month" | "months" => parts.months = parts.months.checked_add(amount)?,
        "week" | "weeks" => parts.days = parts.days.checked_add(amount.checked_mul(7)?)?,
        "day" | "days" => parts.days = parts.days.checked_add(amount)?,
        "hour" | "hours" | "hr" | "hrs" => {
            parts.micros = parts
                .micros
                .checked_add(amount.checked_mul(3_600_000_000)?)?
        }
        "min" | "mins" | "minute" | "minutes" => {
            parts.micros = parts.micros.checked_add(amount.checked_mul(60_000_000)?)?
        }
        "sec" | "secs" | "second" | "seconds" => {
            parts.micros = parts.micros.checked_add(amount.checked_mul(1_000_000)?)?
        }
        _ => return None,
    }
    Some(())
}

/// Parse either spelling of an interval literal into its parts.
///
/// Covers the input grammar the generator emits (`30 days 9 hours`) and the output
/// grammar Postgres prints (`30 days 09:00:00`, `7 mons`, `1 year 2 mons -00:00:07`).
/// Returns `None` for anything it does not fully understand, which is what keeps a
/// literal it cannot read from being rewritten into something that compares wrongly.
fn parse_interval(text: &str) -> Option<IntervalParts> {
    let mut parts = IntervalParts {
        months: 0,
        days: 0,
        micros: 0,
    };
    let mut tokens = text.split_whitespace().peekable();
    let mut saw_component = false;
    let mut negate_all = false;

    while let Some(token) = tokens.next() {
        if token.eq_ignore_ascii_case("ago") {
            if tokens.peek().is_some() {
                return None;
            }
            negate_all = true;
            break;
        }
        if token.contains(':') {
            parts.micros = parts.micros.checked_add(parse_interval_clock(token)?)?;
            saw_component = true;
            continue;
        }
        let amount: i64 = token.parse().ok()?;
        let unit = tokens.next()?;
        add_interval_unit(&mut parts, amount, unit)?;
        saw_component = true;
    }

    if !saw_component {
        return None;
    }
    if negate_all {
        parts = IntervalParts {
            months: parts.months.checked_neg()?,
            days: parts.days.checked_neg()?,
            micros: parts.micros.checked_neg()?,
        };
    }
    Some(parts)
}

/// True when `haystack` ends with `word` as a whole word, ignoring trailing space.
fn ends_with_word(haystack: &str, word: &str) -> bool {
    let trimmed = haystack.trim_end();
    let Some(head) = trimmed.get(trimmed.len().saturating_sub(word.len())..) else {
        return false;
    };
    if !head.eq_ignore_ascii_case(word) {
        return false;
    }
    let before = trimmed.len() - head.len();
    trimmed[..before]
        .chars()
        .next_back()
        .is_none_or(|c| !c.is_alphanumeric() && c != '_')
}

/// Rewrite interval literals to one canonical form, in whichever spelling they arrive.
///
/// Postgres canonicalises an interval when it stores it, and only two of the seven units
/// survive the round trip verbatim: `INTERVAL '7 hours'` comes back as `'07:00:00'`,
/// `'7 weeks'` as `'49 days'`, `'7 months'` as `'7 mons'`. `normalise` copies string
/// literals verbatim by design, so without this pass an access rule using any of the
/// other five generates a policy that looks changed on every push and is dropped and
/// recreated each time, which is the exact failure the convergence suite exists to catch.
///
/// Only literals actually marked as intervals are touched, by the `INTERVAL` keyword
/// before or the `::interval` cast after. Canonicalising every literal that happened to
/// parse would be simpler and would quietly rewrite a text value that reads like a
/// duration; in a policy a wrong comparison is a security question, not a cosmetic one.
/// Anything this cannot parse is left exactly as it was, so the pass can only ever make
/// two spellings of one interval agree, never make two different intervals agree.
fn canonicalise_interval_literals(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut index = 0;

    while index < chars.len() {
        if chars[index] != '\'' {
            out.push(chars[index]);
            index += 1;
            continue;
        }

        let literal_start = index;
        index += 1;
        let mut content = String::new();
        let mut terminated = false;
        while index < chars.len() {
            if chars[index] == '\'' {
                if chars.get(index + 1) == Some(&'\'') {
                    content.push('\'');
                    index += 2;
                    continue;
                }
                index += 1;
                terminated = true;
                break;
            }
            content.push(chars[index]);
            index += 1;
        }
        if !terminated {
            // Unterminated literal: copy the remainder untouched rather than guess.
            out.extend(chars[literal_start..].iter());
            return out;
        }

        let trailing: String = chars[index..].iter().collect();
        let marked_by_cast = trailing
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("::interval");
        let marked_by_keyword = ends_with_word(&out, "interval");

        match (marked_by_cast || marked_by_keyword)
            .then(|| parse_interval(&content))
            .flatten()
        {
            Some(parts) => {
                out.push('\'');
                out.push_str(&format!("{}/{}/{}", parts.months, parts.days, parts.micros));
                out.push('\'');
            }
            None => {
                out.extend(chars[literal_start..index].iter());
            }
        }
    }
    out
}

/// Single quote-aware pass that removes `::type` casts, drops `AS <alias>` and
/// lowercases the bare keywords `TRUE`/`FALSE`/`NULL`. String literals are copied
/// verbatim, so a role name like `'Admin'` keeps its case, a `::` inside a literal
/// is not treated as a cast, and the words "as" inside one are not mistaken for an
/// alias. Only single-word type names are stripped; a multi-word cast such as
/// `::timestamp with time zone` is left alone rather than risk swallowing the
/// operator that follows it.
fn canonicalise_keywords_and_casts(s: &str) -> String {
    fn is_word_char(c: char) -> bool {
        c.is_alphanumeric() || c == '_'
    }

    /// Returns true when the word was `AS`, meaning the *next* word is an alias
    /// Postgres added and must be dropped too.
    fn flush(word: &mut String, out: &mut String, skip_next: &mut bool) -> bool {
        if word.is_empty() {
            return false;
        }
        let upper = word.to_ascii_uppercase();
        if *skip_next {
            // The alias itself, and whatever separator preceded it.
            *skip_next = false;
            word.clear();
            while out.ends_with(' ') {
                out.pop();
            }
            return false;
        }
        match upper.as_str() {
            "TRUE" | "FALSE" | "NULL" => out.push_str(&word.to_ascii_lowercase()),
            // Postgres rewrites `INTERVAL '30 days'` as `'30 days'::interval`, and
            // the cast is already stripped above, so the keyword has to go too or
            // every temporal rule looks changed on every push.
            "INTERVAL" => {
                word.clear();
                while out.ends_with(' ') {
                    out.pop();
                }
                return false;
            }
            "AS" => {
                word.clear();
                while out.ends_with(' ') {
                    out.pop();
                }
                *skip_next = true;
                return true;
            }
            _ => out.push_str(word),
        }
        word.clear();
        false
    }

    let mut out = String::with_capacity(s.len());
    let mut word = String::new();
    let mut chars = s.chars().peekable();
    let mut in_string = false;
    let mut skip_next = false;

    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if c == '\'' {
                in_string = false;
            }
            continue;
        }

        if c == '\'' {
            flush(&mut word, &mut out, &mut skip_next);
            out.push(c);
            in_string = true;
            continue;
        }

        if c == ':' && chars.peek() == Some(&':') {
            flush(&mut word, &mut out, &mut skip_next);
            chars.next(); // second ':'
            while let Some(t) = chars.peek() {
                if is_word_char(*t) {
                    chars.next();
                } else {
                    break;
                }
            }
            // An array type ends `[]`. Consume the pair, never a lone bracket:
            // taking a bare `]` swallowed the one closing an enclosing
            // `ARRAY['a'::text, 'b'::text]`, so the stored form of every
            // multi-role policy lost its final bracket and never compared equal
            // to the generated one, recreated on every push.
            loop {
                let mut ahead = chars.clone();
                if ahead.next() == Some('[') && ahead.next() == Some(']') {
                    chars.next();
                    chars.next();
                } else {
                    break;
                }
            }
            continue;
        }

        if is_word_char(c) {
            word.push(c);
        } else {
            flush(&mut word, &mut out, &mut skip_next);
            out.push(c);
        }
    }
    flush(&mut word, &mut out, &mut skip_next);
    out
}

pub fn diff(
    ast: &SchemaAst,
    db: &DatabaseState,
    ops: &mut Vec<Operation>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    // Comparison is textual, so the expected expression has to name the same schema the stored one
    // does. `DatabaseState::default()` carries no schema (unit tests, an empty target), and there
    // are no stored policies to compare against in that case either.
    let schema = if db.schema.is_empty() {
        crate::generator::sql::rls::DEFAULT_POLICY_SCHEMA
    } else {
        db.schema.as_str()
    };

    // Index DB policies by table name for fast lookup.
    let mut db_policies_by_table: std::collections::HashMap<
        &str,
        Vec<&crate::introspector::rls::DbRlsPolicy>,
    > = std::collections::HashMap::new();
    for policy in &db.rls_policies {
        db_policies_by_table
            .entry(policy.table.as_str())
            .or_default()
            .push(policy);
    }

    // Introspected `relrowsecurity`, NOT "has at least one policy": a deny-all
    // table (RLS on, zero policies) is now the default for a model without
    // access rules, and guessing from the policy list would report it disabled
    // and re-emit ENABLE ROW LEVEL SECURITY on every push.
    let rls_enabled_tables: std::collections::HashSet<&str> =
        db.rls_enabled_tables.iter().map(String::as_str).collect();

    // Models with no access rules at all, collected so the deny-all is visible.
    let mut unrestricted: Vec<String> = Vec::new();

    // Hand-written policies found on managed tables. Left in place, but reported:
    // Postgres ORs permissive policies, so an unmanaged one widens access beyond
    // what the schema declares and the schema would otherwise stop describing reality.
    let mut unmanaged: Vec<String> = Vec::new();

    // ── Per-model: apply / update policies ───────────────────────────────────

    for model in &ast.models {
        let table = model.table_name();

        // A table the schema declares but Supatype did not create is left entirely alone.
        //
        // `ENABLE ROW LEVEL SECURITY` on someone else's table changes what every role except its
        // owner can read: an existing application can stop seeing its own rows. Skipping is also
        // fail-closed for Supatype's API: without the grants (skipped for the same reason) the API
        // has no privileges on the table, so nothing is exposed under rules that are not enforced.
        if let Some(db_table) = db.tables.iter().find(|t| t.name == table) {
            if !crate::managed::is_managed_comment(db_table.comment.as_deref()) {
                warnings.push(format!(
                    "Table \"{table}\" already exists and is not managed by Supatype, so its \
                     access rules cannot be applied: a push may not attach row level security, \
                     policies, privileges or field labels to a table it did not create. `supatype \
                     push` refuses until you run `supatype adopt` to take ownership of it, or point \
                     the model at another table with `tableName`."
                ));
                continue;
            }
        }

        let has_access_rules = model.access().read.is_some()
            || model.access().create.is_some()
            || model.access().update.is_some()
            || model.access().delete.is_some();

        let db_policies: &[&crate::introspector::rls::DbRlsPolicy] = db_policies_by_table
            .get(table)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        let rls_is_enabled = rls_enabled_tables.contains(table);

        if has_access_rules {
            // Enable RLS if not already on.
            if !rls_is_enabled {
                ops.push(Operation::EnableRls {
                    table: table.to_string(),
                    risk: Risk::Safe,
                });
            }

            // Build a map of existing DB policies: name → policy.
            let db_pol_map: std::collections::HashMap<
                &str,
                &crate::introspector::rls::DbRlsPolicy,
            > = db_policies.iter().map(|p| (p.name.as_str(), *p)).collect();

            // For each expected policy, check if it exists and if its expression matches.
            let expected = expected_policies(model.access());
            let mut expected_names: std::collections::HashSet<String> = expected
                .iter()
                .map(|(suffix, _)| format!("{table}_{suffix}"))
                .collect();

            // `<table>_draft_select` is owned by the versions layer, not by this differ, and has to
            // be named here anyway so it is not treated as stale.
            //
            // It carries the managed marker, so the hand-written escape below does not save it: the
            // differ dropped it on every push and the versions layer recreated it at the end of the
            // same migration. A project with two publishable models reported the same two
            // `drop_rls_policy` operations on every `supatype diff`, applied them, and reported
            // them again immediately. A push that is not idempotent teaches people to ignore its
            // output.
            //
            // The same shape as `versions_tables`, which exists so the removed-table pass does not
            // drop the snapshot tables for the same reason. Tables were covered; policies were not.
            if crate::parser::accessors::versions_of(model).is_some_and(|v| v.drafts) {
                expected_names.insert(format!("{table}_draft_select"));
            }

            for (suffix, rule_opt) in &expected {
                let policy_name = format!("{table}_{suffix}");
                let expected_expr = normalise(
                    &access_rule_to_expr(ast, model, rule_opt.unwrap(), schema),
                    table,
                );

                if let Some(db_pol) = db_pol_map.get(policy_name.as_str()) {
                    // Policy exists: compare the USING or WITH CHECK expression.
                    let db_expr = match suffix.as_str() {
                        "insert" => db_pol.check_expr.as_deref().unwrap_or(""),
                        _ => db_pol.using_expr.as_deref().unwrap_or(""),
                    };
                    let db_expr_norm = normalise(db_expr, table);

                    // An update policy has two halves. Comparing only USING meant a
                    // change to the result constraint alone was invisible, so the
                    // policy stayed as it was while the schema said otherwise.
                    let check_differs = suffix == "update" && {
                        let access = model.access();
                        let expected_check = access
                            .update_check
                            .as_ref()
                            .map(|c| normalise(&access_rule_to_expr(ast, model, c, schema), table))
                            .unwrap_or_else(|| expected_expr.clone());
                        normalise(db_pol.check_expr.as_deref().unwrap_or(""), table)
                            != expected_check
                    };

                    // Adopt policies created before ownership markers existed: an
                    // unmarked policy sitting on a name we own gets rewritten (which
                    // stamps it), otherwise the differ would abandon every policy in
                    // every pre-existing project.
                    if db_expr_norm != expected_expr || check_differs || !db_pol.managed {
                        // Expression changed: recreate. CreateRlsPolicy already renders
                        // idempotent SQL (DROP POLICY IF EXISTS + CREATE POLICY), so we must
                        // NOT also emit a separate DropRlsPolicy here: operation ordering runs
                        // CreateRlsPolicy before DropRlsPolicy, so a separate drop would delete
                        // the freshly recreated policy and leave the table with no policy at all.
                        ops.push(Operation::CreateRlsPolicy {
                            table: table.to_string(),
                            policy: policy_name,
                            risk: Risk::Safe,
                        });
                    }
                    // else: expression matches, a no-op (idempotent)
                } else {
                    // Policy does not exist: create it.
                    ops.push(Operation::CreateRlsPolicy {
                        table: table.to_string(),
                        policy: policy_name,
                        risk: Risk::Safe,
                    });
                }
            }

            // Drop stale policies we own. A policy without the managed marker was
            // written by hand (SQL editor, psql) and is left alone, because dropping it
            // would silently delete access control the operator added.
            for db_pol in db_policies {
                if !db_pol.managed && !expected_names.contains(db_pol.name.as_str()) {
                    unmanaged.push(format!("{table}.{}", db_pol.name));
                    continue;
                }
                if !expected_names.contains(db_pol.name.as_str()) {
                    ops.push(Operation::DropRlsPolicy {
                        table: table.to_string(),
                        policy: db_pol.name.clone(),
                        risk: Risk::Safe,
                    });
                }
            }
        } else {
            // No access rules declared → deny by default.
            //
            // This branch previously did nothing unless the table already had
            // policies, so a model without `access` shipped with RLS off while
            // anon/authenticated hold broad grants: readable by anyone, and
            // writable by any signed-in user. RLS on with no policies denies
            // anon and authenticated outright; service_role is BYPASSRLS, so
            // server-side code and seeds are unaffected.
            if !rls_is_enabled {
                ops.push(Operation::EnableRls {
                    table: table.to_string(),
                    risk: Risk::Safe,
                });
            }
            // The versions layer's draft-select policy is its own, whether or not the model has
            // rules of its own; dropped here, the layer recreated it at the end of the same
            // migration and the push was never up to date.
            let draft_select = crate::parser::accessors::versions_of(model)
                .is_some_and(|v| v.drafts)
                .then(|| format!("{table}_draft_select"));
            for db_pol in db_policies {
                if !db_pol.managed {
                    unmanaged.push(format!("{table}.{}", db_pol.name));
                    continue;
                }
                if draft_select.as_deref() == Some(db_pol.name.as_str()) {
                    continue;
                }
                ops.push(Operation::DropRlsPolicy {
                    table: table.to_string(),
                    policy: db_pol.name.clone(),
                    risk: Risk::Safe,
                });
            }
            unrestricted.push(table.to_string());
        }
    }

    if !unrestricted.is_empty() {
        warnings.push(format!(
            "{} model(s) declare no access rules: RLS is enabled with no policies, so all \
             anon/authenticated access is denied (service_role is unaffected): {}. \
             Declare `access` on these models to grant access.",
            unrestricted.len(),
            unrestricted.join(", "),
        ));
    }

    if !unmanaged.is_empty() {
        warnings.push(format!(
            "{} hand-written policy/policies on managed tables were left untouched: {}. Postgres combines permissive policies with OR, so these may grant access the schema does not declare.",
            unmanaged.len(),
            unmanaged.join(", "),
        ));
    }

    junction_diff(
        ast,
        &rls_enabled_tables,
        &db_policies_by_table,
        ops,
        warnings,
        schema,
    );

    // ── Tables in DB with RLS but not in schema (dropped models) ─────────────
    // These are handled by DropTable in table_diff; there is no need to drop policies separately.

    Ok(())
}

// ─── Junction tables ─────────────────────────────────────────────────────────

/// Many-to-many junction tables are generated by the engine, not declared, so
/// the author has no place to put an `access` block for them, which left every
/// junction with RLS off: any signed-in user could add or remove links between
/// rows they had no rights to. Nothing to copy from Supabase here; it has no
/// implicit junctions (you create the join table and write its policies).
///
/// Rule: a link is visible only if BOTH endpoints are readable, and writable
/// only if BOTH endpoints are writable: the intersection of the parent models'
/// rules. Where a parent rule depends on row data (Owner, comparisons, membership) the
/// expression references parent columns that do not exist on the junction table,
/// so it cannot be applied directly; those fall back to deny-all with a warning
/// rather than guessing.
fn junction_diff(
    ast: &SchemaAst,
    rls_enabled_tables: &std::collections::HashSet<&str>,
    db_policies_by_table: &std::collections::HashMap<
        &str,
        Vec<&crate::introspector::rls::DbRlsPolicy>,
    >,
    ops: &mut Vec<Operation>,
    warnings: &mut Vec<String>,
    schema: &str,
) {
    for junction in &ast.junction_tables {
        let table = junction.name.as_str();

        if !rls_enabled_tables.contains(table) {
            ops.push(Operation::EnableRls {
                table: table.to_string(),
                risk: Risk::Safe,
            });
        }

        let parent_a = ast.models.iter().find(|m| m.name == junction.model_a);
        let parent_b = ast.models.iter().find(|m| m.name == junction.model_b);
        let (Some(parent_a), Some(parent_b)) = (parent_a, parent_b) else {
            warnings.push(format!(
                "Junction table '{table}': could not resolve parent models \
                 '{}' / '{}'. RLS is enabled with no policies (all access denied).",
                junction.model_a, junction.model_b,
            ));
            continue;
        };

        let derived = intersect_access(parent_a.access(), parent_b.access());
        let db_policies = db_policies_by_table
            .get(table)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);

        let mut undecidable: Vec<&str> = Vec::new();
        let mut kept: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (suffix, rule) in [
            ("select", derived.read.as_ref()),
            ("insert", derived.create.as_ref()),
            ("update", derived.update.as_ref()),
            ("delete", derived.delete.as_ref()),
        ] {
            let policy_name = format!("{table}_{suffix}");
            let Some(rule) = rule else {
                undecidable.push(suffix);
                continue;
            };
            kept.insert(policy_name.clone());

            // Compare against what is already in the database, exactly as the
            // model path does: emitting the create unconditionally left every
            // diff reporting the same four policies forever.
            let expected_expr = normalise(&access_rule_to_expr(ast, parent_a, rule, schema), table);
            let existing = db_policies.iter().find(|p| p.name == policy_name);
            let needs_write = match existing {
                Some(db_pol) => {
                    let db_expr = match suffix {
                        "insert" => db_pol.check_expr.as_deref().unwrap_or(""),
                        _ => db_pol.using_expr.as_deref().unwrap_or(""),
                    };
                    normalise(db_expr, table) != expected_expr || !db_pol.managed
                }
                None => true,
            };

            if needs_write {
                ops.push(Operation::CreateRlsPolicy {
                    table: table.to_string(),
                    policy: policy_name,
                    risk: Risk::Safe,
                });
            }
        }

        if !undecidable.is_empty() {
            warnings.push(format!(
                "Junction table '{table}' ({} ↔ {}): could not derive {} policy/policies from the \
                 parent models because a parent rule depends on row data. Those operations are \
                 denied for anon/authenticated. Declare matching rules on both parents, or grant \
                 access explicitly, if links must be writable.",
                junction.model_a,
                junction.model_b,
                undecidable.join("/"),
            ));
        }

        // Anything the derivation did not produce is stale, including an
        // operation that used to be derivable and no longer is (a parent rule
        // changed to a row-dependent one). Leaving those in place would keep
        // granting access the parents no longer allow.
        for db_pol in db_policies {
            if !db_pol.managed && !kept.contains(&db_pol.name) {
                continue;
            }
            if !kept.contains(&db_pol.name) {
                ops.push(Operation::DropRlsPolicy {
                    table: table.to_string(),
                    policy: db_pol.name.clone(),
                    risk: Risk::Safe,
                });
            }
        }
    }
}

/// Intersect two parents' rules. `None` for an operation means "cannot express
/// safely, deny". Only rules that do not reference row data can be intersected,
/// because the junction table has none of the parents' columns.
pub(crate) fn intersect_access(a: &AccessAst, b: &AccessAst) -> AccessAst {
    AccessAst {
        read: intersect_rule(a.read.as_ref(), b.read.as_ref()),
        create: intersect_rule(a.create.as_ref(), b.create.as_ref()),
        update: intersect_rule(a.update.as_ref(), b.update.as_ref()),
        // A junction row has no columns of its own to constrain, so splitting the
        // result constraint from the row selection has nothing to say here. The
        // intersected `update` governs both halves.
        update_check: None,
        delete: intersect_rule(a.delete.as_ref(), b.delete.as_ref()),
        // A junction row carries no columns of its own, so there is nothing for a
        // field rule to narrow. Neither parent's field rules can apply here.
        fields: Default::default(),
    }
}

pub(crate) fn intersect_rule(a: Option<&AccessRule>, b: Option<&AccessRule>) -> Option<AccessRule> {
    // An operation neither parent allows stays denied.
    let (a, b) = (a?, b?);
    match (a, b) {
        // Row-dependent rules cannot be evaluated against junction columns: a
        // junction table has none of the parents' columns, so anything naming one
        // is meaningless there. Every composed and comparison rule is treated as
        // row-dependent; some (`Eq<AuthRole, "admin">`) are not, but deciding
        // that needs a full analysis of the tree, and guessing wrong here would
        // silently widen access on a table nobody inspects. The caller turns
        // `None` into a deny plus a warning.
        (
            AccessRule::Owner { .. }
            | AccessRule::Any { .. }
            | AccessRule::All { .. }
            | AccessRule::Not { .. }
            | AccessRule::Compare { .. }
            | AccessRule::NullCheck { .. }
            | AccessRule::Matches { .. }
            | AccessRule::In { .. }
            | AccessRule::Exists { .. },
            _,
        )
        | (
            _,
            AccessRule::Owner { .. }
            | AccessRule::Any { .. }
            | AccessRule::All { .. }
            | AccessRule::Not { .. }
            | AccessRule::Compare { .. }
            | AccessRule::NullCheck { .. }
            | AccessRule::Matches { .. }
            | AccessRule::In { .. }
            | AccessRule::Exists { .. },
        ) => None,

        (AccessRule::Private, _) | (_, AccessRule::Private) => Some(AccessRule::Private),

        (AccessRule::Public, other) | (other, AccessRule::Public) => Some(other.clone()),

        (AccessRule::Authenticated, other) | (other, AccessRule::Authenticated) => {
            Some(other.clone())
        }

        (AccessRule::Role { roles: ra }, AccessRule::Role { roles: rb }) => {
            let shared: Vec<String> = ra.iter().filter(|r| rb.contains(r)).cloned().collect();
            if shared.is_empty() {
                // No role satisfies both parents.
                Some(AccessRule::Private)
            } else {
                Some(AccessRule::Role { roles: shared })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{intersect_rule, normalise};
    use crate::parser::ast::AccessRule;

    // Junction semantics: a link is only as accessible as its least-accessible
    // endpoint, and a rule that depends on row data cannot be applied to a
    // junction table (it has none of the parents' columns) so it must deny.
    #[test]
    fn intersect_takes_the_stricter_of_two_rules() {
        let public = AccessRule::Public;
        let admin = AccessRule::Role {
            roles: vec!["admin".into()],
        };
        let authed = AccessRule::Authenticated;

        assert!(matches!(
            intersect_rule(Some(&public), Some(&admin)),
            Some(AccessRule::Role { ref roles }) if roles == &vec!["admin".to_string()]
        ));
        assert!(matches!(
            intersect_rule(Some(&public), Some(&authed)),
            Some(AccessRule::Authenticated)
        ));
        assert!(matches!(
            intersect_rule(Some(&public), Some(&public)),
            Some(AccessRule::Public)
        ));
        assert!(matches!(
            intersect_rule(Some(&AccessRule::Private), Some(&public)),
            Some(AccessRule::Private)
        ));
    }

    #[test]
    fn intersect_denies_when_no_role_satisfies_both_parents() {
        let editor = AccessRule::Role {
            roles: vec!["editor".into()],
        };
        let admin = AccessRule::Role {
            roles: vec!["admin".into()],
        };
        assert!(matches!(
            intersect_rule(Some(&editor), Some(&admin)),
            Some(AccessRule::Private)
        ));
        // Overlapping role sets keep only the shared roles.
        let a = AccessRule::Role {
            roles: vec!["admin".into(), "editor".into()],
        };
        assert!(matches!(
            intersect_rule(Some(&a), Some(&admin)),
            Some(AccessRule::Role { ref roles }) if roles == &vec!["admin".to_string()]
        ));
    }

    #[test]
    fn intersect_yields_none_for_row_dependent_rules() {
        let owner = AccessRule::Owner {
            field: "user_id".into(),
        };
        assert!(intersect_rule(Some(&owner), Some(&AccessRule::Public)).is_none());
        assert!(intersect_rule(
            Some(&AccessRule::Owner {
                field: "user_id".into()
            }),
            Some(&AccessRule::Public)
        )
        .is_none());
    }

    #[test]
    fn intersect_denies_when_either_parent_omits_the_operation() {
        assert!(intersect_rule(None, Some(&AccessRule::Public)).is_none());
        assert!(intersect_rule(Some(&AccessRule::Public), None).is_none());
    }

    #[test]
    fn normalise_strips_own_table_column_prefix() {
        let generated = "EXISTS (SELECT 1 FROM \"album\" WHERE \"album\".id = album_id AND auth.uid() = \"album\".owner_id)";
        let stored = "(EXISTS ( SELECT 1 FROM album WHERE ((album.id = photo.album_id) AND (uid() = album.owner_id))))";
        assert_eq!(normalise(generated, "photo"), normalise(stored, "photo"));
    }

    // Regression: Private/Public rules generate nothing but a boolean literal, and
    // Postgres stores it lowercase, so every push re-created these policies.
    #[test]
    fn normalise_matches_boolean_literal_case() {
        assert_eq!(
            normalise("FALSE", "setup_bundle_versions"),
            normalise("false", "setup_bundle_versions")
        );
        assert_eq!(
            normalise("TRUE", "setup_bundle_versions"),
            normalise("(true)", "setup_bundle_versions")
        );
    }

    // Regression: Postgres adds an explicit cast to stored literals.
    #[test]
    fn normalise_ignores_stored_casts() {
        let generated = "auth.role() = 'admin'";
        let stored = "(role() = 'admin'::text)";
        assert_eq!(
            normalise(generated, "setup_bundle_versions"),
            normalise(stored, "setup_bundle_versions")
        );
    }

    #[test]
    fn normalise_preserves_string_literal_case_and_contents() {
        // A role literal that happens to spell a keyword must not be case-folded
        // into a different value, and `::` inside a literal is not a cast.
        assert_ne!(
            normalise("auth.role() = 'Admin'", "t"),
            normalise("auth.role() = 'admin'", "t")
        );
        assert_eq!(normalise("x = 'a::b'", "t"), "x = 'a::b'");
    }

    #[test]
    fn normalise_keeps_operator_after_cast() {
        assert_eq!(
            normalise("(status = 'live'::text AND deleted IS NULL)", "t"),
            "status = 'live' AND deleted IS null"
        );
    }

    // Auth calls are wrapped in a scalar subquery so the planner evaluates them
    // once per query rather than once per row. Postgres stores such a subquery
    // with an output alias it invented, so without dropping `AS <alias>` every
    // policy would look changed on every push, the convergence failure this
    // differ has already been bitten by twice.
    #[test]
    fn normalise_matches_a_stored_scalar_subquery() {
        let generated = "(SELECT auth.uid()) = user_id";
        let stored = "(( SELECT auth.uid() AS uid) = post.user_id)";
        assert_eq!(normalise(generated, "post"), normalise(stored, "post"));
    }

    #[test]
    fn normalise_matches_a_stored_role_subquery() {
        let generated = "(SELECT auth.role()) = 'admin'";
        let stored = "(( SELECT auth.role() AS role) = 'admin'::text)";
        assert_eq!(normalise(generated, "post"), normalise(stored, "post"));
    }

    #[test]
    fn normalise_matches_a_wrapped_call_inside_a_subquery() {
        let generated = "EXISTS (SELECT 1 FROM \"album\" WHERE \"album\".id = album_id AND (SELECT auth.uid()) = \"album\".owner_id)";
        let stored = "(EXISTS ( SELECT 1 FROM album WHERE ((album.id = photo.album_id) AND (( SELECT auth.uid() AS uid) = album.owner_id))))";
        assert_eq!(normalise(generated, "photo"), normalise(stored, "photo"));
    }

    // A wrapped call and a bare one are genuinely different SQL with different
    // performance, so the differ must see the rewrite and apply it exactly once.
    #[test]
    fn normalise_still_distinguishes_a_wrapped_call_from_a_bare_one() {
        assert_ne!(
            normalise("(SELECT auth.uid()) = user_id", "post"),
            normalise("auth.uid() = user_id", "post")
        );
    }

    // Regression: the cast stripper consumed `[` and `]` freely to cope with array
    // types like `::text[]`, which also ate the bracket closing the enclosing
    // `ARRAY[…]`. Every multi-role policy therefore differed from its stored form
    // and was dropped and recreated on every single push.
    #[test]
    fn normalise_matches_a_stored_role_array() {
        let generated = "(SELECT auth.role()) = ANY(ARRAY['admin', 'editor'])";
        let stored = "(( SELECT auth.role() AS role) = ANY (ARRAY['admin'::text, 'editor'::text]))";
        assert_eq!(
            normalise(generated, "categories"),
            normalise(stored, "categories")
        );
    }

    #[test]
    fn normalise_still_strips_array_type_casts() {
        assert_eq!(
            normalise("tags = '{a,b}'::text[]", "t"),
            normalise("(t.tags = '{a,b}'::text[])", "t")
        );
        assert!(!normalise("tags = '{a}'::text[]", "t").contains("text"));
    }

    // Postgres rewrites `INTERVAL '30 days'` as `'30 days'::interval`, so the keyword
    // moves into a cast, and the cast is stripped. Without dropping the keyword too,
    // every temporal rule looked changed on every push.
    #[test]
    fn normalise_matches_a_stored_interval() {
        let generated = "created_at >= (SELECT now() - INTERVAL '30 days')";
        let stored = "(post.created_at >= ( SELECT (now() - '30 days'::interval)))";
        assert_eq!(normalise(generated, "post"), normalise(stored, "post"));
    }

    // Regression: Postgres canonicalises an interval literal when it stores it, and
    // only `days` and `years` survive the round trip verbatim. Measured against a live
    // Postgres 17: seconds/minutes/hours collapse into `HH:MM:SS`, weeks are converted
    // to days, and months is abbreviated to `mons`. `normalise` copies string literals
    // verbatim by design, so without an interval-aware pass an access rule using any of
    // those five units generates a policy that looks changed on every push and is
    // dropped and recreated each time.
    #[test]
    fn normalise_matches_a_stored_interval_for_every_unit() {
        // (generated unit, the text Postgres stores for `7 <unit>`)
        let cases = [
            ("seconds", "00:00:07"),
            ("minutes", "00:07:00"),
            ("hours", "07:00:00"),
            ("days", "7 days"),
            ("weeks", "49 days"),
            ("months", "7 mons"),
            ("years", "7 years"),
        ];
        for (unit, stored_text) in cases {
            let generated = format!("created_at >= (SELECT now() - INTERVAL '7 {unit}')");
            let stored =
                format!("(post.created_at >= ( SELECT (now() - '{stored_text}'::interval)))");
            assert_eq!(
                normalise(&generated, "post"),
                normalise(&stored, "post"),
                "interval '7 {unit}' must compare equal to the stored form '{stored_text}'"
            );
        }
    }

    // A multi-unit interval is the shape `After`/`Before` generate, and Postgres
    // rewrites it into mixed notation: `30 days 9 hours` is stored `30 days 09:00:00`.
    #[test]
    fn normalise_matches_a_stored_multi_unit_interval() {
        let generated =
            "starts_at >= (SELECT date_trunc('day', now()) + INTERVAL '30 days 9 hours')";
        let stored = "(event.starts_at >= ( SELECT (date_trunc('day'::text, now()) + '30 days 09:00:00'::interval)))";
        assert_eq!(normalise(generated, "event"), normalise(stored, "event"));
    }

    // Two intervals that mean different things must not be conflated by the
    // canonicalisation: this is what stops the fix from being "make everything equal".
    #[test]
    fn normalise_keeps_different_intervals_distinct() {
        let seven_hours = "x > (SELECT now() - INTERVAL '7 hours')";
        let seven_days = "x > (SELECT now() - INTERVAL '7 days')";
        assert_ne!(normalise(seven_hours, "t"), normalise(seven_days, "t"));
    }

    #[test]
    fn normalise_matches_a_stored_date_trunc() {
        let generated = "created_at >= (SELECT date_trunc('week', now()))";
        let stored = "(post.created_at >= ( SELECT date_trunc('week'::text, now()) AS date_trunc))";
        assert_eq!(normalise(generated, "post"), normalise(stored, "post"));
    }

    // "as" inside a string literal is not an alias.
    #[test]
    fn normalise_does_not_strip_as_inside_a_literal() {
        assert_eq!(
            normalise("name = 'flagged as spam'", "t"),
            "name = 'flagged as spam'"
        );
    }
}

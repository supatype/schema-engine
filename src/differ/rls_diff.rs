use super::{Operation, Risk};
use crate::generator::sql::rls::access_rule_to_expr;
use crate::parser::ast::{AccessAst, AccessRule, SchemaAst};
use crate::state::database_state::DatabaseState;
use anyhow::Result;

/// Policy naming convention — must match generator/sql/rls.rs.
/// `polcmd` column from pg_policy: r=SELECT, a=INSERT, w=UPDATE, d=DELETE, *=ALL.
fn expected_policies(access: &AccessAst) -> Vec<(String, Option<&AccessRule>)> {
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
///   * boolean literals are stored lowercase — generated `FALSE` vs stored `false`
///     (Private/Public rules produce nothing but these, so they never converged);
///   * literals gain an explicit cast — generated `'admin'` vs stored `'admin'::text`;
///   * a scalar subquery gains an output alias — generated `(SELECT auth.uid())` vs
///     stored `( SELECT auth.uid() AS uid)`. Auth calls are wrapped in exactly that
///     shape so the planner evaluates them once per query, so without this every
///     policy would look changed on every push.
fn normalise(s: &str, table: &str) -> String {
    let mut out = s.replace("auth.", "");
    // Parens become spaces rather than vanishing. Deleting them welded tokens
    // together on one side only: generated `ANY(ARRAY[…])` collapsed to
    // `ANYARRAY[…]` while Postgres stores `ANY (ARRAY[…])`, which survives as
    // `ANY ARRAY[…]` — so every multi-role policy was dropped and recreated on
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

/// Single quote-aware pass that removes `::type` casts, drops `AS <alias>` and
/// lowercases the bare keywords `TRUE`/`FALSE`/`NULL`. String literals are copied
/// verbatim, so a role name like `'Admin'` keeps its case, a `::` inside a literal
/// is not treated as a cast, and the words "as" inside one are not mistaken for an
/// alias. Only single-word type names are stripped — a multi-word cast such as
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
            // the cast is already stripped above — so the keyword has to go too or
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
            // to the generated one — recreated on every push.
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
        let admin = AccessRule::Role { roles: vec!["admin".into()] };
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
        let editor = AccessRule::Role { roles: vec!["editor".into()] };
        let admin = AccessRule::Role { roles: vec!["admin".into()] };
        assert!(matches!(
            intersect_rule(Some(&editor), Some(&admin)),
            Some(AccessRule::Private)
        ));
        // Overlapping role sets keep only the shared roles.
        let a = AccessRule::Role { roles: vec!["admin".into(), "editor".into()] };
        assert!(matches!(
            intersect_rule(Some(&a), Some(&admin)),
            Some(AccessRule::Role { ref roles }) if roles == &vec!["admin".to_string()]
        ));
    }

    #[test]
    fn intersect_yields_none_for_row_dependent_rules() {
        let owner = AccessRule::Owner { field: "user_id".into() };
        assert!(intersect_rule(Some(&owner), Some(&AccessRule::Public)).is_none());
        assert!(intersect_rule(
            Some(&AccessRule::Owner { field: "user_id".into() }),
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
    // Postgres stores it lowercase — so every push re-created these policies.
    #[test]
    fn normalise_matches_boolean_literal_case() {
        assert_eq!(normalise("FALSE", "setup_bundle_versions"), normalise("false", "setup_bundle_versions"));
        assert_eq!(normalise("TRUE", "setup_bundle_versions"), normalise("(true)", "setup_bundle_versions"));
    }

    // Regression: Postgres adds an explicit cast to stored literals.
    #[test]
    fn normalise_ignores_stored_casts() {
        let generated = "auth.role() = 'admin'";
        let stored = "(role() = 'admin'::text)";
        assert_eq!(normalise(generated, "setup_bundle_versions"), normalise(stored, "setup_bundle_versions"));
    }

    #[test]
    fn normalise_preserves_string_literal_case_and_contents() {
        // A role literal that happens to spell a keyword must not be case-folded
        // into a different value, and `::` inside a literal is not a cast.
        assert_ne!(normalise("auth.role() = 'Admin'", "t"), normalise("auth.role() = 'admin'", "t"));
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
    // policy would look changed on every push — the convergence failure this
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
        assert_eq!(normalise(generated, "categories"), normalise(stored, "categories"));
    }

    #[test]
    fn normalise_still_strips_array_type_casts() {
        assert_eq!(
            normalise("tags = '{a,b}'::text[]", "t"),
            normalise("(t.tags = '{a,b}'::text[])", "t")
        );
        assert!(!normalise("tags = '{a}'::text[]", "t").contains("text"));
    }

    // Postgres rewrites `INTERVAL '30 days'` as `'30 days'::interval` — the keyword
    // moves into a cast, and the cast is stripped. Without dropping the keyword too,
    // every temporal rule looked changed on every push.
    #[test]
    fn normalise_matches_a_stored_interval() {
        let generated = "created_at >= (SELECT now() - INTERVAL '30 days')";
        let stored = "(post.created_at >= ( SELECT (now() - '30 days'::interval)))";
        assert_eq!(normalise(generated, "post"), normalise(stored, "post"));
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

    // Models with no access rules at all — collected so the deny-all is visible.
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
        // owner can read — an existing application can stop seeing its own rows. Skipping is also
        // fail-closed for Supatype's API: without the grants (skipped for the same reason) the API
        // has no privileges on the table, so nothing is exposed under rules that are not enforced.
        if let Some(db_table) = db.tables.iter().find(|t| t.name == table) {
            if !crate::managed::is_managed_comment(db_table.comment.as_deref()) {
                warnings.push(format!(
                    "Table \"{table}\" already exists and is not managed by Supatype, so its \
                     access rules were NOT applied — no row level security, policies, privileges or \
                     field labels were changed. Run `supatype adopt` to take ownership of it, or \
                     point the model at another table with `tableName`. Until then the API has no \
                     access to it."
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
            let expected_names: std::collections::HashSet<String> = expected
                .iter()
                .map(|(suffix, _)| format!("{table}_{suffix}"))
                .collect();

            for (suffix, rule_opt) in &expected {
                let policy_name = format!("{table}_{suffix}");
                let expected_expr =
                    normalise(&access_rule_to_expr(ast, model, rule_opt.unwrap(), schema), table);

                if let Some(db_pol) = db_pol_map.get(policy_name.as_str()) {
                    // Policy exists — compare the USING or WITH CHECK expression.
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
                        // Expression changed — recreate. CreateRlsPolicy already renders
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
                    // else: expression matches — no-op (idempotent)
                } else {
                    // Policy does not exist — create it.
                    ops.push(Operation::CreateRlsPolicy {
                        table: table.to_string(),
                        policy: policy_name,
                        risk: Risk::Safe,
                    });
                }
            }

            // Drop stale policies we own. A policy without the managed marker was
            // written by hand (SQL editor, psql) and is left alone — dropping it
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
            // anon/authenticated hold broad grants — readable by anyone, and
            // writable by any signed-in user. RLS on with no policies denies
            // anon and authenticated outright; service_role is BYPASSRLS, so
            // server-side code and seeds are unaffected.
            if !rls_is_enabled {
                ops.push(Operation::EnableRls {
                    table: table.to_string(),
                    risk: Risk::Safe,
                });
            }
            for db_pol in db_policies {
                if !db_pol.managed {
                    unmanaged.push(format!("{table}.{}", db_pol.name));
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
            "{} model(s) declare no access rules — RLS is enabled with no policies, so all \
             anon/authenticated access is denied (service_role is unaffected): {}. \
             Declare `access` on these models to grant access.",
            unrestricted.len(),
            unrestricted.join(", "),
        ));
    }

    if !unmanaged.is_empty() {
        warnings.push(format!(
            "{} hand-written policy/policies on managed tables were left untouched: {}.              Postgres combines permissive policies with OR, so these may grant access the              schema does not declare.",
            unmanaged.len(),
            unmanaged.join(", "),
        ));
    }

    junction_diff(ast, &rls_enabled_tables, &db_policies_by_table, ops, warnings, schema);

    // ── Tables in DB with RLS but not in schema (dropped models) ─────────────
    // These are handled by DropTable in table_diff — no need to drop policies separately.

    Ok(())
}

// ─── Junction tables ─────────────────────────────────────────────────────────

/// Many-to-many junction tables are generated by the engine, not declared, so
/// the author has no place to put an `access` block for them — which left every
/// junction with RLS off: any signed-in user could add or remove links between
/// rows they had no rights to. Nothing to copy from Supabase here; it has no
/// implicit junctions (you create the join table and write its policies).
///
/// Rule: a link is visible only if BOTH endpoints are readable, and writable
/// only if BOTH endpoints are writable — the intersection of the parent models'
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
            // model path does — emitting the create unconditionally left every
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

        // Anything the derivation did not produce is stale — including an
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
/// safely — deny". Only rules that do not reference row data can be intersected,
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
        // row-dependent — some (`Eq<AuthRole, "admin">`) are not, but deciding
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

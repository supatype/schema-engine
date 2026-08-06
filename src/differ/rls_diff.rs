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
///   * literals gain an explicit cast — generated `'admin'` vs stored `'admin'::text`.
fn normalise(s: &str, table: &str) -> String {
    let mut out = s.replace("auth.", "");
    out.retain(|c| c != '(' && c != ')' && c != '"');
    let table_prefix = format!("{table}.");
    out = out.replace(&table_prefix, "");
    out = canonicalise_keywords_and_casts(&out);
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Single quote-aware pass that removes `::type` casts and lowercases the bare
/// keywords `TRUE`/`FALSE`/`NULL`. String literals are copied verbatim, so a role
/// name like `'Admin'` keeps its case and a `::` inside a literal is not treated
/// as a cast. Only single-word type names are stripped — a multi-word cast such as
/// `::timestamp with time zone` is left alone rather than risk swallowing the
/// operator that follows it.
fn canonicalise_keywords_and_casts(s: &str) -> String {
    fn is_word_char(c: char) -> bool {
        c.is_alphanumeric() || c == '_'
    }

    fn flush(word: &mut String, out: &mut String) {
        if word.is_empty() {
            return;
        }
        match word.to_ascii_uppercase().as_str() {
            "TRUE" | "FALSE" | "NULL" => out.push_str(&word.to_ascii_lowercase()),
            _ => out.push_str(word),
        }
        word.clear();
    }

    let mut out = String::with_capacity(s.len());
    let mut word = String::new();
    let mut chars = s.chars().peekable();
    let mut in_string = false;

    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if c == '\'' {
                in_string = false;
            }
            continue;
        }

        if c == '\'' {
            flush(&mut word, &mut out);
            out.push(c);
            in_string = true;
            continue;
        }

        if c == ':' && chars.peek() == Some(&':') {
            flush(&mut word, &mut out);
            chars.next(); // second ':'
            while let Some(t) = chars.peek() {
                if is_word_char(*t) || *t == '[' || *t == ']' {
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
            flush(&mut word, &mut out);
            out.push(c);
        }
    }
    flush(&mut word, &mut out);
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
            Some(&AccessRule::Custom { expression: "true".into() }),
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
}

pub fn diff(
    ast: &SchemaAst,
    db: &DatabaseState,
    ops: &mut Vec<Operation>,
    warnings: &mut Vec<String>,
) -> Result<()> {
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
                    normalise(&access_rule_to_expr(ast, model, rule_opt.unwrap()), table);

                if let Some(db_pol) = db_pol_map.get(policy_name.as_str()) {
                    // Policy exists — compare the USING or WITH CHECK expression.
                    let db_expr = match suffix.as_str() {
                        "insert" => db_pol.check_expr.as_deref().unwrap_or(""),
                        _ => db_pol.using_expr.as_deref().unwrap_or(""),
                    };
                    let db_expr_norm = normalise(db_expr, table);

                    // Adopt policies created before ownership markers existed: an
                    // unmarked policy sitting on a name we own gets rewritten (which
                    // stamps it), otherwise the differ would abandon every policy in
                    // every pre-existing project.
                    if db_expr_norm != expected_expr || !db_pol.managed {
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

    junction_diff(ast, &rls_enabled_tables, &db_policies_by_table, ops, warnings);

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
/// rules. Where a parent rule depends on row data (Owner/OwnerFrom/Custom) the
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
            let expected_expr = normalise(&access_rule_to_expr(ast, parent_a, rule), table);
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
        delete: intersect_rule(a.delete.as_ref(), b.delete.as_ref()),
    }
}

pub(crate) fn intersect_rule(a: Option<&AccessRule>, b: Option<&AccessRule>) -> Option<AccessRule> {
    // An operation neither parent allows stays denied.
    let (a, b) = (a?, b?);
    match (a, b) {
        // Row-dependent rules cannot be evaluated against junction columns.
        (AccessRule::Owner { .. } | AccessRule::Custom { .. } | AccessRule::Any { .. }, _)
        | (_, AccessRule::Owner { .. } | AccessRule::Custom { .. } | AccessRule::Any { .. }) => None,

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

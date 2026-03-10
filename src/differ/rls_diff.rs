use super::{Operation, Risk};
use crate::generator::sql::rls::access_rule_to_expr;
use crate::parser::ast::{AccessAst, AccessRule, SchemaAst};
use crate::state::database_state::DatabaseState;
use anyhow::Result;

/// Policy naming convention — must match generator/sql/rls.rs.
/// `polcmd` column from pg_policy: r=SELECT, a=INSERT, w=UPDATE, d=DELETE, *=ALL.
fn expected_policies(access: &AccessAst) -> Vec<(String, Option<&AccessRule>)> {
    vec![
        (format!("select"), access.read.as_ref()),
        (format!("insert"), access.create.as_ref()),
        (format!("update"), access.update.as_ref()),
        (format!("delete"), access.delete.as_ref()),
    ]
    .into_iter()
    .filter_map(|(suffix, rule)| rule.map(|r| (suffix, Some(r))))
    .collect()
}

/// Normalise an expression for comparison: trim and collapse consecutive whitespace.
fn normalise(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
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

    // Set of tables that have ANY RLS policy in the DB (proxy for RLS being enabled).
    let rls_enabled_tables: std::collections::HashSet<&str> =
        db_policies_by_table.keys().copied().collect();

    // Track which table names appear in schema (to detect tables that lost access rules).
    let _schema_table_names: std::collections::HashSet<&str> =
        ast.models.iter().map(|m| m.table_name.as_str()).collect();

    // ── Per-model: apply / update policies ───────────────────────────────────

    for model in &ast.models {
        let table = model.table_name.as_str();
        let has_access_rules = model.access.read.is_some()
            || model.access.create.is_some()
            || model.access.update.is_some()
            || model.access.delete.is_some();

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
            let expected = expected_policies(&model.access);
            let expected_names: std::collections::HashSet<String> = expected
                .iter()
                .map(|(suffix, _)| format!("{table}_{suffix}"))
                .collect();

            for (suffix, rule_opt) in &expected {
                let policy_name = format!("{table}_{suffix}");
                let expected_expr = normalise(&access_rule_to_expr(rule_opt.unwrap()));

                if let Some(db_pol) = db_pol_map.get(policy_name.as_str()) {
                    // Policy exists — compare the USING or WITH CHECK expression.
                    let db_expr = match suffix.as_str() {
                        "insert" => db_pol.check_expr.as_deref().unwrap_or(""),
                        _ => db_pol.using_expr.as_deref().unwrap_or(""),
                    };
                    let db_expr_norm = normalise(db_expr);

                    if db_expr_norm != expected_expr {
                        // Expression changed — drop and recreate.
                        ops.push(Operation::DropRlsPolicy {
                            table: table.to_string(),
                            policy: policy_name.clone(),
                            risk: Risk::Safe,
                        });
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

            // Drop DB policies that are no longer in the schema (stale policies).
            for db_pol in db_policies {
                if !expected_names.contains(db_pol.name.as_str()) {
                    ops.push(Operation::DropRlsPolicy {
                        table: table.to_string(),
                        policy: db_pol.name.clone(),
                        risk: Risk::Safe,
                    });
                }
            }
        } else if rls_is_enabled {
            // Table had RLS but access rules were removed from schema.
            // Drop all policies. Leave RLS enabled (safest default — no policies = no access).
            for db_pol in db_policies {
                ops.push(Operation::DropRlsPolicy {
                    table: table.to_string(),
                    policy: db_pol.name.clone(),
                    risk: Risk::Safe,
                });
            }
            warnings.push(format!(
                "Table '{table}' had RLS policies removed from schema. Existing policies dropped. \
                 RLS remains ENABLED with no policies — all access is blocked. \
                 Add access rules or manually disable RLS if this is intentional."
            ));
        }
    }

    // ── Tables in DB with RLS but not in schema (dropped models) ─────────────
    // These are handled by DropTable in table_diff — no need to drop policies separately.

    Ok(())
}

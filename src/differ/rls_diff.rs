//! The warnings about access the schema does not describe: deny-all tables, hand-written policies
//! on managed tables, junction operations no rule can grant, and tables the engine does not own.
//!
//! Policies are ledger objects since Phase 4.7b and row-level security since 4.8 (D9): the
//! desired set holds them and the reconcile makes them, so this module emits no operation.

use std::collections::{HashMap, HashSet};

use crate::introspector::rls::DbRlsPolicy;
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

/// The policies a model's table carries that the engine makes: one per declared operation, the
/// versions layer's draft select when the model drafts, and under tier 2 masking the one admitting
/// `service_role` through the `api` views.
fn engine_policy_names(model: &crate::parser::ast::ModelAst) -> HashSet<String> {
    let table = model.table_name();
    let mut names: HashSet<String> = expected_policies(model.access())
        .into_iter()
        .map(|(suffix, _)| crate::managed::policy_name(table, &suffix))
        .collect();
    names.insert(crate::managed::policy_name(
        table,
        crate::generator::sql::rls::SERVICE_ROLE_POLICY,
    ));
    if crate::parser::accessors::versions_of(model).is_some_and(|v| v.drafts) {
        names.insert(crate::managed::policy_name(table, "draft_select"));
    }
    names
}

pub fn diff(ast: &SchemaAst, db: &DatabaseState, warnings: &mut Vec<String>) -> Result<()> {
    let mut db_policies_by_table: HashMap<&str, Vec<&DbRlsPolicy>> = HashMap::new();
    for policy in &db.rls_policies {
        db_policies_by_table
            .entry(policy.table.as_str())
            .or_default()
            .push(policy);
    }

    // Models with no access rules at all, collected so the deny-all is visible.
    let mut unrestricted: Vec<String> = Vec::new();

    // Hand-written policies found on managed tables. Left in place, but reported: Postgres ORs
    // permissive policies, so an unmanaged one widens access beyond what the schema declares.
    let mut unmanaged: Vec<String> = Vec::new();

    for model in &ast.models {
        let table = model.table_name();

        // A table the schema declares but Supatype did not create is left entirely alone.
        //
        // `ENABLE ROW LEVEL SECURITY` on someone else's table changes what every role except its
        // owner can read: an existing application can stop seeing its own rows. Skipping is also
        // fail-closed for Supatype's API: without the grants (skipped for the same reason) the API
        // has no privileges on the table, so nothing is exposed under rules that are not enforced.
        if let Some(db_table) = db.tables.iter().find(|t| t.name == table) {
            if !db.owns_table(db_table) {
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

        // RLS is on whether or not the model declares rules (the reconcile's, D9): with no
        // policies it denies anon and authenticated outright, while service_role is BYPASSRLS, so
        // server-side code and seeds are unaffected.
        let has_access_rules = !expected_policies(model.access()).is_empty();
        if !has_access_rules {
            unrestricted.push(table.to_string());
        }

        let ours = engine_policy_names(model);
        for db_pol in db_policies_by_table.get(table).into_iter().flatten() {
            if !db.owns_policy(db_pol) && !ours.contains(&db_pol.name) {
                unmanaged.push(format!("{table}.{}", db_pol.name));
            }
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

    junction_diff(ast, warnings);
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
/// rather than guessing. The policies and RLS itself are the desired set's.
fn junction_diff(ast: &SchemaAst, warnings: &mut Vec<String>) {
    for junction in &ast.junction_tables {
        let table = junction.name.as_str();
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
        let undecidable: Vec<&str> = [
            ("select", derived.read.is_none()),
            ("insert", derived.create.is_none()),
            ("update", derived.update.is_none()),
            ("delete", derived.delete.is_none()),
        ]
        .into_iter()
        .filter_map(|(suffix, missing)| missing.then_some(suffix))
        .collect();

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
    use super::intersect_rule;
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
}

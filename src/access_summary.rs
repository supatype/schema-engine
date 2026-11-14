//! What each API role may do on each model's table, and on each many-to-many junction (a link),
//! once a push applies, beside what it may do now.
//!
//! `anon` holds a privilege only where the engine can prove a rule needs no login
//! ([`crate::generator::sql::grants`]), so a rule meant to be public that the analysis cannot see
//! through leaves a signed-out caller with `401 42501` and nothing said (issue 16). The plan a
//! `diff` prints carries this summary, so the author sees what each role is left with.
//!
//! **After** is what the push grants, from the rules alone: the same verbs in both field-masking
//! tiers, since tier 2's `api` view is granted exactly what tier 1's table would be.
//! **Before** is what the database grants now, read from the catalog: on the table, on its `api`
//! view, and through `PUBLIC`, which every role is a member of.
//!
//! A link's access follows from its ends' rows ([`crate::generator::sql::junction_access`]),
//! except where an end's read rule reads the link table itself: reading the ends back would
//! recurse, so the link keeps the intersection of its ends' rules, which has no policy for an
//! operation a rule decides from row data. That operation is denied however the privileges read
//! (`SELECT` stays granted for the end's policy to read the link): it is named in [`Denied`], and
//! left out of what the role may do after.

use serde::Serialize;

use crate::generator::sql::field_views::VIEW_SCHEMA;
use crate::generator::sql::grants::{api_privileges, junction_privileges, GRANTED_ROLES, PUBLIC};
use crate::generator::sql::junction_access::{junction_access, JunctionAccess};
use crate::generator::sql::rls::access_rule_to_expr;
use crate::introspector::catalog::CatalogState;
use crate::parser::accessors::{db_table_name, platform_access};
use crate::parser::ast::{AccessAst, AccessRule, JunctionTableAst, ModelAst, SchemaAst};

/// One API role's access to one table, as rule verbs in [`VERBS`] order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleAccess {
    /// The model's name, or a link's table name.
    pub model: String,
    pub table: String,
    pub role: String,
    /// Whether the table is a many-to-many junction: a link, whose access follows from its ends.
    pub link: bool,
    /// What the role may do now. Empty for a table the database does not have yet.
    pub before: Vec<&'static str>,
    /// What the role may do once the push applies.
    pub after: Vec<&'static str>,
    /// What the role can reach once the push applies, from the rules: `after` says which
    /// privileges are granted, but a rule that renders `FALSE` (`Private`) leaves a grant that
    /// reaches no row. Verbs the rules shut out are left out here.
    pub effective: Vec<Effective>,
    /// What a link denies because its access could not be derived, and why. Absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denied: Option<Denied>,
}

/// One operation a role can reach, and which rows it reaches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Effective {
    pub verb: &'static str,
    /// [`ALL_ROWS`] or [`BY_RULE`].
    pub rows: &'static str,
}

/// The rule renders `TRUE`: every row.
pub const ALL_ROWS: &str = "all rows";

/// The rule decides row by row, from the caller or the row's data.
pub const BY_RULE: &str = "rows decided by rule";

/// Operations of a link denied to every API role because the engine could not derive them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Denied {
    pub verbs: Vec<&'static str>,
    pub reason: &'static str,
}

/// Why a link denies an operation both of its ends declare: an end's read rule reads the link, so
/// its access is the intersection of its ends' rules, and that leaves a row-dependent one without
/// a policy.
pub const RECURSIVE: &str = "an end's read rule reads this link table";

/// Why a link denies everything: an end is not a model of the schema.
pub const UNRESOLVED: &str = "a parent model is not in the schema";

/// Each row privilege with the access rule verb that governs it, in the order a rule lists them.
const VERBS: [(&str, &str); 4] = [
    ("SELECT", "read"),
    ("INSERT", "create"),
    ("UPDATE", "update"),
    ("DELETE", "delete"),
];

/// Every model's access for each API role, then every link's, each in [`GRANTED_ROLES`] order.
pub fn summarize(ast: &SchemaAst, catalog: &CatalogState, schema: &str) -> Vec<RoleAccess> {
    let mut out: Vec<RoleAccess> = ast
        .models
        .iter()
        .flat_map(|model| GRANTED_ROLES.map(|role| model_access(ast, model, role, schema)))
        .collect();
    out.extend(ast.junction_tables.iter().flat_map(|j| link_access(ast, j)));
    for entry in &mut out {
        entry.before =
            verbs(|privilege| held(catalog, schema, &entry.table, &entry.role, privilege));
        // What a link denies is no access either side of the push, however its privileges read.
        if let Some(denied) = &entry.denied {
            entry.before.retain(|verb| !denied.verbs.contains(verb));
            entry.after.retain(|verb| !denied.verbs.contains(verb));
        }
        if entry.link {
            entry.effective = linked_effective(&entry.after);
        }
    }
    out
}

/// One model's access for one API role.
fn model_access(ast: &SchemaAst, model: &ModelAst, role: &'static str, schema: &str) -> RoleAccess {
    let after = in_verbs(&api_privileges(ast, model, role));
    RoleAccess {
        model: model.name.clone(),
        table: db_table_name(model).to_string(),
        role: role.to_string(),
        link: false,
        before: Vec::new(),
        effective: effective(ast, model, schema, &after),
        after,
        denied: None,
    }
}

/// What the rules leave reachable of the verbs in `after`: a rule that renders `FALSE` shuts its
/// verb out however the privilege reads, and one that renders `TRUE` reaches every row.
fn effective(
    ast: &SchemaAst,
    model: &ModelAst,
    schema: &str,
    after: &[&'static str],
) -> Vec<Effective> {
    VERBS
        .iter()
        .zip(rules(platform_access(model)))
        .filter(|((_, verb), _)| after.contains(verb))
        .filter_map(|((_, verb), rule)| {
            let rows = match access_rule_to_expr(ast, model, rule?, schema).as_str() {
                "FALSE" => return None,
                "TRUE" => ALL_ROWS,
                _ => BY_RULE,
            };
            Some(Effective { verb, rows })
        })
        .collect()
}

/// A link follows its ends' rows, so each verb it keeps is decided by their rules.
fn linked_effective(after: &[&'static str]) -> Vec<Effective> {
    after
        .iter()
        .map(|verb| Effective {
            verb,
            rows: BY_RULE,
        })
        .collect()
}

/// A link's access for each API role: its privileges, and what it denies for want of a rule.
fn link_access(ast: &SchemaAst, junction: &JunctionTableAst) -> [RoleAccess; 2] {
    let denied = undecided(ast, junction);
    GRANTED_ROLES.map(|role| RoleAccess {
        model: junction.name.clone(),
        table: junction.name.clone(),
        role: role.to_string(),
        link: true,
        before: Vec::new(),
        effective: Vec::new(),
        after: in_verbs(&junction_privileges(ast, junction, role)),
        denied: denied.clone(),
    })
}

/// The operations of a link the engine could not derive: those both ends declare and their
/// intersection leaves without a rule, or all of them when an end is not in the schema.
fn undecided(ast: &SchemaAst, junction: &JunctionTableAst) -> Option<Denied> {
    let JunctionAccess::Intersected(derived) = junction_access(ast, junction) else {
        return None;
    };
    let end = |name: &str| {
        ast.models
            .iter()
            .find(|m| m.name == name)
            .map(platform_access)
    };
    let (Some(a), Some(b)) = (end(&junction.model_a), end(&junction.model_b)) else {
        let verbs = VERBS.iter().map(|(_, verb)| *verb).collect();
        return Some(Denied {
            verbs,
            reason: UNRESOLVED,
        });
    };
    let verbs: Vec<&'static str> = VERBS
        .iter()
        .zip(rules(a).into_iter().zip(rules(b)).zip(rules(&derived)))
        .filter(|(_, ((a, b), derived))| a.is_some() && b.is_some() && derived.is_none())
        .map(|((_, verb), _)| *verb)
        .collect();
    (!verbs.is_empty()).then_some(Denied {
        verbs,
        reason: RECURSIVE,
    })
}

/// The rules of `access` in [`VERBS`] order.
fn rules(access: &AccessAst) -> [Option<&AccessRule>; 4] {
    [
        access.read.as_ref(),
        access.create.as_ref(),
        access.update.as_ref(),
        access.delete.as_ref(),
    ]
}

/// The verbs of the privileges in `granted`.
fn in_verbs(granted: &[&str]) -> Vec<&'static str> {
    verbs(|privilege| granted.contains(&privilege))
}

/// The verbs whose privilege `has` says is held.
fn verbs(has: impl Fn(&str) -> bool) -> Vec<&'static str> {
    VERBS
        .iter()
        .filter(|(privilege, _)| has(privilege))
        .map(|(_, verb)| *verb)
        .collect()
}

/// Whether `role` holds `privilege` on `table` now, on the table or any of its columns, in
/// `schema` or on the `api` view the API reads under tier 2, itself or through `PUBLIC`.
fn held(catalog: &CatalogState, schema: &str, table: &str, role: &str, privilege: &str) -> bool {
    let on_tables = catalog
        .table_grants
        .iter()
        .map(|g| (&g.schema, &g.table, &g.grantee, &g.privileges));
    let on_columns = catalog
        .column_grants
        .iter()
        .map(|g| (&g.schema, &g.table, &g.grantee, &g.privileges));
    on_tables
        .chain(on_columns)
        .any(|(at_schema, at_table, grantee, privileges)| {
            (at_schema == schema || at_schema == VIEW_SCHEMA)
                && at_table == table
                && (grantee == role || grantee == PUBLIC)
                && privileges.iter().any(|p| p == privilege)
        })
}

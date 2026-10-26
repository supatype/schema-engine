//! Who may read and write a many-to-many link: the policies and privileges of a junction table.
//!
//! A junction is generated, not declared, so its author has nowhere to write an `access` block.
//! Its rules follow from its two ends, the way a foreign key's do from the row holding it:
//!
//! - **Read**: a link is visible when both of its ends are visible to the caller. Each end is
//!   tested by reading its row, so the end's own policies decide, a draft-reading Studio policy
//!   included, and the link of a post the caller may not see stays hidden with it.
//! - **Write** (insert, update, delete): a link may be added or removed by a caller who can see both
//!   ends and may update at least one of them. Tagging a post is an edit of the post, which is how
//!   Prisma's `connect` and a hand-written Supabase policy treat it: the editor of a post may tag it
//!   with any tag they can see, without the right to edit the tag.
//!
//! An end's read is a subquery on its table, so when an end's own read rule reads the junction as a
//! membership source the two policies would read each other and Postgres would refuse every query
//! ("infinite recursion detected in policy"). Such a junction keeps the older derivation, the
//! intersection of the ends' rules (`differ::rls_diff::intersect_access`), which denies what a
//! row-dependent rule decides and says so in a push warning.

use crate::differ::rls_diff::{expected_policies, intersect_access};
use crate::differ::table_diff::versions_record_id;
use crate::generator::sql::rls;
use crate::parser::accessors::{db_table_name, platform_access};
use crate::parser::ast::{
    AccessAst, AccessRule, JunctionTableAst, MembershipSource, ModelAst, SchemaAst,
};
use crate::sql_quote::{quote_ident, quote_qualified};
use anyhow::{bail, Result};

/// The policy suffixes that read a link and that write one.
const READ: &str = "select";
const WRITES: [&str; 3] = ["insert", "update", "delete"];

/// One end of a link: the model, and the junction column naming its row.
#[derive(Clone, Copy)]
pub(crate) struct End<'a> {
    pub model: &'a ModelAst,
    pub fk: &'a str,
}

/// How a junction's access is derived.
pub(crate) enum JunctionAccess<'a> {
    /// From its ends' rows: the rule this module describes.
    Linked([End<'a>; 2]),
    /// The intersection of its ends' rules, where reading the ends would recurse, or where an end
    /// is not in the schema (every operation denied).
    Intersected(Box<AccessAst>),
}

/// How `junction`'s access is derived in `ast`.
pub(crate) fn junction_access<'a>(
    ast: &'a SchemaAst,
    junction: &'a JunctionTableAst,
) -> JunctionAccess<'a> {
    let model = |name: &str| ast.models.iter().find(|m| m.name == name);
    let (Some(a), Some(b)) = (model(&junction.model_a), model(&junction.model_b)) else {
        return JunctionAccess::Intersected(Box::default());
    };
    let reads_junction = |m: &ModelAst| {
        platform_access(m)
            .read
            .as_ref()
            .is_some_and(|rule| reads_table(rule, &junction.name))
    };
    if reads_junction(a) || reads_junction(b) {
        return JunctionAccess::Intersected(Box::new(intersect_access(a.access(), b.access())));
    }
    JunctionAccess::Linked([
        End {
            model: a,
            fk: &junction.fk_a,
        },
        End {
            model: b,
            fk: &junction.fk_b,
        },
    ])
}

/// Whether `rule` reads `table` as a membership source, at any depth.
fn reads_table(rule: &AccessRule, table: &str) -> bool {
    let source_reads = |source: &MembershipSource| match source {
        MembershipSource::Rows {
            table: t, filter, ..
        } => t == table || filter.as_deref().is_some_and(|f| reads_table(f, table)),
        _ => false,
    };
    match rule {
        AccessRule::In { source, .. } | AccessRule::Exists { source } => source_reads(source),
        AccessRule::Any { rules } | AccessRule::All { rules } => {
            rules.iter().any(|r| reads_table(r, table))
        }
        AccessRule::Not { rule } => reads_table(rule, table),
        _ => false,
    }
}

/// Whether either end of a linked junction declares an update rule, which is what lets anyone
/// write a link at all.
fn writable(ends: &[End<'_>; 2]) -> bool {
    ends.iter()
        .any(|end| platform_access(end.model).update.is_some())
}

/// The suffixes of the policies `access` puts on the junction.
pub(crate) fn policy_suffixes(access: &JunctionAccess<'_>) -> Vec<String> {
    match access {
        JunctionAccess::Linked(ends) => {
            let writes = if writable(ends) { &WRITES[..] } else { &[] };
            std::iter::once(READ)
                .chain(writes.iter().copied())
                .map(str::to_string)
                .collect()
        }
        JunctionAccess::Intersected(derived) => expected_policies(derived)
            .into_iter()
            .map(|(suffix, _)| suffix)
            .collect(),
    }
}

/// The `CREATE POLICY` for `junction`'s `suffix` policy.
pub(crate) fn policy_sql(
    schema: &str,
    ast: &SchemaAst,
    junction: &JunctionTableAst,
    suffix: &str,
) -> Result<String> {
    let table = junction.name.as_str();
    match junction_access(ast, junction) {
        JunctionAccess::Linked(ends) => {
            let expr = linked_expr(schema, ast, table, &ends, suffix != READ);
            Ok(rls::render_policy_with_expr(schema, table, suffix, &expr))
        }
        JunctionAccess::Intersected(derived) => {
            let Some(model) = ast.models.iter().find(|m| m.name == junction.model_a) else {
                bail!(
                    "junction {table}: its model {} is not in the schema",
                    junction.model_a
                );
            };
            let Some(rule) = rule_for(&derived, suffix) else {
                bail!("junction {table} has no derivable access rule for {suffix}");
            };
            Ok(rls::render_policy_migration_sql(
                schema, table, suffix, ast, model, rule,
            ))
        }
    }
}

fn rule_for<'a>(access: &'a AccessAst, suffix: &str) -> Option<&'a AccessRule> {
    match suffix {
        "select" => access.read.as_ref(),
        "insert" => access.create.as_ref(),
        "update" => access.update.as_ref(),
        _ => access.delete.as_ref(),
    }
}

/// Both ends readable and, for a write, at least one of them updatable.
fn linked_expr(
    schema: &str,
    ast: &SchemaAst,
    junction: &str,
    ends: &[End<'_>; 2],
    write: bool,
) -> String {
    let read = ends
        .iter()
        .map(|end| end_expr(schema, ast, junction, *end, None))
        .collect::<Vec<_>>()
        .join("\n    AND ");
    if !write {
        return read;
    }
    let update = ends
        .iter()
        .filter_map(|end| {
            let rule = platform_access(end.model).update.as_ref()?;
            Some(end_expr(schema, ast, junction, *end, Some(rule)))
        })
        .collect::<Vec<_>>()
        .join("\n      OR ");
    format!("{read}\n    AND ({update})")
}

/// `EXISTS` a row of `end` the link names that the caller can read, and that `rule` admits when
/// given. The subquery reads the end's table as the caller, so its policies apply; `rule` is the
/// end's update rule, which its read policy does not decide.
fn end_expr(
    schema: &str,
    ast: &SchemaAst,
    junction: &str,
    end: End<'_>,
    rule: Option<&AccessRule>,
) -> String {
    let table = db_table_name(end.model);
    let (key, _) = versions_record_id(end.model);
    let mut expr = format!(
        "EXISTS (SELECT 1 FROM {} WHERE {}.{} = {}.{}",
        quote_qualified(schema, table),
        quote_ident(table),
        quote_ident(&key),
        quote_ident(junction),
        quote_ident(end.fk),
    );
    if let Some(rule) = rule {
        let admitted = rls::access_rule_to_expr(ast, end.model, rule, schema);
        expr.push_str(&format!(" AND ({admitted})"));
    }
    expr.push(')');
    expr
}

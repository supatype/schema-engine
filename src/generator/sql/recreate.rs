//! A column dropped and added again (`RecreateColumn`), around everything that depends on it.
//!
//! Postgres refuses to drop a column anything else depends on, and the push never cascades, so
//! each dependent is dropped first and made again after, from the catalog's own definition, so no
//! clause is lost to the engine not modelling it. Two kinds cannot be made again that way and
//! refuse the push before it changes anything: a view (it may be anything, and others may depend
//! on it in turn), and anything in another schema (the push works in its own).
//!
//! The engine's own objects among the dependents are the reconcile's: one it keeps as it is is
//! made again here like the user's, since nothing else would; one it makes, replaces or drops
//! itself in this push is only dropped here, and left to it.
//!
//! Two things are left as they are, on purpose:
//! - A function body that names the column. A trigger or policy that reads the column only inside
//!   a function it calls has no `pg_depend` entry on the column, so it is not a dependent: Postgres
//!   drops the column without touching it, it stays in place, and its function sees the new
//!   column on its next call.
//! - A rule on the table itself. It reads as a rewrite rule like a view's, so it is named as a
//!   view and refuses the push the same way; rules on tables are rare enough not to be made again.

use std::collections::BTreeSet;

use anyhow::{bail, Result};

use super::migration::{field_to_column_def, normalize_fk_action, quote_ident_list};
use crate::desired::ObjectKey;
use crate::differ::ColumnDependencySnapshot;
use crate::introspector::fingerprint::ObjectKind;
use crate::ledger::reconcile::Action;
use crate::managed::ObjectNames;
use crate::parser::ast::FieldAst;
use crate::sql_quote::{quote_ident, quote_qualified};

/// The kinds of a recreated column's dependents, in the order they are dropped: triggers and
/// policies, which nothing depends on; then foreign keys, since one may need a unique constraint
/// or index on the column; then the other constraints; then the indexes of their own. They come
/// back in the reverse order, so a key's unique constraint or index is there before the key.
const DEPENDENCY_DROP_ORDER: [&str; 5] =
    ["trigger", "policy", "foreign_key", "constraint", "index"];

/// What the reconcile of the same push does with the engine's objects, by key.
#[derive(Debug, Clone, Default)]
pub struct Reconciled {
    /// The engine's objects it leaves as they are.
    kept: BTreeSet<ObjectKey>,
    /// Every object it has an action for: the engine's, kept or not.
    engines: BTreeSet<ObjectKey>,
}

impl Reconciled {
    pub fn of(actions: &[Action]) -> Reconciled {
        let leaves_in_place = |a: &&Action| {
            matches!(
                a,
                Action::Keep { .. }
                    | Action::Restate { .. }
                    | Action::Adopt { .. }
                    | Action::Rename { .. }
                    | Action::Released { .. }
            )
        };
        Reconciled {
            kept: actions
                .iter()
                .filter(leaves_in_place)
                .map(|a| a.key().clone())
                .collect(),
            engines: actions.iter().map(|a| a.key().clone()).collect(),
        }
    }

    fn matches(set: &BTreeSet<ObjectKey>, schema: &str, dep: &ColumnDependencySnapshot) -> bool {
        let (parent, name) = match dep.kind.as_str() {
            "view" => ("", dep.table.as_str()),
            _ => (dep.table.as_str(), dep.name.as_str()),
        };
        set.iter().any(|k| {
            k.schema == dependency_schema(schema, dep)
                && k.parent == parent
                && k.name == name
                && kinds_of(&dep.kind).contains(&k.kind)
        })
    }

    /// Whether `dep` is the engine's, for the reconcile to see to.
    fn is_engines(&self, schema: &str, dep: &ColumnDependencySnapshot) -> bool {
        Self::matches(&self.engines, schema, dep)
    }

    /// Whether the recreate makes `dep` again: the user's always, the engine's when the reconcile
    /// leaves it as it is.
    fn restores(&self, schema: &str, dep: &ColumnDependencySnapshot) -> bool {
        !self.is_engines(schema, dep) || Self::matches(&self.kept, schema, dep)
    }
}

/// The ledger kinds a dependent of `kind` may be recorded as.
fn kinds_of(kind: &str) -> &'static [ObjectKind] {
    match kind {
        "index" => &[ObjectKind::Index],
        "foreign_key" => &[ObjectKind::ForeignKey],
        "constraint" => &[
            ObjectKind::PrimaryKey,
            ObjectKind::Unique,
            ObjectKind::Check,
        ],
        "trigger" => &[ObjectKind::Trigger],
        "policy" => &[ObjectKind::Policy],
        "view" => &[ObjectKind::View],
        _ => &[],
    }
}

fn dependency_schema<'a>(schema: &'a str, dep: &'a ColumnDependencySnapshot) -> &'a str {
    dep.schema.as_deref().unwrap_or(schema)
}

/// A column dropped and added again, around what depends on it: each dependent is dropped first
/// and made again after, by the name and shape it has in the catalog. One the new column's
/// definition makes itself (a `CONSTRAINT` it names), or the engine's unique or type check for the
/// column, is left to the definition, which knows whether the column still has it. A view, or a
/// dependent in another schema, that is not the engine's refuses the push.
pub fn recreate_column_sql(
    names: &ObjectNames,
    table: &str,
    column: &str,
    field: &FieldAst,
    dependencies: &[ColumnDependencySnapshot],
    schema: &str,
    reconciled: &Reconciled,
) -> Result<String> {
    refuse_what_cannot_come_back(table, column, dependencies, schema, reconciled)?;
    let by_kind = |kind: &'static str| dependencies.iter().filter(move |dep| dep.kind == kind);
    let mut stmts: Vec<String> = DEPENDENCY_DROP_ORDER
        .into_iter()
        .flat_map(by_kind)
        .map(|dep| drop_dependency_sql(schema, dep))
        .collect();

    let target = quote_qualified(schema, table);
    stmts.push(format!(
        "ALTER TABLE {target} DROP COLUMN IF EXISTS {};",
        quote_ident(column)
    ));
    let col_def = field_to_column_def(names, table, column, field)?;
    stmts.push(format!("ALTER TABLE {target} ADD COLUMN {col_def};"));

    stmts.extend(
        DEPENDENCY_DROP_ORDER
            .into_iter()
            .rev()
            .flat_map(by_kind)
            .filter(|dep| reconciled.restores(schema, dep))
            .filter(|dep| !made_by_column_definition(names, table, column, &col_def, dep))
            .map(|dep| restore_dependency_sql(schema, column, dep)),
    );
    Ok(stmts.join("\n"))
}

/// An error naming every view, and every dependent in another schema, on `table.column` that is
/// not the engine's: the recreate cannot drop and make those again, so the push stops before it
/// changes anything.
fn refuse_what_cannot_come_back(
    table: &str,
    column: &str,
    dependencies: &[ColumnDependencySnapshot],
    schema: &str,
    reconciled: &Reconciled,
) -> Result<()> {
    let blocking: Vec<String> = dependencies
        .iter()
        .filter(|dep| dep.kind == "view" || dependency_schema(schema, dep) != schema)
        .filter(|dep| !reconciled.is_engines(schema, dep))
        .map(|dep| describe(schema, dep))
        .collect();
    if blocking.is_empty() {
        return Ok(());
    }
    let (depend, them) = if blocking.len() == 1 {
        ("depends", "it")
    } else {
        ("depend", "them")
    };
    bail!(
        "{schema}.{table}.{column} has to be dropped and added again for this change, and {} \
         {depend} on it. Supatype does not drop and make again a view, or anything in another \
         schema, so nothing was changed. Drop {them}, push again, then make {them} again.",
        blocking.join(", "),
    )
}

/// `view public.titles`, or `foreign key other.notes.notes_post_fkey`: a dependent as an error
/// names it.
fn describe(schema: &str, dep: &ColumnDependencySnapshot) -> String {
    let at = dependency_schema(schema, dep);
    match dep.kind.as_str() {
        "view" => format!("view {at}.{}", dep.table),
        kind => format!("{} {at}.{}.{}", kind.replace('_', " "), dep.table, dep.name),
    }
}

/// Whether the recreated column's own definition `col_def` makes `dep` (a `CONSTRAINT` it names),
/// or would have if the column still had it (the engine's unique or type check for the column).
fn made_by_column_definition(
    names: &ObjectNames,
    table: &str,
    column: &str,
    col_def: &str,
    dep: &ColumnDependencySnapshot,
) -> bool {
    dep.table == table
        && (col_def.contains(&format!("CONSTRAINT {} ", quote_ident(&dep.name)))
            || dep.name == names.unique(table, column)
            || dep.name == names.type_check(table, column))
}

/// The drop of one object that depends on a recreated column. `IF EXISTS`, as one may have gone
/// with another before it, or with the reconcile's removals.
fn drop_dependency_sql(schema: &str, dep: &ColumnDependencySnapshot) -> String {
    let on = quote_qualified(dependency_schema(schema, dep), &dep.table);
    let name = quote_ident(&dep.name);
    match dep.kind.as_str() {
        "index" => format!(
            "DROP INDEX IF EXISTS {};",
            quote_qualified(dependency_schema(schema, dep), &dep.name)
        ),
        "trigger" => format!("DROP TRIGGER IF EXISTS {name} ON {on};"),
        "policy" => format!("DROP POLICY IF EXISTS {name} ON {on};"),
        _ => format!("ALTER TABLE {on} DROP CONSTRAINT IF EXISTS {name};"),
    }
}

/// One dependent of a recreated column, made again as the catalog described it.
///
/// The names are the snapshot's, schema-qualified here; everything else comes from the catalog's
/// own definition, so no clause is lost to the engine not modelling it. Only the definition's
/// names are not trusted: `pg_get_constraintdef` leaves a referenced table unqualified when it is
/// on the `search_path` of the read, which need not be the push's.
pub(super) fn restore_dependency_sql(
    schema: &str,
    column: &str,
    dep: &ColumnDependencySnapshot,
) -> String {
    let cols = dep
        .columns
        .as_deref()
        .map_or_else(|| quote_ident(column), quote_ident_list);
    let on = quote_qualified(dependency_schema(schema, dep), &dep.table);
    let name = quote_ident(&dep.name);
    match (dep.kind.as_str(), dep.definition.as_deref()) {
        ("index", _) => restore_index_sql(&on, &name, &cols, dep),
        // A primary key, unique, exclusion or check constraint names only columns of its own
        // table, so its definition is restored as printed.
        ("constraint", Some(definition)) => {
            format!("ALTER TABLE {on} ADD CONSTRAINT {name} {definition};")
        }
        // `pg_get_triggerdef` is the whole statement.
        ("trigger", Some(definition)) => format!("{definition};"),
        // What follows `CREATE POLICY name ON table`, as the introspection composed it.
        ("policy", Some(definition)) => format!("CREATE POLICY {name} ON {on}{definition};"),
        _ => restore_foreign_key_sql(schema, &on, &name, &cols, dep),
    }
}

/// A foreign key on, or to, a recreated column.
fn restore_foreign_key_sql(
    schema: &str,
    on: &str,
    name: &str,
    cols: &str,
    dep: &ColumnDependencySnapshot,
) -> String {
    let ref_table = quote_qualified(
        dep.foreign_schema.as_deref().unwrap_or(schema),
        dep.foreign_table.as_deref().unwrap_or("?"),
    );
    let ref_cols = dep
        .foreign_columns
        .as_deref()
        .map_or_else(|| "\"id\"".to_string(), quote_ident_list);
    let clauses = dep
        .definition
        .as_deref()
        .and_then(after_referenced_columns)
        .map(str::to_string)
        .unwrap_or_else(|| {
            dep.on_delete
                .as_deref()
                .map(|a| format!(" ON DELETE {}", normalize_fk_action(a)))
                .unwrap_or_default()
        });
    format!(
        "ALTER TABLE {on} ADD CONSTRAINT {name} FOREIGN KEY ({cols}) REFERENCES {ref_table} ({ref_cols}){clauses};"
    )
}

/// An index on a recreated column, from `USING` on as `pg_get_indexdef` printed it (method, keys
/// with their order and operator classes, `INCLUDE`, storage options, `WHERE`).
fn restore_index_sql(on: &str, name: &str, cols: &str, dep: &ColumnDependencySnapshot) -> String {
    let unique = if dep.unique { "UNIQUE " } else { "" };
    let using = dep.definition.as_deref().and_then(|def| {
        find_outside_quotes(def, " USING ").map(|at| def[at + " USING ".len()..].to_string())
    });
    let using = using.unwrap_or_else(|| {
        let method = quote_ident(dep.index_method.as_deref().unwrap_or("btree"));
        format!("{method} ({cols})")
    });
    format!("CREATE {unique}INDEX IF NOT EXISTS {name} ON {on} USING {using};")
}

/// What a `pg_get_constraintdef` foreign key says after its referenced column list: ` MATCH FULL
/// ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED` and the like, empty for a key with no clauses.
fn after_referenced_columns(definition: &str) -> Option<&str> {
    let references = &definition[find_outside_quotes(definition, "REFERENCES ")?..];
    let open = find_outside_quotes(references, "(")?;
    let close = open + find_outside_quotes(&references[open..], ")")?;
    Some(&references[close + 1..])
}

/// Where `needle` first occurs in `sql` outside a double-quoted identifier.
fn find_outside_quotes(sql: &str, needle: &str) -> Option<usize> {
    let mut quoted = false;
    for (at, ch) in sql.char_indices() {
        if ch == '"' {
            quoted = !quoted;
        } else if !quoted && sql[at..].starts_with(needle) {
            return Some(at);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recreated column's key in another schema, by catalog definition: the referenced table is
    /// qualified from the snapshot, every clause after it is the catalog's, and a quoted `)` in a
    /// referenced column's name does not end the column list early.
    #[test]
    fn a_recreated_columns_foreign_key_is_restored_from_its_definition() {
        use crate::introspector::constraints::{DbConstraint, DbConstraintType};
        let key = DbConstraint {
            table: "posts".into(),
            name: "posts_author_id_fkey".into(),
            constraint_type: DbConstraintType::ForeignKey,
            columns: vec!["author_id".into()],
            foreign_table: Some("users".into()),
            foreign_schema: Some("auth".into()),
            foreign_columns: Some(vec!["odd) id".into()]),
            check_expression: None,
            on_delete: Some("SET NULL".into()),
            definition: Some(
                "FOREIGN KEY (author_id) REFERENCES users(\"odd) id\") ON UPDATE RESTRICT \
                 ON DELETE SET NULL MATCH FULL DEFERRABLE INITIALLY DEFERRED"
                    .into(),
            ),
            comment: None,
            foreign_key_options: Some(Default::default()),
        };
        let db = crate::state::database_state::DatabaseState {
            constraints: vec![key],
            ..Default::default()
        };
        let deps =
            crate::differ::column_diff::discover_column_dependencies("posts", "author_id", &db);
        assert_eq!(
            restore_dependency_sql("public", "author_id", &deps[0]),
            "ALTER TABLE \"public\".\"posts\" ADD CONSTRAINT \"posts_author_id_fkey\" \
             FOREIGN KEY (\"author_id\") REFERENCES \"auth\".\"users\" (\"odd) id\") \
             ON UPDATE RESTRICT ON DELETE SET NULL MATCH FULL DEFERRABLE INITIALLY DEFERRED;"
        );
    }

    fn dependency(kind: &str, name: &str, definition: Option<&str>) -> ColumnDependencySnapshot {
        ColumnDependencySnapshot {
            kind: kind.into(),
            table: "posts".into(),
            name: name.into(),
            schema: None,
            columns: Some(vec!["title".into()]),
            foreign_table: None,
            foreign_schema: None,
            foreign_columns: None,
            on_delete: None,
            definition: definition.map(str::to_string),
            unique: true,
            index_method: Some("btree".into()),
        }
    }

    /// A snapshot without a definition (written before one was recorded) restores from its parts.
    #[test]
    fn a_dependency_without_a_definition_is_restored_from_its_parts() {
        assert_eq!(
            restore_dependency_sql(
                "public",
                "title",
                &dependency("index", "posts_title_idx", None)
            ),
            "CREATE UNIQUE INDEX IF NOT EXISTS \"posts_title_idx\" ON \"public\".\"posts\" \
             USING \"btree\" (\"title\");"
        );
    }

    /// A policy is made again from what follows its name and table, under the snapshot's names.
    #[test]
    fn a_policy_is_restored_under_its_quoted_name_and_table() {
        let policy = dependency(
            "policy",
            "hide secret",
            Some(" AS RESTRICTIVE FOR SELECT TO authenticated USING ((title <> 'x'::text))"),
        );
        assert_eq!(
            restore_dependency_sql("public", "title", &policy),
            "CREATE POLICY \"hide secret\" ON \"public\".\"posts\" AS RESTRICTIVE FOR SELECT \
             TO authenticated USING ((title <> 'x'::text));"
        );
    }

    /// The engine's own dependent that the reconcile replaces is left to it; one it keeps is made
    /// again here; the user's is always made again.
    #[test]
    fn only_what_the_reconcile_does_not_make_again_is_restored() {
        let key = |name: &str| ObjectKey {
            kind: ObjectKind::Policy,
            schema: "public".into(),
            parent: "posts".into(),
            name: name.into(),
        };
        let reconciled = Reconciled {
            kept: BTreeSet::from([key("kept")]),
            engines: BTreeSet::from([key("kept"), key("replaced")]),
        };
        let restored =
            |name: &str| reconciled.restores("public", &dependency("policy", name, None));
        assert!(restored("kept"));
        assert!(!restored("replaced"));
        assert!(restored("users_own"));
    }

    /// A user's view on the column, and a key in another schema, refuse the push by name; the
    /// engine's own view is its business.
    #[test]
    fn a_users_view_or_other_schemas_dependent_refuses_by_name() {
        let view = ColumnDependencySnapshot {
            table: "titles".into(),
            ..dependency("view", "titles", Some(""))
        };
        let elsewhere = ColumnDependencySnapshot {
            table: "notes".into(),
            schema: Some("other".into()),
            ..dependency("foreign_key", "notes_post_fkey", None)
        };
        let refused = refuse_what_cannot_come_back(
            "posts",
            "title",
            &[view.clone(), elsewhere],
            "public",
            &Reconciled::default(),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            refused,
            "public.posts.title has to be dropped and added again for this change, and view \
             public.titles, foreign key other.notes.notes_post_fkey depend on it. Supatype does \
             not drop and make again a view, or anything in another schema, so nothing was \
             changed. Drop them, push again, then make them again."
        );
        let engines = Reconciled {
            kept: BTreeSet::new(),
            engines: BTreeSet::from([ObjectKey {
                kind: ObjectKind::View,
                schema: "public".into(),
                parent: String::new(),
                name: "titles".into(),
            }]),
        };
        assert!(
            refuse_what_cannot_come_back("posts", "title", &[view], "public", &engines).is_ok()
        );
    }
}

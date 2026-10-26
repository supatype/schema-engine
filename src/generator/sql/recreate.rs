//! A column dropped and added again (`RecreateColumn`), or its type changed in place
//! (`AlterColumn`), around what depends on it.
//!
//! Postgres refuses to drop a column anything else depends on, and to change the type of one a
//! trigger, a policy or a view reads; the push never cascades, so each dependent in the way is
//! dropped first and made again after, from the catalog's own definition, so no clause is lost to
//! the engine not modelling it. Two kinds cannot be made again that way and refuse the push before
//! it changes anything: a view (it may be anything, and others may depend on it in turn), and
//! anything in another schema (the push works in its own). Both changes share this one path, so a
//! dependent is handled the same whichever of them the push makes.
//!
//! The engine's own objects among the dependents are the reconcile's: one it keeps as it is is
//! made again here like the user's, since nothing else would; one it makes, replaces or drops
//! itself in this push is only dropped here, and left to it. The engine's own views are made
//! again whenever their table changes, so here they are only dropped.
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
    /// A reconcile with no action for any object.
    pub const NONE: Reconciled = Reconciled {
        kept: BTreeSet::new(),
        engines: BTreeSet::new(),
    };

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

/// How a column changes under what depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnChange {
    /// Dropped and added again: everything that depends on it would go with it.
    Recreate,
    /// Its type changed in place. Postgres rebuilds the indexes and constraints on it itself, and
    /// refuses while a trigger, a policy or a view reads it.
    Retype,
}

impl ColumnChange {
    /// Whether `dep` is in the way of this change.
    fn is_in_the_way(self, dep: &ColumnDependencySnapshot) -> bool {
        match self {
            ColumnChange::Recreate => true,
            ColumnChange::Retype => matches!(dep.kind.as_str(), "trigger" | "policy" | "view"),
        }
    }

    /// What the change does to the column, as a refusal says it.
    fn described(self) -> &'static str {
        match self {
            ColumnChange::Recreate => "has to be dropped and added again for this change",
            ColumnChange::Retype => "changes type in this push",
        }
    }
}

/// One column a push changes, what depends on it, and what the push's reconcile does with the
/// engine's objects among them.
#[derive(Debug, Clone, Copy)]
pub struct ColumnSite<'a> {
    pub schema: &'a str,
    pub table: &'a str,
    pub column: &'a str,
    pub dependencies: &'a [ColumnDependencySnapshot],
    pub reconciled: &'a Reconciled,
}

impl ColumnSite<'_> {
    /// The dependents in the way of `change`, of `kind`.
    fn in_the_way<'s>(
        &'s self,
        change: ColumnChange,
        kind: &'static str,
    ) -> impl Iterator<Item = &'s ColumnDependencySnapshot> + 's {
        self.dependencies
            .iter()
            .filter(move |dep| dep.kind == kind && change.is_in_the_way(dep))
    }

    /// `middle` with what is in the way of `change` dropped before it and made again after it, or
    /// an error naming what cannot be made again. One the engine's reconcile makes, replaces or
    /// drops itself is only dropped; one `made_by_middle` says `middle` makes is not made again.
    fn around(
        &self,
        change: ColumnChange,
        middle: Vec<String>,
        made_by_middle: impl Fn(&ColumnDependencySnapshot) -> bool,
    ) -> Result<String> {
        self.refuse_what_cannot_come_back(change)?;
        let mut stmts = self.drop_engines_views(change);
        stmts.extend(
            DEPENDENCY_DROP_ORDER
                .into_iter()
                .flat_map(|kind| self.in_the_way(change, kind))
                .map(|dep| drop_dependency_sql(self.schema, dep)),
        );
        stmts.extend(middle);
        stmts.extend(
            DEPENDENCY_DROP_ORDER
                .into_iter()
                .rev()
                .flat_map(|kind| self.in_the_way(change, kind))
                .filter(|dep| self.reconciled.restores(self.schema, dep))
                .filter(|dep| !made_by_middle(dep))
                .map(|dep| restore_dependency_sql(self.schema, self.column, dep)),
        );
        Ok(stmts.join("\n"))
    }

    /// The drop of each of the engine's views on the column: the push makes its views again
    /// whenever their table changes, after the operations, so here they only go.
    fn drop_engines_views(&self, change: ColumnChange) -> Vec<String> {
        self.in_the_way(change, "view")
            .filter(|dep| self.reconciled.is_engines(self.schema, dep))
            .map(|dep| drop_dependency_sql(self.schema, dep))
            .collect()
    }

    /// An error naming every view, and every dependent in another schema, in the way of `change`
    /// that is not the engine's: the push cannot drop and make those again, so it stops before it
    /// changes anything.
    fn refuse_what_cannot_come_back(&self, change: ColumnChange) -> Result<()> {
        let schema = self.schema;
        let blocking: Vec<String> = self
            .dependencies
            .iter()
            .filter(|dep| change.is_in_the_way(dep))
            .filter(|dep| dep.kind == "view" || dependency_schema(schema, dep) != schema)
            .filter(|dep| !self.reconciled.is_engines(schema, dep))
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
            "{schema}.{}.{} {}, and {} {depend} on it. Supatype does not drop and make again a \
             view, or anything in another schema, so nothing was changed. Drop {them}, push \
             again, then make {them} again.",
            self.table,
            self.column,
            change.described(),
            blocking.join(", "),
        )
    }
}

/// A column dropped and added again, around what depends on it: each dependent is dropped first
/// and made again after, by the name and shape it has in the catalog. One the new column's
/// definition makes itself (a `CONSTRAINT` it names), or the engine's unique or type check for the
/// column, is left to the definition, which knows whether the column still has it. A view, or a
/// dependent in another schema, that is not the engine's refuses the push.
pub fn recreate_column_sql(
    names: &ObjectNames,
    site: &ColumnSite<'_>,
    field: &FieldAst,
) -> Result<String> {
    let (table, column) = (site.table, site.column);
    let target = quote_qualified(site.schema, table);
    let col_def = field_to_column_def(names, table, column, field)?;
    let middle = vec![
        format!(
            "ALTER TABLE {target} DROP COLUMN IF EXISTS {};",
            quote_ident(column)
        ),
        format!("ALTER TABLE {target} ADD COLUMN {col_def};"),
    ];
    site.around(ColumnChange::Recreate, middle, |dep| {
        made_by_column_definition(names, table, column, &col_def, dep)
    })
}

/// A column's type changed in place (`retype`), around what Postgres refuses it under: each
/// trigger and policy that reads the column is dropped first and made again after, as for a column
/// dropped and added again, and the engine's own views on it go and are made again with their
/// table. A view, or a dependent in another schema, that is not the engine's refuses the push.
pub fn retype_column_sql(site: &ColumnSite<'_>, retype: String) -> Result<String> {
    site.around(ColumnChange::Retype, vec![retype], |_| false)
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
        // A view dependent is named by the view itself.
        "view" => format!("DROP VIEW IF EXISTS {on};"),
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

    /// A view on `posts.title`: `titles` in the project schema, or one in `schema`.
    fn view(schema: Option<&str>, name: &str) -> ColumnDependencySnapshot {
        ColumnDependencySnapshot {
            table: name.into(),
            schema: schema.map(str::to_string),
            ..dependency("view", name, Some(""))
        }
    }

    /// A key on `posts.title` from a table in another schema.
    fn key_elsewhere() -> ColumnDependencySnapshot {
        ColumnDependencySnapshot {
            table: "notes".into(),
            schema: Some("other".into()),
            ..dependency("foreign_key", "notes_post_fkey", None)
        }
    }

    /// A reconcile with an action for the view `schema.name`, so the engine's.
    fn with_engines_view(schema: &str, name: &str) -> Reconciled {
        let key = ObjectKey {
            kind: ObjectKind::View,
            schema: schema.into(),
            parent: String::new(),
            name: name.into(),
        };
        Reconciled {
            engines: BTreeSet::from([key]),
            ..Reconciled::default()
        }
    }

    fn site<'a>(
        deps: &'a [ColumnDependencySnapshot],
        reconciled: &'a Reconciled,
    ) -> ColumnSite<'a> {
        ColumnSite {
            schema: "public",
            table: "posts",
            column: "title",
            dependencies: deps,
            reconciled,
        }
    }

    /// A user's view on the column, and a key in another schema, refuse the push by name; the
    /// engine's own view is its business.
    #[test]
    fn a_users_view_or_other_schemas_dependent_refuses_by_name() {
        let deps = [view(None, "titles"), key_elsewhere()];
        let refused = site(&deps, &Reconciled::default())
            .refuse_what_cannot_come_back(ColumnChange::Recreate)
            .unwrap_err()
            .to_string();
        assert_eq!(
            refused,
            "public.posts.title has to be dropped and added again for this change, and view \
             public.titles, foreign key other.notes.notes_post_fkey depend on it. Supatype does \
             not drop and make again a view, or anything in another schema, so nothing was \
             changed. Drop them, push again, then make them again."
        );
        let engines = with_engines_view("public", "titles");
        assert!(site(&[view(None, "titles")], &engines)
            .refuse_what_cannot_come_back(ColumnChange::Recreate)
            .is_ok());
    }

    /// A type change in place is refused only by what Postgres refuses it under: a user's view
    /// names the same refusal as a recreate, worded for the type change; a key in another schema,
    /// which Postgres rebuilds itself, is not in the way.
    #[test]
    fn a_type_change_is_refused_only_by_what_reads_the_column() {
        let deps = [view(None, "titles"), key_elsewhere()];
        let refused = retype_column_sql(&site(&deps, &Reconciled::default()), "ALTER;".into())
            .unwrap_err()
            .to_string();
        assert!(
            refused.starts_with(
                "public.posts.title changes type in this push, and view public.titles depends on it."
            ),
            "{refused}"
        );
        let elsewhere = [key_elsewhere()];
        let retyped = retype_column_sql(&site(&elsewhere, &Reconciled::default()), "ALTER;".into());
        assert_eq!(retyped.unwrap(), "ALTER;");
    }

    /// Around a type change, a policy and a trigger on the column are dropped and made again, the
    /// engine's own view on it only dropped, and an index left to Postgres.
    #[test]
    fn a_type_change_drops_and_restores_what_reads_the_column() {
        let policy = Some(" AS PERMISSIVE FOR SELECT TO PUBLIC");
        let trigger = Some("CREATE TRIGGER t BEFORE UPDATE OF title ON posts");
        let deps = [
            dependency("policy", "posts_select", policy),
            dependency("trigger", "t", trigger),
            dependency("index", "posts_title_idx", None),
            view(Some("api"), "posts"),
        ];
        let engines = with_engines_view("api", "posts");
        let sql = retype_column_sql(&site(&deps, &engines), "ALTER;".into()).unwrap();
        assert_eq!(
            sql.lines().collect::<Vec<_>>(),
            [
                "DROP VIEW IF EXISTS \"api\".\"posts\";",
                "DROP TRIGGER IF EXISTS \"t\" ON \"public\".\"posts\";",
                "DROP POLICY IF EXISTS \"posts_select\" ON \"public\".\"posts\";",
                "ALTER;",
                "CREATE POLICY \"posts_select\" ON \"public\".\"posts\" AS PERMISSIVE FOR SELECT \
                 TO PUBLIC;",
                "CREATE TRIGGER t BEFORE UPDATE OF title ON posts;",
            ]
        );
    }
}

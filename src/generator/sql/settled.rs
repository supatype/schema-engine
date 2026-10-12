//! Leaving alone what a push would only make again as it is (LK7).
//!
//! The drafts and publishing layer and tier 2's `api` views are rendered as scripts that drop and
//! make again their policies, triggers and views. Each of those statements takes ACCESS EXCLUSIVE
//! on the table or view it acts on, so a push that changed nothing about them still queued every
//! read and write of a versioned table, or of an API view, behind it. The reconcile already knows,
//! from the catalog, which of those objects are in place exactly as this push wants them (`Keep`,
//! `Restate`): their statements are left out of the scripts, and nothing else is.
//!
//! A view is made again whenever the push changes its table, whatever its reconcile action: a
//! draft view's `jsonb_populate_record(NULL::table, ...)` takes its columns from the table when it
//! is made, so its statement reads the same while what it shows is stale. A view and the triggers
//! on it go together: dropping the view drops them, so one that is made again takes the others
//! with it.

use std::collections::BTreeSet;

use crate::desired::statements::{attribute_all, split_statements};
use crate::desired::ObjectKey;
use crate::differ::Operation;
use crate::introspector::fingerprint::ObjectKind;
use crate::ledger::reconcile::Action;
use crate::parser::accessors::versions_table_name;

/// The kinds whose statements take a lock on a table or view that every read or write waits on.
const LOCKING: &[ObjectKind] = &[ObjectKind::Policy, ObjectKind::Trigger, ObjectKind::View];

/// The objects of a push that are in place as it wants them, and need no statement.
#[derive(Debug, Clone, Default)]
pub struct Settled {
    keys: BTreeSet<ObjectKey>,
}

impl Settled {
    /// What `reconcile` keeps as it is, less each view of a table `operations` change and every
    /// view or trigger that goes with one made again.
    pub fn of(reconcile: &[Action], operations: &[Operation]) -> Settled {
        let mut keys: BTreeSet<ObjectKey> = reconcile
            .iter()
            .filter(|a| matches!(a, Action::Keep { .. } | Action::Restate { .. }))
            .map(|a| a.key().clone())
            .filter(|k| LOCKING.contains(&k.kind))
            .collect();
        let changed = changed_tables(operations);
        // A draft view reads its model's table and its snapshot table.
        let view_changed =
            |n: &str| changed.contains(n) || changed.contains(&versions_table_name(n));
        keys.retain(|k| !(k.kind == ObjectKind::View && view_changed(&k.name)));
        let views: BTreeSet<(String, String)> = reconcile
            .iter()
            .map(Action::key)
            .filter(|k| k.kind == ObjectKind::View)
            .filter_map(view_named)
            .collect();
        let unsettled: BTreeSet<(String, String)> = reconcile
            .iter()
            .map(Action::key)
            .filter(|k| !keys.contains(k))
            .filter_map(view_named)
            .filter(|v| views.contains(v))
            .collect();
        keys.retain(|k| view_named(k).is_none_or(|v| !unsettled.contains(&v)));
        Settled { keys }
    }

    /// `sql` without the statements that act only on settled objects. Every other statement is
    /// kept exactly as rendered.
    pub fn leave_out(&self, sql: &str, schema: &str) -> String {
        if self.keys.is_empty() {
            return sql.to_string();
        }
        attribute_all(schema, split_statements(sql))
            .into_iter()
            .filter(|s| {
                let keys = s.attribution.keys();
                keys.is_empty() || !keys.iter().all(|k| self.keys.contains(k))
            })
            .map(|s| s.sql)
            .collect()
    }

    pub fn contains(&self, key: &ObjectKey) -> bool {
        self.keys.contains(key)
    }
}

/// `(schema, view)` for a view, or the relation a trigger sits on, which may be a view: what goes
/// with a view when it is dropped and made again.
fn view_named(key: &ObjectKey) -> Option<(String, String)> {
    match key.kind {
        ObjectKind::View => Some((key.schema.clone(), key.name.clone())),
        ObjectKind::Trigger => Some((key.schema.clone(), key.parent.clone())),
        _ => None,
    }
}

/// Every table `operations` change, by every name it has in them.
pub fn changed_tables(operations: &[Operation]) -> BTreeSet<String> {
    operations
        .iter()
        .flat_map(tables_of)
        .map(str::to_string)
        .collect()
}

fn tables_of(op: &Operation) -> Vec<&str> {
    match op {
        Operation::RenameTable { from, to, .. } => vec![from, to],
        Operation::CreateVersionsTable {
            table,
            versions_table,
            ..
        } => vec![table, versions_table],
        Operation::CreateTable { table, .. }
        | Operation::DropTable { table, .. }
        | Operation::AddColumn { table, .. }
        | Operation::DropColumn { table, .. }
        | Operation::RenameColumn { table, .. }
        | Operation::AlterColumn { table, .. }
        | Operation::RecreateColumn { table, .. }
        | Operation::AddIndex { table, .. }
        | Operation::AddForeignKey { table, .. }
        | Operation::AddUniqueConstraint { table, .. }
        | Operation::CreateRlsPolicy { table, .. }
        | Operation::CreateJunctionTable { table, .. } => vec![table],
        Operation::EnableExtension { .. } => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::differ::Risk;
    use crate::ledger::Status;

    fn key(kind: ObjectKind, schema: &str, parent: &str, name: &str) -> ObjectKey {
        ObjectKey {
            kind,
            schema: schema.into(),
            parent: parent.into(),
            name: name.into(),
        }
    }

    fn keep(key: ObjectKey) -> Action {
        Action::Keep {
            key,
            create_sql: String::new(),
            status: Status::Managed,
        }
    }

    #[test]
    fn statements_of_settled_objects_are_left_out_and_nothing_else() {
        let policy = key(ObjectKind::Policy, "public", "posts", "posts_select");
        let settled = Settled::of(&[keep(policy)], &[]);
        let sql = "DROP POLICY IF EXISTS \"posts_select\" ON \"public\".\"posts\";\n\
                   CREATE POLICY \"posts_select\" ON \"public\".\"posts\" FOR SELECT USING (true);\n\
                   CREATE POLICY \"other\" ON \"public\".\"posts\" FOR SELECT USING (true);\n\
                   GRANT SELECT ON \"public\".\"posts\" TO authenticated;\n";
        let out = settled.leave_out(sql, "public");
        assert!(!out.contains("\"posts_select\""), "{out}");
        assert!(out.contains("\"other\""), "{out}");
        assert!(out.contains("GRANT SELECT"), "{out}");
    }

    #[test]
    fn a_view_of_a_changed_table_and_the_triggers_on_it_are_made_again() {
        let view = key(ObjectKind::View, "api", "", "staff");
        let trigger = key(ObjectKind::Trigger, "api", "staff", "staff_write");
        let other = key(ObjectKind::View, "api", "", "tags");
        let dropped = Operation::DropColumn {
            table: "staff".into(),
            column: "x".into(),
            risk: Risk::Destructive,
        };
        let settled = Settled::of(
            &[
                keep(view.clone()),
                keep(trigger.clone()),
                keep(other.clone()),
            ],
            &[dropped],
        );
        assert!(!settled.contains(&view));
        assert!(!settled.contains(&trigger));
        assert!(settled.contains(&other));
    }

    #[test]
    fn a_trigger_not_settled_takes_its_view_with_it() {
        let view = key(ObjectKind::View, "api", "", "staff");
        let trigger = key(ObjectKind::Trigger, "api", "staff", "staff_write");
        let replaced = Action::Replace {
            key: trigger,
            create_sql: String::new(),
            previous_sql: String::new(),
            inline: true,
            status: Status::Managed,
            drifted: None,
        };
        let settled = Settled::of(&[keep(view.clone()), replaced], &[]);
        assert!(!settled.contains(&view));
    }
}

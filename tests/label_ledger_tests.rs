//! Phase 4.7 of the managed-object ownership plan: security labels on the ledger.
//!
//! A field rule is enforced by a `SECURITY LABEL FOR supatype` on its column, which the masking
//! extension reads. The labels were re-asserted on every push, and a sweep cleared every label
//! under our provider that the push did not re-assert. Each label is a ledger object now: set by
//! the reconcile, recorded, replaced when its rule changes, put back when it is taken off by hand,
//! and taken off when its rule goes. A label under our provider with no row is ours only where the
//! last push's schema set it (an older engine's): anyone with the extension can write under the
//! provider, and taking a person's own mask off would unmask the column (F15 (b), E23).

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{
    introspector::fingerprint::ObjectKind,
    ledger::{self, reconcile::Action, LedgerRow},
    parser,
    parser::ast::SchemaAst,
    push,
};

use common::{exec, push};

/// `salary` readable only by its owner, also writable only by its owner, or with no field rule.
#[derive(Clone, Copy)]
enum SalaryRule {
    None,
    Read,
    ReadWrite,
}

fn owner_only() -> Value {
    json!({ "type": "compare",
            "left": { "kind": "column", "name": "user_id" },
            "op": "eq",
            "right": { "kind": "claim", "path": "uid" } })
}

fn employees(rule: SalaryRule) -> SchemaAst {
    let mut access = json!({ "read": { "type": "public" }, "update": { "type": "public" } });
    match rule {
        SalaryRule::None => {}
        SalaryRule::Read => access["fields"] = json!({ "salary": { "read": owner_only() } }),
        SalaryRule::ReadWrite => {
            access["fields"] = json!({ "salary": { "read": owner_only(), "write": owner_only() } })
        }
    }
    let doc = json!({
        "astVersion": 2,
        "models": [{
            "name": "Employee",
            "fields": {
                "id": { "kind": "integer", "primaryKey": true, "required": true,
                        "annotations": { "db": { "pgType": "INTEGER", "unique": false } } },
                "salary": { "kind": "decimal",
                            "annotations": { "db": { "pgType": "NUMERIC", "unique": false } } },
                "user_id": { "kind": "text", "required": true,
                             "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
            },
            "options": { "timestamps": false, "softDelete": false, "singleton": false },
            "annotations": { "db": { "tableName": "employees", "indexes": [] },
                             "platform": { "access": access } }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

async fn label_rows(pool: &PgPool) -> Vec<LedgerRow> {
    let mut conn = pool.acquire().await.unwrap();
    ledger::load(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.key.kind == ObjectKind::SecurityLabel)
        .collect()
}

/// `table.column` of every recorded label.
async fn labelled(pool: &PgPool) -> Vec<String> {
    label_rows(pool)
        .await
        .into_iter()
        .map(|r| r.key.parent)
        .collect()
}

/// The label our provider holds on `employees.<column>`, if any.
async fn live_label(pool: &PgPool, column: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT l.label FROM pg_seclabel l
           JOIN pg_attribute a ON a.attrelid = l.objoid AND a.attnum = l.objsubid
          WHERE l.objoid = 'public.employees'::regclass AND l.provider = 'supatype'
            AND a.attname = $1",
    )
    .bind(column)
    .fetch_optional(pool)
    .await
    .unwrap()
}

fn applied(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::Applied { .. })
}

fn up_to_date(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::UpToDate { .. })
}

fn is_label(action: &Action) -> bool {
    action.key().kind == ObjectKind::SecurityLabel
}

const READ_LABEL: &str = "MASK READ public.\"can_read_employees__salary\"";

#[tokio::test]
async fn a_label_is_recorded_replaced_when_its_rule_changes_and_taken_off_when_it_goes() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            return;
        }
        let read = employees(SalaryRule::Read);
        assert!(applied(&push(&pool, &read).await.unwrap()));
        assert_eq!(
            live_label(&pool, "salary").await.as_deref(),
            Some(READ_LABEL)
        );
        assert_eq!(labelled(&pool).await, ["employees.salary"]);
        let again = push(&pool, &read).await.unwrap();
        assert!(up_to_date(&again), "{again:?}");

        let outcome = push(&pool, &employees(SalaryRule::ReadWrite))
            .await
            .unwrap();
        assert!(applied(&outcome), "{outcome:?}");
        let label = live_label(&pool, "salary").await.unwrap_or_default();
        assert!(
            label.contains("WRITE public.\"can_write_employees__salary\""),
            "the label kept its old rule: {label}"
        );

        let outcome = push(&pool, &employees(SalaryRule::None)).await.unwrap();
        assert!(applied(&outcome), "{outcome:?}");
        assert_eq!(
            live_label(&pool, "salary").await,
            None,
            "the column stayed masked by a rule that no longer exists"
        );
        assert!(label_rows(&pool).await.is_empty());
    })
    .await;
}

#[tokio::test]
async fn a_label_taken_off_by_hand_is_put_back() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            return;
        }
        let read = employees(SalaryRule::Read);
        push(&pool, &read).await.unwrap();
        exec(
            &pool,
            "SECURITY LABEL FOR supatype ON COLUMN public.employees.salary IS NULL",
        )
        .await
        .unwrap();

        let plan = push::prepare(&pool, &read, "public").await.unwrap();
        let labels: Vec<&Action> = plan
            .reconcile
            .actions
            .iter()
            .filter(|a| is_label(a))
            .collect();
        assert!(
            matches!(labels[..], [Action::Recreate { .. }]),
            "{labels:?}"
        );
        common::apply_with_consent(&pool, plan, &read).await;
        assert_eq!(
            live_label(&pool, "salary").await.as_deref(),
            Some(READ_LABEL)
        );
    })
    .await;
}

/// What an older engine left: the labels it set, and no rows. The one the schema still asks for
/// is claimed without being touched. One someone set by hand, on a column no rule of the last
/// push's schema names, is theirs and left alone (F15 (b), E23). Once the rule goes from the
/// schema, the label the last push's schema set is taken off, as the sweep took it off, and a
/// rollback would put it back as it was.
#[tokio::test]
async fn labels_under_our_provider_with_no_row_are_ours_only_where_a_push_set_them() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            return;
        }
        let read = employees(SalaryRule::Read);
        push(&pool, &read).await.unwrap();
        exec(
            &pool,
            r#"DELETE FROM _supatype.managed_objects WHERE kind = 'security_label';
               SECURITY LABEL FOR supatype ON COLUMN public.employees.user_id
                 IS 'MASK READ public."can_read_employees__salary"';"#,
        )
        .await
        .unwrap();

        let plan = push::prepare(&pool, &read, "public").await.unwrap();
        let labels: Vec<&Action> = plan
            .reconcile
            .actions
            .iter()
            .filter(|a| is_label(a))
            .collect();
        assert_eq!(labels.len(), 1, "{labels:?}");
        let kept = labels[0];
        assert_eq!(kept.key().parent, "employees.salary");
        assert!(
            matches!(kept, Action::Adopt { .. }) && kept.sql().is_empty(),
            "the label the schema asks for is claimed as it is: {kept:?}"
        );
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap();
        assert!(live_label(&pool, "user_id").await.is_some());
        assert_eq!(labelled(&pool).await, ["employees.salary"]);

        // An older engine's label, no row, and the rule gone from the schema: dropped.
        exec(
            &pool,
            "DELETE FROM _supatype.managed_objects WHERE kind = 'security_label'",
        )
        .await
        .unwrap();
        let none = employees(SalaryRule::None);
        let plan = push::prepare(&pool, &none, "public").await.unwrap();
        let stale = plan
            .reconcile
            .actions
            .iter()
            .find(|a| is_label(a) && a.key().parent == "employees.salary")
            .expect("the label the last push set");
        assert!(matches!(stale, Action::Drop { .. }), "{stale:?}");
        assert!(
            stale
                .rollback_sql()
                .iter()
                .any(|s| s.contains(r#""employees"."salary" IS 'MASK READ"#)),
            "the rollback restores the label it took off: {:?}",
            stale.rollback_sql()
        );
        assert!(
            !plan
                .reconcile
                .actions
                .iter()
                .any(|a| is_label(a) && a.key().parent == "employees.user_id"),
            "the label set by hand is not Supatype's"
        );
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap();
        assert_eq!(live_label(&pool, "salary").await, None);
        assert!(live_label(&pool, "user_id").await.is_some());
    })
    .await;
}

/// A label under our provider on a table rather than a column, which the ledger records, is
/// dropped when nothing declares it. Its key has no `table.column` parent, and rendering the drop
/// panicked ("is on the reconcile with no drop statement") instead of taking the label off. With
/// no row it is someone else's, and left alone (F15 (b)).
#[test]
fn a_table_label_under_our_provider_is_dropped_not_a_panic() {
    use supatype_engine::introspector::catalog::{CatalogState, DbSecurityLabel};
    use supatype_engine::introspector::fingerprint::ObjectKey;
    use supatype_engine::state::database_state::DatabaseState;

    let ast = parser::parse(r#"{ "astVersion": 2, "models": [] }"#).unwrap();
    let catalog = CatalogState {
        security_labels: vec![DbSecurityLabel {
            schema: "public".into(),
            table: "theirs".into(),
            column: None,
            provider: "supatype".into(),
            label: "MASK READ x".into(),
        }],
        ..CatalogState::default()
    };
    let db = DatabaseState {
        schema: "public".into(),
        ..DatabaseState::default()
    };
    let is_theirs =
        |a: &Action| a.key().kind == ObjectKind::SecurityLabel && a.key().parent == "theirs";

    let unrecorded = push::State::of(db.clone(), catalog.clone(), vec![]);
    let decision = push::decide(&ast, &unrecorded, None).unwrap();
    assert!(
        !decision.reconcile.actions.iter().any(is_theirs),
        "a label no row records was claimed: {:?}",
        decision.reconcile.actions
    );

    let live = &unrecorded.fingerprints;
    let label = live
        .iter()
        .find(|f| f.kind == ObjectKind::SecurityLabel)
        .expect("the label is read");
    let row = LedgerRow {
        key: ObjectKey {
            kind: ObjectKind::SecurityLabel,
            schema: "public".into(),
            parent: "theirs".into(),
            name: "supatype".into(),
        },
        desired_fp: String::new(),
        desired_sql: "SECURITY LABEL FOR supatype ON TABLE \"public\".\"theirs\" IS 'MASK READ x';"
            .into(),
        live_fp: label.fingerprint.clone(),
        live_def: label.definition.clone(),
        status: ledger::Status::Managed,
        migration_id: None,
    };
    let recorded = push::State::of(db, catalog, vec![row]);
    let decision = push::decide(&ast, &recorded, None).unwrap();
    assert!(
        decision.reconcile.actions.iter().any(is_theirs),
        "{:?}",
        decision.reconcile.actions
    );
    let migration = supatype_engine::generator::sql::migration::Migration::render(
        &decision.diff,
        &decision.reconcile.actions,
        false,
        "public",
        &ast,
    )
    .unwrap();
    assert!(
        migration
            .up()
            .contains(r#"SECURITY LABEL FOR supatype ON TABLE "public"."theirs" IS NULL"#),
        "{}",
        migration.up()
    );
}

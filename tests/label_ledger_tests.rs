//! Phase 4.7 of the managed-object ownership plan: security labels on the ledger.
//!
//! A field rule is enforced by a `SECURITY LABEL FOR supatype` on its column, which the masking
//! extension reads. The labels were re-asserted on every push, and a sweep cleared every label
//! under our provider that the push did not re-assert. Each label is a ledger object now: set by
//! the reconcile, recorded, replaced when its rule changes, put back when it is taken off by hand,
//! and taken off when its rule goes. A label under our provider with no row is ours by location
//! (plan section 5): nothing else writes under it, so it is claimed or taken off, as the sweep
//! took it off.

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
/// is claimed without being touched; one on a column no rule names is taken off, as the sweep
/// took it off, and a rollback would put it back as it was.
#[tokio::test]
async fn labels_under_our_provider_with_no_row_are_ours() {
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
        assert_eq!(labels.len(), 2, "{labels:?}");
        let kept = labels
            .iter()
            .find(|a| a.key().parent == "employees.salary")
            .unwrap();
        assert!(
            matches!(kept, Action::Adopt { .. }) && kept.sql().is_empty(),
            "the label the schema asks for is claimed as it is: {kept:?}"
        );
        let stale = labels
            .iter()
            .find(|a| a.key().parent == "employees.user_id")
            .unwrap();
        assert!(matches!(stale, Action::Drop { .. }), "{stale:?}");
        assert!(
            stale
                .rollback_sql()
                .iter()
                .any(|s| s.contains(r#""employees"."user_id" IS 'MASK READ"#)),
            "the rollback restores the label it took off: {:?}",
            stale.rollback_sql()
        );

        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap();
        assert_eq!(live_label(&pool, "user_id").await, None);
        assert_eq!(
            live_label(&pool, "salary").await.as_deref(),
            Some(READ_LABEL)
        );
        assert_eq!(labelled(&pool).await, ["employees.salary"]);
        assert!(up_to_date(&push(&pool, &read).await.unwrap()));
    })
    .await;
}

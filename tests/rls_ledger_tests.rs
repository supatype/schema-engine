//! Phase 4.8 of the managed-object ownership plan: row-level security enablement on the ledger
//! (D9).
//!
//! Every model and junction table has RLS on, owned by the ledger: re-asserted when someone turns
//! it off, and never turned off by a push. `FORCE ROW LEVEL SECURITY` is not the engine's: neither
//! applied nor fingerprinted, so one set by hand is not drift and stays.

mod common;

use serde_json::json;
use sqlx::PgPool;
use supatype_engine::{
    introspector::fingerprint::ObjectKind,
    ledger::{self, reconcile::Action},
    parser,
    parser::ast::SchemaAst,
    push,
};

use common::{exec, push};

fn posts() -> SchemaAst {
    let doc = json!({
        "astVersion": 2,
        "models": [{
            "name": "Post",
            "fields": {
                "id": { "kind": "integer", "primaryKey": true, "required": true,
                        "annotations": { "db": { "pgType": "INTEGER", "unique": false } } }
            },
            "options": { "timestamps": false, "softDelete": false, "singleton": false },
            "annotations": { "db": { "tableName": "posts", "indexes": [] },
                             "platform": { "access": { "read": { "type": "public" } } } }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// `relrowsecurity` and `relforcerowsecurity` of `public.posts`.
async fn rls(pool: &PgPool) -> (bool, bool) {
    sqlx::query_as(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class
          WHERE oid = 'public.posts'::regclass",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn recorded(pool: &PgPool) -> Vec<String> {
    let mut conn = pool.acquire().await.unwrap();
    ledger::load(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.key.kind == ObjectKind::RlsAttributes && r.key.schema == "public")
        .map(|r| r.key.parent)
        .collect()
}

fn up_to_date(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::UpToDate { .. })
}

fn rls_actions(plan: &push::Plan<'_>) -> Vec<Action> {
    plan.reconcile
        .actions
        .iter()
        .filter(|a| a.key().kind == ObjectKind::RlsAttributes)
        .cloned()
        .collect()
}

#[tokio::test]
async fn rls_is_on_recorded_and_put_back_when_turned_off() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts()).await.unwrap();
        assert_eq!(rls(&pool).await, (true, false));
        assert_eq!(recorded(&pool).await, ["posts"]);
        assert!(up_to_date(&push(&pool, &posts()).await.unwrap()));

        exec(&pool, "ALTER TABLE public.posts DISABLE ROW LEVEL SECURITY")
            .await
            .unwrap();
        let ast = posts();
        let plan = push::prepare(&pool, &ast, "public").await.unwrap();
        let actions = rls_actions(&plan);
        assert!(matches!(actions[..], [Action::Drift { .. }]), "{actions:?}");
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap();
        assert_eq!(rls(&pool).await, (true, false));
    })
    .await;
}

#[tokio::test]
async fn force_set_by_hand_is_not_the_engines() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts()).await.unwrap();
        exec(&pool, "ALTER TABLE public.posts FORCE ROW LEVEL SECURITY")
            .await
            .unwrap();

        let again = push(&pool, &posts()).await.unwrap();
        assert!(
            up_to_date(&again),
            "a hand-set FORCE is not drift: {again:?}"
        );
        assert_eq!(rls(&pool).await, (true, true));
    })
    .await;
}

/// What an older engine left: RLS on and no row. It is taken over by name, the statement that
/// asserts it changing nothing, and recorded.
#[tokio::test]
async fn an_older_engines_rls_is_taken_over() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts()).await.unwrap();
        exec(
            &pool,
            "DELETE FROM _supatype.managed_objects WHERE kind = 'rls_attributes'",
        )
        .await
        .unwrap();

        let ast = posts();
        let plan = push::prepare(&pool, &ast, "public").await.unwrap();
        let actions = rls_actions(&plan);
        assert!(
            matches!(actions[..], [Action::Replace { .. }]),
            "{actions:?}"
        );
        assert!(
            actions[0]
                .rollback_sql()
                .iter()
                .all(|s| !s.contains("DISABLE")),
            "a rollback never turns RLS off: {:?}",
            actions[0].rollback_sql()
        );
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap();
        assert_eq!(recorded(&pool).await, ["posts"]);
        assert!(up_to_date(&push(&pool, &posts()).await.unwrap()));
    })
    .await;
}

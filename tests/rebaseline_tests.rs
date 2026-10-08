//! Phase 5d of the managed-object ownership plan: `doctor --rebaseline` (section 3.2).
//!
//! When a fingerprint moves with no change anyone wants undone (a Postgres upgrade that deparses
//! differently, or a hand edit the operator decides to keep), rebaselining records each drifted
//! object's live definition as the baseline. It changes no object, lists every one it moved, and
//! leaves anything that is not drift (a missing object) to a push.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{differ::doctor, inspect, parser, parser::ast::SchemaAst, push};

use common::{exec, push};

fn posts(indexes: Value) -> SchemaAst {
    let doc = json!({
        "astVersion": 2,
        "models": [{
            "name": "Post",
            "fields": {
                "id": { "kind": "integer", "primaryKey": true, "required": true,
                        "annotations": { "db": { "pgType": "INTEGER", "unique": false } } },
                "title": { "kind": "text", "required": true,
                           "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
            },
            "options": { "timestamps": false, "softDelete": false, "singleton": false },
            "annotations": { "db": { "tableName": "posts", "indexes": indexes },
                             "platform": { "access": { "read": { "type": "public" } } } }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

fn names(items: &[doctor::DoctorItem]) -> Vec<String> {
    items
        .iter()
        .map(|i| format!("{} {}.{}", i.kind, i.table, i.name))
        .collect()
}

async fn rls_enabled(pool: &PgPool) -> bool {
    sqlx::query_scalar("SELECT relrowsecurity FROM pg_class WHERE oid = 'public.posts'::regclass")
        .fetch_one(pool)
        .await
        .unwrap()
}

fn non_interactive() -> push::ApplyOptions {
    push::ApplyOptions::default()
}

#[tokio::test]
async fn rebaselining_accepts_the_drift_and_changes_nothing() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!([]));
        push(&pool, &ast).await.unwrap();
        exec(&pool, "ALTER TABLE public.posts DISABLE ROW LEVEL SECURITY")
            .await
            .unwrap();

        let report = inspect::rebaseline(&pool, &ast, "public", true)
            .await
            .unwrap();
        assert_eq!(names(&report.rebaselined), ["rls_attributes posts.rls"]);
        let item = &report.rebaselined[0];
        assert_eq!(item.recorded.as_deref(), Some("enabled=t"));
        assert_eq!(item.live.as_deref(), Some("enabled=f"));
        assert!(report.drifted.is_empty(), "{report:#?}");
        assert!(!rls_enabled(&pool).await, "rebaselining changed the object");

        // Accepted: doctor is clean, and a push without a terminal neither refuses nor puts it back.
        let after = inspect::doctor(&pool, &ast, "public", false).await.unwrap();
        assert!(!doctor::has_strict_issues(&after), "{after:#?}");
        let outcome = common::push_with(&pool, &ast, non_interactive())
            .await
            .unwrap();
        assert!(
            matches!(outcome, push::Outcome::UpToDate { .. }),
            "{outcome:?}"
        );
        assert!(!rls_enabled(&pool).await);
    })
    .await;
}

#[tokio::test]
async fn a_grant_revoked_to_nothing_is_rebaselined_too() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!([]));
        push(&pool, &ast).await.unwrap();
        // No catalog row is left for a role holding nothing; the reconcile fingerprints it anyway.
        exec(&pool, "REVOKE ALL ON public.posts FROM anon")
            .await
            .unwrap();

        let report = inspect::rebaseline(&pool, &ast, "public", true)
            .await
            .unwrap();
        assert!(
            names(&report.rebaselined).contains(&"table_grant posts.anon".to_string()),
            "{report:#?}"
        );
        let after = inspect::doctor(&pool, &ast, "public", false).await.unwrap();
        assert!(after.drifted.is_empty(), "{:#?}", after.drifted);
    })
    .await;
}

#[tokio::test]
async fn a_missing_object_is_left_to_a_push() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!([{ "fields": ["title"], "name": "posts_title_idx",
                                 "unique": false, "using": "btree" }]));
        push(&pool, &ast).await.unwrap();
        exec(&pool, "DROP INDEX public.posts_title_idx")
            .await
            .unwrap();

        let report = inspect::doctor(&pool, &ast, "public", true).await.unwrap();
        assert!(report.rebaselined.is_empty(), "{:#?}", report.rebaselined);
        assert_eq!(names(&report.missing), ["index posts.posts_title_idx"]);
    })
    .await;
}

#[tokio::test]
async fn drift_on_access_is_rebaselined_only_with_consent() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!([{ "fields": ["title"], "name": "posts_title_idx",
                                 "unique": false, "using": "btree" }]));
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            "ALTER TABLE public.posts DISABLE ROW LEVEL SECURITY;
             DROP INDEX public.posts_title_idx;
             CREATE INDEX posts_title_idx ON public.posts USING hash (title);",
        )
        .await
        .unwrap();

        // Without consent: the index is rebaselined, the access rule is refused and still drift.
        let report = inspect::doctor(&pool, &ast, "public", true).await.unwrap();
        assert_eq!(names(&report.rebaselined), ["index posts.posts_title_idx"]);
        assert_eq!(
            names(&report.rebaseline_refused),
            ["rls_attributes posts.rls"]
        );
        let refused = &report.rebaseline_refused[0];
        assert!(refused.message.contains("--overwrite-drift"), "{refused:?}");
        assert_eq!(refused.live.as_deref(), Some("enabled=f"));
        assert_eq!(names(&report.drifted), ["rls_attributes posts.rls"]);
        assert!(report.blocking);

        // A push still asks before putting it back.
        let refused = common::push_with(&pool, &ast, non_interactive())
            .await
            .expect_err("the access rule was taken as the baseline without consent");
        assert!(
            refused
                .downcast_ref::<supatype_engine::ledger::drift::SecurityDrift>()
                .is_some(),
            "{refused:#}"
        );

        // With consent it is recorded too.
        let report = inspect::rebaseline(&pool, &ast, "public", true)
            .await
            .unwrap();
        assert_eq!(names(&report.rebaselined), ["rls_attributes posts.rls"]);
        assert!(report.rebaseline_refused.is_empty());
        let after = inspect::doctor(&pool, &ast, "public", false).await.unwrap();
        assert!(!doctor::has_strict_issues(&after), "{after:#?}");
    })
    .await;
}

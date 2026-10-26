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
        assert!(
            refused.message.contains("--accept-access-drift"),
            "{refused:?}"
        );
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

#[tokio::test]
async fn a_push_adopt_or_rebaseline_refuses_while_another_holds_the_engine_lock() {
    use sqlx::Connection;
    use supatype_engine::{adopt, push::EngineBusy};
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!([]));
        push(&pool, &ast).await.unwrap();
        let indexed = posts(json!([{ "fields": ["title"], "name": "posts_title_idx",
                                     "unique": false, "using": "btree" }]));
        let busy = |e: anyhow::Error| {
            assert!(e.downcast_ref::<EngineBusy>().is_some(), "{e:#}");
            assert!(format!("{e:#}").contains("try again"), "{e:#}");
        };

        // Another session mid-push, mid-adopt or mid-rebaseline.
        let mut other = sqlx::PgConnection::connect_with(&pool.connect_options())
            .await
            .unwrap();
        sqlx::query("SELECT pg_advisory_lock(872014, 2)")
            .execute(&mut other)
            .await
            .unwrap();
        busy(
            push(&pool, &indexed)
                .await
                .expect_err("pushed while another held the lock"),
        );
        busy(
            adopt::run(
                &pool,
                &ast,
                "public",
                adopt::Request {
                    apply: true,
                    ..Default::default()
                },
            )
            .await
            .expect_err("adopted while another held the lock"),
        );
        busy(
            inspect::rebaseline(&pool, &ast, "public", false)
                .await
                .expect_err("rebaselined while another held the lock"),
        );
        // A push with nothing to change still writes (the storage and versions layers, Studio's
        // metadata), and a rollback writes objects, history and ledger.
        busy(
            push(&pool, &ast)
                .await
                .expect_err("an up-to-date push ran while another held the lock"),
        );
        busy(
            supatype_engine::state::migration_history::apply_rollback(&pool, "public")
                .await
                .expect_err("rolled back while another held the lock"),
        );
        // A preview writes nothing, so it does not need the lock.
        adopt::run(&pool, &ast, "public", adopt::Request::default())
            .await
            .unwrap();
        sqlx::query("SELECT pg_advisory_unlock(872014, 2)")
            .execute(&mut other)
            .await
            .unwrap();

        // The realtime signal the CLI holds around its own push is not a reason to refuse.
        sqlx::query("SELECT pg_advisory_lock(872014, 1)")
            .execute(&mut other)
            .await
            .unwrap();
        push(&pool, &indexed)
            .await
            .expect("refused while only the realtime signal was held");
        inspect::rebaseline(&pool, &indexed, "public", false)
            .await
            .unwrap();
        other.close().await.unwrap();
    })
    .await;
}

/// An up-to-date push re-reads what it decided from before it writes, as an applying push does:
/// a change landing between the plan and the apply refuses it rather than being written over.
#[tokio::test]
async fn an_up_to_date_push_refuses_when_the_database_moved_after_its_plan() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!([]));
        push(&pool, &ast).await.unwrap();
        let plan = supatype_engine::push::prepare(&pool, &ast, "public")
            .await
            .unwrap();
        sqlx::raw_sql("CREATE POLICY sneaky ON public.posts FOR SELECT USING (true)")
            .execute(&pool)
            .await
            .unwrap();
        let e = supatype_engine::push::apply(&pool, plan, Default::default())
            .await
            .expect_err("applied a plan the database had moved away from");
        assert!(
            format!("{e:#}").contains("changed after this push was planned"),
            "{e:#}"
        );
    })
    .await;
}

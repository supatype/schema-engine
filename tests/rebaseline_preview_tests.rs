//! F22 (C04): `doctor --rebaseline` records only the drift the person saw.
//!
//! The CLI previews what a rebaseline would record and waits for a yes. Drift that appears while
//! it waits was never seen, so the rebaseline takes the keys of what the preview listed and
//! refuses, writing nothing, when the drift it finds is not exactly that set, as `adopt` refuses
//! when its conflicts moved.

mod common;

use serde_json::json;
use sqlx::PgPool;
use supatype_engine::{inspect, parser, parser::ast::SchemaAst};

use common::{exec, push};

fn posts() -> SchemaAst {
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
            "annotations": { "db": { "tableName": "posts", "indexes": [] },
                             "platform": { "access": { "read": { "type": "public" },
                                                       "create": { "type": "public" } } } }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// The live fingerprint the ledger records for each of the posts policies, in name order.
async fn baselines(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT name || '=' || live_fp FROM _supatype.managed_objects
          WHERE kind = 'policy' ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

fn keys(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| n.to_string()).collect()
}

#[tokio::test]
async fn a_rebaseline_refuses_drift_the_preview_did_not_show() {
    common::with_integration_pool(|pool| async move {
        let ast = posts();
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            "ALTER POLICY posts_select ON public.posts USING (false)",
        )
        .await
        .unwrap();
        let preview = inspect::doctor(&pool, &ast, "public", false).await.unwrap();
        assert_eq!(preview.drifted.len(), 1, "{preview:#?}");
        let seen = keys(&["policy:posts.posts_select"]);

        // Edited while the person reads the preview.
        exec(
            &pool,
            "ALTER POLICY posts_insert ON public.posts WITH CHECK (false)",
        )
        .await
        .unwrap();
        let before = baselines(&pool).await;
        let refused = inspect::rebaseline_previewed(&pool, &ast, "public", true, Some(&seen))
            .await
            .expect_err("recorded drift the preview did not show");
        let changed = refused
            .downcast_ref::<inspect::DriftChangedSincePreview>()
            .unwrap_or_else(|| panic!("refused for another reason: {refused:#}"));
        assert_eq!(changed.unseen, ["policy:posts.posts_insert"]);
        assert!(changed.gone.is_empty(), "{changed:?}");
        assert_eq!(baselines(&pool).await, before, "a refused rebaseline wrote");

        // A key the preview showed that is no longer drifted is a change too.
        exec(
            &pool,
            "ALTER POLICY posts_insert ON public.posts WITH CHECK (true)",
        )
        .await
        .unwrap();
        let both = keys(&["policy:posts.posts_select", "policy:posts.posts_insert"]);
        let refused = inspect::rebaseline_previewed(&pool, &ast, "public", true, Some(&both))
            .await
            .expect_err("rebaselined a set that is no longer the one previewed");
        let changed = refused
            .downcast_ref::<inspect::DriftChangedSincePreview>()
            .unwrap_or_else(|| panic!("refused for another reason: {refused:#}"));
        assert_eq!(changed.gone, ["policy:posts.posts_insert"]);

        // The set the preview showed is the set there: recorded.
        let report = inspect::rebaseline_previewed(&pool, &ast, "public", true, Some(&seen))
            .await
            .unwrap();
        assert_eq!(report.rebaselined.len(), 1, "{report:#?}");
        assert!(report.drifted.is_empty(), "{report:#?}");
    })
    .await;
}

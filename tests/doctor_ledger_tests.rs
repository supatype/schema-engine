//! Phase 5b of the managed-object ownership plan: doctor reads the reconcile (section 8).
//!
//! Doctor used to derive its own expectations and knew tables, unique constraints and indexes. It
//! reports the reconcile's categories now, for every kind the ledger owns: missing, drifted, stale,
//! conflicting, unmanaged (columns included, D4) and released. After one push it reports nothing
//! at all (section 11).

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{
    differ::doctor::{self, DoctorReport},
    parser,
    parser::ast::SchemaAst,
};

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

fn title_index() -> Value {
    json!([{ "fields": ["title"], "name": "posts_title_idx", "unique": false, "using": "btree" }])
}

async fn doctor_of(pool: &PgPool, ast: &SchemaAst) -> DoctorReport {
    common::doctor(pool, ast).await
}

fn names(items: &[doctor::DoctorItem]) -> Vec<String> {
    items
        .iter()
        .map(|i| format!("{} {}.{}", i.kind, i.table, i.name))
        .collect()
}

fn is_clean(report: &DoctorReport) -> bool {
    report.missing.is_empty()
        && report.stale_managed.is_empty()
        && report.unmanaged_drift.is_empty()
        && report.drifted.is_empty()
        && report.conflicting.is_empty()
        && report.released.is_empty()
}

#[tokio::test]
async fn after_one_push_of_the_kitchen_sink_doctor_reports_nothing() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(include_str!("fixtures/kitchen_sink_example.json")).unwrap();
        exec(
            &pool,
            "CREATE SCHEMA IF NOT EXISTS auth;
             CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT UNIQUE);",
        )
        .await
        .unwrap();
        push(&pool, &ast).await.unwrap();
        let report = doctor_of(&pool, &ast).await;
        assert!(is_clean(&report), "{report:#?}");
        assert!(!doctor::has_strict_issues(&report));
        assert!(!report.blocking, "the engine says a push would act");
    })
    .await;
}

#[tokio::test]
async fn an_owned_object_removed_by_hand_is_missing_and_access_changed_is_drifted() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(title_index());
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            "DROP INDEX public.posts_title_idx;
             ALTER TABLE public.posts DISABLE ROW LEVEL SECURITY;",
        )
        .await
        .unwrap();

        let report = doctor_of(&pool, &ast).await;
        assert_eq!(names(&report.missing), ["index posts.posts_title_idx"]);
        let drifted = &report.drifted;
        assert_eq!(names(drifted), ["rls_attributes posts.rls"], "{report:#?}");
        assert_eq!(drifted[0].recorded.as_deref(), Some("enabled=t"));
        assert_eq!(drifted[0].live.as_deref(), Some("enabled=f"));
        assert!(
            drifted[0].message.contains("after asking"),
            "{}",
            drifted[0].message
        );
        assert!(doctor::has_strict_issues(&report));
        assert!(report.blocking, "the engine does not say a push would act");
    })
    .await;
}

#[tokio::test]
async fn a_dropped_declaration_is_stale_and_a_taken_name_conflicts() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts(title_index())).await.unwrap();

        // The schema stops asking for the index: owned, so a push drops it.
        let report = doctor_of(&pool, &posts(json!([]))).await;
        assert_eq!(
            names(&report.stale_managed),
            ["index posts.posts_title_idx"]
        );

        // Someone else's index already holds a name the schema needs, on another column.
        exec(&pool, "CREATE INDEX posts_id_idx ON public.posts (title)")
            .await
            .unwrap();
        let wants_id =
            posts(json!([{ "fields": ["id"], "name": "posts_id_idx", "unique": false, "using": "btree" }]));
        let report = doctor_of(&pool, &wants_id).await;
        assert!(
            names(&report.conflicting).contains(&"index posts.posts_id_idx".to_string()),
            "{report:#?}"
        );
    })
    .await;
}

#[tokio::test]
async fn what_someone_added_to_a_model_table_is_unmanaged_columns_included() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!([]));
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            "ALTER TABLE public.posts ADD COLUMN notes text;
             CREATE INDEX posts_notes_idx ON public.posts (notes);",
        )
        .await
        .unwrap();

        let report = doctor_of(&pool, &ast).await;
        let unmanaged = names(&report.unmanaged_drift);
        assert!(
            unmanaged.contains(&"column posts.notes".to_string()),
            "{unmanaged:?}"
        );
        assert!(
            unmanaged.contains(&"index posts.posts_notes_idx".to_string()),
            "{unmanaged:?}"
        );
        assert!(
            !doctor::has_strict_issues(&report),
            "someone else's objects are reported, not failures"
        );
    })
    .await;
}

#[tokio::test]
async fn an_unrecorded_object_the_push_would_replace_is_reported() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!([]));
        push(&pool, &ast).await.unwrap();
        // A policy under the schema's name that Supatype never recorded, made differently: the
        // push replaces it (a policy's name says whose it is), so doctor must not stay silent.
        exec(
            &pool,
            "DELETE FROM _supatype.managed_objects WHERE kind = 'policy';
             ALTER POLICY posts_select ON public.posts USING (false);",
        )
        .await
        .unwrap();

        let report = doctor_of(&pool, &ast).await;
        assert_eq!(names(&report.conflicting), ["policy posts.posts_select"]);
        let item = &report.conflicting[0];
        assert!(item.message.contains("replaces it"), "{item:?}");
        assert!(
            item.live.as_deref().unwrap_or_default().contains("false"),
            "{item:?}"
        );
        assert!(doctor::has_strict_issues(&report));
    })
    .await;
}

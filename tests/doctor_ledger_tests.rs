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
        && report.claimed.is_empty()
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

/// What an older engine leaves: its policies, grants, RLS attributes and schemas, with no row, and
/// its grants as it made them on the supatype image. The image's default privileges give the API
/// roles everything on a new table, and that engine revoked only those of the four privileges the
/// rules govern which they do not allow (here, every write), so `TRUNCATE`, `REFERENCES`, `TRIGGER`
/// and `MAINTAIN` stayed.
const FORGET_THE_ACCESS_ROWS: &str = "DELETE FROM _supatype.managed_objects
    WHERE kind IN ('policy', 'table_grant', 'rls_attributes', 'schema');
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated;
    GRANT ALL ON public.posts TO anon, authenticated;
    REVOKE INSERT, UPDATE, DELETE ON public.posts FROM anon, authenticated";

/// A clean upgrade: Supatype's own objects with no row yet are claimed, reported apart from the
/// conflicts and failing nothing, and the push records them without asking.
#[tokio::test]
async fn an_older_engines_own_objects_are_claimed_not_conflicting() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!([]));
        push(&pool, &ast).await.unwrap();
        exec(&pool, FORGET_THE_ACCESS_ROWS).await.unwrap();

        let report = doctor_of(&pool, &ast).await;
        let claimed = names(&report.claimed);
        assert!(
            claimed.contains(&"policy posts.posts_select".to_string()),
            "{claimed:?}"
        );
        assert!(
            claimed.contains(&"rls_attributes posts.rls".to_string()),
            "{claimed:?}"
        );
        assert!(
            claimed.contains(&"table_grant posts.anon".to_string()),
            "{claimed:?}"
        );
        assert!(report.conflicting.is_empty(), "{report:#?}");
        assert!(report.drifted.is_empty(), "{report:#?}");
        assert!(report.claimed[0]
            .message
            .contains("next `supatype push` records it"));
        assert!(!doctor::has_strict_issues(&report), "{report:#?}");
        assert!(!report.blocking);

        // Recorded without consent: nothing was changed by hand.
        push(&pool, &ast)
            .await
            .expect("a clean upgrade asks nothing");
        assert!(is_clean(&doctor_of(&pool, &ast).await));
    })
    .await;
}

/// Hand edits made under an older engine, which recorded nothing: each policy and RLS attribute is
/// compared with what the last push's schema makes of it, and one that differs is drift on access,
/// so the push asks before overwriting it, as it would after the upgrade.
#[tokio::test]
async fn an_older_engines_object_edited_by_hand_is_drift() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!([]));
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            &format!(
                "{FORGET_THE_ACCESS_ROWS};
                 ALTER POLICY posts_select ON public.posts USING (false);
                 ALTER TABLE public.posts DISABLE ROW LEVEL SECURITY;"
            ),
        )
        .await
        .unwrap();

        let report = doctor_of(&pool, &ast).await;
        assert_eq!(
            names(&report.drifted),
            ["policy posts.posts_select", "rls_attributes posts.rls"]
        );
        let claimed = names(&report.claimed);
        assert!(
            !claimed.contains(&"policy posts.posts_select".to_string()),
            "{claimed:?}"
        );
        let item = &report.drifted[0];
        assert!(
            item.live.as_deref().unwrap_or_default().contains("false"),
            "{item:?}"
        );
        assert!(item.message.contains("after asking"), "{item:?}");
        assert!(doctor::has_strict_issues(&report));

        let refused = push(&pool, &ast)
            .await
            .expect_err("overwrote a hand edit made under the older engine without consent");
        let drift = refused
            .downcast_ref::<supatype_engine::ledger::drift::SecurityDrift>()
            .unwrap_or_else(|| panic!("{refused:#}"));
        assert_eq!(drift.objects.len(), 2, "{drift}");

        common::push_with(
            &pool,
            &ast,
            supatype_engine::push::ApplyOptions {
                overwrite_drift: true,
                ..Default::default()
            },
        )
        .await
        .expect("applied with consent");
        assert!(is_clean(&doctor_of(&pool, &ast).await));
    })
    .await;
}

/// A privilege an older engine's grant would not hold, given the database's default privileges, was
/// granted by hand: drift on access, refused without consent like a policy edited by hand.
#[tokio::test]
async fn a_privilege_granted_by_hand_under_an_older_engine_is_drift() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!([]));
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            &format!("{FORGET_THE_ACCESS_ROWS}; GRANT DELETE ON public.posts TO anon;"),
        )
        .await
        .unwrap();

        let report = doctor_of(&pool, &ast).await;
        assert_eq!(names(&report.drifted), ["table_grant posts.anon"]);
        let claimed = names(&report.claimed);
        assert!(
            claimed.contains(&"table_grant posts.authenticated".to_string()),
            "{claimed:?}"
        );
        let item = &report.drifted[0];
        assert!(
            item.live.as_deref().unwrap_or_default().contains("DELETE"),
            "{item:?}"
        );
        assert!(
            !item
                .recorded
                .as_deref()
                .unwrap_or_default()
                .contains("DELETE"),
            "{item:?}"
        );

        let refused = push(&pool, &ast)
            .await
            .expect_err("took a privilege granted by hand under the older engine without consent");
        let drift = refused
            .downcast_ref::<supatype_engine::ledger::drift::SecurityDrift>()
            .unwrap_or_else(|| panic!("{refused:#}"));
        assert_eq!(drift.objects.len(), 1, "{drift}");

        common::push_with(
            &pool,
            &ast,
            supatype_engine::push::ApplyOptions {
                overwrite_drift: true,
                ..Default::default()
            },
        )
        .await
        .expect("applied with consent");
        assert!(is_clean(&doctor_of(&pool, &ast).await));
    })
    .await;
}

/// Where the default privileges give the API roles nothing, an older engine left nothing beyond
/// the four it governs: `TRUNCATE` on a model table was granted by hand.
#[tokio::test]
async fn a_privilege_the_defaults_never_gave_is_drift() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!([]));
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            "DELETE FROM _supatype.managed_objects
               WHERE kind IN ('policy', 'table_grant', 'rls_attributes', 'schema');
             GRANT TRUNCATE ON public.posts TO anon;",
        )
        .await
        .unwrap();

        let report = doctor_of(&pool, &ast).await;
        assert_eq!(names(&report.drifted), ["table_grant posts.anon"]);
        assert!(push(&pool, &ast).await.is_err(), "refused without consent");
    })
    .await;
}

/// With no earlier schema to compare with, nothing says whether they were changed by hand, so the
/// push does not replace them without consent and names each as not checked (F16, fail closed).
#[tokio::test]
async fn without_an_earlier_schema_the_push_says_it_could_not_check() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!([]));
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            &format!(
                "{FORGET_THE_ACCESS_ROWS};
                 UPDATE _supatype.migrations SET schema_snapshot = NULL WHERE true;
                 UPDATE _supatype.schema_state SET ast_snapshot = NULL WHERE true;
                 ALTER POLICY posts_select ON public.posts USING (false);"
            ),
        )
        .await
        .unwrap();
        let refused = push(&pool, &ast)
            .await
            .expect_err("replaced what it could not check without consent");
        let drift = refused
            .downcast_ref::<supatype_engine::ledger::drift::SecurityDrift>()
            .unwrap_or_else(|| panic!("refused as something else: {refused:#}"));
        let select = drift
            .objects
            .iter()
            .find(|o| o.key.name == "posts_select")
            .unwrap_or_else(|| panic!("{drift}"));
        assert!(select.unchecked.is_some(), "{select:?}");
        assert!(drift.to_string().contains("not checked"), "{drift}");
    })
    .await;
}

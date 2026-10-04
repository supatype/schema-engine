//! Phase 4.10 of the managed-object ownership plan: primary keys, the engine's schemas and serial
//! sequences on the ledger.
//!
//! A primary key is created with its table and dropped with it; one dropped by hand is put back.
//! The engine's own schemas and a serial column's sequence are created if missing and never
//! dropped (plan section 15): a schema may hold what is not ours, and a sequence goes with its
//! column. Their rows are forgotten when nothing asks for them.

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

fn int_pk() -> Value {
    json!({ "kind": "integer", "primaryKey": true, "required": true,
            "annotations": { "db": { "pgType": "INTEGER", "unique": false } } })
}

fn serial() -> Value {
    json!({ "kind": "serial", "required": false,
            "annotations": { "db": { "pgType": "SERIAL", "unique": false } } })
}

/// `posts` with an id, the given extra fields, and history if `versioned`.
fn posts(extra: Value, versioned: bool) -> SchemaAst {
    let mut fields = json!({ "id": int_pk(),
        "title": { "kind": "text", "required": true,
                   "annotations": { "db": { "pgType": "TEXT", "unique": false } } } });
    for (name, field) in extra.as_object().unwrap() {
        fields[name] = field.clone();
    }
    let mut options = json!({ "timestamps": false, "softDelete": false, "singleton": false });
    if versioned {
        options["versions"] = json!({ "drafts": false, "keep": 5 });
    }
    let doc = json!({
        "astVersion": 2,
        "locales": ["en"],
        "defaultLocale": "en",
        "publishing": {
            "draftVisibility": ["admin"],
            "previewDefaultTtl": 900,
            "previewMaxRecordTtl": 604800,
            "previewMaxProjectTtl": 86400,
            "previewAllowProjectScope": true
        },
        "models": [{
            "name": "Post",
            "fields": fields,
            "options": options,
            "annotations": { "db": { "tableName": "posts", "indexes": [] }, "platform": {} }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

async fn rows(pool: &PgPool, kind: ObjectKind) -> Vec<LedgerRow> {
    let mut conn = pool.acquire().await.unwrap();
    ledger::load(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.key.kind == kind)
        .collect()
}

async fn names(pool: &PgPool, kind: ObjectKind) -> Vec<String> {
    let mut names: Vec<String> = rows(pool, kind)
        .await
        .into_iter()
        .map(|r| r.key.name)
        .collect();
    names.sort();
    names
}

async fn exists(pool: &PgPool, sql: &str) -> bool {
    sqlx::query_scalar::<_, bool>(sql)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn up_to_date(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::UpToDate { .. })
}

#[tokio::test]
async fn a_primary_key_is_recorded_and_put_back_when_dropped_by_hand() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!({}), false);
        push(&pool, &ast).await.unwrap();
        assert!(names(&pool, ObjectKind::PrimaryKey)
            .await
            .contains(&"posts_pkey".to_string()));
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));

        exec(&pool, "ALTER TABLE public.posts DROP CONSTRAINT posts_pkey")
            .await
            .unwrap();
        let plan = push::prepare(&pool, &ast, "public").await.unwrap();
        let pk = plan
            .reconcile
            .actions
            .iter()
            .find(|a| a.key().kind == ObjectKind::PrimaryKey && a.key().name == "posts_pkey")
            .cloned();
        assert!(matches!(pk, Some(Action::Recreate { .. })), "{pk:?}");
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap();
        assert!(
            exists(
                &pool,
                "SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'posts_pkey')"
            )
            .await
        );
    })
    .await;
}

#[tokio::test]
async fn the_engines_schemas_are_recorded_and_never_dropped() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts(json!({}), true)).await.unwrap();
        let schemas = names(&pool, ObjectKind::Schema).await;
        for schema in ["_platform", "_supatype", "draft", "supatype"] {
            assert!(
                schemas.contains(&schema.to_string()),
                "{schema}: {schemas:?}"
            );
        }
        assert!(up_to_date(
            &push(&pool, &posts(json!({}), true)).await.unwrap()
        ));

        // No versioned model any more: `draft` is no longer asked for, and it stays.
        common::push_with(
            &pool,
            &posts(json!({}), false),
            push::ApplyOptions {
                force: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(
            exists(
                &pool,
                "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'draft')"
            )
            .await,
            "a schema was dropped"
        );
        assert!(!names(&pool, ObjectKind::Schema)
            .await
            .contains(&"draft".to_string()));
    })
    .await;
}

#[tokio::test]
async fn a_serial_columns_sequence_is_recorded_and_goes_with_its_column() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts(json!({ "position": serial() }), false))
            .await
            .unwrap();
        let sequences = rows(&pool, ObjectKind::Sequence).await;
        assert_eq!(
            sequences
                .iter()
                .map(|r| r.key.name.as_str())
                .collect::<Vec<_>>(),
            ["posts_position_seq"]
        );
        assert!(sequences[0].live_def.contains("owned_by=posts.position"));
        assert!(up_to_date(
            &push(&pool, &posts(json!({ "position": serial() }), false))
                .await
                .unwrap()
        ));

        common::push_with(
            &pool,
            &posts(json!({}), false),
            push::ApplyOptions {
                force: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(
            !exists(
                &pool,
                "SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'posts_position_seq')"
            )
            .await
        );
        assert!(rows(&pool, ObjectKind::Sequence).await.is_empty());
    })
    .await;
}

/// What an older engine left: the keys and schemas, and no rows. A primary key that is exactly
/// what we would create is adopted without being touched; the schemas are ours by name.
#[tokio::test]
async fn an_upgrade_adopts_the_keys_and_claims_the_schemas() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!({}), false);
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            "DELETE FROM _supatype.managed_objects WHERE kind IN ('primary_key', 'schema')",
        )
        .await
        .unwrap();

        let plan = push::prepare(&pool, &ast, "public").await.unwrap();
        let pk = plan
            .reconcile
            .actions
            .iter()
            .find(|a| a.key().kind == ObjectKind::PrimaryKey && a.key().name == "posts_pkey")
            .cloned();
        assert!(
            matches!(&pk, Some(a @ Action::Adopt { .. }) if a.sql().is_empty()),
            "{pk:?}"
        );
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap();
        assert!(names(&pool, ObjectKind::PrimaryKey)
            .await
            .contains(&"posts_pkey".to_string()));
        assert!(names(&pool, ObjectKind::Schema)
            .await
            .contains(&"_platform".to_string()));
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
    })
    .await;
}

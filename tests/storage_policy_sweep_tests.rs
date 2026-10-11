//! The policies on `storage.objects`, against Postgres, since they moved onto the ledger (Phase
//! 4.7b) and the sweep that used to retire them was deleted.
//!
//! A push drops every storage policy it recorded that the schema no longer names: a removed
//! bucket, a renamed model, the last bucket gone. It also drops the unmarked `storage_<label>_*`
//! policies engines before the marker wrote, because the caller roles now hold INSERT, UPDATE and
//! DELETE and those old policies would take effect. A policy someone wrote by hand is never
//! touched.

mod common;

use supatype_engine::{introspector::fingerprint::ObjectKind, ledger, parser, push::Outcome};

const MEDIA: &str = r#"{
  "astVersion": 2,
  "models": [],
  "storageBuckets": [{
    "id": "media", "public": false, "accessMode": "private",
    "access": { "read": { "type": "authenticated" }, "create": { "type": "authenticated" } }
  }]
}"#;

const NO_BUCKETS: &str = r#"{ "astVersion": 2, "models": [], "storageBuckets": [] }"#;

async fn push(pool: &sqlx::PgPool, schema: &str) -> Outcome {
    let ast = parser::parse(schema).expect("schema parses");
    common::push(pool, &ast).await.expect("push applies")
}

async fn policies(pool: &sqlx::PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT polname::text FROM pg_policy WHERE polrelid = 'storage.objects'::regclass ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .expect("list policies")
}

/// The storage policies the ledger records, by name.
async fn recorded(pool: &sqlx::PgPool) -> Vec<String> {
    let mut conn = pool.acquire().await.unwrap();
    ledger::load(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.key.kind == ObjectKind::Policy && r.key.schema == "storage")
        .map(|r| r.key.name)
        .collect()
}

#[tokio::test]
async fn removing_the_last_bucket_drops_ours_and_keeps_a_hand_written_policy() {
    common::with_integration_pool(|pool| async move {
        push(&pool, MEDIA).await;
        let ours = vec!["storage_media_ins", "storage_media_sel"];
        assert_eq!(policies(&pool).await, ours);
        assert_eq!(recorded(&pool).await, ours);
        let again = push(&pool, MEDIA).await;
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");

        // What an engine before the marker left behind, and one the developer wrote.
        common::exec(
            &pool,
            "CREATE POLICY storage_old_del ON storage.objects FOR DELETE USING (TRUE);
             CREATE POLICY team_rule ON storage.objects FOR SELECT USING (FALSE);",
        )
        .await
        .expect("fixture policies");

        push(&pool, NO_BUCKETS).await;
        assert_eq!(policies(&pool).await, vec!["team_rule"]);
        assert!(recorded(&pool).await.is_empty());
    })
    .await;
}

#[tokio::test]
async fn a_database_that_never_had_storage_pushes_cleanly() {
    common::with_integration_pool(|pool| async move {
        common::exec(&pool, "DROP SCHEMA IF EXISTS storage CASCADE")
            .await
            .expect("no storage schema");
        push(&pool, NO_BUCKETS).await;
    })
    .await;
}

/// A steady-state push with buckets re-asserts the storage layer, and used to take ACCESS EXCLUSIVE
/// on `storage.objects` (and `storage.buckets`) every time, to enable row-level security already on
/// and add columns already there, behind every upload in progress. With the storage service mid
/// write (ROW EXCLUSIVE, held), the push now applies without waiting on it.
#[tokio::test(flavor = "multi_thread")]
async fn an_up_to_date_push_does_not_wait_on_a_write_to_storage_objects() {
    common::with_integration_pool(|pool| async move {
        push(&pool, MEDIA).await;
        let side = common::locks::side_pool(&pool, 1).await;
        let mut writer = side.begin().await.unwrap();
        sqlx::raw_sql("LOCK TABLE storage.objects, storage.buckets IN ROW EXCLUSIVE MODE")
            .execute(&mut *writer)
            .await
            .unwrap();
        let started = std::time::Instant::now();
        let again = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            common::push(&pool, &parser::parse(MEDIA).unwrap()),
        )
        .await
        .expect("the push waited on the storage service's write");
        writer.rollback().await.unwrap();
        let again = again.expect("push applies");
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "took {:?}",
            started.elapsed()
        );
    })
    .await;
}

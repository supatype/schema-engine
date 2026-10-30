//! Every bucket row carries a concrete `access_mode`, and `public` says the same thing.
//!
//! The storage service and the CLI decide who reads a bucket from `access_mode` alone (`public`,
//! `private` or `custom`), with `public` true exactly when the mode is `public`. A row with no mode
//! is read from its `public` flag. Engines before this one could leave a row with no mode, and the
//! storage service could leave a custom bucket flagged public. A push now writes both columns for
//! every bucket it makes and brings every older row into line, the same way each time.
//!
//! On a bucket that already exists, a push rewrites only what the schema names about it, so a
//! change made at runtime to anything the schema leaves out survives the next push.

mod common;

use supatype_engine::generator::sql::storage;
use supatype_engine::parser::ast::{SchemaAst, StorageBucketAst};

const MEDIA: &str = r#"{
  "astVersion": 2,
  "models": [],
  "storageBuckets": [{ "id": "media", "public": false, "accessMode": "private" }]
}"#;

async fn push(pool: &sqlx::PgPool) {
    let ast = supatype_engine::parser::parse(MEDIA).expect("schema parses");
    common::push(pool, &ast).await.expect("push applies");
}

/// Each bucket's id, mode, flag and row version, by id. The row version (`xmin`) moves whenever
/// the row is written, so an unchanged one proves a push left the row alone.
async fn buckets(pool: &sqlx::PgPool) -> Vec<(String, Option<String>, bool, String)> {
    sqlx::query_as(
        "SELECT id, access_mode, public, xmin::text FROM storage.buckets
          WHERE id <> 'media' ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .expect("read buckets")
}

fn modes(rows: &[(String, Option<String>, bool, String)]) -> Vec<(&str, Option<&str>, bool)> {
    rows.iter()
        .map(|(id, mode, public, _)| (id.as_str(), mode.as_deref(), *public))
        .collect()
}

#[tokio::test]
async fn a_push_gives_every_older_bucket_row_a_mode_that_agrees_with_its_flag() {
    common::with_integration_pool(|pool| async move {
        push(&pool).await;
        // What older engines and the storage service left behind, and a mode nobody knows.
        common::exec(
            &pool,
            "INSERT INTO storage.buckets (id, name, public, access_mode) VALUES
               ('legacy_public', 'legacy_public', true, NULL),
               ('legacy_private', 'legacy_private', false, NULL),
               ('stale_custom', 'stale_custom', true, 'custom'),
               ('odd_mode', 'odd_mode', true, 'shared');",
        )
        .await
        .expect("fixture buckets");

        push(&pool).await;
        let first = buckets(&pool).await;
        assert_eq!(
            modes(&first),
            vec![
                ("legacy_private", Some("private"), false),
                ("legacy_public", Some("public"), true),
                // A mode the engine does not know is not its to correct.
                ("odd_mode", Some("shared"), true),
                ("stale_custom", Some("custom"), false),
            ]
        );

        push(&pool).await;
        assert_eq!(
            buckets(&pool).await,
            first,
            "a second push rewrites no bucket row"
        );
    })
    .await;
}

#[test]
fn a_bucket_with_no_mode_is_written_with_the_one_its_flag_implies() {
    let bucket = |id: &str, public: bool| StorageBucketAst {
        id: id.to_string(),
        public: Some(public),
        allowed_mime_types: None,
        file_size_limit: None,
        access_mode: None,
        access: None,
        s3_bucket_policy: None,
    };
    let mut ast: SchemaAst = supatype_engine::parser::parse(r#"{ "astVersion": 2, "models": [] }"#)
        .expect("schema parses");
    ast.storage_buckets = vec![bucket("open", true), bucket("shut", false)];
    let sql = storage::generate(&ast).expect("storage sql generates");
    assert!(
        sql.contains("VALUES ('open', 'open', true, NULL, NULL, 'public', NULL)"),
        "{sql}"
    );
    assert!(
        sql.contains("VALUES ('shut', 'shut', false, NULL, NULL, 'private', NULL)"),
        "{sql}"
    );
}

#[test]
fn a_custom_bucket_is_never_written_public() {
    let ast = supatype_engine::parser::parse(
        r#"{ "astVersion": 2, "models": [],
             "storageBuckets": [{ "id": "c", "public": true, "accessMode": "custom" }] }"#,
    )
    .expect("schema parses");
    let sql = storage::generate(&ast).expect("storage sql generates");
    assert!(
        sql.contains("VALUES ('c', 'c', false, NULL, NULL, 'custom', NULL)"),
        "{sql}"
    );
}

/// `docs` names nothing about itself, `notes` is made by a field alone, `pics` names its mode and
/// size limit, and `flagged` names only its `public` flag.
const VISIBILITY: &str = r#"{
  "astVersion": 2,
  "models": [{
    "name": "note",
    "annotations": { "db": { "tableName": "note" } },
    "fields": {
      "id": { "kind": "uuid", "required": true },
      "file": { "kind": "file", "required": false, "bucket": "notes" }
    }
  }],
  "storageBuckets": [
    { "id": "docs" },
    { "id": "pics", "accessMode": "private", "fileSizeLimit": 5, "allowedMimeTypes": ["image/png"] },
    { "id": "flagged", "public": false }
  ]
}"#;

/// What Studio or the storage API does to a bucket at runtime: opens it and changes its limits.
const RUNTIME_CHANGE: &str = "UPDATE storage.buckets
    SET access_mode = 'public', public = true, file_size_limit = 99,
        allowed_mime_types = ARRAY['text/plain'], s3_bucket_policy = '{}'
  WHERE true";

type Row = (
    String,
    String,
    bool,
    Option<i64>,
    Option<Vec<String>>,
    Option<String>,
);

async fn visibility_rows(pool: &sqlx::PgPool) -> Vec<Row> {
    sqlx::query_as(
        "SELECT id, access_mode, public, file_size_limit, allowed_mime_types, s3_bucket_policy
           FROM storage.buckets ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .expect("read buckets")
}

fn row(id: &str, mode: &str, limit: i64, mime: &str, policy: Option<&str>) -> Row {
    let public = mode == "public";
    let mime = Some(vec![mime.to_string()]);
    (
        id.into(),
        mode.into(),
        public,
        Some(limit),
        mime,
        policy.map(Into::into),
    )
}

#[tokio::test]
async fn a_push_reasserts_only_what_the_schema_names_about_a_bucket() {
    common::with_integration_pool(|pool| async move {
        let ast = supatype_engine::parser::parse(VISIBILITY).expect("schema parses");
        common::push(&pool, &ast).await.expect("first push");
        common::exec(&pool, RUNTIME_CHANGE)
            .await
            .expect("runtime change");
        common::push(&pool, &ast).await.expect("second push");

        assert_eq!(
            visibility_rows(&pool).await,
            vec![
                row("docs", "public", 99, "text/plain", Some("{}")),
                // `public: false` alone names the bucket's visibility.
                row("flagged", "private", 99, "text/plain", Some("{}")),
                row("notes", "public", 99, "text/plain", Some("{}")),
                row("pics", "private", 5, "image/png", Some("{}")),
            ]
        );
    })
    .await;
}

#[tokio::test]
async fn a_bucket_that_names_nothing_is_made_private() {
    common::with_integration_pool(|pool| async move {
        let ast = supatype_engine::parser::parse(VISIBILITY).expect("schema parses");
        common::push(&pool, &ast).await.expect("push");
        let modes: Vec<(String, String, bool)> =
            sqlx::query_as("SELECT id, access_mode, public FROM storage.buckets ORDER BY id")
                .fetch_all(&pool)
                .await
                .unwrap();
        let expected = [("docs", "private", false), ("flagged", "private", false)]
            .into_iter()
            .chain([("notes", "private", false), ("pics", "private", false)])
            .map(|(i, m, p)| (i.to_string(), m.to_string(), p))
            .collect::<Vec<_>>();
        assert_eq!(modes, expected);
    })
    .await;
}

/// A bucket built without the parser, here from its wire format, says whether it names its
/// visibility by the fields themselves, so a push reasserts exactly what it names.
#[test]
fn a_bucket_built_without_the_parser_reasserts_only_the_visibility_it_names() {
    let bucket = |json: serde_json::Value| -> StorageBucketAst {
        serde_json::from_value(json).expect("bucket deserializes")
    };
    let mut ast: SchemaAst = supatype_engine::parser::parse(r#"{ "astVersion": 2, "models": [] }"#)
        .expect("schema parses");
    ast.storage_buckets = vec![
        bucket(serde_json::json!({ "id": "moded", "accessMode": "public" })),
        bucket(serde_json::json!({ "id": "flagged", "public": true })),
        bucket(serde_json::json!({ "id": "silent" })),
    ];
    let sql = storage::generate(&ast).expect("storage sql generates");
    let upsert = |id: &str| -> String {
        let start = sql
            .find(&format!("VALUES ('{id}'"))
            .unwrap_or_else(|| panic!("no upsert for {id}: {sql}"));
        let end = start + sql[start..].find(";\n").expect("statement ends");
        sql[start..end].to_string()
    };
    for id in ["moded", "flagged"] {
        let stmt = upsert(id);
        assert!(stmt.contains("'public', NULL)"), "{stmt}");
        assert!(
            stmt.contains("access_mode = EXCLUDED.access_mode"),
            "{stmt}"
        );
        assert!(stmt.contains("public = EXCLUDED.public"), "{stmt}");
    }
    let silent = upsert("silent");
    assert!(silent.contains("'private', NULL)"), "{silent}");
    assert!(silent.contains("ON CONFLICT (id) DO NOTHING"), "{silent}");
}

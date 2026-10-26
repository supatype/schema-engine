//! Push and adopt read the database as it is, not as the last push left it.
//!
//! Both used to diff against `_supatype.schema_state`, a snapshot the previous push wrote, while
//! `diff` introspected the live catalog. So the three disagreed about anything changed outside
//! Supatype since then:
//!
//! * a table whose ownership comment was removed was unmanaged to `diff`, and `push` still said
//!   "Schema up to date" because the snapshot had the comment (supatype#87);
//! * `adopt` read the same snapshot and found nothing to stamp, a dead end (supatype#86);
//! * a column dropped by hand was invisible to `push`, which planned nothing to restore it.
//!
//! These drive the engine binary, the same entry point the CLI uses, against a throwaway database.

mod common;

use std::process::Command;

const ONE_MODEL: &str = r#"{
  "astVersion": 2,
  "models": [{
    "name": "Widget",
    "fields": {
      "id": { "kind": "integer", "primaryKey": true, "required": true,
              "annotations": { "db": { "pgType": "INTEGER", "unique": false } } },
      "name": { "kind": "text",
              "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
    },
    "options": {},
    "annotations": { "db": { "tableName": "widget", "indexes": [] }, "platform": {} }
  }]
}"#;

struct Run {
    ok: bool,
    stdout: String,
    stderr: String,
}

/// Run the engine binary on `ONE_MODEL` against `url`, ignoring any `DATABASE_URL` in the
/// environment, which in CI names the shared admin database rather than this test's.
fn engine(url: &str, args: &[&str]) -> Run {
    let input = std::env::temp_dir().join(format!(
        "live-state-{}-{}.json",
        std::process::id(),
        common::EPHEMERAL_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    std::fs::write(&input, ONE_MODEL).expect("write the AST");
    let out = Command::new(env!("CARGO_BIN_EXE_supatype-engine"))
        .env_remove("DATABASE_URL")
        .arg("-i")
        .arg(&input)
        .args(args)
        .args(["--database-url", url])
        .output()
        .expect("run the engine");
    let _ = std::fs::remove_file(&input);
    Run {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn push(url: &str) -> Run {
    engine(url, &["push", "--force", "--non-interactive"])
}

async fn sql(url: &str, statement: &str) {
    let pool = sqlx::PgPool::connect(url).await.expect("connect");
    sqlx::raw_sql(statement)
        .execute(&pool)
        .await
        .unwrap_or_else(|e| panic!("{statement}: {e}"));
    pool.close().await;
}

#[tokio::test]
async fn push_refuses_a_table_that_lost_its_ownership_marker_with_nothing_to_apply() {
    common::with_integration_url(|url| async move {
        let first = push(&url);
        assert!(first.ok, "first push: {}", first.stderr);
        sql(&url, "COMMENT ON TABLE public.widget IS NULL").await;

        let again = push(&url);
        assert!(
            !again.ok,
            "a push over an unmanaged table must refuse, got stdout {} stderr {}",
            again.stdout, again.stderr
        );
        assert!(again.stderr.contains("does not manage"), "{}", again.stderr);
        // Machine-readable on stdout, so the CLI can name the tables and offer to adopt them
        // without matching the wording above.
        let refusal: serde_json::Value = again
            .stdout
            .lines()
            .find_map(|l| serde_json::from_str(l).ok())
            .unwrap_or_else(|| panic!("no JSON refusal on stdout: {}", again.stdout));
        assert_eq!(refusal["reason"], "unmanaged_model_tables");
        assert_eq!(refusal["tables"], serde_json::json!(["widget"]));
    })
    .await;
}

#[tokio::test]
async fn adopt_offers_to_stamp_the_table_push_refuses() {
    common::with_integration_url(|url| async move {
        assert!(push(&url).ok);
        sql(&url, "COMMENT ON TABLE public.widget IS NULL").await;

        let preview = engine(&url, &["adopt"]);
        assert!(preview.ok, "{}", preview.stderr);
        assert!(
            preview.stdout.contains("COMMENT ON TABLE") && preview.stdout.contains("widget"),
            "adopt must offer to stamp the table, got {}",
            preview.stdout
        );
    })
    .await;
}

#[tokio::test]
async fn push_restores_a_column_dropped_outside_supatype() {
    common::with_integration_url(|url| async move {
        assert!(push(&url).ok);
        sql(&url, "ALTER TABLE public.widget DROP COLUMN name").await;

        let again = push(&url);
        assert!(again.ok, "{}", again.stderr);

        let pool = sqlx::PgPool::connect(&url).await.expect("connect");
        let restored: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
              WHERE table_schema = 'public' AND table_name = 'widget' AND column_name = 'name')",
        )
        .fetch_one(&pool)
        .await
        .expect("query");
        pool.close().await;
        assert!(
            restored,
            "push must see the drop and put the column back: {}",
            again.stdout
        );
    })
    .await;
}

#[tokio::test]
async fn no_cache_is_still_accepted_and_says_it_is_no_longer_needed() {
    common::with_integration_url(|url| async move {
        let run = engine(
            &url,
            &["push", "--force", "--non-interactive", "--no-cache"],
        );
        assert!(run.ok, "{}", run.stderr);
        assert!(
            run.stderr.contains("--no-cache is no longer needed"),
            "a script passing it must keep working and be told, got {}",
            run.stderr
        );
    })
    .await;
}

async fn rls_on(url: &str) -> bool {
    let pool = sqlx::PgPool::connect(url).await.expect("connect");
    let on: bool = sqlx::query_scalar(
        "SELECT relrowsecurity FROM pg_class WHERE oid = 'public.widget'::regclass",
    )
    .fetch_one(&pool)
    .await
    .expect("read relrowsecurity");
    pool.close().await;
    on
}

/// Plan 3.5: a pipeline must not silently revert access someone changed on purpose. A push that
/// is not interactive refuses with the objects on stdout, where the CLI reads them, and applies
/// nothing; `--overwrite-drift` puts Supatype's definitions back.
#[tokio::test]
async fn a_non_interactive_push_refuses_to_overwrite_access_changed_by_hand() {
    common::with_integration_url(|url| async move {
        assert!(push(&url).ok);
        sql(&url, "ALTER TABLE public.widget DISABLE ROW LEVEL SECURITY").await;

        let refused = push(&url);
        assert!(!refused.ok, "{}", refused.stdout);
        let result: serde_json::Value = serde_json::from_str(refused.stdout.trim())
            .unwrap_or_else(|e| panic!("the refusal is JSON ({e}): {}", refused.stdout));
        assert_eq!(result["reason"], "security_drift", "{result}");
        assert_eq!(
            result["objects"][0]["key"]["kind"], "rls_attributes",
            "{result}"
        );
        assert!(!rls_on(&url).await, "a refused push changed the database");

        let consented = engine(
            &url,
            &["push", "--force", "--non-interactive", "--overwrite-drift"],
        );
        assert!(consented.ok, "{}", consented.stderr);
        assert!(rls_on(&url).await);
    })
    .await;
}

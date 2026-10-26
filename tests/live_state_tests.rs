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
async fn push_refuses_a_table_it_has_no_record_of_with_nothing_to_apply() {
    common::with_integration_url(|url| async move {
        let first = push(&url);
        assert!(first.ok, "first push: {}", first.stderr);
        // Neither a ledger row nor an older engine's stamp: not ours (Phase 4.11). A comment alone
        // no longer decides it, so both go.
        sql(
            &url,
            "DELETE FROM _supatype.managed_objects WHERE kind = 'table' AND name = 'widget';
             COMMENT ON TABLE public.widget IS NULL",
        )
        .await;

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
async fn adopt_offers_to_take_the_table_push_refuses() {
    common::with_integration_url(|url| async move {
        assert!(push(&url).ok);
        sql(
            &url,
            "DELETE FROM _supatype.managed_objects WHERE kind = 'table' AND name = 'widget';
             COMMENT ON TABLE public.widget IS NULL",
        )
        .await;

        let preview = engine(&url, &["adopt"]);
        assert!(preview.ok, "{}", preview.stderr);
        let outcome: serde_json::Value =
            serde_json::from_str(&preview.stdout).expect("adopt prints its outcome as JSON");
        assert_eq!(outcome["status"], "preview");
        assert!(
            outcome["adopt"].as_array().is_some_and(|items| items
                .iter()
                .any(|i| i["kind"] == "table" && i["name"] == "widget")),
            "adopt must offer to take the table, got {}",
            preview.stdout
        );

        // And taking it is what the push was waiting for.
        assert!(engine(&url, &["adopt", "--yes"]).ok);
        let again = push(&url);
        assert!(
            again.ok,
            "the push still refuses after adopt: {}",
            again.stderr
        );
    })
    .await;
}

/// `--adopt-none` adopts no conflict while still releasing what `--release` names, as HTTP
/// `keys: []` does; with no `--key` at all every conflict is adopted. It cannot be combined with
/// `--key`.
#[tokio::test]
async fn adopt_none_releases_without_adopting_any_conflict() {
    common::with_integration_url(|url| async move {
        assert!(push(&url).ok);
        sql(
            &url,
            "DELETE FROM _supatype.managed_objects WHERE kind = 'table' AND name = 'widget';
             COMMENT ON TABLE public.widget IS NULL;
             CREATE INDEX widget_name_mine ON public.widget (name);",
        )
        .await;

        let both = engine(
            &url,
            &["adopt", "--yes", "--adopt-none", "--key", "table:widget"],
        );
        assert!(!both.ok, "--adopt-none with --key must be refused");

        let none = engine(
            &url,
            &[
                "adopt",
                "--yes",
                "--adopt-none",
                "--release",
                "index:widget.widget_name_mine",
            ],
        );
        assert!(none.ok, "{}", none.stderr);
        let outcome: serde_json::Value = serde_json::from_str(&none.stdout).unwrap();
        assert_eq!(outcome["adopt"], serde_json::json!([]), "{}", none.stdout);
        assert_eq!(outcome["release"].as_array().map(Vec::len), Some(1));
        let status = |name: &'static str| {
            let url = url.clone();
            async move {
                let pool = sqlx::PgPool::connect(&url).await.unwrap();
                let status: Option<String> = sqlx::query_scalar(
                    "SELECT status FROM _supatype.managed_objects WHERE name = $1",
                )
                .bind(name)
                .fetch_optional(&pool)
                .await
                .unwrap();
                pool.close().await;
                status
            }
        };
        assert_eq!(
            status("widget_name_mine").await.as_deref(),
            Some("released")
        );
        assert_eq!(status("widget").await, None, "the table was adopted");
        assert!(!push(&url).ok, "the table is still a conflict");
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

/// While another session holds the engine's lock, each writing command refuses, and says so on
/// stdout as `{"status":"refused","reason":"engine_busy",...}`, where a caller reads the result,
/// exiting non-zero.
#[tokio::test]
async fn a_writer_refuses_on_stdout_while_the_engine_is_busy() {
    use sqlx::Connection;
    common::with_integration_url(|url| async move {
        let first = push(&url);
        assert!(first.ok, "first push: {}", first.stderr);
        let mut other = sqlx::PgConnection::connect(&url).await.unwrap();
        sqlx::query("SELECT pg_advisory_lock(872014, 2)")
            .execute(&mut other)
            .await
            .unwrap();
        for args in [
            &["push", "--force", "--non-interactive"][..],
            &["adopt", "--yes"],
            &["doctor", "--rebaseline"],
            &["rollback"],
        ] {
            let run = engine(&url, args);
            assert!(
                !run.ok,
                "{args:?} ran while the engine was busy: {}",
                run.stdout
            );
            let refusal: serde_json::Value = run
                .stdout
                .lines()
                .find_map(|l| serde_json::from_str(l).ok())
                .unwrap_or_else(|| panic!("{args:?}: no JSON refusal on stdout: {}", run.stdout));
            assert_eq!(refusal["status"], "refused", "{args:?}");
            assert_eq!(refusal["reason"], "engine_busy", "{args:?}");
            assert!(
                refusal["message"].as_str().unwrap().contains("try again"),
                "{args:?}: {refusal}"
            );
            assert!(run.stderr.contains("try again"), "{args:?}: {}", run.stderr);
        }
    })
    .await;
}

/// Rebaselining drift on access takes `--accept-access-drift`; `--overwrite-drift`, the push's
/// consent to put Supatype's definitions back, is refused by doctor with a pointer to it.
#[tokio::test]
async fn doctor_rebaselines_access_drift_with_its_own_consent() {
    common::with_integration_url(|url| async move {
        let first = push(&url);
        assert!(first.ok, "first push: {}", first.stderr);
        sql(&url, "ALTER TABLE public.widget DISABLE ROW LEVEL SECURITY").await;

        let refused = engine(&url, &["doctor", "--rebaseline", "--overwrite-drift"]);
        assert!(
            !refused.ok,
            "doctor took --overwrite-drift: {}",
            refused.stdout
        );
        assert!(
            refused.stderr.contains("--accept-access-drift"),
            "{}",
            refused.stderr
        );

        let without = engine(&url, &["doctor", "--rebaseline"]);
        assert!(without.ok, "{}", without.stderr);
        let report: serde_json::Value = serde_json::from_str(&without.stdout).unwrap();
        let message = report["rebaselineRefused"][0]["message"].as_str().unwrap();
        assert!(message.contains("--accept-access-drift"), "{report}");

        let with = engine(&url, &["doctor", "--rebaseline", "--accept-access-drift"]);
        assert!(with.ok, "{}", with.stderr);
        let report: serde_json::Value = serde_json::from_str(&with.stdout).unwrap();
        assert_eq!(
            report["rebaselined"][0]["kind"], "rls_attributes",
            "{report}"
        );
        assert!(report.get("rebaselineRefused").is_none(), "{report}");
    })
    .await;
}

/// `capabilities` needs no input and no database: the CLI asks it before relying on a flag.
#[test]
fn capabilities_prints_the_features_this_engine_supports() {
    let out = Command::new(env!("CARGO_BIN_EXE_supatype-engine"))
        .arg("capabilities")
        .output()
        .expect("run the engine");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        body,
        serde_json::json!({ "features": ["adopt_keys", "adopt_none", "release", "reclaim",
            "rebaseline", "accept_access_drift", "rebaseline_keys", "overwrite_drift", "engine_busy", "identity_columns"] })
    );
}

//! The `seed` subcommand, end to end: the real binary, a real database.
//!
//! Everything below this level is already tested in isolation. What only this level can
//! prove is that the pieces are wired to each other: that the command reads a document,
//! validates it against the schema, writes the rows, records the run in the ledger inside
//! the same transaction, prints the result document the runners parse, and exits with the
//! code CI branches on.
//!
//! The exit codes are the reason several of these exist. `1` and `2` are a promise that CI
//! can tell "the seed data is wrong" from "this environment is not set up", and a promise
//! nothing asserts is one that quietly stops being true.

mod common;

use sqlx::ConnectOptions;
use std::path::{Path, PathBuf};
use std::process::Command;

const SCHEMA: &str = r#"{
    "astVersion": 2,
    "models": [
        {
            "name": "Organiser",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {"kind": "genRandomUuid"},
                       "annotations": {"db": {"unique": true}}},
                "slug": {"kind": "text", "required": true, "annotations": {"db": {"unique": true}}},
                "name": {"kind": "text", "required": true},
                "events": {"kind": "relation", "cardinality": "hasMany", "target": "Event"}
            },
            "annotations": {"db": {"tableName": "organiser"}}
        },
        {
            "name": "Event",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {"kind": "genRandomUuid"},
                       "annotations": {"db": {"unique": true}}},
                "title": {"kind": "text", "required": true},
                "organiser": {"kind": "relation", "cardinality": "belongsTo", "target": "Organiser",
                              "required": false,
                              "annotations": {"db": {"foreignKey": "organiser_id"}}}
            },
            "annotations": {"db": {"tableName": "event"}}
        }
    ]
}"#;

fn engine_binary() -> PathBuf {
    // The test binary sits in target/<profile>/deps, so the engine is two levels up.
    let mut path = std::env::current_exe().expect("this test has a path");
    path.pop();
    path.pop();
    path.push(format!("supatype-engine{}", std::env::consts::EXE_SUFFIX));
    assert!(
        path.exists(),
        "the engine binary is not built at {}: run `cargo build` first",
        path.display()
    );
    path
}

/// A directory of this test's own, so two tests running at once do not share files.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("supatype-seed-command-{name}"));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

fn write(dir: &Path, name: &str, contents: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("writes the fixture");
    path.to_string_lossy().into_owned()
}

/// An IR document carrying the fingerprint of the schema above.
fn ir(operations: &str) -> String {
    let ast = supatype_engine::parser::parse(SCHEMA).expect("the schema parses");
    let fingerprint = supatype_engine::seed::fingerprint::fingerprint(&ast);
    format!(r#"{{"irVersion":1,"schemaFingerprint":"{fingerprint}","operations":{operations}}}"#)
}

struct Run {
    code: i32,
    result: serde_json::Value,
}

fn seed(args: &[&str]) -> Run {
    let output = Command::new(engine_binary())
        .arg("seed")
        .args(args)
        .output()
        .expect("the engine runs");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let result = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "the result document must be JSON ({e}):\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    Run {
        code: output.status.code().unwrap_or(-1),
        result,
    }
}

/// Apply the schema, then hand the test a connection string for it.
macro_rules! with_schema {
    (|$pool:ident, $url:ident| $body:block) => {
        common::with_integration_pool(|$pool| async move {
            let ast = supatype_engine::parser::parse(SCHEMA).expect("the schema parses");
            common::push(&$pool, &ast)
                .await
                .expect("the schema applies");
            sqlx::raw_sql("CREATE SCHEMA IF NOT EXISTS _supatype")
                .execute(&$pool)
                .await
                .expect("the internal schema");
            sqlx::raw_sql(&supatype_engine::seed::ledger::create_seeds_table_sql())
                .execute(&$pool)
                .await
                .expect("the ledger table");

            let $url = $pool.connect_options().to_url_lossy().to_string();
            $body
        })
        .await;
    };
}

fn ast_file(dir: &Path) -> String {
    write(dir, "schema.json", SCHEMA)
}

#[tokio::test]
async fn it_writes_a_document_and_records_the_run() {
    with_schema!(|pool, url| {
        let dir = scratch("writes");
        let ast = ast_file(&dir);
        let document = write(
            &dir,
            "seed.json",
            &ir(r#"[{"op":"create","model":"Organiser","data":{"slug":"n","name":"Northern"}}]"#),
        );

        let run = seed(&["--input", &ast, "--ir", &document, "--database-url", &url]);
        assert_eq!(run.code, 0, "{:#}", run.result);
        assert_eq!(run.result["ok"], true);
        assert_eq!(run.result["files"][0]["status"], "committed");
        assert_eq!(run.result["files"][0]["written"]["Organiser"], 1);

        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM organiser")
            .fetch_one(&pool)
            .await
            .expect("counts");
        assert_eq!(rows, 1);

        // The ledger row is the other half of the job: a run nobody recorded is a run
        // nobody can audit.
        let recorded: i64 =
            sqlx::query_scalar("SELECT count(*) FROM _supatype.seeds WHERE status = 'committed'")
                .fetch_one(&pool)
                .await
                .expect("counts");
        assert_eq!(recorded, 1);
    });
}

/// The whole reason the command owns the transaction rather than the executor.
#[tokio::test]
async fn a_failed_run_writes_no_rows_and_records_a_rollback() {
    with_schema!(|pool, url| {
        let dir = scratch("fails");
        let ast = ast_file(&dir);
        let document = write(
            &dir,
            "seed.json",
            &ir(r#"[{"op":"createMany","model":"Organiser","rows":[
                {"slug":"dup","name":"A"},
                {"slug":"dup","name":"B"}
            ]}]"#),
        );

        let run = seed(&["--input", &ast, "--ir", &document, "--database-url", &url]);
        assert_eq!(run.code, 1, "a failed seed exits 1: {:#}", run.result);
        assert_eq!(run.result["ok"], false);
        assert_eq!(run.result["error"]["kind"], "constraint");
        assert_eq!(run.result["error"]["constraint"], "unique");
        assert_eq!(run.result["error"]["model"], "Organiser");

        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM organiser")
            .fetch_one(&pool)
            .await
            .expect("counts");
        assert_eq!(rows, 0, "the transaction rolled back");

        let rolled: i64 =
            sqlx::query_scalar("SELECT count(*) FROM _supatype.seeds WHERE status = 'rolled_back'")
                .fetch_one(&pool)
                .await
                .expect("counts");
        assert_eq!(rolled, 1, "the failure is recorded as what it was");
    });
}

/// Without `--atomic`, a failure in the second document leaves the first committed, and
/// the report has to say so rather than leaving the reader to guess.
#[tokio::test]
async fn documents_are_separate_transactions_by_default() {
    with_schema!(|pool, url| {
        let dir = scratch("separate");
        let ast = ast_file(&dir);
        let first = write(
            &dir,
            "01.json",
            &ir(r#"[{"op":"create","model":"Organiser","data":{"slug":"a","name":"A"}}]"#),
        );
        let second = write(
            &dir,
            "02.json",
            &ir(r#"[{"op":"createMany","model":"Organiser","rows":[
                {"slug":"b","name":"B"},
                {"slug":"b","name":"B again"}
            ]}]"#),
        );

        let run = seed(&[
            "--input",
            &ast,
            "--ir",
            &first,
            "--ir",
            &second,
            "--database-url",
            &url,
        ]);
        assert_eq!(run.code, 1);
        assert_eq!(run.result["files"][0]["status"], "committed");
        assert_eq!(run.result["files"][1]["status"], "rolledBack");

        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM organiser")
            .fetch_one(&pool)
            .await
            .expect("counts");
        assert_eq!(rows, 1, "the first document stayed");
    });
}

/// With `--atomic`, it does not: the first document rolls back with the second, and the
/// report must not still call it committed.
#[tokio::test]
async fn atomic_rolls_every_document_back_together() {
    with_schema!(|pool, url| {
        let dir = scratch("atomic");
        let ast = ast_file(&dir);
        let first = write(
            &dir,
            "01.json",
            &ir(r#"[{"op":"create","model":"Organiser","data":{"slug":"a","name":"A"}}]"#),
        );
        let second = write(
            &dir,
            "02.json",
            &ir(r#"[{"op":"createMany","model":"Organiser","rows":[
                {"slug":"b","name":"B"},
                {"slug":"b","name":"B again"}
            ]}]"#),
        );

        let run = seed(&[
            "--input",
            &ast,
            "--ir",
            &first,
            "--ir",
            &second,
            "--database-url",
            &url,
            "--atomic",
        ]);
        assert_eq!(run.code, 1);
        assert_eq!(run.result["atomic"], true);
        assert_eq!(
            run.result["files"][0]["status"], "rolledBack",
            "the first document did not survive: {:#}",
            run.result
        );

        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM organiser")
            .fetch_one(&pool)
            .await
            .expect("counts");
        assert_eq!(rows, 0, "nothing was left behind");
    });
}

/// Nested writes are the headline of the builder, so the command has to carry them.
#[tokio::test]
async fn a_nested_document_writes_both_levels_linked() {
    with_schema!(|pool, url| {
        let dir = scratch("nested");
        let ast = ast_file(&dir);
        let document = write(
            &dir,
            "seed.json",
            &ir(
                r#"[{"op":"create","model":"Organiser","id":"northern","data":{
                "slug":"n","name":"Northern",
                "events":{"create":[{"title":"Conf"}]}
            }}]"#,
            ),
        );

        let run = seed(&["--input", &ast, "--ir", &document, "--database-url", &url]);
        assert_eq!(run.code, 0, "{:#}", run.result);

        let linked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM event e JOIN organiser o ON o.id = e.organiser_id",
        )
        .fetch_one(&pool)
        .await
        .expect("counts");
        assert_eq!(linked, 1);
    });
}

/// `runOnce` is for a backfill rather than a fixture, and it asks about this exact
/// document, not just this file.
#[tokio::test]
async fn run_once_skips_a_document_already_applied() {
    with_schema!(|pool, url| {
        let dir = scratch("runonce");
        let ast = ast_file(&dir);
        let document = write(
            &dir,
            "backfill.json",
            &ir(r#"[{"op":"create","model":"Organiser","data":{"slug":"once","name":"Once"}}]"#),
        );

        let first = seed(&[
            "--input",
            &ast,
            "--ir",
            &document,
            "--database-url",
            &url,
            "--run-once",
        ]);
        assert_eq!(first.code, 0);
        assert_eq!(first.result["files"][0]["status"], "committed");

        let again = seed(&[
            "--input",
            &ast,
            "--ir",
            &document,
            "--database-url",
            &url,
            "--run-once",
        ]);
        assert_eq!(again.code, 0);
        assert_eq!(again.result["files"][0]["status"], "skipped");

        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM organiser")
            .fetch_one(&pool)
            .await
            .expect("counts");
        assert_eq!(rows, 1, "the second run wrote nothing");
    });
}

/// A seed that is wrong is exit 1, and it must not have written anything on the way to
/// finding that out.
#[tokio::test]
async fn an_invalid_document_fails_before_it_writes() {
    with_schema!(|pool, url| {
        let dir = scratch("invalid");
        let ast = ast_file(&dir);
        let good = write(
            &dir,
            "01.json",
            &ir(r#"[{"op":"create","model":"Organiser","data":{"slug":"a","name":"A"}}]"#),
        );
        let bad = write(
            &dir,
            "02.json",
            &ir(r#"[{"op":"create","model":"Organiser","data":{"nonsense":"x"}}]"#),
        );

        let run = seed(&[
            "--input",
            &ast,
            "--ir",
            &good,
            "--ir",
            &bad,
            "--database-url",
            &url,
        ]);
        assert_eq!(run.code, 1, "{:#}", run.result);
        assert_eq!(run.result["error"]["kind"], "validation");

        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM organiser")
            .fetch_one(&pool)
            .await
            .expect("counts");
        assert_eq!(
            rows, 0,
            "the valid document must not run when a later one is invalid"
        );
    });
}

/// And an environment that is not set up is exit 2, which is the whole point of the split:
/// CI retries one of these and not the other.
#[test]
fn an_unreachable_database_exits_two() {
    let dir = scratch("unreachable");
    let ast = ast_file(&dir);
    let document = write(
        &dir,
        "seed.json",
        &ir(r#"[{"op":"create","model":"Organiser","data":{"slug":"a","name":"A"}}]"#),
    );

    let run = seed(&[
        "--input",
        &ast,
        "--ir",
        &document,
        "--database-url",
        "postgresql://nobody:nobody@127.0.0.1:1/nothing",
    ]);
    assert_eq!(run.code, 2, "{:#}", run.result);
    assert_eq!(run.result["error"]["kind"], "connection");
}

/// A document that is not there is the environment, not the seed.
#[test]
fn a_missing_document_exits_two() {
    let dir = scratch("missing");
    let ast = ast_file(&dir);
    let run = seed(&[
        "--input",
        &ast,
        "--ir",
        &dir.join("nothing-here.json").to_string_lossy(),
        "--database-url",
        "postgresql://nobody:nobody@127.0.0.1:1/nothing",
    ]);
    assert_eq!(run.code, 2, "{:#}", run.result);
    assert_eq!(run.result["error"]["kind"], "document");
}

/// `--status` answers "what has been applied here", including whether a file has changed
/// since it was applied.
#[tokio::test]
async fn status_reports_what_ran_and_whether_it_drifted() {
    with_schema!(|pool, url| {
        let _ = &pool;
        let dir = scratch("status");
        let ast = ast_file(&dir);

        let first = write(
            &dir,
            "seed.json",
            &ir(
                r#"[{"op":"upsert","model":"Organiser","where":{"slug":"n"},"data":{"name":"A"}}]"#,
            ),
        );
        assert_eq!(
            seed(&["--input", &ast, "--ir", &first, "--database-url", &url]).code,
            0
        );

        let status = seed(&["--database-url", &url, "--status"]);
        assert_eq!(status.code, 0);
        assert_eq!(status.result["files"][0]["status"], "committed");
        assert_eq!(
            status.result["files"][0]["drifted"], false,
            "one run cannot have drifted"
        );

        // Same file, different content: the question the ledger exists to answer.
        let changed = write(
            &dir,
            "seed.json",
            &ir(
                r#"[{"op":"upsert","model":"Organiser","where":{"slug":"n"},"data":{"name":"B"}}]"#,
            ),
        );
        assert_eq!(
            seed(&["--input", &ast, "--ir", &changed, "--database-url", &url]).code,
            0
        );

        let after = seed(&["--database-url", &url, "--status"]);
        assert_eq!(
            after.result["files"][0]["drifted"], true,
            "the document changed since it was applied: {:#}",
            after.result
        );
    });
}

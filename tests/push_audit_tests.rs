//! Who pushed what, and which renames it applied (RN1, the audit trail).
//!
//! A migration row recorded the SQL a rename ran and nothing about who asked for it: the only "who"
//! was a `pushedBy` inside the schema sources manifest, set by the client and checked by nothing.
//! The row now carries `pushed_by`, `pushed_via`, `pushed_from`, `pushed_by_verified` and
//! `renames`, each rename with who declared it and when, from the project's rename journal.
//!
//! The journal rides in the schema (`renameJournal`), and the engine reads each entry as a declared
//! rename: a database that still has the old column renames it, one that has already applied it
//! does nothing, and one two renames behind follows the chain back to the name it has.

mod common;

use std::process::Command;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::parser::{self, ast::SchemaAst};
use supatype_engine::push::{self, Outcome};
use supatype_engine::server::types::DbRequest;
use supatype_engine::state::audit::{PushAudit, PushChannel};
use supatype_engine::state::migration_history;

use common::{exec, push_with};

fn text() -> Value {
    json!({ "kind": "text", "required": false,
            "annotations": { "db": { "pgType": "TEXT", "unique": false } } })
}

fn uuid_id() -> Value {
    json!({ "kind": "uuid", "primaryKey": true, "required": true,
            "default": { "kind": "genRandomUuid" },
            "annotations": { "db": { "pgType": "UUID", "unique": false } } })
}

/// `member` with `fields` beside its uuid `id`, and the rename journal `journal`.
fn member(fields: Value, journal: Value) -> SchemaAst {
    parser::parse(&member_doc(fields, journal).to_string()).expect("fixture parses")
}

fn member_doc(fields: Value, journal: Value) -> Value {
    let mut all = json!({ "id": uuid_id() });
    for (name, field) in fields.as_object().unwrap() {
        all[name] = field.clone();
    }
    json!({ "astVersion": 2, "renameJournal": journal, "models": [{
        "name": "member",
        "fields": all,
        "options": { "timestamps": false, "softDelete": false },
        "annotations": { "db": { "tableName": "member", "indexes": [] },
                         "platform": { "access": { "read": { "type": "public" } } } }
    }]})
}

/// One journal entry, as `supatype/renames.json` holds it.
fn entry(from: &str, to: &str, by: &str) -> Value {
    json!({ "id": format!("{from}-{to}"), "kind": "column", "table": "member", "from": from,
            "to": to, "declared_by": by, "declared_at": "2026-10-12T10:00:00.000Z" })
}

const ADA: &str = "Ada Lovelace <ada@example.com>";
const GRACE: &str = "Grace Hopper <grace@example.com>";

/// The schema with `column` and an empty journal.
fn with_column(column: &str) -> SchemaAst {
    member(json!({ column: text() }), json!([]))
}

/// `member.title`, with the journal saying `name` became `title`.
fn renamed() -> SchemaAst {
    member(
        json!({ "title": text() }),
        json!([entry("name", "title", ADA)]),
    )
}

fn with_audit(by: &str) -> push::ApplyOptions {
    push::ApplyOptions {
        audit: PushAudit {
            pushed_by: Some(by.into()),
            pushed_via: Some(PushChannel::Cli),
            pushed_from: Some("build-host".into()),
            pushed_by_verified: false,
        },
        ..Default::default()
    }
}

async fn values(pool: &PgPool, column: &str) -> Vec<String> {
    sqlx::query_scalar(&format!(
        "SELECT {column} FROM public.member ORDER BY {column}"
    ))
    .fetch_all(pool)
    .await
    .unwrap()
}

type AuditRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<bool>,
    Option<Value>,
);

/// The audit columns of the latest migration row.
async fn latest_audit(pool: &PgPool) -> AuditRow {
    sqlx::query_as(
        "SELECT pushed_by, pushed_via, pushed_from, pushed_by_verified, renames
           FROM _supatype.migrations ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(pool)
    .await
    .expect("the migration row has the audit columns")
}

/// A database at `column`, holding Alice and Bob.
async fn at(pool: &PgPool, column: &str) {
    push_with(pool, &with_column(column), with_audit(ADA))
        .await
        .unwrap();
    exec(
        pool,
        &format!("INSERT INTO public.member ({column}) VALUES ('Alice'), ('Bob')"),
    )
    .await
    .unwrap();
}

/// Pushes `ast` and checks the data moved to `title`, and that the rename `from` -> `title` is
/// recorded with who declared it.
async fn renames_to_title(pool: &PgPool, ast: &SchemaAst, from: &str) {
    let outcome = push_with(pool, ast, with_audit(GRACE))
        .await
        .expect("the declared rename applies without force");
    assert!(matches!(outcome, Outcome::Applied { .. }), "{outcome:?}");
    assert_eq!(
        values(pool, "title").await,
        ["Alice", "Bob"],
        "the data moved"
    );

    let (by, via, pushed_from, verified, renames) = latest_audit(pool).await;
    assert_eq!(by.as_deref(), Some(GRACE));
    assert_eq!(via.as_deref(), Some("cli"));
    assert_eq!(pushed_from.as_deref(), Some("build-host"));
    assert_eq!(verified, Some(false));
    let renames = renames.expect("the rename is recorded");
    assert_eq!(renames[0]["from"], json!(from));
    assert_eq!(renames[0]["to"], json!("title"));
    assert_eq!(renames[0]["declared_by"], json!(ADA));
}

#[tokio::test]
async fn a_journal_rename_replays_on_a_second_database_and_is_a_no_op_once_applied() {
    common::with_integration_pool(|first| async move {
        common::with_integration_pool(|second| async move {
            at(&first, "name").await;
            at(&second, "name").await;

            renames_to_title(&first, &renamed(), "name").await;
            let again = push_with(&first, &renamed(), with_audit(GRACE))
                .await
                .expect("the same journal again");
            assert!(
                matches!(again, Outcome::UpToDate { .. }),
                "an applied rename is a no-op: {again:?}"
            );

            // The second database replays the same journal: a rename there too, not a drop.
            renames_to_title(&second, &renamed(), "name").await;
        })
        .await;
    })
    .await;
}

/// `name` became `label`, then `label` became `title`. A database still at `name` is two renames
/// behind; it follows the chain back to the column it has. One at `label` takes the last step.
#[tokio::test]
async fn a_chain_of_renames_replays_on_a_database_two_renames_behind() {
    let chain = || {
        member(
            json!({ "title": text() }),
            json!([entry("name", "label", ADA), entry("label", "title", ADA)]),
        )
    };
    common::with_integration_pool(|two_behind| async move {
        common::with_integration_pool(|one_behind| async move {
            at(&two_behind, "name").await;
            at(&one_behind, "label").await;
            renames_to_title(&two_behind, &chain(), "name").await;
            renames_to_title(&one_behind, &chain(), "label").await;
        })
        .await;
    })
    .await;
}

/// `renamedFrom` in the schema may name several old fields, tried in order: the first one the
/// database still has is the one renamed.
#[tokio::test]
async fn renamed_from_may_name_several_old_fields() {
    common::with_integration_pool(|pool| async move {
        at(&pool, "name").await;
        let mut title = text();
        title["annotations"]["db"]["renamedFrom"] = json!(["label", "name"]);
        let ast = member(json!({ "title": title }), json!([]));
        push_with(&pool, &ast, with_audit(GRACE))
            .await
            .expect("the rename from `name` applies without force");
        assert_eq!(values(&pool, "title").await, ["Alice", "Bob"]);
    })
    .await;
}

#[tokio::test]
async fn a_push_with_no_rename_records_none_and_the_list_shows_the_author() {
    common::with_integration_pool(|pool| async move {
        at(&pool, "name").await;
        let (by, via, _, verified, renames) = latest_audit(&pool).await;
        assert_eq!(by.as_deref(), Some(ADA));
        assert_eq!(via.as_deref(), Some("cli"));
        assert_eq!(verified, Some(false));
        assert_eq!(renames, None, "a push that renamed nothing records none");

        let listed = migration_history::list_migrations_summary(&pool)
            .await
            .unwrap();
        let row = serde_json::to_value(&listed[0]).unwrap();
        assert_eq!(row["pushedBy"], json!(ADA));
        assert_eq!(row["pushedVia"], json!("cli"));
        assert_eq!(row["pushedFrom"], json!("build-host"));
        assert_eq!(row["pushedByVerified"], json!(false));
    })
    .await;
}

#[test]
fn a_channel_outside_the_known_ones_is_refused_where_it_enters() {
    let request = |via: &str| serde_json::from_value::<DbRequest>(json!({ "pushed_via": via }));
    let err = request("email")
        .err()
        .expect("an unknown channel is refused");
    assert!(err.to_string().contains("self-host"), "{err}");
    let ok = request("self-host").expect("a known channel");
    assert_eq!(ok.audit.pushed_via, Some(PushChannel::SelfHost));
}

fn engine() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_supatype-engine"));
    cmd.env_remove("DATABASE_URL");
    cmd
}

/// What a control plane and the docker CLI pass the binary: the audit as flags, the journal in the
/// schema they push.
#[tokio::test]
async fn the_binary_records_the_audit_flags_and_the_journal_in_the_schema() {
    common::with_integration_url(|url| async move {
        let pool = PgPool::connect(&url).await.unwrap();
        at(&pool, "name").await;

        let doc = member_doc(
            json!({ "title": text() }),
            json!([entry("name", "title", ADA)]),
        );
        let input =
            std::env::temp_dir().join(format!("audit-ast-{}.json", common::ephemeral_name("f")));
        std::fs::write(&input, doc.to_string()).unwrap();
        let push = |extra: &[&str]| {
            engine()
                .args([
                    "--input",
                    input.to_str().unwrap(),
                    "push",
                    "--database-url",
                    &url,
                ])
                .arg("--non-interactive")
                .args(extra)
                .output()
                .expect("run the engine")
        };
        let refused = push(&["--pushed-via", "email"]);
        let out = push(&[
            "--pushed-by",
            "service_role",
            "--pushed-via",
            "self-host",
            "--pushed-from",
            "control-plane",
            "--pushed-by-verified",
        ]);
        let _ = std::fs::remove_file(&input);
        assert!(!refused.status.success(), "an unknown channel is refused");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );

        let (by, via, from, verified, renames) = latest_audit(&pool).await;
        assert_eq!(by.as_deref(), Some("service_role"));
        assert_eq!(via.as_deref(), Some("self-host"));
        assert_eq!(from.as_deref(), Some("control-plane"));
        assert_eq!(verified, Some(true));
        assert_eq!(renames.expect("recorded")[0]["declared_by"], json!(ADA));
        assert_eq!(values(&pool, "title").await, ["Alice", "Bob"]);
        pool.close().await;
    })
    .await;
}

/// A database bootstrapped by an engine from before the audit columns gets them: the bootstrap's
/// version is a fingerprint of its statements, so the new columns are a new version.
#[tokio::test]
async fn an_older_history_table_gains_the_audit_columns() {
    common::with_integration_pool(|pool| async move {
        exec(
            &pool,
            "CREATE SCHEMA _supatype;
             CREATE TABLE _supatype.migrations (
                 id SERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE, hash TEXT NOT NULL,
                 applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                 rolled_back BOOLEAN NOT NULL DEFAULT FALSE, engine_version TEXT NOT NULL)",
        )
        .await
        .unwrap();
        push_with(&pool, &with_column("name"), with_audit(ADA))
            .await
            .unwrap();
        let (by, ..) = latest_audit(&pool).await;
        assert_eq!(by.as_deref(), Some(ADA));
    })
    .await;
}

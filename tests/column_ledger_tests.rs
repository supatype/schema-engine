//! Phase 4.9 of the managed-object ownership plan: columns on the ledger (D4).
//!
//! A managed table's column set was authoritative: a column absent from the schema was dropped,
//! whoever added it. Each column the schema declares is a ledger row now, and the column differ
//! may drop only a column the ledger records. A column someone added to a managed table is never
//! the engine's and survives; declaring it adopts it. The column differ still makes every change
//! to a column the engine owns, because a column holds data that a drop and re-create would lose.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{
    introspector::fingerprint::ObjectKind,
    ledger::{self, reconcile::Action},
    parser,
    parser::ast::SchemaAst,
    push,
};

use common::{exec, push};

fn text() -> Value {
    json!({ "kind": "text", "annotations": { "db": { "pgType": "TEXT", "unique": false } } })
}

/// `posts` with an id, a title and the given extra fields, timestamps on.
fn posts(extra: Value) -> SchemaAst {
    let mut fields = json!({
        "id": { "kind": "integer", "primaryKey": true, "required": true,
                "annotations": { "db": { "pgType": "INTEGER", "unique": false } } },
        "title": text()
    });
    for (name, field) in extra.as_object().unwrap() {
        fields[name] = field.clone();
    }
    let doc = json!({
        "astVersion": 2,
        "models": [{
            "name": "Post",
            "fields": fields,
            "options": { "timestamps": true, "softDelete": false, "singleton": false },
            "annotations": { "db": { "tableName": "posts", "indexes": [] },
                             "platform": { "access": { "read": { "type": "public" } } } }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

fn forced() -> push::ApplyOptions {
    push::ApplyOptions {
        force: true,
        ..Default::default()
    }
}

async fn recorded(pool: &PgPool) -> Vec<String> {
    let mut conn = pool.acquire().await.unwrap();
    let mut names: Vec<String> = ledger::load(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.key.kind == ObjectKind::Column && r.key.parent == "posts")
        .map(|r| r.key.name)
        .collect();
    names.sort();
    names
}

async fn live_columns(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns
          WHERE table_schema = 'public' AND table_name = 'posts' ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

fn up_to_date(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::UpToDate { .. })
}

fn warned_about(outcome: &push::Outcome, needle: &str) -> bool {
    match outcome {
        push::Outcome::Applied { warnings, .. } | push::Outcome::UpToDate { warnings, .. } => {
            warnings.iter().any(|w| w.contains(needle))
        }
    }
}

#[tokio::test]
async fn every_column_the_schema_declares_is_recorded_option_columns_included() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts(json!({}))).await.unwrap();
        assert_eq!(live_columns(&pool).await, recorded(&pool).await);
        assert_eq!(
            recorded(&pool).await,
            ["created_at", "id", "title", "updated_at"]
        );
        assert!(up_to_date(&push(&pool, &posts(json!({}))).await.unwrap()));
    })
    .await;
}

#[tokio::test]
async fn a_column_someone_added_survives_and_declaring_it_adopts_it() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts(json!({}))).await.unwrap();
        exec(
            &pool,
            "ALTER TABLE public.posts ADD COLUMN notes text;
             INSERT INTO public.posts (id, title, notes) VALUES (1, 'a', 'mine');",
        )
        .await
        .unwrap();

        // Any push leaves it, and says why.
        let outcome = common::push_with(&pool, &posts(json!({})), forced())
            .await
            .unwrap();
        let notes: String = sqlx::query_scalar("SELECT notes FROM public.posts WHERE id = 1")
            .fetch_one(&pool)
            .await
            .expect("a column the engine never made was dropped");
        assert_eq!(notes, "mine");
        assert!(warned_about(&outcome, "\"posts\".\"notes\""), "{outcome:?}");
        assert!(!recorded(&pool).await.contains(&"notes".to_string()));

        // Declaring it adopts it: recorded, and nothing run against it.
        let declared = posts(json!({ "notes": text() }));
        let plan = push::prepare(&pool, &declared, "public").await.unwrap();
        let notes = plan
            .reconcile
            .actions
            .iter()
            .find(|a| a.key().kind == ObjectKind::Column && a.key().name == "notes")
            .cloned();
        assert!(
            matches!(notes, Some(Action::Adopt { .. })) && notes.as_ref().unwrap().sql().is_empty(),
            "{notes:?}"
        );
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap();
        assert!(recorded(&pool).await.contains(&"notes".to_string()));
    })
    .await;
}

#[tokio::test]
async fn a_declared_column_the_schema_drops_is_dropped() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts(json!({ "summary": text() })))
            .await
            .unwrap();
        assert!(recorded(&pool).await.contains(&"summary".to_string()));

        common::push_with(&pool, &posts(json!({})), forced())
            .await
            .unwrap();
        assert!(!live_columns(&pool).await.contains(&"summary".to_string()));
        assert!(!recorded(&pool).await.contains(&"summary".to_string()));
    })
    .await;
}

/// What an older engine left: its columns, and no rows. Until a push records them they are not
/// provably the engine's, so the first push after an upgrade leaves a column the schema dropped in
/// the same breath, and says so: the conservative direction, since a later push can drop it but
/// nothing can bring the data back.
#[tokio::test]
async fn an_upgrade_records_the_declared_columns_and_drops_nothing_unrecorded() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts(json!({ "summary": text() })))
            .await
            .unwrap();
        exec(
            &pool,
            "DELETE FROM _supatype.managed_objects WHERE kind = 'column'",
        )
        .await
        .unwrap();

        let outcome = common::push_with(&pool, &posts(json!({})), forced())
            .await
            .unwrap();
        assert!(live_columns(&pool).await.contains(&"summary".to_string()));
        assert!(
            warned_about(&outcome, "\"posts\".\"summary\""),
            "{outcome:?}"
        );
        assert_eq!(
            recorded(&pool).await,
            ["created_at", "id", "title", "updated_at"]
        );
    })
    .await;
}

/// A column released with `adopt --release` is the user's again: removing it from the schema and
/// forcing the push leaves it, as it leaves one Supatype never had.
#[tokio::test]
async fn a_released_column_is_never_dropped() {
    common::with_integration_pool(|pool| async move {
        let with_summary = posts(json!({ "summary": text() }));
        push(&pool, &with_summary).await.unwrap();
        let summary = ["column:posts.summary".to_string()];
        supatype_engine::adopt::run(
            &pool,
            &with_summary,
            "public",
            supatype_engine::adopt::Request {
                release: &summary,
                apply: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        common::push_with(&pool, &posts(json!({})), forced())
            .await
            .unwrap();
        assert!(live_columns(&pool).await.contains(&"summary".to_string()));
    })
    .await;
}

/// `timestamps` turned on for a table that predates it: the option's columns are added, with the
/// definition `CREATE TABLE` gives them, and recorded. One dropped by hand is put back the same way.
#[tokio::test]
async fn an_option_column_the_table_lacks_is_added() {
    common::with_integration_pool(|pool| async move {
        let mut plain = posts(json!({}));
        plain.models[0].options.timestamps = false;
        push(&pool, &plain).await.unwrap();
        exec(
            &pool,
            "INSERT INTO public.posts (id, title) VALUES (1, 'a')",
        )
        .await
        .unwrap();
        assert_eq!(recorded(&pool).await, ["id", "title"]);

        push(&pool, &posts(json!({}))).await.unwrap();
        assert_eq!(
            recorded(&pool).await,
            ["created_at", "id", "title", "updated_at"]
        );
        let filled: bool = sqlx::query_scalar(
            "SELECT created_at IS NOT NULL AND updated_at IS NOT NULL FROM public.posts",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(filled, "the existing row has no timestamps");
        assert!(up_to_date(&push(&pool, &posts(json!({}))).await.unwrap()));

        exec(&pool, "ALTER TABLE public.posts DROP COLUMN updated_at")
            .await
            .unwrap();
        push(&pool, &posts(json!({}))).await.unwrap();
        assert!(live_columns(&pool)
            .await
            .contains(&"updated_at".to_string()));
        assert!(up_to_date(&push(&pool, &posts(json!({}))).await.unwrap()));
    })
    .await;
}

/// A rename is a similarity guess, so only a column that is ours may be its source: one someone
/// added (`subtitel`) is not renamed into a declared one (`subtitle`), which is added beside it.
#[tokio::test]
async fn a_column_someone_added_is_never_renamed_into_a_declared_one() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts(json!({}))).await.unwrap();
        exec(
            &pool,
            "ALTER TABLE public.posts ADD COLUMN subtitel text;
             INSERT INTO public.posts (id, title, subtitel) VALUES (1, 'a', 'mine');",
        )
        .await
        .unwrap();

        let with_subtitle = posts(json!({ "subtitle": text() }));
        let plan = push::prepare(&pool, &with_subtitle, "public")
            .await
            .unwrap();
        assert!(
            !plan
                .diff
                .operations
                .iter()
                .any(|op| matches!(op, supatype_engine::differ::Operation::RenameColumn { .. })),
            "{:?}",
            plan.diff.operations
        );
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap();
        let columns = live_columns(&pool).await;
        assert!(columns.contains(&"subtitel".to_string()), "{columns:?}");
        assert!(columns.contains(&"subtitle".to_string()), "{columns:?}");
        assert!(!recorded(&pool).await.contains(&"subtitel".to_string()));

        // One of ours is still renamed.
        let renamed = posts(json!({ "sub_title": text() }));
        let plan = push::prepare(&pool, &renamed, "public").await.unwrap();
        assert!(
            plan.diff.operations.iter().any(|op| matches!(
                op,
                supatype_engine::differ::Operation::RenameColumn { from, to, .. }
                    if from == "subtitle" && to == "sub_title"
            )),
            "{:?}",
            plan.diff.operations
        );
    })
    .await;
}

/// A column the engine owns is changed in place by the column differ, with its data, and its row
/// follows.
#[tokio::test]
async fn an_owned_column_is_altered_in_place_and_keeps_its_data() {
    common::with_integration_pool(|pool| async move {
        let as_text = json!({ "rank": text() });
        push(&pool, &posts(as_text)).await.unwrap();
        exec(
            &pool,
            "INSERT INTO public.posts (id, title, rank) VALUES (1, 'a', '42')",
        )
        .await
        .unwrap();

        let as_integer = json!({ "rank": { "kind": "integer",
            "annotations": { "db": { "pgType": "INTEGER", "unique": false } } } });
        common::push_with(&pool, &posts(as_integer.clone()), forced())
            .await
            .unwrap();
        let rank: i32 = sqlx::query_scalar("SELECT rank FROM public.posts WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rank, 42, "the retype lost the data");
        assert!(up_to_date(&push(&pool, &posts(as_integer)).await.unwrap()));
    })
    .await;
}

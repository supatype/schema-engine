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
/// nothing can bring the data back. The last push's schema declared it, though, so that push
/// records it as ours, and the next one drops it.
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
            ["created_at", "id", "summary", "title", "updated_at"]
        );

        common::push_with(&pool, &posts(json!({})), forced())
            .await
            .unwrap();
        assert!(!live_columns(&pool).await.contains(&"summary".to_string()));
        assert_eq!(
            recorded(&pool).await,
            ["created_at", "id", "title", "updated_at"]
        );
    })
    .await;
}

/// The same upgrade, but the column was never the engine's: nothing the last push's schema
/// declared, so it is not recorded and no push ever drops it.
#[tokio::test]
async fn an_upgrade_records_no_column_no_schema_declared() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts(json!({}))).await.unwrap();
        exec(
            &pool,
            "ALTER TABLE public.posts ADD COLUMN notes text;
             DELETE FROM _supatype.managed_objects WHERE kind = 'column'",
        )
        .await
        .unwrap();
        for _ in 0..2 {
            common::push_with(&pool, &posts(json!({})), forced())
                .await
                .unwrap();
            assert!(live_columns(&pool).await.contains(&"notes".to_string()));
        }
        assert!(!recorded(&pool).await.contains(&"notes".to_string()));
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

/// A push whose only change is to a released column leaves it as it is and has nothing to do: no
/// type change, no migration recorded. A release-only adopt says it released, and a reclaim says
/// the next push asks before overwriting what changed while it was released.
#[tokio::test]
async fn a_change_to_a_released_column_is_left_and_records_nothing() {
    common::with_integration_pool(|pool| async move {
        let with_summary = posts(json!({ "summary": text() }));
        push(&pool, &with_summary).await.unwrap();
        let summary = ["column:posts.summary".to_string()];
        let released = supatype_engine::adopt::run(
            &pool,
            &with_summary,
            "public",
            supatype_engine::adopt::Request {
                release: &summary,
                apply: true,
                keys: Some(&[]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(released.status, "released");

        let migrations = || async {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM _supatype.migrations")
                .fetch_one(&pool)
                .await
                .unwrap()
        };
        let before = migrations().await;
        let narrowed = posts(json!({ "summary": { "kind": "text",
            "annotations": { "db": { "pgType": "VARCHAR(20)", "unique": false } } } }));
        let outcome = common::push_with(&pool, &narrowed, forced()).await.unwrap();
        assert!(up_to_date(&outcome), "{outcome:?}");
        assert!(warned_about(&outcome, "released column"), "{outcome:?}");
        assert_eq!(migrations().await, before);
        let kind: String = sqlx::query_scalar(
            "SELECT data_type FROM information_schema.columns
              WHERE table_name = 'posts' AND column_name = 'summary'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(kind, "text");

        let reclaimed = supatype_engine::adopt::run(
            &pool,
            &narrowed,
            "public",
            supatype_engine::adopt::Request {
                reclaim: &summary,
                apply: true,
                keys: Some(&[]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(reclaimed.status, "reclaimed");
        assert!(
            reclaimed.reclaim[0].message.contains("asks about first"),
            "{:?}",
            reclaimed.reclaim
        );
    })
    .await;
}

/// A column someone added that the schema does not declare can be adopted by name (#63): it is
/// recorded as adopted, kept by every push rather than dropped as an undeclared column of ours, and
/// its row stays while the column does. Adopting it is asked for by name only.
#[tokio::test]
async fn a_column_someone_added_can_be_adopted_and_is_kept() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!({}));
        push(&pool, &ast).await.unwrap();
        exec(&pool, "ALTER TABLE public.posts ADD COLUMN extra TEXT")
            .await
            .unwrap();

        // Not a conflict: adopting every conflict leaves it alone.
        supatype_engine::adopt::run(
            &pool,
            &ast,
            "public",
            supatype_engine::adopt::Request {
                apply: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(!recorded(&pool).await.contains(&"extra".to_string()));

        let extra = ["column:posts.extra".to_string()];
        let outcome = supatype_engine::adopt::run(
            &pool,
            &ast,
            "public",
            supatype_engine::adopt::Request {
                apply: true,
                keys: Some(&extra),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(outcome.adopt.len(), 1, "{:?}", outcome.adopt);
        let status: String = sqlx::query_scalar(
            "SELECT status FROM _supatype.managed_objects
              WHERE kind = 'column' AND parent = 'posts' AND name = 'extra'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(status, "adopted");

        let after = push(&pool, &ast).await.unwrap();
        assert!(up_to_date(&after), "{after:?}");
        assert!(live_columns(&pool).await.contains(&"extra".to_string()));
        assert!(recorded(&pool).await.contains(&"extra".to_string()));
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

/// Only a column that is ours may be a rename's source: one someone added (`subtitel`) is not
/// renamed into a declared one (`subtitle`), which is added beside it, and a declaration naming it
/// is refused. Renames are declared, never guessed from similar names (D1).
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

        // Declaring a rename from someone else's column is refused, naming it.
        let mut from_theirs = text();
        from_theirs["annotations"]["db"]["renamedFrom"] = json!("subtitel");
        let refused = push::prepare(&pool, &posts(json!({ "sub_title": from_theirs })), "public")
            .await
            .err()
            .expect("subtitel is not ours to rename");
        assert!(
            format!("{refused:#}").contains("\"subtitel\""),
            "{refused:#}"
        );

        // One of ours is still renamed, when the rename is declared.
        let mut declared = text();
        declared["annotations"]["db"]["renamedFrom"] = json!("subtitle");
        let renamed = posts(json!({ "sub_title": declared }));
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

/// 64 bytes: one past what Postgres keeps of a name.
const LONG_KEY: &str = "conference_attendee_registration_preferences_and_requirements_id";

/// `prefs`, and `diets` belonging to it through `key`, with a scalar field `extra` of its own.
fn diets_with_key(key: &str, extra: &str) -> SchemaAst {
    let pk = json!({ "kind": "uuid", "primaryKey": true, "required": true,
                     "default": { "kind": "genRandomUuid" } });
    let public = json!({ "access": { "read": { "type": "public" } } });
    let doc = json!({
        "astVersion": 2,
        "models": [{
            "name": "Prefs",
            "fields": { "id": pk.clone(), "label": text() },
            "options": { "timestamps": false, "softDelete": false },
            "annotations": { "db": { "tableName": "prefs", "indexes": [] }, "platform": public }
        }, {
            "name": "Diet",
            "fields": {
                "id": pk,
                "prefs": { "kind": "relation", "cardinality": "belongsTo", "target": "Prefs",
                           "onDelete": "cascade",
                           "annotations": { "db": { "foreignKey": key } } },
                extra: text()
            },
            "options": { "timestamps": false, "softDelete": false },
            "annotations": { "db": { "tableName": "diets", "indexes": [] }, "platform": public }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// A column name past 63 bytes is the name Postgres keeps, its first 63 bytes: the push records the
/// column under that name, and the next push finds it there and has nothing to do.
#[tokio::test]
async fn a_column_name_past_the_identifier_limit_is_recorded_as_postgres_keeps_it() {
    common::with_integration_pool(|pool| async move {
        let long_note = "dietary_notes_".repeat(5);
        let ast = diets_with_key(LONG_KEY, &long_note);
        let outcome = push(&pool, &ast).await.expect("the push applies");
        assert!(
            matches!(outcome, push::Outcome::Applied { .. }),
            "{outcome:?}"
        );
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));

        let mut conn = pool.acquire().await.unwrap();
        let mut recorded: Vec<String> = ledger::load(&mut conn)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.key.kind == ObjectKind::Column && r.key.parent == "diets")
            .map(|r| r.key.name)
            .collect();
        recorded.sort();
        let mut expected = vec![&LONG_KEY[..63], &long_note[..63], "id"];
        expected.sort();
        assert_eq!(recorded, expected);
    })
    .await;
}

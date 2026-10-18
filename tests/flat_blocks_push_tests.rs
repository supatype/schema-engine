//! A push moves block entries still in the flat shape (`{ type, meta?, ...fields }`, before 0.7.0)
//! to `{ type, data, meta? }`, in the live table and in every snapshot of a versioned model.
//!
//! The schema is kitchen-sink's `Page` as the CLI sends it (`hero`, `prose` and `speakerGrid`, with
//! localized strings and a `Localized<RichText>`, `versions: { drafts: true }`), and a `Section`
//! model without versions holding a `Blocks` column and a `Localized<Blocks>` one. The expected
//! shapes are the ones `examples/kitchen-sink/seed.ts` writes and UPGRADING.md's manual move makes.

mod common;

use common::{exec, with_integration_pool};
use serde_json::{json, Value};
use supatype_engine::parser::{self, ast::SchemaAst};
use supatype_engine::push::{self, Outcome};

fn schema() -> SchemaAst {
    parser::parse(include_str!("fixtures/flat_blocks.json")).expect("fixture parses")
}

fn expected() -> Value {
    serde_json::from_str(include_str!("fixtures/flat_blocks_expected.json")).expect("expected")
}

/// Kitchen-sink's home page as rows saved before 0.7.0 hold it, and a page mixing entries already
/// moved with flat ones in every shape a field can be in.
const HOME: &str = r#"[
  {"type": "hero", "heading": "Kitchen Sink Conference",
   "subheading": "One schema, two front ends, every feature that ships.",
   "cta": {"label": "See the talks", "href": "/talks", "target": "_self"}},
  {"type": "prose", "body": "Two days of people explaining how their database is laid out. Catering is adequate."},
  {"type": "speakerGrid", "heading": "Speaking", "limit": 6, "meta": {"anchor": "speakers"}}
]"#;

const MIXED: &str = r#"[
  {"type": "hero", "data": {"heading": {"en": "Kitchen Sink Conference", "fr": "La conférence évier de cuisine"}}},
  {"type": "hero", "heading": {"en": "Already a map"}, "subheading": null},
  {"type": "prose", "body": {"root": {"type": "root", "version": 1, "direction": null, "format": "", "indent": 0, "children": []}}},
  {"type": "prose", "body": {"en": "A map of plain text"}}
]"#;

/// Pushes the schema, then writes `home` and `mixed` pages and two snapshots of `home`, as a
/// project that saved them before upgrading has them.
async fn flat_pages(pool: &sqlx::PgPool) {
    common::push(pool, &schema()).await.expect("first push");
    for (slug, body) in [("home", HOME), ("mixed", MIXED)] {
        sqlx::query(
            "INSERT INTO page (title, slug, body) VALUES (jsonb_build_object('en', $1::text), $1, $2::jsonb)",
        )
        .bind(slug)
        .bind(body)
        .execute(pool)
        .await
        .expect("seed a page");
    }
    for status in ["published", "draft"] {
        sqlx::query(
            "INSERT INTO page_versions (record_id, status, data) \
             SELECT id, $1, to_jsonb(p) FROM page p WHERE slug = 'home'",
        )
        .bind(status)
        .execute(pool)
        .await
        .expect("seed a snapshot");
    }
}

async fn bodies(pool: &sqlx::PgPool) -> Value {
    let (pages,): (Value,) = sqlx::query_as("SELECT jsonb_object_agg(slug, body) FROM page")
        .fetch_one(pool)
        .await
        .expect("read pages");
    pages
}

async fn snapshot_bodies(pool: &sqlx::PgPool) -> Vec<Value> {
    let rows: Vec<(Value,)> =
        sqlx::query_as("SELECT data -> 'body' FROM page_versions ORDER BY version")
            .fetch_all(pool)
            .await
            .expect("read snapshots");
    rows.into_iter().map(|(v,)| v).collect()
}

fn warnings(outcome: &Outcome) -> Vec<String> {
    let json = outcome.to_json();
    serde_json::from_value(json["warnings"].clone()).expect("warnings are strings")
}

async fn last_sql_up(pool: &sqlx::PgPool) -> String {
    let (sql,): (String,) =
        sqlx::query_as("SELECT sql_up FROM _supatype.migrations ORDER BY id DESC LIMIT 1")
            .fetch_one(pool)
            .await
            .expect("read the history");
    sql
}

/// The kitchen-sink page and both its snapshots come out in the shapes `seed.ts` writes, the push
/// says how many entries it moved, and the history records it.
#[tokio::test]
async fn a_push_moves_flat_kitchen_sink_pages_and_their_snapshots() {
    with_integration_pool(|pool| async move {
        flat_pages(&pool).await;
        let outcome = common::push(&pool, &schema()).await.expect("push");

        let expected = expected();
        assert_eq!(bodies(&pool).await["home"], expected["home"]);
        assert_eq!(bodies(&pool).await["mixed"], expected["mixed"]);
        assert_eq!(
            snapshot_bodies(&pool).await,
            vec![expected["home"].clone(), expected["home"].clone()],
            "every snapshot is moved, not only the newest"
        );
        let said = "Converted 6 block entries in page.body (2 version rows)";
        assert!(
            warnings(&outcome).iter().any(|w| w == said),
            "{:?}",
            warnings(&outcome)
        );
        let recorded = last_sql_up(&pool).await;
        assert!(recorded.contains(&format!("-- {said}")), "{recorded}");
        assert!(
            recorded.contains("UPDATE \"public\".\"page_versions\""),
            "{recorded}"
        );
    })
    .await;
}

/// The snapshot table's guard is back on once the push has moved its rows: an update of a
/// version's `data` still changes nothing.
#[tokio::test]
async fn the_snapshot_guard_is_on_again_after_the_move() {
    with_integration_pool(|pool| async move {
        flat_pages(&pool).await;
        common::push(&pool, &schema()).await.expect("push");

        exec(
            &pool,
            "UPDATE page_versions SET data = '{\"body\": []}' WHERE TRUE",
        )
        .await
        .expect("update snapshots");
        let home = expected()["home"].clone();
        assert_eq!(snapshot_bodies(&pool).await, vec![home.clone(), home]);
    })
    .await;
}

/// A second push finds nothing to move and is up to date, and touches no row.
#[tokio::test]
async fn a_second_push_changes_nothing() {
    with_integration_pool(|pool| async move {
        flat_pages(&pool).await;
        common::push(&pool, &schema()).await.expect("push");
        let before: Vec<(String,)> = sqlx::query_as("SELECT xmin::text FROM page ORDER BY slug")
            .fetch_all(&pool)
            .await
            .expect("xmin");

        let again = common::push(&pool, &schema()).await.expect("second push");
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");
        let after: Vec<(String,)> = sqlx::query_as("SELECT xmin::text FROM page ORDER BY slug")
            .fetch_all(&pool)
            .await
            .expect("xmin");
        assert_eq!(before, after, "no row was rewritten");
        assert_eq!(bodies(&pool).await["home"], expected()["home"]);
    })
    .await;
}

/// The plan `supatype diff` prints says what a push would move, and moves nothing itself.
#[tokio::test]
async fn the_plan_shows_the_pending_conversion() {
    with_integration_pool(|pool| async move {
        flat_pages(&pool).await;
        let ast = schema();
        let plan = push::plan(&pool, &ast, "public").await.expect("plan");
        let json = plan.to_json().expect("plan json");

        assert_eq!(
            json["blockConversions"],
            json!([{ "table": "page", "column": "body", "entries": 6, "versionRows": 2 }])
        );
        let warnings: Vec<String> = serde_json::from_value(json["warnings"].clone()).unwrap();
        assert!(
            warnings.iter().any(
                |w| w.starts_with("Will convert 6 block entries in page.body (2 version rows)")
            ),
            "{warnings:?}"
        );
        let file = plan.migration(false).expect("migration").file();
        assert!(file.contains("UPDATE \"public\".\"page\" AS t"), "{file}");
        assert!(
            file.contains("UPDATE \"public\".\"page_versions\" AS t"),
            "{file}"
        );
        let home: Value = serde_json::from_str(HOME).unwrap();
        assert_eq!(bodies(&pool).await["home"], home, "planning wrote nothing");
    })
    .await;
}

/// `section` has no versions. Each row is one case: SQL NULL, JSON null, an empty array, a block
/// type the schema does not declare, values that are not objects, a flat entry beside one already
/// moved, and an entry edited in Studio while flat (`data` and the old field beside it).
const SECTIONS: &[(i32, Option<&str>)] = &[
    (1, None),
    (2, Some("null")),
    (3, Some("[]")),
    (4, Some(r#"[{"type": "video", "url": "/v.mp4"}]"#)),
    (5, Some(r#"["text", 42]"#)),
    (
        6,
        Some(
            r#"[{"type": "hero", "heading": "Hi"}, {"type": "speakerGrid", "data": {"limit": 3}}]"#,
        ),
    ),
    (
        7,
        Some(r#"[{"type": "hero", "heading": "Old", "data": {"heading": {"en": "New"}}}]"#),
    ),
    (
        8,
        Some(r#"[{"type": "speakerGrid", "data": {"limit": 3}}]"#),
    ),
];

async fn seed_sections(pool: &sqlx::PgPool) {
    common::push(pool, &schema()).await.expect("first push");
    for (id, body) in SECTIONS {
        sqlx::query("INSERT INTO section (id, body) VALUES ($1::text::uuid, $2::jsonb)")
            .bind(format!("00000000-0000-0000-0000-00000000000{id}"))
            .bind(*body)
            .execute(pool)
            .await
            .expect("seed a section");
    }
}

async fn section_bodies(pool: &sqlx::PgPool) -> Vec<(Option<Value>, String)> {
    sqlx::query_as("SELECT body, xmin::text FROM section ORDER BY id")
        .fetch_all(pool)
        .await
        .expect("read sections")
}

/// Only the flat entry naming a declared block is moved. Everything else is kept as it was, the
/// rows holding nothing to move are not rewritten, and what was left is said.
#[tokio::test]
async fn only_flat_entries_of_declared_blocks_are_moved() {
    with_integration_pool(|pool| async move {
        seed_sections(&pool).await;
        let before = section_bodies(&pool).await;
        let outcome = common::push(&pool, &schema()).await.expect("push");
        let after = section_bodies(&pool).await;

        let moved = json!([
            {"type": "hero", "data": {"heading": {"en": "Hi"}}},
            {"type": "speakerGrid", "data": {"limit": 3}}
        ]);
        for (i, ((was, was_xmin), (is, is_xmin))) in before.iter().zip(&after).enumerate() {
            if i == 5 {
                assert_eq!(is.as_ref(), Some(&moved));
            } else {
                assert_eq!(is, was, "row {} is kept", i + 1);
                assert_eq!(is_xmin, was_xmin, "row {} is not rewritten", i + 1);
            }
        }
        let said = warnings(&outcome);
        for line in [
            "Converted 1 block entry in section.body",
            "Left as stored in section.body: 3 block entries, each not an object",
            "Left as stored in section.body: 1 block entry with `data` and fields beside it",
        ] {
            assert!(said.iter().any(|w| w.starts_with(line)), "{line}: {said:?}");
        }
    })
    .await;
}

/// A `Localized<Blocks>` column holds one array per locale, and each locale's flat entries move.
#[tokio::test]
async fn each_locale_of_localized_blocks_is_moved() {
    with_integration_pool(|pool| async move {
        common::push(&pool, &schema()).await.expect("first push");
        exec(
            &pool,
            r#"INSERT INTO section (id, "localizedBody") VALUES (gen_random_uuid(),
               '{"en": [{"type": "prose", "body": "Hello"}], "fr": [{"type": "hero", "data": {"heading": {"fr": "Salut"}}}]}')"#,
        )
        .await
        .expect("seed");
        common::push(&pool, &schema()).await.expect("push");

        let (value,): (Value,) = sqlx::query_as(r#"SELECT "localizedBody" FROM section"#)
            .fetch_one(&pool)
            .await
            .expect("read");
        let text = &value["en"][0]["data"]["body"]["en"]["root"]["children"][0]["children"][0];
        assert_eq!(text["text"], "Hello", "{value}");
        assert_eq!(value["fr"][0]["data"]["heading"]["fr"], "Salut", "{value}");
    })
    .await;
}

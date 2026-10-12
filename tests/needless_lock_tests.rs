//! A push takes no table lock it does not need (LK7).
//!
//! ENG-LOCK bounded every lock a push waits for to 3 s, but some pushes still took ACCESS
//! EXCLUSIVE on tables they did not change: the versions layer dropped and made again its policies
//! and triggers, and turned row-level security on, on every push; tier 2's `api` views were made
//! again on every push; a unique constraint built its index under that lock; `SET NOT NULL`
//! scanned the table under it; and an index replaced, put back or rolled back was dropped and
//! built inside the transaction. Each test here watches `pg_locks` from another session while an
//! application writes, as `online_ddl_tests` does.

mod common;

use std::collections::BTreeSet;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::push::{ApplyOptions, Outcome};
use supatype_engine::{parser, parser::ast::SchemaAst, state::migration_history};

use common::locks::{App, LockSampler};
use common::{exec, push, push_with};

const ACCESS_SHARE: &str = "AccessShareLock";

fn uuid_pk() -> Value {
    json!({ "kind": "uuid", "primaryKey": true, "required": true,
            "default": { "kind": "genRandomUuid" },
            "annotations": { "db": { "pgType": "UUID", "unique": false, "index": false } } })
}

fn text(required: bool, unique: bool) -> Value {
    json!({ "kind": "text", "required": required,
            "annotations": { "db": { "pgType": "TEXT", "unique": unique, "index": false } } })
}

fn integer() -> Value {
    json!({ "kind": "integer", "required": false,
            "annotations": { "db": { "pgType": "INTEGER" } } })
}

fn plain_model(name: &str, table: &str, fields: Value, indexes: Value, options: Value) -> Value {
    json!({ "name": name, "fields": fields, "options": options,
            "annotations": { "db": { "tableName": table, "indexes": indexes },
                             "platform": { "access": {} } } })
}

fn versioned(name: &str, table: &str, drafts: bool) -> Value {
    plain_model(
        name,
        table,
        json!({ "id": uuid_pk(), "title": text(true, false) }),
        json!([]),
        json!({ "timestamps": false, "softDelete": false,
                "versions": { "drafts": drafts, "keep": 5 } }),
    )
}

fn publishing_schema(models: Vec<Value>) -> SchemaAst {
    let doc = json!({
        "astVersion": 2,
        "locales": ["en"],
        "defaultLocale": "en",
        "publishing": {
            "draftVisibility": ["admin", "developer", "editor"],
            "previewDefaultTtl": 900,
            "previewMaxRecordTtl": 604800,
            "previewMaxProjectTtl": 86400,
            "previewAllowProjectScope": true
        },
        "models": models
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

fn tag_model() -> Value {
    plain_model(
        "Tag",
        "tags",
        json!({ "id": uuid_pk(), "label": text(false, false) }),
        json!([]),
        json!({ "timestamps": false, "softDelete": false }),
    )
}

/// `posts` publishing through drafts and `notes` keeping history, and `tags` when `with_tags`.
fn versioned_schema(with_tags: bool) -> SchemaAst {
    let mut models = vec![
        versioned("Post", "posts", true),
        versioned("Note", "notes", false),
    ];
    if with_tags {
        models.push(tag_model());
    }
    publishing_schema(models)
}

const VERSIONED_RELATIONS: &[&str] = &[
    "public.posts",
    "public.posts_versions",
    "public.notes",
    "public.notes_versions",
    "draft.posts",
];

/// The locks seen that are stronger than ACCESS SHARE.
fn stronger_than_access_share(seen: &BTreeSet<(String, String)>) -> Vec<&(String, String)> {
    seen.iter()
        .filter(|(_, mode)| mode != ACCESS_SHARE)
        .collect()
}

/// Pushes `ast` while an application writes to `posts` and `notes`, returning the outcome and
/// every lock another session held on `relations` meanwhile.
async fn push_watched(
    pool: &PgPool,
    ast: &SchemaAst,
    relations: &[&str],
    app_statements: &[&str],
) -> (Outcome, BTreeSet<(String, String)>) {
    let app = App::start(pool, app_statements).await;
    let locks = LockSampler::start_qualified(pool, relations, vec![app.pid]).await;
    let outcome = push(pool, ast).await.expect("the push applies");
    let seen = locks.finish().await;
    app.finish().await;
    (outcome, seen)
}

const VERSIONED_APP: &[&str] = &[
    "INSERT INTO public.notes (title) VALUES ('note')",
    "SELECT count(*) FROM public.posts",
];

/// LK7: a push with nothing to change re-asserts the versions layer without dropping and making
/// again its policies and triggers or turning on row-level security that is on: it takes nothing
/// stronger than ACCESS SHARE on the versioned tables, their history tables and the draft view.
#[tokio::test(flavor = "multi_thread")]
async fn an_up_to_date_push_of_a_versioned_schema_takes_nothing_stronger_than_access_share() {
    common::with_integration_pool(|pool| async move {
        let ast = versioned_schema(false);
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            "INSERT INTO public.posts (title) VALUES ('a'), ('b');",
        )
        .await
        .unwrap();

        let (outcome, seen) = push_watched(&pool, &ast, VERSIONED_RELATIONS, VERSIONED_APP).await;
        assert!(matches!(outcome, Outcome::UpToDate { .. }), "{outcome:?}");
        let strong = stronger_than_access_share(&seen);
        assert!(strong.is_empty(), "an up-to-date push locked {strong:?}");
    })
    .await;
}

/// LK7: a push that only adds a table leaves the versioned tables and their draft view alone.
#[tokio::test(flavor = "multi_thread")]
async fn a_push_that_adds_another_table_leaves_the_versioned_tables_alone() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &versioned_schema(false)).await.unwrap();
        let draft_view = relation_oid(&pool, "draft.posts").await;

        let (outcome, seen) = push_watched(
            &pool,
            &versioned_schema(true),
            VERSIONED_RELATIONS,
            VERSIONED_APP,
        )
        .await;
        assert!(matches!(outcome, Outcome::Applied { .. }), "{outcome:?}");
        let strong = stronger_than_access_share(&seen);
        assert!(strong.is_empty(), "adding a table locked {strong:?}");
        assert_eq!(relation_oid(&pool, "draft.posts").await, draft_view);

        // Settled, and the layer still works: a draft saved through the function is readable.
        let again = push(&pool, &versioned_schema(true)).await.unwrap();
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");
        exec(&pool, "INSERT INTO public.notes (title) VALUES ('kept')")
            .await
            .unwrap();
        let history: i64 = sqlx::query_scalar("SELECT count(*) FROM public.notes_versions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(history >= 1, "the audit trigger still records history");
    })
    .await;
}

/// LK7: a policy of the layer changed by hand is still put back (drift), and a field added to a
/// versioned model still remakes its draft view, so skipping what is settled skips nothing else.
#[tokio::test(flavor = "multi_thread")]
async fn what_changed_in_the_versions_layer_is_still_made_again() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &versioned_schema(false)).await.unwrap();
        exec(
            &pool,
            "DROP POLICY posts_versions_select ON public.posts_versions;
             DROP TRIGGER notes_versions_audit ON public.notes;",
        )
        .await
        .unwrap();
        let outcome = push_with(
            &pool,
            &versioned_schema(false),
            ApplyOptions {
                overwrite_drift: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(matches!(outcome, Outcome::Applied { .. }), "{outcome:?}");
        let policy: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_policy WHERE polname = 'posts_versions_select')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(policy, "the dropped policy was made again");
        let trigger: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'notes_versions_audit')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(trigger, "the dropped trigger was made again");

        let mut wider = versioned("Post", "posts", true);
        wider["fields"]["body"] = text(false, false);
        let ast = publishing_schema(vec![wider, versioned("Note", "notes", false)]);
        let outcome = push(&pool, &ast).await.unwrap();
        assert!(matches!(outcome, Outcome::Applied { .. }), "{outcome:?}");
        let columns: Vec<String> = sqlx::query_scalar(
            "SELECT attname::text FROM pg_attribute
              WHERE attrelid = 'draft.posts'::regclass AND attnum > 0 ORDER BY attnum",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(columns.contains(&"body".to_string()), "{columns:?}");
        let again = push(&pool, &ast).await.unwrap();
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}

async fn relation_oid(pool: &PgPool, relation: &str) -> Option<i64> {
    sqlx::query_scalar("SELECT to_regclass($1)::oid::bigint")
        .bind(relation)
        .fetch_one(pool)
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------------------------
// Tier 2: the `api` views
// ---------------------------------------------------------------------------------------------

/// The API roles and the auth helpers, as a provisioned database has them, without
/// `supatype_mask`, so a push picks tier 2.
async fn tier_two(pool: &PgPool) {
    exec(
        pool,
        "CREATE SCHEMA IF NOT EXISTS auth;
         DO $$ BEGIN
           BEGIN CREATE ROLE anon NOLOGIN NOINHERIT;
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
           BEGIN CREATE ROLE authenticated NOLOGIN NOINHERIT;
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
           BEGIN CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS;
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
         END $$;",
    )
    .await
    .expect("roles and auth schema");
    exec(
        pool,
        &supatype_engine::generator::sql::rls::generate_auth_helpers(),
    )
    .await
    .expect("auth helpers");
}

fn masked_schema(with_tags: bool) -> SchemaAst {
    let staff = json!({
        "name": "Staff",
        "fields": { "id": uuid_pk(), "name": text(true, false), "salary": integer() },
        "options": { "timestamps": false, "softDelete": false },
        "annotations": {
            "db": { "tableName": "staff", "indexes": [] },
            "platform": { "access": {
                "read": { "type": "authenticated" },
                "create": { "type": "role", "roles": ["admin"] },
                "update": { "type": "role", "roles": ["admin"] },
                "delete": { "type": "role", "roles": ["admin"] },
                "fields": { "salary": { "read": { "type": "role", "roles": ["admin"] } } }
            } }
        }
    });
    let mut models = vec![staff];
    if with_tags {
        models.push(tag_model());
    }
    let doc = json!({ "astVersion": 2, "models": models });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// LK7: under tier 2, a push that adds a table leaves the `api` view of a table it does not change
/// as it is: not dropped and made again, and not locked beyond ACCESS SHARE.
#[tokio::test(flavor = "multi_thread")]
async fn a_tier_two_push_that_adds_another_table_leaves_the_api_views_alone() {
    common::with_integration_pool(|pool| async move {
        tier_two(&pool).await;
        push(&pool, &masked_schema(false)).await.unwrap();
        let view = relation_oid(&pool, "api.staff").await;
        assert!(view.is_some(), "tier 2 made the api view");

        let (outcome, seen) = push_watched(
            &pool,
            &masked_schema(true),
            &["api.staff", "public.staff"],
            &["SELECT count(*) FROM api.staff"],
        )
        .await;
        assert!(matches!(outcome, Outcome::Applied { .. }), "{outcome:?}");
        let strong = stronger_than_access_share(&seen);
        assert!(strong.is_empty(), "adding a table locked {strong:?}");
        assert_eq!(relation_oid(&pool, "api.staff").await, view);
        assert!(relation_oid(&pool, "api.tags").await.is_some());
        let again = push(&pool, &masked_schema(true)).await.unwrap();
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// A table with rows: unique constraints, NOT NULL and index rebuilds
// ---------------------------------------------------------------------------------------------

/// What the schema says about `items.label`.
#[derive(Clone, Copy, Default)]
struct Label {
    required: bool,
    unique: bool,
    /// An index on it: `Some(method)`.
    index: Option<&'static str>,
}

fn items(label: Label) -> SchemaAst {
    let indexes = match label.index {
        Some(using) => json!([{ "fields": ["label"], "unique": false, "using": using }]),
        None => json!([]),
    };
    let model = plain_model(
        "Item",
        "items",
        json!({ "id": uuid_pk(), "label": text(label.required, label.unique), "qty": integer() }),
        indexes,
        json!({ "timestamps": false, "softDelete": false }),
    );
    let doc = json!({ "astVersion": 2, "models": [model] });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// `rows` items, each with a distinct label, analysed.
async fn fill(pool: &PgPool, rows: u32) {
    exec(
        pool,
        &format!(
            "INSERT INTO public.items (label, qty)
             SELECT md5(i::text), i FROM generate_series(1, {rows}) AS i;
             ANALYZE public.items;"
        ),
    )
    .await
    .expect("fill the table");
}

const ITEMS_APP: &[&str] = &[
    "INSERT INTO public.items (label, qty) VALUES (md5(random()::text), 1)",
    "SELECT count(*) FROM public.items WHERE qty = 7",
];

/// Pushes `ast` on a table of 200k rows while the application writes, returning what was locked.
async fn push_items_watched(pool: &PgPool, ast: &SchemaAst) -> BTreeSet<(String, String)> {
    let (outcome, seen) = push_watched(pool, ast, &["public.items"], ITEMS_APP).await;
    assert!(matches!(outcome, Outcome::Applied { .. }), "{outcome:?}");
    seen
}

fn saw(seen: &BTreeSet<(String, String)>, mode: &str) -> bool {
    seen.iter().any(|(_, m)| m == mode)
}

async fn invalid_indexes(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM pg_index WHERE NOT indisvalid")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// LK7: a unique constraint added to a table with rows has its index built concurrently after
/// commit and attached with `ADD CONSTRAINT ... UNIQUE USING INDEX`, so the build never holds a
/// lock that stops reads or writes. The constraint is recorded, and the next push changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_unique_constraint_on_a_table_with_rows_builds_its_index_concurrently() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &items(Label::default())).await.unwrap();
        fill(&pool, 200_000).await;
        let target = items(Label {
            unique: true,
            ..Label::default()
        });

        let seen = push_items_watched(&pool, &target).await;
        eprintln!("locks seen on items: {seen:?}");
        assert!(
            !saw(&seen, "ShareLock"),
            "built under a write lock: {seen:?}"
        );
        let ran = last_migration(&pool).await;
        let after = ran
            .split_once("-- After the transaction")
            .map(|(_, after)| after)
            .unwrap_or_else(|| panic!("nothing ran after commit: {ran}"));
        assert!(after.contains("CREATE UNIQUE INDEX CONCURRENTLY"), "{ran}");
        assert!(after.contains("UNIQUE USING INDEX"), "{ran}");
        let unique: Option<String> = sqlx::query_scalar(
            "SELECT conname::text FROM pg_constraint
              WHERE conrelid = 'public.items'::regclass AND contype = 'u'",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();
        let name = unique.expect("the unique constraint is in place");
        let recorded: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM _supatype.managed_objects
                             WHERE kind = 'unique' AND name = $1)",
        )
        .bind(&name)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(recorded, "{name} is on the ledger");
        assert_eq!(invalid_indexes(&pool).await, 0);
        let again = push(&pool, &target).await.unwrap();
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}

/// LK7: a unique constraint the rows break leaves nothing behind and fails the push saying so.
#[tokio::test(flavor = "multi_thread")]
async fn a_unique_constraint_the_rows_break_leaves_no_index_behind() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &items(Label::default())).await.unwrap();
        fill(&pool, 1_000).await;
        exec(
            &pool,
            "UPDATE public.items SET label = 'same' WHERE qty <= 2",
        )
        .await
        .unwrap();
        let target = items(Label {
            unique: true,
            ..Label::default()
        });
        let err = push(&pool, &target).await.expect_err("the rows break it");
        let message = format!("{err:#}");
        assert!(message.contains("could not be"), "{message}");
        assert_eq!(invalid_indexes(&pool).await, 0, "{message}");
        let indexes: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_index WHERE indrelid = 'public.items'::regclass",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(indexes, 1, "only the primary key's index is left");

        exec(
            &pool,
            "UPDATE public.items SET label = md5(qty::text) WHERE qty <= 2",
        )
        .await
        .unwrap();
        let outcome = push(&pool, &target).await.unwrap();
        assert!(matches!(outcome, Outcome::Applied { .. }), "{outcome:?}");
        let again = push(&pool, &target).await.unwrap();
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}

/// LK7: `SET NOT NULL` on a table with rows is proved by a `CHECK (... IS NOT NULL)` added NOT
/// VALID and validated after commit, under a lock that lets writes through, so Postgres skips its
/// own scan under ACCESS EXCLUSIVE; the helper check is dropped once the column is NOT NULL.
#[tokio::test(flavor = "multi_thread")]
async fn set_not_null_on_a_table_with_rows_scans_without_stopping_writes() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &items(Label::default())).await.unwrap();
        fill(&pool, 200_000).await;
        let target = items(Label {
            required: true,
            ..Label::default()
        });

        let seen = push_items_watched(&pool, &target).await;
        eprintln!("locks seen on items: {seen:?}");
        // Read off what the push ran, since a validation of 200k rows can finish between two
        // samples: the check is added NOT VALID in the transaction, and `SET NOT NULL` runs after.
        let ran = last_migration(&pool).await;
        let (in_transaction, after) = ran
            .split_once("-- After the transaction")
            .unwrap_or_else(|| panic!("nothing ran after commit: {ran}"));
        assert!(!in_transaction.contains("SET NOT NULL"), "{ran}");
        assert!(in_transaction.contains("IS NOT NULL) NOT VALID"), "{ran}");
        assert!(after.contains("VALIDATE CONSTRAINT"), "{ran}");
        assert!(after.contains("SET NOT NULL"), "{ran}");
        let not_null: bool = sqlx::query_scalar(
            "SELECT attnotnull FROM pg_attribute
              WHERE attrelid = 'public.items'::regclass AND attname = 'label'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(not_null, "label is NOT NULL");
        let checks: Vec<String> = sqlx::query_scalar(
            "SELECT conname::text FROM pg_constraint
              WHERE conrelid = 'public.items'::regclass AND contype = 'c'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(checks.is_empty(), "the helper check is gone: {checks:?}");
        let again = push(&pool, &target).await.unwrap();
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}

/// LK7: a NULL in the column fails `SET NOT NULL` before anything is applied, as before.
#[tokio::test(flavor = "multi_thread")]
async fn set_not_null_with_a_null_row_is_refused() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &items(Label::default())).await.unwrap();
        fill(&pool, 1_000).await;
        exec(&pool, "UPDATE public.items SET label = NULL WHERE qty = 5")
            .await
            .unwrap();
        let target = items(Label {
            required: true,
            ..Label::default()
        });
        let err = push(&pool, &target).await.expect_err("a NULL row");
        assert!(format!("{err:#}").contains("NULL"), "{err:#}");
        let checks: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_constraint
              WHERE conrelid = 'public.items'::regclass AND contype = 'c'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(checks, 0, "no helper check is left behind");
    })
    .await;
}

/// What the last push recorded that it ran: the migration, then what ran after its commit.
async fn last_migration(pool: &PgPool) -> String {
    sqlx::query_scalar("SELECT sql_up FROM _supatype.migrations ORDER BY id DESC LIMIT 1")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn label_index(pool: &PgPool) -> Option<(String, String)> {
    sqlx::query_as(
        "SELECT c.relname::text, am.amname::text FROM pg_index i
           JOIN pg_class c ON c.oid = i.indexrelid
           JOIN pg_am am ON am.oid = c.relam
          WHERE i.indrelid = 'public.items'::regclass AND NOT i.indisprimary AND i.indisvalid",
    )
    .fetch_optional(pool)
    .await
    .unwrap()
}

/// LK7: an index whose definition changes on a table with rows is built again concurrently under
/// a temporary name, the old one dropped concurrently and the new one renamed into place, so
/// neither the build nor the drop stops writes.
#[tokio::test(flavor = "multi_thread")]
async fn an_index_replaced_on_a_table_with_rows_is_rebuilt_concurrently() {
    common::with_integration_pool(|pool| async move {
        let before = items(Label {
            index: Some("btree"),
            ..Label::default()
        });
        push(&pool, &before).await.unwrap();
        fill(&pool, 200_000).await;
        let (name, _) = label_index(&pool).await.expect("the index is built");

        let target = items(Label {
            index: Some("brin"),
            ..Label::default()
        });
        let seen = push_items_watched(&pool, &target).await;
        eprintln!("locks seen on items: {seen:?}");
        assert!(
            !saw(&seen, "ShareLock"),
            "built under a write lock: {seen:?}"
        );
        assert!(
            !saw(&seen, "AccessExclusiveLock"),
            "dropped under ACCESS EXCLUSIVE: {seen:?}"
        );
        assert_eq!(label_index(&pool).await, Some((name, "brin".to_string())));
        assert_eq!(invalid_indexes(&pool).await, 0);
        let again = push(&pool, &target).await.unwrap();
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}

/// LK7: an index of ours dropped by hand on a table with rows is put back concurrently.
#[tokio::test(flavor = "multi_thread")]
async fn an_index_changed_by_hand_is_put_back_concurrently() {
    common::with_integration_pool(|pool| async move {
        let target = items(Label {
            index: Some("btree"),
            ..Label::default()
        });
        push(&pool, &target).await.unwrap();
        fill(&pool, 200_000).await;
        let (name, _) = label_index(&pool).await.expect("the index is built");
        exec(
            &pool,
            &format!(
                "DROP INDEX public.\"{name}\";
                 CREATE INDEX \"{name}\" ON public.items USING brin (label);"
            ),
        )
        .await
        .unwrap();

        let seen = push_items_watched(&pool, &target).await;
        eprintln!("locks seen on items: {seen:?}");
        assert!(
            !saw(&seen, "ShareLock"),
            "built under a write lock: {seen:?}"
        );
        assert!(!saw(&seen, "AccessExclusiveLock"), "{seen:?}");
        assert_eq!(label_index(&pool).await, Some((name, "btree".to_string())));
    })
    .await;
}

/// LK7: rolling back a push that built an index on a table with rows drops it concurrently, after
/// the rollback's transaction, so the drop does not stop the table's reads and writes.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_drops_an_index_concurrently() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &items(Label::default())).await.unwrap();
        fill(&pool, 200_000).await;
        push(
            &pool,
            &items(Label {
                index: Some("btree"),
                ..Label::default()
            }),
        )
        .await
        .unwrap();
        assert!(label_index(&pool).await.is_some());

        let app = App::start(&pool, ITEMS_APP).await;
        let locks = LockSampler::start_qualified(&pool, &["public.items"], vec![app.pid]).await;
        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("roll back");
        let seen = locks.finish().await;
        app.finish().await;
        eprintln!("locks seen on items: {seen:?}");
        assert!(!saw(&seen, "AccessExclusiveLock"), "{seen:?}");
        assert_eq!(label_index(&pool).await, None);
        let recorded: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM _supatype.managed_objects WHERE kind = 'index'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(recorded, 0, "the index's row went with it");
    })
    .await;
}

//! Keys, indexes and triggers keep their identity across renames, template changes and upgrades
//! (F2, F8 and F12 of the pre-launch fix plan).
//!
//! Each test is one of the pre-launch reproductions, against a real database:
//! - E04 and E05: renaming a table renames its keys in place, so a referenced key is never dropped;
//! - E06 (case B) and the engine-upgrade case: a template that only rewords a key's `CREATE`
//!   changes nothing in the database and rewrites only the ledger;
//! - E32: a new model whose key name clashes with an existing one takes the digit itself;
//! - A1-N1: a key that is dropped and made again takes the foreign keys on it down and back up;
//! - E20: a long name 0.6.0 let Postgres cut is renamed to this engine's name, not duplicated;
//! - E13: a user's own object in `api` under one of our names is refused, and adoptable.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{
    adopt, introspector::fingerprint::ObjectKind, ledger, parser, parser::ast::SchemaAst, push,
};

use common::{exec, push};

fn uuid_pk() -> Value {
    json!({ "kind": "uuid", "primaryKey": true, "required": true,
            "default": { "kind": "genRandomUuid" },
            "annotations": { "db": { "pgType": "UUID", "unique": false } } })
}

fn text(unique: bool) -> Value {
    json!({ "kind": "text", "required": false,
            "annotations": { "db": { "pgType": "TEXT", "unique": unique } } })
}

fn belongs_to(target: &str, column: &str) -> Value {
    json!({ "kind": "relation", "cardinality": "belongsTo", "target": target, "onDelete": "cascade",
            "annotations": { "db": { "foreignKey": column } } })
}

fn model(name: &str, table: &str, fields: Value, indexes: Value) -> Value {
    json!({
        "name": name,
        "fields": fields,
        "options": { "timestamps": false, "softDelete": false },
        "annotations": { "db": { "tableName": table, "indexes": indexes } }
    })
}

fn schema(models: Vec<Value>) -> SchemaAst {
    let doc = json!({ "astVersion": 2, "models": models });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// `posts` (under `table`) with a unique title, and `comments` referencing it. Any other table name
/// declares itself renamed from `posts`, since a push renames only what the schema declares.
fn blog(table: &str) -> SchemaAst {
    let mut post = model(
        "Post",
        table,
        json!({ "id": uuid_pk(), "title": text(true) }),
        json!([]),
    );
    if table != "posts" {
        post["annotations"]["db"]["renamedFrom"] = json!("posts");
    }
    schema(vec![
        post,
        model(
            "Comment",
            "comments",
            json!({ "id": uuid_pk(), "body": text(false), "post": belongs_to("Post", "post_id") }),
            json!([]),
        ),
    ])
}

/// Every constraint and index in `public`, `name|oid`, in name order: a rebuild shows as a new
/// oid, a rename as a new name beside the same oid.
async fn objects(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT conname || '|' || oid FROM pg_constraint WHERE connamespace = 'public'::regnamespace
         UNION ALL
         SELECT c.relname || '|' || c.oid FROM pg_class c
          WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'i'
         UNION ALL
         SELECT tgname || '|' || oid FROM pg_trigger
          WHERE NOT tgisinternal AND tgrelid IN
                (SELECT oid FROM pg_class WHERE relnamespace = 'public'::regnamespace)
         ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The oids alone, sorted: unchanged when nothing was dropped and made again.
fn oids(objects: &[String]) -> Vec<String> {
    let mut oids: Vec<String> = objects
        .iter()
        .map(|o| o.rsplit_once('|').unwrap().1.to_string())
        .collect();
    oids.sort();
    oids
}

fn names(objects: &[String]) -> Vec<&str> {
    objects
        .iter()
        .map(|o| o.rsplit_once('|').unwrap().0)
        .collect()
}

async fn ledger_names(pool: &PgPool, kind: ObjectKind) -> Vec<(String, String)> {
    let mut conn = pool.acquire().await.unwrap();
    ledger::load(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.key.kind == kind && r.key.schema == "public")
        .map(|r| (r.key.parent, r.key.name))
        .collect()
}

fn assert_up_to_date(outcome: &push::Outcome) {
    assert!(
        matches!(outcome, push::Outcome::UpToDate { .. }),
        "expected 0 operations: {outcome:?}"
    );
}

/// E04 and E05: `posts` becomes `postings`. Its primary key, which `comments` references, and its
/// unique title are renamed in place: the same indexes under the new table's names, the foreign
/// key untouched, the rows kept, the ledger rows moved to the new names.
#[tokio::test]
async fn renaming_a_referenced_table_renames_its_keys_in_place() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &blog("posts")).await.unwrap();
        exec(
            &pool,
            "WITH p AS (INSERT INTO posts (title) VALUES ('P1') RETURNING id)
             INSERT INTO comments (body, post_id) SELECT 'C1', id FROM p;",
        )
        .await
        .unwrap();
        let before = objects(&pool).await;

        let renamed = blog("postings");
        // A rename declined after planning: the key renames planned with it must not run.
        let mut declined = push::prepare(&pool, &renamed, "public").await.unwrap();
        declined.diff.operations.retain(|op| {
            !matches!(op, supatype_engine::differ::Operation::RenameTable { .. })
        });
        let refused = push::apply(&pool, declined, push::ApplyOptions::default())
            .await
            .expect_err("renames planned with a declined table rename refuse");
        assert!(refused.to_string().contains("no longer part of it"), "{refused}");
        assert_eq!(before, objects(&pool).await, "nothing was applied");

        let plan = push::prepare(&pool, &renamed, "public").await.unwrap();
        let sql = plan.migration(false).unwrap().file();
        assert!(
            sql.contains(
                "ALTER TABLE \"public\".\"postings\" RENAME CONSTRAINT \"posts_pkey\" TO \"postings_pkey\";"
            ),
            "{sql}"
        );
        assert!(!sql.contains("DROP CONSTRAINT IF EXISTS \"posts_pkey\""), "{sql}");
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .expect("the rename applies");

        let after = objects(&pool).await;
        assert_eq!(oids(&before), oids(&after), "nothing was rebuilt: {after:?}");
        let after_names = names(&after);
        for name in ["postings_pkey", "postings_title_key", "comments_post_id_fkey"] {
            assert!(after_names.contains(&name), "{name} in {after_names:?}");
        }
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM comments JOIN postings p ON p.id = post_id")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 1);
        let keys = ledger_names(&pool, ObjectKind::PrimaryKey).await;
        assert!(keys.contains(&("postings".into(), "postings_pkey".into())), "{keys:?}");
        assert!(!keys.iter().any(|(_, n)| n == "posts_pkey"), "{keys:?}");
        assert_up_to_date(&push(&pool, &renamed).await.unwrap());
    })
    .await;
}

/// E06 case B and the engine upgrade: the ledger records every key and index as an engine whose
/// template wrote `PRIMARY KEY("id")` rather than `PRIMARY KEY ("id")` would have. The structure
/// is the same, so the next push touches nothing and only rewrites the rows to today's wording.
#[tokio::test]
async fn a_template_that_only_rewords_a_key_changes_nothing() {
    common::with_integration_pool(|pool| async move {
        let ast = blog("posts");
        push(&pool, &ast).await.unwrap();
        exec(&pool, "INSERT INTO posts (title) VALUES ('t');")
            .await
            .unwrap();
        // The engine's own fingerprint formula, over the reworded statement.
        exec(
            &pool,
            "UPDATE _supatype.managed_objects SET desired_sql = replace(desired_sql, ' (', '(')
              WHERE kind IN ('index', 'foreign_key', 'unique', 'primary_key');
             UPDATE _supatype.managed_objects
                SET desired_fp = left(encode(sha256(convert_to(kind || chr(31) ||
                    rtrim(regexp_replace(desired_sql, '\\s+', ' ', 'g'), ';'), 'UTF8')), 'hex'), 16)
              WHERE kind IN ('index', 'foreign_key', 'unique', 'primary_key');",
        )
        .await
        .unwrap();
        let before = objects(&pool).await;

        assert_up_to_date(&push(&pool, &ast).await.unwrap());
        assert_eq!(
            before,
            objects(&pool).await,
            "no key was dropped or renamed"
        );
        let reworded: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM _supatype.managed_objects
              WHERE kind IN ('index', 'foreign_key', 'unique', 'primary_key')
                AND desired_sql LIKE '%KEY(%'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(reworded, 0, "the rows are restated in today's wording");
        assert_up_to_date(&push(&pool, &ast).await.unwrap());
    })
    .await;
}

/// E32: two tables whose names agree for 58 bytes both want `<58 bytes>_pkey`. The existing one
/// has it and keeps it; the model added later, which sorts first, takes the digit.
#[tokio::test]
async fn a_new_model_does_not_move_an_existing_keys_digit() {
    common::with_integration_pool(|pool| async move {
        let base = "o".repeat(58);
        let (first, second) = (format!("{base}aa"), format!("{base}bb"));
        let bee = || {
            model(
                "Bee",
                &second,
                json!({ "id": uuid_pk(), "label": text(false) }),
                json!([]),
            )
        };
        let kid = || {
            model(
                "Child",
                "kids",
                json!({ "id": uuid_pk(), "parent": belongs_to("Bee", "parent_id") }),
                json!([]),
            )
        };
        push(&pool, &schema(vec![bee(), kid()])).await.unwrap();
        exec(
            &pool,
            &format!("INSERT INTO \"{second}\" (label) VALUES ('x');"),
        )
        .await
        .unwrap();
        let before = objects(&pool).await;

        let ay = model(
            "Ay",
            &first,
            json!({ "id": uuid_pk(), "label": text(false) }),
            json!([]),
        );
        let grown = schema(vec![ay, bee(), kid()]);
        push(&pool, &grown).await.expect("adding a model applies");

        let keys = ledger_names(&pool, ObjectKind::PrimaryKey).await;
        assert!(
            keys.contains(&(second.clone(), format!("{base}_pkey"))),
            "{keys:?}"
        );
        assert!(
            keys.contains(&(first.clone(), format!("{}_pkey1", &base[..57]))),
            "{keys:?}"
        );
        let after = objects(&pool).await;
        assert!(
            before.iter().all(|o| after.contains(o)),
            "every existing key kept its name and oid: {before:?} -> {after:?}"
        );
        assert_up_to_date(&push(&pool, &grown).await.unwrap());
    })
    .await;
}

/// A1-N1: a primary key the push drops and makes again (here, put back after a change recorded as
/// made by hand) takes down the foreign keys that reference it first, ours and a user's alike, and
/// makes them again after it. The migration says so.
#[tokio::test]
async fn a_rebuilt_primary_key_takes_its_foreign_keys_with_it() {
    common::with_integration_pool(|pool| async move {
        let ast = blog("posts");
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            "CREATE TABLE public.likes (post_id uuid CONSTRAINT likes_post_fk REFERENCES public.posts (id));
             WITH p AS (INSERT INTO posts (title) VALUES ('P1') RETURNING id)
             INSERT INTO comments (body, post_id) SELECT 'C1', id FROM p;
             UPDATE _supatype.managed_objects SET live_fp = 'changed'
              WHERE kind = 'primary_key' AND name = 'posts_pkey';",
        )
        .await
        .unwrap();

        let plan = push::prepare(&pool, &ast, "public").await.unwrap();
        let sql = plan.migration(false).unwrap().file();
        let at = |needle: &str| sql.find(needle).unwrap_or_else(|| panic!("{needle} in {sql}"));
        let pk_drop = at("DROP CONSTRAINT IF EXISTS \"posts_pkey\"");
        assert!(at("DROP CONSTRAINT IF EXISTS \"comments_post_id_fkey\"") < pk_drop, "{sql}");
        assert!(at("DROP CONSTRAINT IF EXISTS \"likes_post_fk\"") < pk_drop, "{sql}");
        assert!(sql.contains("which this push drops and makes again"), "{sql}");
        let said = &plan.diff.warnings;
        assert!(
            said.iter().any(|w| w.contains("likes_post_fk") && w.contains("posts_pkey")),
            "the plan says which foreign keys it rebuilds: {said:?}"
        );
        let pk_add = at("ADD CONSTRAINT \"posts_pkey\"");
        assert!(at("ADD CONSTRAINT \"likes_post_fk\"") > pk_add, "{sql}");
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .expect("the key is rebuilt with its foreign keys around it");

        let fks: Vec<String> = sqlx::query_scalar(
            "SELECT conname::text FROM pg_constraint WHERE contype = 'f'
               AND connamespace = 'public'::regnamespace ORDER BY 1",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(fks, ["comments_post_id_fkey", "likes_post_fk"]);
        let user_rows = ledger_names(&pool, ObjectKind::ForeignKey).await;
        assert!(!user_rows.iter().any(|(_, n)| n == "likes_post_fk"), "the user's key gets no row");
        assert_up_to_date(&push(&pool, &ast).await.unwrap());
    })
    .await;
}

/// The long-name fixture of E20: a table name long enough that the foreign key, the declared
/// indexes and the `updated_at` triggers all pass 63 bytes.
fn long_names() -> SchemaAst {
    let raw = include_str!("fixtures/long_names.json");
    parser::parse(raw).expect("fixture parses")
}

/// E20, as 0.6.0 left the database: every long name cut to 63 bytes by Postgres, and no ledger
/// row for any of them (0.6.0 had no ledger). The first push renames each to this engine's name,
/// keeps every object (same oid), duplicates nothing, and the next push has nothing to do.
#[tokio::test]
async fn long_names_an_older_engine_let_postgres_cut_are_renamed_not_duplicated() {
    common::with_integration_pool(|pool| async move {
        let ast = long_names();
        push(&pool, &ast).await.unwrap();
        // Back to 0.6.0's names, which `format!` built and Postgres cut, with no ledger rows.
        exec(
            &pool,
            "DO $old$ DECLARE r record; BEGIN
               FOR r IN SELECT kind, parent, name FROM _supatype.managed_objects
                         WHERE schema_name = 'public' AND kind IN ('foreign_key', 'index', 'trigger')
               LOOP
                 IF r.kind = 'foreign_key' THEN
                   EXECUTE format('ALTER TABLE public.%I RENAME CONSTRAINT %I TO %I', r.parent, r.name,
                     left(r.parent || '_inviting_organisation_administrator_account_id_fkey', 63));
                 ELSIF r.kind = 'trigger' THEN
                   EXECUTE format('ALTER TRIGGER %I ON public.%I RENAME TO %I', r.name, r.parent,
                     left(r.parent || '_updated_at_trigger', 63));
                 ELSIF r.name LIKE '%invitation_reference%' THEN
                   EXECUTE format('ALTER INDEX public.%I RENAME TO %I', r.name, left(r.parent ||
                     '_invitation_reference_code_for_external_auditing_inviting_organisation_administrator_account_id_idx', 63));
                 ELSE
                   EXECUTE format('ALTER INDEX public.%I RENAME TO %I', r.name,
                     left(r.parent || '_inviting_organisation_administrator_account_id_idx', 63));
                 END IF;
               END LOOP;
               DELETE FROM _supatype.managed_objects
                WHERE schema_name = 'public' AND kind IN ('foreign_key', 'index', 'trigger');
             END $old$;",
        )
        .await
        .unwrap();
        let before = objects(&pool).await;
        assert!(
            names(&before).iter().any(|n| n.ends_with("_upda")),
            "the fixture holds a name Postgres cut: {before:?}"
        );

        push(&pool, &ast).await.expect("the upgrade push applies");
        let after = objects(&pool).await;
        assert_eq!(oids(&before), oids(&after), "renamed, not rebuilt or duplicated: {after:?}");
        assert!(
            !names(&after).iter().any(|n| n.ends_with("_upda") || n.ends_with("_inviting_o")),
            "no 0.6.0 name is left: {after:?}"
        );
        let report = common::doctor(&pool, &ast).await;
        assert!(report.unmanaged_drift.is_empty(), "{:?}", report.unmanaged_drift);
        assert_up_to_date(&push(&pool, &ast).await.unwrap());
    })
    .await;
}

/// E13: a user's own `api` schema holds a view and a function under the names the field-rule
/// layer gives its own. The push refuses them as conflicts and changes neither; once `adopt` hands
/// them over, the next push brings them to the schema. A user's object under any other name stays.
#[tokio::test]
async fn a_users_own_api_objects_under_our_names_are_refused_and_adoptable() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(include_str!("fixtures/rls_field_rules.json")).unwrap();
        exec(
            &pool,
            "CREATE SCHEMA api;
             CREATE TABLE public.my_users_src (id int, label text);
             CREATE VIEW api.users AS SELECT id, label, 'USER VIEW' AS marker FROM public.my_users_src;
             CREATE FUNCTION api.users__write() RETURNS trigger LANGUAGE plpgsql
               AS $f$ BEGIN RAISE NOTICE 'USER FN'; RETURN NEW; END $f$;
             CREATE VIEW api.reports AS SELECT 1 AS user_report;",
        )
        .await
        .unwrap();
        let view = || async {
            sqlx::query_scalar::<_, String>("SELECT pg_get_viewdef('api.users'::regclass)")
                .fetch_one(&pool)
                .await
                .unwrap()
        };
        let mine = view().await;
        match push(&pool, &ast).await {
            Err(refused) => {
                let message = refused.to_string();
                assert!(message.contains("view api.users"), "{message}");
                assert!(message.contains("function api.users__write()"), "{message}");
            }
            // A database that loads the masking extension makes no `api` views and leaves the
            // user's alone; one that makes them must not have replaced the user's silently.
            Ok(_) => {
                assert_eq!(view().await, mine, "the user's view was replaced silently");
                eprintln!("SKIP: this image enforces field rules without `api` views");
                return;
            }
        }
        assert_eq!(view().await, mine, "the user's view is untouched");

        adopt::run(
            &pool,
            &ast,
            "public",
            adopt::Request {
                apply: true,
                ..Default::default()
            },
        )
        .await
        .expect("the conflicts are adoptable");
        push(&pool, &ast).await.expect("adopted, the push applies");
        assert!(!view().await.contains("USER VIEW"), "brought to the schema");
        let reports: bool = sqlx::query_scalar("SELECT to_regclass('api.reports') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(reports, "a user's view under another name stays");
    })
    .await;
}

//! A push on a table that holds rows changes it without making the application wait (IN-C).
//!
//! An index used to be built, and a foreign key or check validated, inside the push's transaction:
//! `CREATE INDEX` holds a lock that stops every write to the table for the whole build, and adding
//! a key holds one until the push commits. Now a new index on a table with rows is built with
//! `CREATE INDEX CONCURRENTLY` once the transaction has committed, and a key or check is added
//! `NOT VALID` and validated after it, under a lock that lets reads and writes through. A change
//! that rewrites a large table is flagged in the plan and needs consent.

mod common;

use std::time::Duration;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::push::{self, ApplyOptions, Outcome};
use supatype_engine::{parser, parser::ast::SchemaAst, state::migration_history};

use common::locks::{App, LockSampler, BLOCKS_WRITES};
use common::{exec, push, push_with};

fn uuid_field() -> Value {
    json!({ "kind": "uuid", "primaryKey": true, "required": true,
            "default": { "kind": "genRandomUuid" },
            "annotations": { "db": { "pgType": "UUID", "unique": false } } })
}

fn model(name: &str, table: &str, fields: Value, indexes: Value) -> Value {
    json!({ "name": name, "fields": fields,
            "options": { "timestamps": false, "softDelete": false },
            "annotations": { "db": { "tableName": table, "indexes": indexes },
                             "platform": { "access": {} } } })
}

/// What the schema says about `items` beyond its plain columns.
#[derive(Clone, Copy, Default)]
struct Items {
    /// `owner_id` is a relation to `owners`, with its foreign key.
    owner_relation: bool,
    /// An index on `label`, unique or not.
    label_index: Option<bool>,
    /// `qty` as `bigint` rather than `integer`.
    qty_bigint: bool,
}

fn schema(items: Items) -> SchemaAst {
    let owner_column = if items.owner_relation {
        json!({ "kind": "relation", "cardinality": "belongsTo", "target": "Owner",
                "onDelete": "restrict", "required": false,
                "annotations": { "db": { "foreignKey": "owner_id" } } })
    } else {
        json!({ "kind": "uuid", "required": false,
                "annotations": { "db": { "pgType": "UUID", "unique": false } } })
    };
    let owner_key = if items.owner_relation {
        "owner"
    } else {
        "owner_id"
    };
    let qty = if items.qty_bigint {
        json!({ "kind": "bigInt", "required": false,
                "annotations": { "db": { "pgType": "BIGINT" } } })
    } else {
        json!({ "kind": "integer", "required": false,
                "annotations": { "db": { "pgType": "INTEGER" } } })
    };
    let mut fields = json!({
        "id": uuid_field(),
        "label": { "kind": "text", "required": false,
                   "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
        "qty": qty,
    });
    fields[owner_key] = owner_column;
    let indexes = match items.label_index {
        Some(unique) => json!([{ "fields": ["label"], "unique": unique, "using": "btree" }]),
        None => json!([]),
    };
    let doc = json!({ "astVersion": 2, "models": [
        model("Owner", "owners", json!({ "id": uuid_field() }), json!([])),
        model("Item", "items", fields, indexes),
    ]});
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// `rows` items over 100 owners, each with a distinct label, then `ANALYZE` so the planner and
/// the push's row estimate know the table's size.
async fn fill(pool: &PgPool, rows: u32) {
    exec(
        pool,
        &format!(
            "INSERT INTO public.owners (id) SELECT gen_random_uuid() FROM generate_series(1, 100);
             INSERT INTO public.items (owner_id, label, qty)
             SELECT (SELECT id FROM public.owners ORDER BY id OFFSET (i % 100) LIMIT 1),
                    md5(i::text), i
               FROM generate_series(1, {rows}) AS i;
             ANALYZE public.items;"
        ),
    )
    .await
    .expect("fill the table");
}

async fn invalid_indexes(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM pg_index WHERE NOT indisvalid")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn ledger_has(pool: &PgPool, kind: &str, name: &str) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM _supatype.managed_objects WHERE kind = $1 AND name = $2)",
    )
    .bind(kind)
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// `(name, validated)` of every foreign key on `items`.
async fn item_keys(pool: &PgPool) -> Vec<(String, bool)> {
    sqlx::query_as(
        "SELECT conname::text, convalidated FROM pg_constraint
          WHERE conrelid = 'public.items'::regclass AND contype = 'f' ORDER BY conname",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn index_on_label(pool: &PgPool) -> Option<String> {
    sqlx::query_scalar(
        "SELECT indexrelid::regclass::text FROM pg_index
          WHERE indrelid = 'public.items'::regclass AND indisvalid
            AND indnatts = 1
            AND indkey[0] = (SELECT attnum FROM pg_attribute
                              WHERE attrelid = 'public.items'::regclass AND attname = 'label')",
    )
    .fetch_optional(pool)
    .await
    .unwrap()
}

/// IN-C 2: on a table with 200k rows, a push that adds an index and a foreign key never holds a
/// lock that stops the application's writes for longer than its short lock timeout. The index is
/// built concurrently and the key validated after commit, both recorded once they are in place,
/// and a rollback undoes them.
#[tokio::test(flavor = "multi_thread")]
async fn an_index_and_a_foreign_key_on_a_table_with_rows_never_stop_its_writes() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(Items::default())).await.unwrap();
        fill(&pool, 200_000).await;

        let app = App::start(
            &pool,
            &[
                "INSERT INTO public.items (label, qty) VALUES (md5(random()::text), 1)",
                "SELECT count(*) FROM public.items WHERE qty = 7",
            ],
        )
        .await;
        let locks = LockSampler::start(&pool, &["items"], vec![app.pid]).await;
        let target = schema(Items {
            owner_relation: true,
            label_index: Some(false),
            ..Items::default()
        });
        let outcome = push(&pool, &target).await;
        let seen = locks.finish().await;
        let (longest, ran) = app.finish().await;

        assert!(
            matches!(outcome, Ok(Outcome::Applied { .. })),
            "{outcome:?}"
        );
        eprintln!("locks seen on items: {seen:?}; longest app statement {longest:?} of {ran}");
        assert!(
            !seen.iter().any(|(_, mode)| mode == "ShareLock"),
            "the index was built under a lock that stops writes: {seen:?}"
        );
        assert!(
            seen.iter()
                .any(|(_, mode)| mode == "ShareUpdateExclusiveLock"),
            "nothing was built or validated online: {seen:?}"
        );
        assert!(
            longest < Duration::from_secs(3),
            "an application statement waited {longest:?}"
        );
        assert!(BLOCKS_WRITES.contains(&"ShareLock"));

        let index = index_on_label(&pool).await.expect("the index was built");
        assert_eq!(invalid_indexes(&pool).await, 0);
        assert!(ledger_has(&pool, "index", index.trim_start_matches("public.")).await);
        let keys = item_keys(&pool).await;
        assert_eq!(keys.len(), 1, "{keys:?}");
        assert!(keys[0].1, "the key was validated: {keys:?}");
        assert!(ledger_has(&pool, "foreign_key", &keys[0].0).await);

        // Settled: the next push changes nothing.
        let again = push(&pool, &target).await.unwrap();
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");

        // A rollback takes both away, and their rows with them.
        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("roll back");
        assert_eq!(index_on_label(&pool).await, None);
        assert!(item_keys(&pool).await.is_empty());
        assert!(!ledger_has(&pool, "foreign_key", &keys[0].0).await);
    })
    .await;
}

/// IN-C 2: a unique index the rows break cannot be built concurrently. The build leaves an
/// INVALID index, which is dropped, so nothing is half there; the push fails saying so, records
/// no row for the index, and the next push, once the rows are fixed, builds it.
#[tokio::test(flavor = "multi_thread")]
async fn a_unique_index_the_rows_break_leaves_nothing_behind_and_is_built_once_they_are_fixed() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(Items::default())).await.unwrap();
        fill(&pool, 1_000).await;
        exec(
            &pool,
            "UPDATE public.items SET label = 'same' WHERE qty <= 2",
        )
        .await
        .unwrap();
        let target = schema(Items {
            label_index: Some(true),
            ..Items::default()
        });

        let err = push(&pool, &target)
            .await
            .expect_err("a unique index the rows break fails the push");
        let message = format!("{err:#}");
        assert!(message.contains("items_label"), "{message}");
        assert!(message.contains("could not be built"), "{message}");
        assert_eq!(invalid_indexes(&pool).await, 0, "{message}");
        assert_eq!(index_on_label(&pool).await, None);

        exec(
            &pool,
            "UPDATE public.items SET label = md5(qty::text) WHERE qty <= 2",
        )
        .await
        .unwrap();
        let outcome = push(&pool, &target).await.unwrap();
        assert!(matches!(outcome, Outcome::Applied { .. }), "{outcome:?}");
        let index = index_on_label(&pool).await.expect("built on the next push");
        assert!(ledger_has(&pool, "index", index.trim_start_matches("public.")).await);
        let again = push(&pool, &target).await.unwrap();
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}

/// IN-C 2: a foreign key added `NOT VALID` whose validation has not run yet (the engine stopped
/// between the commit and the validation) is pending: doctor says so, and the next push validates
/// it rather than making it again.
#[tokio::test(flavor = "multi_thread")]
async fn a_key_not_yet_validated_is_pending_and_the_next_push_validates_it() {
    common::with_integration_pool(|pool| async move {
        let target = schema(Items {
            owner_relation: true,
            ..Items::default()
        });
        push(&pool, &schema(Items::default())).await.unwrap();
        fill(&pool, 1_000).await;
        push(&pool, &target).await.unwrap();
        let name = item_keys(&pool).await[0].0.clone();

        // The state a push leaves when it stops after its commit: the key in place, NOT VALID,
        // and its row recording it so.
        exec(
            &pool,
            &format!(
                "ALTER TABLE public.items DROP CONSTRAINT \"{name}\";
                 ALTER TABLE public.items ADD CONSTRAINT \"{name}\" FOREIGN KEY (owner_id)
                   REFERENCES public.owners (id) ON DELETE RESTRICT NOT VALID;"
            ),
        )
        .await
        .unwrap();
        let state = common::live_state(&pool).await;
        let live = state
            .fingerprints
            .iter()
            .find(|f| f.name == name)
            .expect("the key is live")
            .clone();
        sqlx::query(
            "UPDATE _supatype.managed_objects SET live_fp = $1, live_def = $2
              WHERE kind = 'foreign_key' AND name = $3",
        )
        .bind(&live.fingerprint)
        .bind(&live.definition)
        .bind(&name)
        .execute(&pool)
        .await
        .unwrap();

        let report = common::doctor(&pool, &target).await;
        assert!(
            report.pending.iter().any(|i| i.name == name),
            "doctor names the key as pending: {report:#?}"
        );
        assert!(report.drifted.is_empty(), "{report:#?}");

        let outcome = push(&pool, &target).await.unwrap();
        assert!(matches!(outcome, Outcome::UpToDate { .. }), "{outcome:?}");
        assert_eq!(item_keys(&pool).await, vec![(name.clone(), true)]);
        let report = common::doctor(&pool, &target).await;
        assert!(report.pending.is_empty(), "{report:#?}");
        assert!(report.drifted.is_empty(), "{report:#?}");
    })
    .await;
}

/// IN-C 3: a type change that rewrites a table of more than 100k rows is flagged in the plan with
/// the table's estimated size, and a push refuses it without consent. A small table's rewrite is
/// flagged and applied.
#[tokio::test(flavor = "multi_thread")]
async fn a_rewrite_of_a_large_table_is_flagged_and_refused_without_consent() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(Items::default())).await.unwrap();
        fill(&pool, 120_000).await;
        let target = schema(Items {
            qty_bigint: true,
            ..Items::default()
        });

        let plan = push::plan(&pool, &target, "public").await.unwrap();
        let json = plan.to_json().unwrap().to_string();
        assert!(
            json.contains("locks items while it rewrites ~1"),
            "the plan flags the rewrite: {json}"
        );

        let refused = push(&pool, &target)
            .await
            .expect_err("a large rewrite needs consent");
        let message = format!("{refused:#}");
        assert!(message.contains("rewrite"), "{message}");
        assert!(message.contains("items"), "{message}");
        let qty: String = sqlx::query_scalar(
            "SELECT data_type FROM information_schema.columns
              WHERE table_name = 'items' AND column_name = 'qty'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(qty, "integer", "nothing was applied");

        let forced = push_with(
            &pool,
            &target,
            ApplyOptions {
                force: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(matches!(forced, Outcome::Applied { .. }), "{forced:?}");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rewrite_of_a_small_table_is_flagged_and_applied() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(Items::default())).await.unwrap();
        fill(&pool, 100).await;
        let outcome = push(
            &pool,
            &schema(Items {
                qty_bigint: true,
                ..Items::default()
            }),
        )
        .await
        .unwrap();
        let Outcome::Applied { warnings, .. } = outcome else {
            panic!("{outcome:?}")
        };
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("locks items while it rewrites")),
            "{warnings:?}"
        );
    })
    .await;
}

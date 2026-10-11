//! Generated names, applied: what a push creates is what the desired set and the ledger look for.
//!
//! Each schema here names something past Postgres's 63-byte limit, or two things alike. Before
//! names were chosen as Postgres chooses them, each of these pushes failed: `42P07` on the second
//! of two uniques trimmed to one name, or "not found in the catalog after the push applied it"
//! for an object Postgres had quietly renamed by truncation, or for a serial's sequence that kept
//! its old table's name through a rename.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{
    introspector::fingerprint::ObjectKind, ledger, parser, parser::ast::SchemaAst, push,
    state::migration_history,
};

use common::{exec, push};

fn text(unique: bool) -> Value {
    json!({ "kind": "text", "annotations": { "db": { "pgType": "TEXT", "unique": unique } } })
}

fn id() -> Value {
    json!({ "kind": "integer", "primaryKey": true, "required": true,
            "annotations": { "db": { "pgType": "INTEGER", "unique": false } } })
}

fn serial_id() -> Value {
    json!({ "kind": "serial", "primaryKey": true, "required": true })
}

fn model(name: &str, table: &str, fields: Value) -> Value {
    json!({
        "name": name,
        "fields": fields,
        "options": { "timestamps": false, "softDelete": false, "singleton": false },
        "annotations": { "db": { "tableName": table, "indexes": [] },
                         "platform": { "access": { "read": { "type": "public" } } } }
    })
}

fn schema(models: Vec<Value>) -> SchemaAst {
    let doc = json!({ "astVersion": 2, "models": models });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

fn forced() -> push::ApplyOptions {
    push::ApplyOptions {
        force: true,
        ..Default::default()
    }
}

fn up_to_date(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::UpToDate { .. })
}

/// The names of the recorded rows of `kind` in `public`.
async fn recorded(pool: &PgPool, kind: ObjectKind) -> Vec<String> {
    let mut conn = pool.acquire().await.unwrap();
    let mut rows: Vec<String> = ledger::load(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.key.kind == kind && r.key.schema == "public")
        .map(|r| r.key.name)
        .collect();
    rows.sort();
    rows
}

async fn names_in_catalog(pool: &PgPool, sql: &str) -> Vec<String> {
    sqlx::query_scalar(sql).fetch_all(pool).await.unwrap()
}

async fn sequences(pool: &PgPool) -> Vec<String> {
    names_in_catalog(
        pool,
        "SELECT relname::text FROM pg_class
          WHERE relnamespace = 'public'::regnamespace AND relkind = 'S' ORDER BY 1",
    )
    .await
}

#[tokio::test]
async fn two_long_uniques_on_one_table_keep_distinct_names() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(vec![model(
            "Invitation",
            "organization_membership_invitations",
            json!({ "id": id(), "notification_preference_email": text(true),
                    "notification_preference_phone": text(true) }),
        )]);
        push(&pool, &ast).await.unwrap();
        assert_eq!(
            recorded(&pool, ObjectKind::Unique).await,
            [
                "organization_membership_invit_notification_preference_email_key",
                "organization_membership_invit_notification_preference_phone_key",
            ]
        );
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
    })
    .await;
}

#[tokio::test]
async fn uniques_named_alike_across_tables_take_a_digit() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(vec![
            model(
                "Order",
                "order",
                json!({ "id": id(), "item_code": text(true) }),
            ),
            model(
                "OrderItem",
                "order_item",
                json!({ "id": id(), "code": text(true) }),
            ),
        ]);
        push(&pool, &ast).await.unwrap();
        assert_eq!(
            recorded(&pool, ObjectKind::Unique).await,
            ["order_item_code_key", "order_item_code_key1"]
        );
        let on_order_item = names_in_catalog(
            &pool,
            "SELECT conname::text FROM pg_constraint
              WHERE conrelid = 'public.order_item'::regclass AND contype = 'u'",
        )
        .await;
        assert_eq!(on_order_item, ["order_item_code_key1"]);
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
    })
    .await;
}

#[tokio::test]
async fn a_long_model_index_and_singleton_index_are_found_after_the_push() {
    common::with_integration_pool(|pool| async move {
        let mut m = model(
            "Invitation",
            "organization_membership_invitations",
            json!({ "id": id(), "notification_preference_email": text(false),
                    "notification_preference_phone": text(false) }),
        );
        m["annotations"]["db"]["indexes"] = json!([
            { "fields": ["notification_preference_email", "notification_preference_phone"],
          "unique": false, "using": "btree" }
        ]);
        m["options"]["singleton"] = json!(true);
        let ast = schema(vec![m]);
        push(&pool, &ast).await.unwrap();
        assert_eq!(
            recorded(&pool, ObjectKind::Index).await,
            [
                "organization_membership_invit_notification_preference_email_idx",
                "organization_membership_invitations_singleton_idx",
            ]
        );
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
    })
    .await;
}

#[tokio::test]
async fn long_storage_policy_names_are_found_after_the_push() {
    common::with_integration_pool(|pool| async move {
        let file = json!({ "kind": "image", "bucket": "product-variant-gallery-images-public",
                           "annotations": { "db": { "pgType": "JSONB" } } });
        let mut m = model(
            "ProductVariantImage",
            "product_variant_images",
            json!({ "id": id(), "image": file }),
        );
        m["annotations"]["platform"]["access"] =
            json!({ "read": { "type": "public" }, "create": { "type": "authenticated" } });
        let ast = schema(vec![m]);
        push(&pool, &ast).await.unwrap();
        let storage = names_in_catalog(
            &pool,
            "SELECT policyname::text FROM pg_policies
              WHERE schemaname = 'storage' AND policyname LIKE 'product_variant_images_%'
              ORDER BY 1",
        )
        .await;
        assert_eq!(
            storage,
            [
                "product_variant_images_product-variant-gallery-images-publi_ins",
                "product_variant_images_product-variant-gallery-images-publi_sel",
            ]
        );
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
    })
    .await;
}

fn posts_in(table: &str) -> SchemaAst {
    schema(vec![model(
        "Post",
        table,
        json!({ "id": serial_id(), "slug": text(true) }),
    )])
}

/// A rename keeps the rows, the primary key follows the table's new name, and the serial's
/// sequence is renamed with it so the ledger finds it. The old table's affordance functions go
/// before the rename, not after it (when their row type has the new name and the drop by the old
/// one finds nothing, leaving them behind), and the rollback puts everything back.
#[tokio::test]
async fn a_renamed_table_takes_its_sequence_and_primary_key_with_it() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts_in("posts")).await.unwrap();
        exec(&pool, "INSERT INTO public.posts (slug) VALUES ('a')")
            .await
            .unwrap();
        assert_eq!(sequences(&pool).await, ["posts_id_seq"]);

        common::push_with(&pool, &posts_in("posts_archive"), forced())
            .await
            .unwrap();
        assert_eq!(sequences(&pool).await, ["posts_archive_id_seq"]);
        assert_eq!(
            recorded(&pool, ObjectKind::Sequence).await,
            ["posts_archive_id_seq"]
        );
        assert_eq!(
            recorded(&pool, ObjectKind::PrimaryKey).await,
            ["posts_archive_pkey"]
        );
        let pk = names_in_catalog(
            &pool,
            "SELECT conname::text FROM pg_constraint
              WHERE conrelid = 'public.posts_archive'::regclass AND contype = 'p'",
        )
        .await;
        assert_eq!(pk, ["posts_archive_pkey"]);
        let functions = names_in_catalog(
            &pool,
            "SELECT p.oid::regprocedure::text FROM pg_proc p
              WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'can_%'
              ORDER BY 1",
        )
        .await;
        assert_eq!(
            functions,
            [
                "can_create_posts_archive(posts_archive)",
                "can_delete_posts_archive(posts_archive)",
                "can_read_posts_archive(posts_archive)",
                "can_update_posts_archive(posts_archive)",
            ],
            "the old table's functions were left behind"
        );
        // The default still draws from the same, renamed, sequence.
        let next: i32 =
            sqlx::query_scalar("INSERT INTO public.posts_archive (slug) VALUES ('b') RETURNING id")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(next, 2);
        assert!(up_to_date(
            &push(&pool, &posts_in("posts_archive")).await.unwrap()
        ));
        // Rolling it back renames the table and its sequence back, and puts the old table's
        // affordance functions back on its row type once it has its name again.
        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("the rename rolls back");
        assert_eq!(sequences(&pool).await, ["posts_id_seq"]);
        let functions = names_in_catalog(
            &pool,
            "SELECT p.oid::regprocedure::text FROM pg_proc p
              WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'can_%'
              ORDER BY 1",
        )
        .await;
        assert_eq!(
            functions,
            [
                "can_create_posts(posts)",
                "can_delete_posts(posts)",
                "can_read_posts(posts)",
                "can_update_posts(posts)",
            ]
        );
        assert!(up_to_date(&push(&pool, &posts_in("posts")).await.unwrap()));
    })
    .await;
}

fn tickets(column: &str) -> SchemaAst {
    schema(vec![model(
        "Ticket",
        "tickets",
        json!({ "id": id(), column: { "kind": "serial", "required": true } }),
    )])
}

#[tokio::test]
async fn a_renamed_serial_column_takes_its_sequence_with_it() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &tickets("ticket_number")).await.unwrap();
        assert_eq!(sequences(&pool).await, ["tickets_ticket_number_seq"]);

        push(&pool, &tickets("ticket_numbers")).await.unwrap();
        assert_eq!(sequences(&pool).await, ["tickets_ticket_numbers_seq"]);
        assert_eq!(
            recorded(&pool, ObjectKind::Sequence).await,
            ["tickets_ticket_numbers_seq"]
        );
        assert!(up_to_date(
            &push(&pool, &tickets("ticket_numbers")).await.unwrap()
        ));

        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("the rename rolls back");
        assert_eq!(sequences(&pool).await, ["tickets_ticket_number_seq"]);
    })
    .await;
}

#[tokio::test]
async fn checks_named_alike_across_tables_take_a_digit() {
    common::with_integration_pool(|pool| async move {
        let email = json!({ "kind": "email", "annotations": { "db": { "pgType": "TEXT" } } });
        let ast = schema(vec![
            model("Post", "post", json!({ "id": id(), "tag_email": email })),
            model("PostTag", "post_tag", json!({ "id": id(), "email": email })),
        ]);
        push(&pool, &ast).await.unwrap();
        assert_eq!(
            recorded(&pool, ObjectKind::Check).await,
            ["post_tag_email_check", "post_tag_email_check1"]
        );
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
    })
    .await;
}

/// A table name at the identifier limit with timestamps, a slug, rich text, access rules and
/// drafts: every function, trigger, policy, view and snapshot table it generates fits, and the
/// push finds each one it made.
#[tokio::test]
async fn a_long_table_with_every_generated_object_pushes_and_converges() {
    common::with_integration_pool(|pool| async move {
        let table = "a_very_long_table_name_for_testing_postgres_identifier_truncati";
        let mut m = model(
            "Long",
            table,
            json!({
                "id": { "kind": "uuid", "primaryKey": true, "required": true,
                        "default": { "kind": "genRandomUuid" },
                        "annotations": { "db": { "pgType": "UUID", "unique": false } } },
                "title": text(false),
                "a_rather_long_slug_column_name_that_goes_on": {
                    "kind": "slug", "required": false, "from": "title",
                    "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
                "body": { "kind": "richText", "required": false,
                          "annotations": { "db": { "pgType": "JSONB", "unique": false } } }
            }),
        );
        m["options"]["timestamps"] = json!(true);
        m["options"]["versions"] = json!({ "drafts": true, "keep": 5 });
        m["annotations"]["platform"]["access"] = json!({
            "read": { "type": "public" }, "create": { "type": "authenticated" },
            "update": { "type": "authenticated" }, "delete": { "type": "authenticated" }
        });
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
            "models": [m]
        });
        let ast = parser::parse(&doc.to_string()).unwrap();
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            &format!("INSERT INTO public.\"{table}\" (title) VALUES ('Hello World')"),
        )
        .await
        .unwrap();
        let slug: String = sqlx::query_scalar(&format!(
            "SELECT a_rather_long_slug_column_name_that_goes_on FROM public.\"{table}\""
        ))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(slug, "hello-world", "the slug trigger did not run");
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
    })
    .await;
}

fn order(fields: Value) -> Value {
    model("Order", "order", fields)
}

fn order_item(fields: Value) -> Value {
    model("OrderItem", "order_item", fields)
}

async fn uniques_on(pool: &PgPool, table: &str) -> Vec<String> {
    names_in_catalog(
        pool,
        &format!(
            "SELECT conname::text FROM pg_constraint
              WHERE conrelid = 'public.{table}'::regclass AND contype = 'u' ORDER BY 1"
        ),
    )
    .await
}

/// Names never depend on declaration order: a push of the same models in another order changes
/// nothing. Adding a model whose name clashes with an existing one's renames nothing either (F2d):
/// `order` sorts before `order_item`, so from the schema alone it would take `order_item_code_key`
/// and move the existing `order_item.code` unique to `order_item_code_key1`. The ledger records
/// the existing name, so it keeps it and the new `order` takes the digit. Once both exist,
/// reordering them renames nothing.
#[tokio::test]
async fn reordering_models_renames_nothing() {
    common::with_integration_pool(|pool| async move {
        let item = || order_item(json!({ "id": id(), "code": text(true) }));
        let order_model = || order(json!({ "id": id(), "item_code": text(true) }));

        push(&pool, &schema(vec![item()])).await.unwrap();
        assert_eq!(
            uniques_on(&pool, "order_item").await,
            ["order_item_code_key"]
        );

        // A new clashing model: the new constraint takes the digit, the existing one stays.
        push_with_force(&pool, &schema(vec![order_model(), item()])).await;
        assert_eq!(uniques_on(&pool, "order").await, ["order_item_code_key1"]);
        assert_eq!(
            uniques_on(&pool, "order_item").await,
            ["order_item_code_key"]
        );

        // Reordered, in either direction: nothing to do.
        for models in [vec![item(), order_model()], vec![order_model(), item()]] {
            assert!(up_to_date(&push(&pool, &schema(models)).await.unwrap()));
        }
        assert_eq!(uniques_on(&pool, "order").await, ["order_item_code_key1"]);
        assert_eq!(
            uniques_on(&pool, "order_item").await,
            ["order_item_code_key"]
        );
    })
    .await;
}

async fn push_with_force(pool: &PgPool, ast: &SchemaAst) {
    common::push_with(pool, ast, forced()).await.unwrap();
}

/// `order.item_id` and `order_item.id` both make `order_item_id_seq`, and Postgres gives it to
/// whichever table it creates first, which need not be the one the engine would have predicted.
/// The ledger records each sequence under the name its own column's sequence has, so its rows
/// match the catalog, the next push has nothing to do and doctor finds nothing.
#[tokio::test]
async fn two_serials_named_alike_are_recorded_as_postgres_named_them() {
    two_serials_named_alike(false).await;
}

/// The same, first pushed with the models the other way round, so Postgres creates `order_item`
/// first and gives it the undigited name.
#[tokio::test]
async fn two_serials_named_alike_declared_the_other_way_round() {
    two_serials_named_alike(true).await;
}

async fn two_serials_named_alike(first_reversed: bool) {
    common::with_integration_pool(|pool| async move {
        let models = |reversed: bool| {
            let o = order(json!({ "id": id(), "item_id": { "kind": "serial", "required": true } }));
            let i = order_item(json!({ "id": serial_id() }));
            if reversed {
                vec![i, o]
            } else {
                vec![o, i]
            }
        };
        let ast = schema(models(first_reversed));
        push(&pool, &ast).await.unwrap();

        let mut conn = pool.acquire().await.unwrap();
        let rows: Vec<ledger::LedgerRow> = ledger::load(&mut conn)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.key.kind == ObjectKind::Sequence && r.key.schema == "public")
            .collect();
        drop(conn);
        assert_eq!(rows.len(), 2, "{rows:?}");
        for (table, column) in [("order", "item_id"), ("order_item", "id")] {
            let actual: String = sqlx::query_scalar(&format!(
                "SELECT split_part(pg_get_serial_sequence('public.{table}', '{column}'), '.', 2)"
            ))
            .fetch_one(&pool)
            .await
            .unwrap();
            let actual = actual.trim_matches('"').to_string();
            let row = rows
                .iter()
                .find(|r| r.key.name == actual)
                .unwrap_or_else(|| panic!("no row for {actual}: {rows:?}"));
            assert!(
                row.desired_sql
                    .ends_with(&format!("OWNED BY \"public\".\"{table}\".\"{column}\";")),
                "{actual} is recorded as another column's: {}",
                row.desired_sql
            );
            assert!(
                row.live_def.contains(&format!("{table}.{column}")),
                "{actual}: {}",
                row.live_def
            );
        }

        for reversed in [false, true] {
            let ast = schema(models(reversed));
            assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
            let report = supatype_engine::inspect::doctor(&pool, &ast, "public", false)
                .await
                .unwrap();
            assert!(
                !supatype_engine::differ::doctor::has_strict_issues(&report),
                "{report:?}"
            );
        }
    })
    .await;
}

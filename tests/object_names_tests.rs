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
/// sequence is renamed with it so the ledger finds it; the rollback renames it back.
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
        // Its rollback renames the sequence back with the table. (Not applied here: rolling a
        // table rename back recreates the old table's `can_*` functions before the table has its
        // old name again, which fails on its own, whatever the sequence.)
        let down: String = sqlx::query_scalar(
            "SELECT sql_down FROM _supatype.migrations ORDER BY id DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let back = down
            .find("ALTER TABLE \"public\".\"posts_archive\" RENAME TO \"posts\";")
            .expect("the rollback renames the table back");
        assert!(
            down[back..].contains("'posts_id_seq'"),
            "the rollback leaves the sequence named for the new table:\n{down}"
        );
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

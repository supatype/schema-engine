//! The names a push gives the objects it creates.
//!
//! Every generated name is the one Postgres would have chosen for an unnamed object, emitted
//! explicitly so that no object is ever named by anyone but us: `makeObjectName`'s fitting to the
//! 63-byte identifier limit (the longer of table and column gives way first, the label is always
//! kept), and `ChooseRelationName`'s digit on the label when the name is already taken in the
//! schema. Postgres silently truncates a long identifier, so a name built in full here and
//! truncated there is a name nothing can find again; and two objects given the same name are
//! `42P07` on the second.
//!
//! The long-name expectations below are what Postgres 16 itself chose for unnamed constraints and
//! indexes on these tables (read back from `pg_constraint` and `pg_class`).

use serde_json::{json, Value};
use supatype_engine::desired::desired_objects;
use supatype_engine::introspector::fingerprint::ObjectKind;
use supatype_engine::managed::{
    clip_identifier, expected_check_constraint_name, expected_model_constraint_name,
    expected_model_index_name, expected_unique_constraint_name, foreign_key_name, make_object_name,
    policy_name, primary_key_name, type_check_name, ObjectNames, MAX_IDENTIFIER_BYTES,
};
use supatype_engine::parser;
use supatype_engine::parser::ast::{AccessRule, SchemaAst};

#[test]
fn the_defaults_are_postgres_defaults() {
    assert_eq!(primary_key_name("posts"), "posts_pkey");
    assert_eq!(
        foreign_key_name("posts", "author_id"),
        "posts_author_id_fkey"
    );
    assert_eq!(
        expected_unique_constraint_name("users", "email"),
        "users_email_key"
    );
    assert_eq!(type_check_name("users", "email"), "users_email_check");
    assert_eq!(
        expected_check_constraint_name("users", "name"),
        "users_name_bounds"
    );
    assert_eq!(
        expected_model_constraint_name(
            "talk",
            &rule(json!({ "type": "compare", "op": "lte",
            "left": col("starts_at"), "right": col("ends_at") }))
        ),
        "talk_starts_at_lte_ends_at"
    );
    assert_eq!(
        expected_model_index_name("talk", &["day".into(), "starts_at".into()]),
        "talk_day_starts_at_idx"
    );
}

#[test]
fn a_short_name_is_untouched() {
    assert_eq!(
        make_object_name("posts", Some("author_id"), "fkey"),
        "posts_author_id_fkey"
    );
}

/// The case the old trim got wrong: it cut the end off `{table}_{column}` and both columns lost
/// the part that tells them apart, so the second `UNIQUE` failed with `42P07`.
#[test]
fn the_longer_name_gives_way_first_as_in_postgres() {
    let table = "organization_membership_invitations";
    assert_eq!(
        expected_unique_constraint_name(table, "notification_preference_email"),
        "organization_membership_invit_notification_preference_email_key"
    );
    assert_eq!(
        expected_unique_constraint_name(table, "notification_preference_phone"),
        "organization_membership_invit_notification_preference_phone_key"
    );
    assert_eq!(
        type_check_name(table, "notification_preference_phone"),
        "organization_membership_invi_notification_preference_phon_check"
    );
}

#[test]
fn long_names_match_what_postgres_chose() {
    // Postgres had already cut the table's own name to 63 bytes.
    let table = "a_very_long_table_name_for_testing_postgres_identifier_truncati";
    let column = "a_rather_long_column_name_that_is_also_quite_long";
    assert_eq!(
        primary_key_name(table),
        "a_very_long_table_name_for_testing_postgres_identifier_tru_pkey"
    );
    assert_eq!(
        foreign_key_name(table, column),
        "a_very_long_table_name_for_te_a_rather_long_column_name_th_fkey"
    );
    assert_eq!(
        expected_model_index_name(table, &[column.to_string()]),
        "a_very_long_table_name_for_te_a_rather_long_column_name_tha_idx"
    );
    assert_eq!(
        make_object_name(table, Some("id"), "seq"),
        "a_very_long_table_name_for_testing_postgres_identifier_t_id_seq"
    );
    // Counted in bytes and cut back to a character boundary, as `pg_mbcliplen` cuts.
    assert_eq!(
        expected_unique_constraint_name(table, "ñandú_ñandú_ñandú_ñandú_ñandú"),
        "a_very_long_table_name_for_te_ñandú_ñandú_ñandú_ñand_key"
    );
    assert_eq!(
        clip_identifier(&"é".repeat(43)),
        "é".repeat(31),
        "a stated name is cut as Postgres cuts it"
    );
}

#[test]
fn every_helper_respects_the_limit() {
    let long = "x".repeat(100);
    for name in [
        primary_key_name(&long),
        foreign_key_name(&long, &long),
        expected_unique_constraint_name(&long, &long),
        type_check_name(&long, &long),
        expected_check_constraint_name(&long, &long),
        expected_model_constraint_name(&long, &rule(min_length("body", 2))),
        expected_model_index_name(&long, &[long.clone(), long.clone()]),
        make_object_name(&"é".repeat(40), None, "idx"),
    ] {
        assert!(name.len() <= MAX_IDENTIFIER_BYTES, "{name}");
    }
}

fn text(unique: bool) -> Value {
    json!({ "kind": "text", "annotations": { "db": { "pgType": "TEXT", "unique": unique } } })
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

fn id() -> Value {
    json!({ "kind": "integer", "primaryKey": true, "required": true,
            "annotations": { "db": { "pgType": "INTEGER", "unique": false } } })
}

fn parse(models: Vec<Value>) -> SchemaAst {
    parser::parse(&json!({ "astVersion": 2, "models": models }).to_string()).unwrap()
}

/// `order.item_code` and `order_item.code` both make `order_item_code_key`, and unique
/// constraints share one namespace per schema: the first in order of table name keeps it and the
/// second gets the digit Postgres would have given it.
fn clashing_uniques() -> SchemaAst {
    parse(vec![
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
    ])
}

#[test]
fn a_clash_across_tables_takes_a_digit() {
    let names = ObjectNames::for_schema(&clashing_uniques());
    assert_eq!(names.unique("order", "item_code"), "order_item_code_key");
    assert_eq!(names.unique("order_item", "code"), "order_item_code_key1");
}

/// Declaration order decides no name: the same models and fields in another order take the same
/// names, so reordering a schema never renames another model's constraints, indexes or sequences.
#[test]
fn reordering_models_and_fields_renames_nothing() {
    let serial = json!({ "kind": "serial", "required": true });
    let email = json!({ "kind": "email", "annotations": { "db": { "pgType": "TEXT" } } });
    let order = |reversed: bool| {
        let fields = if reversed {
            json!({ "tag_email": email, "item_id": serial, "item_code": text(true), "id": id() })
        } else {
            json!({ "id": id(), "item_code": text(true), "item_id": serial, "tag_email": email })
        };
        model("Order", "order", fields)
    };
    let item = || {
        model(
            "OrderItem",
            "order_item",
            json!({ "id": id(), "code": text(true), "id_seq": text(false), "tag_email": email }),
        )
    };
    let forward = parse(vec![order(false), item()]);
    let backward = parse(vec![item(), order(true)]);
    let keys = |ast: &SchemaAst| {
        let mut keys: Vec<String> = desired_objects(ast, "public")
            .unwrap()
            .into_iter()
            .map(|o| o.key.to_string())
            .collect();
        keys.sort();
        keys
    };
    assert_eq!(keys(&forward), keys(&backward));
    for ast in [&forward, &backward] {
        let names = ObjectNames::for_schema(ast);
        assert_eq!(names.unique("order", "item_code"), "order_item_code_key");
        assert_eq!(names.unique("order_item", "code"), "order_item_code_key1");
    }
}

#[test]
fn the_desired_set_keys_are_the_names_the_generator_writes() {
    let ast = clashing_uniques();
    let desired = desired_objects(&ast, "public").unwrap();
    let uniques: Vec<(&str, &str, &str)> = desired
        .iter()
        .filter(|o| o.key.kind == ObjectKind::Unique)
        .map(|o| {
            (
                o.key.parent.as_str(),
                o.key.name.as_str(),
                o.create_sql.as_str(),
            )
        })
        .collect();
    assert_eq!(
        uniques.len(),
        2,
        "one was lost to the other's key: {uniques:?}"
    );
    for (table, name, create) in &uniques {
        assert!(
            create.contains(&format!("\"{name}\"")),
            "{table}: key {name} is not the name its CREATE gives: {create}"
        );
    }
    let tables: Vec<&str> = desired
        .iter()
        .filter(|o| o.key.kind == ObjectKind::Table)
        .map(|o| o.create_sql.as_str())
        .collect();
    assert!(
        tables
            .iter()
            .any(|sql| sql.contains("CONSTRAINT \"order_item_code_key1\" UNIQUE")),
        "the CREATE TABLE names the inline unique differently: {tables:?}"
    );
}

/// A long model index is created under the name its desired key carries: the push used to write
/// the full `{table}_{fields}_idx`, Postgres cut it, and the ledger looked for one it never found.
#[test]
fn a_long_index_is_created_under_its_key() {
    let table = "organization_membership_invitations";
    let mut m = model(
        "Invite",
        table,
        json!({ "id": id(), "notification_preference_email": text(false),
                "notification_preference_phone": text(false) }),
    );
    m["annotations"]["db"]["indexes"] = json!([
        { "fields": ["notification_preference_email", "notification_preference_phone"],
          "unique": false, "using": "btree" }
    ]);
    m["options"]["singleton"] = json!(true);
    let ast = parse(vec![m]);
    let desired = desired_objects(&ast, "public").unwrap();
    let indexes: Vec<_> = desired
        .iter()
        .filter(|o| o.key.kind == ObjectKind::Index)
        .collect();
    assert_eq!(indexes.len(), 2, "{indexes:?}");
    for index in indexes {
        assert!(
            index.key.name.len() <= MAX_IDENTIFIER_BYTES,
            "{}",
            index.key.name
        );
        assert!(
            index
                .create_sql
                .contains(&format!("\"{}\"", index.key.name)),
            "key {} is not the name its CREATE gives: {}",
            index.key.name,
            index.create_sql
        );
    }
    let mut names: Vec<&str> = desired
        .iter()
        .filter(|o| o.key.kind == ObjectKind::Index)
        .map(|o| o.key.name.as_str())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "organization_membership_invit_notification_preference_email_idx",
            "organization_membership_invitations_singleton_idx",
        ]
    );
}

/// A table name long enough that `{table}_{suffix}` passes 63 bytes: every policy name is fitted
/// as Postgres fits its own, and the key is the name the `CREATE POLICY` gives.
#[test]
fn long_policy_names_are_fitted_and_match_their_keys() {
    let table = "product_variant_images_for_the_seasonal_catalogue_collection_x";
    assert_eq!(
        policy_name(table, "select"),
        "product_variant_images_for_the_seasonal_catalogue_collec_select"
    );
    let mut m = model("Image", table, json!({ "id": id(), "path": text(false) }));
    m["annotations"]["platform"]["access"] = json!({
        "read": { "type": "public" }, "create": { "type": "authenticated" },
        "update": { "type": "authenticated" }, "delete": { "type": "authenticated" }
    });
    let ast = parse(vec![m]);
    let desired = desired_objects(&ast, "public").unwrap();
    let policies: Vec<_> = desired
        .iter()
        .filter(|o| o.key.kind == ObjectKind::Policy && o.key.schema == "public")
        .collect();
    // One per rule, and the two that admit a Studio user, fitted the same way.
    assert_eq!(policies.len(), 6, "{policies:?}");
    for policy in policies {
        assert!(
            policy.key.name.len() <= MAX_IDENTIFIER_BYTES,
            "{}",
            policy.key.name
        );
        assert!(
            policy
                .create_sql
                .contains(&format!("CREATE POLICY \"{}\"", policy.key.name)),
            "key {} is not the name its CREATE gives: {}",
            policy.key.name,
            policy.create_sql
        );
    }
}

/// `product_variant_images` storing into `product-variant-gallery-images-public` names its
/// storage policies past 63 bytes; they are fitted, and the key is the name created.
#[test]
fn long_storage_policy_names_are_fitted() {
    let file = json!({ "kind": "image", "bucket": "product-variant-gallery-images-public",
                       "annotations": { "db": { "pgType": "JSONB" } } });
    let mut m = model(
        "ProductVariantImage",
        "product_variant_images",
        json!({ "id": id(), "image": file }),
    );
    m["annotations"]["platform"]["access"] =
        json!({ "read": { "type": "public" }, "create": { "type": "authenticated" } });
    let ast = parse(vec![m]);
    let desired = desired_objects(&ast, "public").unwrap();
    let names: Vec<&str> = desired
        .iter()
        .filter(|o| o.key.kind == ObjectKind::Policy && o.key.schema == "storage")
        .map(|o| o.key.name.as_str())
        .collect();
    assert!(
        names.contains(&"product_variant_images_product-variant-gallery-images-publi_sel"),
        "{names:?}"
    );
    assert!(
        names.contains(&"product_variant_images_product-variant-gallery-images-publi_ins"),
        "{names:?}"
    );
    for name in names {
        assert!(name.len() <= MAX_IDENTIFIER_BYTES, "{name}");
    }
}

/// A serial's sequence is keyed by Postgres's name for it, however long, where it used to be left
/// unrecorded past 63 bytes.
#[test]
fn a_long_serial_sequence_is_predicted() {
    let table = "a_very_long_table_name_for_testing_postgres_identifier_truncati";
    let ast = parse(vec![model(
        "Long",
        table,
        json!({ "id": { "kind": "serial", "primaryKey": true, "required": true } }),
    )]);
    let desired = desired_objects(&ast, "public").unwrap();
    let sequences: Vec<&str> = desired
        .iter()
        .filter(|o| o.key.kind == ObjectKind::Sequence)
        .map(|o| o.key.name.as_str())
        .collect();
    assert_eq!(
        sequences,
        ["a_very_long_table_name_for_testing_postgres_identifier_t_id_seq"]
    );
}

/// Check and foreign key names are chosen as Postgres chooses them: free of every constraint name
/// in the schema, not only those on the same table. `post.tag_email` and `post_tag.email` both
/// make `post_tag_email_check`, and the second takes the digit.
#[test]
fn a_check_clash_across_tables_takes_a_digit() {
    let email = json!({ "kind": "email", "annotations": { "db": { "pgType": "TEXT" } } });
    let ast = parse(vec![
        model("Post", "post", json!({ "id": id(), "tag_email": email })),
        model("PostTag", "post_tag", json!({ "id": id(), "email": email })),
    ]);
    let names = ObjectNames::for_schema(&ast);
    assert_eq!(
        names.type_check("post", "tag_email"),
        "post_tag_email_check"
    );
    assert_eq!(
        names.type_check("post_tag", "email"),
        "post_tag_email_check1"
    );
    let desired = desired_objects(&ast, "public").unwrap();
    let checks: Vec<&str> = desired
        .iter()
        .filter(|o| o.key.kind == ObjectKind::Check)
        .map(|o| o.key.name.as_str())
        .collect();
    assert!(checks.contains(&"post_tag_email_check1"), "{checks:?}");
}

/// A table name at the identifier limit, with every generated function and trigger it can have:
/// each name fits, so Postgres stores what the desired set keys.
fn long_everything() -> Value {
    let table = "a_very_long_table_name_for_testing_postgres_identifier_truncati";
    let mut m = model(
        "Long",
        table,
        json!({
            "id": id(),
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
    m
}

fn with_publishing(models: Vec<Value>) -> SchemaAst {
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
    parser::parse(&doc.to_string()).unwrap()
}

#[test]
fn every_generated_name_of_a_long_table_fits() {
    let ast = with_publishing(vec![long_everything()]);
    let desired = desired_objects(&ast, "public").unwrap();
    let kinds = [
        ObjectKind::Function,
        ObjectKind::Trigger,
        ObjectKind::Policy,
        ObjectKind::Table,
        ObjectKind::Index,
        ObjectKind::Check,
        ObjectKind::PrimaryKey,
        ObjectKind::ForeignKey,
        ObjectKind::Unique,
        ObjectKind::View,
    ];
    let mut seen = 0;
    for object in desired.iter().filter(|o| kinds.contains(&o.key.kind)) {
        let ident = object.key.name.split('(').next().unwrap();
        assert!(
            ident.len() <= MAX_IDENTIFIER_BYTES,
            "{:?} {} is {} bytes",
            object.key.kind,
            ident,
            ident.len()
        );
        seen += 1;
    }
    let names: Vec<&str> = desired.iter().map(|o| o.key.name.as_str()).collect();
    for expected in [
        "a_very_long_table_name_for_testing_postgres_identifier_versions",
        "a_very_long_table_name_for_testing_postgres__updated_at_trigger",
    ] {
        assert!(
            names.iter().any(|n| n.starts_with(expected)),
            "{expected} missing from {names:?}"
        );
    }
    assert!(seen > 20, "{seen}");
}

// Model-level constraints (CK1): named for what they check, not where they sit in the list.

fn rule(value: Value) -> AccessRule {
    serde_json::from_value(value).expect("a constraint rule")
}

fn col(name: &str) -> Value {
    json!({ "kind": "column", "name": name })
}

fn lit(value: Value) -> Value {
    json!({ "kind": "literal", "value": value })
}

fn length(column: &str) -> Value {
    json!({ "kind": "length", "column": column, "form": "chars" })
}

fn items(column: &str) -> Value {
    json!({ "kind": "itemCount", "column": column, "form": "array" })
}

fn compare(left: Value, op: &str, right: Value) -> Value {
    json!({ "type": "compare", "op": op, "left": left, "right": right })
}

fn min_length(column: &str, n: i64) -> Value {
    compare(length(column), "gte", lit(json!(n)))
}

fn not_null(column: &str) -> Value {
    json!({ "type": "nullCheck", "operand": col(column), "isNull": false })
}

fn name_of(value: Value) -> String {
    expected_model_constraint_name("chat_message", &rule(value))
}

#[test]
fn a_model_constraint_is_named_for_what_it_checks() {
    let eq_draft = compare(col("status"), "eq", lit(json!("draft")));
    let cases = [
        (min_length("body", 2), "chat_message_body_min_length"),
        (
            compare(length("body"), "gt", lit(json!(1))),
            "chat_message_body_min_length",
        ),
        (
            compare(length("body"), "lte", lit(json!(500))),
            "chat_message_body_max_length",
        ),
        (
            compare(length("body"), "lt", lit(json!(500))),
            "chat_message_body_max_length",
        ),
        (
            compare(length("code"), "eq", lit(json!(6))),
            "chat_message_code_length_eq",
        ),
        // A literal on the left reads the other way round.
        (
            compare(lit(json!(2)), "lte", length("body")),
            "chat_message_body_min_length",
        ),
        (
            compare(items("tags"), "gte", lit(json!(1))),
            "chat_message_tags_min_items",
        ),
        (
            compare(items("tags"), "lte", lit(json!(3))),
            "chat_message_tags_max_items",
        ),
        (
            compare(col("price"), "gte", lit(json!(0))),
            "chat_message_price_min",
        ),
        (
            compare(col("price"), "lt", lit(json!(100))),
            "chat_message_price_max",
        ),
        (eq_draft.clone(), "chat_message_status_eq"),
        (
            compare(col("status"), "neq", lit(json!("gone"))),
            "chat_message_status_ne",
        ),
        (
            compare(col("sku"), "like", lit(json!("A%"))),
            "chat_message_sku_like",
        ),
        (
            compare(col("starts_at"), "lte", col("ends_at")),
            "chat_message_starts_at_lte_ends_at",
        ),
        (compare(col("a"), "gt", col("b")), "chat_message_a_gt_b"),
        (
            compare(length("a"), "lte", length("b")),
            "chat_message_a_length_lte_b_length",
        ),
        (
            not_null("published_at"),
            "chat_message_published_at_not_null",
        ),
        (
            json!({ "type": "nullCheck", "operand": col("deleted_at"), "isNull": true }),
            "chat_message_deleted_at_null",
        ),
        (
            json!({ "type": "matches", "column": "sku", "pattern": "^[A-Z]{3}$" }),
            "chat_message_sku_format",
        ),
        (
            json!({ "type": "not", "rule": { "type": "nullCheck",
                    "operand": col("deleted_at"), "isNull": true } }),
            "chat_message_deleted_at_not_null",
        ),
        (
            json!({ "type": "not", "rule": eq_draft.clone() }),
            "chat_message_not_status_eq",
        ),
        (
            json!({ "type": "any", "rules": [eq_draft, not_null("published_at")] }),
            "chat_message_status_eq_or_published_at_not_null",
        ),
        (
            json!({ "type": "all", "rules": [
                min_length("body", 2), compare(length("body"), "lte", lit(json!(500)))
            ] }),
            "chat_message_body_min_length_and_body_max_length",
        ),
    ];
    for (value, want) in cases {
        let shown = value.to_string();
        assert_eq!(name_of(value), want, "{shown}");
    }
}

/// The name says what is checked, not the bound: tightening a minimum from 2 to 3 keeps the
/// constraint's name, so the push replaces it under that name rather than renaming it.
#[test]
fn the_bound_is_not_part_of_the_name() {
    assert_eq!(
        name_of(min_length("body", 2)),
        name_of(min_length("body", 3))
    );
}

fn hash_suffixed(name: &str) -> bool {
    let Some((_, suffix)) = name.rsplit_once('_') else {
        return false;
    };
    suffix.len() == 8 && suffix.chars().all(|c| c.is_ascii_hexdigit())
}

fn reminders_lte(later: &str) -> AccessRule {
    rule(compare(col("first_reminder_sent_at"), "lte", col(later)))
}

#[test]
fn a_long_name_is_cut_to_the_limit_with_a_hash_of_the_whole() {
    let table = "organization_membership_invitation_reminder_schedules";
    let first = expected_model_constraint_name(table, &reminders_lte("second_reminder_sent_at"));
    let second = expected_model_constraint_name(table, &reminders_lte("third_reminder_sent_at"));
    for name in [&first, &second] {
        assert_eq!(name.len(), MAX_IDENTIFIER_BYTES, "{name}");
        assert!(name.starts_with(table), "{name}");
        assert!(hash_suffixed(name), "{name}");
    }
    assert_ne!(
        first, second,
        "the same 54-byte prefix, told apart by the hash"
    );
    assert_eq!(
        first,
        expected_model_constraint_name(table, &reminders_lte("second_reminder_sent_at")),
        "deterministic"
    );
    // Cut on a character boundary.
    let wide = expected_model_constraint_name(&"\u{e9}".repeat(40), &rule(min_length("body", 2)));
    assert!(wide.len() <= MAX_IDENTIFIER_BYTES, "{wide}");
    assert!(hash_suffixed(&wide), "{wide}");
    // A name that fits is never hashed.
    assert!(!hash_suffixed(&name_of(min_length("body", 2))));
}

fn with_rules(table: &str, rules: Vec<Value>) -> SchemaAst {
    let mut m = model(
        "Message",
        table,
        json!({ "id": id(), "body": text(false), "tags": text(false) }),
    );
    m["annotations"]["db"]["constraints"] = json!(rules);
    parse(vec![m])
}

/// The name each of the one model's rules gets, in declared order.
fn rule_names(ast: &SchemaAst) -> Vec<String> {
    let names = ObjectNames::for_schema(ast);
    let model = &ast.models[0];
    model
        .annotations
        .db
        .constraints
        .iter()
        .enumerate()
        .map(|(index, rule)| names.model_constraint(model.table_name(), index, rule))
        .collect()
}

/// Two rules that would take the same name: the one whose rule sorts first keeps it and the other
/// takes `_2`, whatever order they are declared in, so reordering renames nothing.
#[test]
fn two_rules_wanting_one_name_are_told_apart_whatever_their_order() {
    let (two, five) = (min_length("body", 2), min_length("body", 5));
    let forward = with_rules("chat_message", vec![two.clone(), five.clone()]);
    assert_eq!(
        rule_names(&forward),
        [
            "chat_message_body_min_length",
            "chat_message_body_min_length_2"
        ]
    );
    let backward = with_rules("chat_message", vec![five, two]);
    assert_eq!(
        rule_names(&backward),
        [
            "chat_message_body_min_length_2",
            "chat_message_body_min_length"
        ]
    );
}

/// A collision on a long table still fits, and still differs.
#[test]
fn a_collision_on_a_long_table_still_fits() {
    let table = "organization_membership_invitation_reminder_schedules_x";
    let ast = with_rules(
        table,
        vec![
            min_length("body", 2),
            min_length("body", 5),
            min_length("body", 9),
        ],
    );
    let chosen = rule_names(&ast);
    for name in &chosen {
        assert!(name.len() <= MAX_IDENTIFIER_BYTES, "{name}");
    }
    let distinct: std::collections::BTreeSet<&String> = chosen.iter().collect();
    assert_eq!(distinct.len(), 3, "{chosen:?}");
}

/// The desired set carries the readable name, and its `CREATE` gives that name.
#[test]
fn the_desired_check_is_created_under_its_readable_name() {
    let ast = with_rules("chat_message", vec![min_length("body", 2)]);
    let desired = desired_objects(&ast, "public").unwrap();
    let check = desired
        .iter()
        .find(|o| o.key.kind == ObjectKind::Check && o.key.name == "chat_message_body_min_length")
        .unwrap_or_else(|| panic!("{desired:?}"));
    assert!(
        check.create_sql.contains(
            r#"ADD CONSTRAINT "chat_message_body_min_length" CHECK (char_length("body") >= 2)"#
        ),
        "{}",
        check.create_sql
    );
}

/// A rule keeps the name the ledger records for it: once the rule that held the plain name is
/// removed, the one that took `_2` keeps `_2`, and of two rules the one recorded under the plain
/// name keeps it whichever sorts first.
#[test]
fn a_recorded_rule_name_is_kept() {
    let table = "chat_message";
    let mut alone = with_rules(table, vec![min_length("body", 5)]);
    assert_eq!(rule_names(&alone), ["chat_message_body_min_length"]);
    alone.recorded_names.record(
        table,
        "check",
        "chat_message_body_min_length_2",
        Some(r#"char_length("body") >= 5"#),
    );
    assert_eq!(rule_names(&alone), ["chat_message_body_min_length_2"]);

    let mut both = with_rules(table, vec![min_length("body", 2), min_length("body", 5)]);
    both.recorded_names.record(
        table,
        "check",
        "chat_message_body_min_length",
        Some(r#"char_length("body") >= 5"#),
    );
    assert_eq!(
        rule_names(&both),
        [
            "chat_message_body_min_length_2",
            "chat_message_body_min_length"
        ]
    );
}

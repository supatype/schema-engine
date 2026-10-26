//! `Owner<"relation">` and the models a relation can reach (O1 to O4, decision D11).
//!
//! The engine could not tell an auth user id from any other UUID key, so an owner rule through a
//! relation to an ordinary model compiled to a comparison of the caller's id with that model's key,
//! which no caller ever matches. The CLI now marks a `SupatypeAuthUserId` field
//! (`annotations.db.authUserId`), and:
//!
//! - O1: a relation owner must reach a user model (keyed by a marked field) or a model with an
//!   owner rule of its own, and anything else is refused;
//! - O2: an owner that is a plain UUID, not marked as an auth user id, is warned about;
//! - O3: a related model's owner is found in any of its rules, so `read: Public` beside
//!   `update: Owner<"user_id">` still yields a policy that matches, and a related model owned
//!   through its own `id` is compared directly, with no subquery;
//! - O4: a chain of more than one relation is refused, since only one is followed.

use serde_json::{json, Value};
use supatype_engine::generator::sql::rls;
use supatype_engine::parser::{self, ast::SchemaAst};

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

fn uuid_pk(auth_user_id: bool) -> Value {
    let mut db = json!({ "pgType": "UUID", "unique": false });
    if auth_user_id {
        db["authUserId"] = json!(true);
    }
    json!({ "kind": "uuid", "primaryKey": true, "required": true,
            "default": { "kind": "genRandomUuid" }, "annotations": { "db": db } })
}

fn uuid(auth_user_id: bool) -> Value {
    let mut db = json!({ "pgType": "UUID", "unique": false });
    if auth_user_id {
        db["authUserId"] = json!(true);
    }
    json!({ "kind": "uuid", "required": true, "annotations": { "db": db } })
}

fn text() -> Value {
    json!({ "kind": "text", "required": false,
            "annotations": { "db": { "pgType": "TEXT", "unique": false } } })
}

fn belongs_to(target: &str, fk: &str) -> Value {
    json!({ "kind": "relation", "cardinality": "belongsTo", "target": target,
            "annotations": { "db": { "foreignKey": fk } } })
}

fn owner(field: &str) -> Value {
    json!({ "type": "owner", "field": field })
}

fn public() -> Value {
    json!({ "type": "public" })
}

fn model(name: &str, fields: Value, access: Value) -> Value {
    json!({
        "name": name,
        "fields": fields,
        "options": { "timestamps": false, "softDelete": false },
        "annotations": {
            "db": { "tableName": name.to_lowercase(), "indexes": [] },
            "platform": { "access": access }
        }
    })
}

fn document(models: Vec<Value>) -> String {
    json!({ "astVersion": 2, "models": models }).to_string()
}

/// A user model: keyed by the auth user id when `marked`, else by a plain UUID.
fn user(marked: bool) -> Value {
    model(
        "User",
        json!({ "id": uuid_pk(marked), "name": text() }),
        json!({ "read": public() }),
    )
}

/// A post owned through its author.
fn post(access: Value) -> Value {
    model(
        "Post",
        json!({ "id": uuid_pk(false), "title": text(), "author": belongs_to("User", "author_id") }),
        access,
    )
}

/// A comment owned through the post it is on.
fn comment() -> Value {
    model(
        "Comment",
        json!({ "id": uuid_pk(false), "body": text(), "post": belongs_to("Post", "post_id") }),
        json!({ "read": public(), "update": owner("post"), "delete": owner("post") }),
    )
}

fn parse_err(schema: &str) -> String {
    parser::parse(schema)
        .expect_err("schema must be refused")
        .to_string()
}

fn model_named<'a>(ast: &'a SchemaAst, name: &str) -> &'a parser::ast::ModelAst {
    ast.models
        .iter()
        .find(|m| m.name == name)
        .unwrap_or_else(|| panic!("model {name} exists"))
}

fn update_expr(ast: &SchemaAst, name: &str) -> String {
    let model = model_named(ast, name);
    let rule = model.access().update.clone().expect("update rule");
    rls::access_rule_to_expr(ast, model, &rule, "public")
}

const UID: &str = "(SELECT _supatype.jwt_uid())";

// ---------------------------------------------------------------------------------------------
// O1: what a relation owner may reach
// ---------------------------------------------------------------------------------------------

#[test]
fn a_relation_owner_to_a_user_model_compares_the_key_directly() {
    let schema = document(vec![
        user(true),
        post(json!({ "read": public(), "update": owner("author") })),
    ]);
    let ast = parser::parse(&schema).expect("a post owned by its author parses");
    assert_eq!(update_expr(&ast, "Post"), format!("{UID} = \"author_id\""));
}

#[test]
fn a_relation_owner_to_a_model_that_is_neither_a_user_nor_owned_is_refused() {
    let schema = document(vec![
        user(true),
        model(
            "Category",
            json!({ "id": uuid_pk(false), "name": text() }),
            json!({ "read": public() }),
        ),
        model(
            "Post",
            json!({ "id": uuid_pk(false), "category": belongs_to("Category", "category_id") }),
            json!({ "read": public(), "update": owner("category") }),
        ),
    ]);
    let message = parse_err(&schema);
    assert!(
        message.contains("Model 'Post': Owner<\"category\"> is invalid"),
        "{message}"
    );
    assert!(
        message.contains("model 'Category', which is neither a user model"),
        "{message}"
    );
    assert!(message.contains("SupatypeAuthUserId"), "{message}");
}

/// A model keyed by a UUID the database does not generate was taken for a user model. Nothing in
/// the schema said so, and the CLI generates every UUID key, so only the marker counts now.
#[test]
fn an_unmarked_uuid_key_does_not_make_a_user_model() {
    let mut plain = user(false);
    plain["fields"]["id"]
        .as_object_mut()
        .unwrap()
        .remove("default");
    let schema = document(vec![
        plain,
        post(json!({ "read": public(), "update": owner("author") })),
    ]);
    let message = parse_err(&schema);
    assert!(
        message.contains("model 'User', which is neither a user model"),
        "{message}"
    );
}

#[test]
fn a_relation_owner_written_as_its_key_column_is_checked_too() {
    let schema = document(vec![
        user(false),
        post(json!({ "read": public(), "update": owner("author_id") })),
    ]);
    let message = parse_err(&schema);
    assert!(
        message.contains("Owner<\"author_id\"> is invalid"),
        "{message}"
    );
}

// ---------------------------------------------------------------------------------------------
// O2: a plain UUID owner is warned about
// ---------------------------------------------------------------------------------------------

fn note(owner_marked: bool) -> String {
    document(vec![model(
        "Note",
        json!({ "id": uuid_pk(false), "owner_id": uuid(owner_marked), "body": text() }),
        json!({ "read": owner("owner_id"), "update": owner("owner_id") }),
    )])
}

#[test]
fn a_plain_uuid_owner_is_accepted_with_a_warning() {
    let ast = parser::parse(&note(false)).expect("a plain UUID owner still parses (A7-N3)");
    let warnings: Vec<&String> = ast
        .warnings
        .iter()
        .filter(|w| w.contains("Owner<\"owner_id\">"))
        .collect();
    assert_eq!(
        warnings.len(),
        1,
        "one warning per owner field: {:?}",
        ast.warnings
    );
    assert!(
        warnings[0].contains("Model 'Note'") && warnings[0].contains("SupatypeAuthUserId"),
        "{}",
        warnings[0]
    );
}

#[test]
fn an_owner_marked_as_an_auth_user_id_is_not_warned_about() {
    let ast = parser::parse(&note(true)).expect("parses");
    assert!(
        ast.warnings.iter().all(|w| !w.contains("Owner<")),
        "{:?}",
        ast.warnings
    );
}

// ---------------------------------------------------------------------------------------------
// O3: the related model's owner, wherever it is declared
// ---------------------------------------------------------------------------------------------

/// Read is public and only update names the owner: the related model's owner is still its author,
/// so a comment's owner is the author of its post. The rule was `read.or(update)`, which stopped at
/// `Public` and compared the caller's id with the post's id, which no caller matches.
#[test]
fn a_public_read_does_not_hide_the_related_models_owner() {
    let schema = document(vec![
        user(true),
        post(json!({ "read": public(), "update": owner("author"), "delete": owner("author") })),
        comment(),
    ]);
    let ast = parser::parse(&schema).expect("parses");
    assert_eq!(
        update_expr(&ast, "Comment"),
        format!(
            "EXISTS (SELECT 1 FROM \"post\" WHERE \"post\".\"id\" = \"post_id\" AND {UID} = \"post\".\"author_id\")"
        )
    );
}

/// A related model owned through its own `id` is owned by whoever that id is, so the key is
/// compared directly: the same answer as the subquery, without one.
#[test]
fn a_related_model_owned_by_its_id_is_compared_directly() {
    let schema = document(vec![
        model(
            "Profile",
            json!({ "id": uuid_pk(false), "name": text() }),
            json!({ "read": owner("id"), "update": owner("id") }),
        ),
        model(
            "Setting",
            json!({ "id": uuid_pk(false), "profile": belongs_to("Profile", "profile_id") }),
            json!({ "read": public(), "update": owner("profile") }),
        ),
    ]);
    let ast = parser::parse(&schema).expect("parses");
    assert_eq!(
        update_expr(&ast, "Setting"),
        format!("{UID} = \"profile_id\"")
    );
}

// ---------------------------------------------------------------------------------------------
// O4: one relation, no more
// ---------------------------------------------------------------------------------------------

#[test]
fn an_ownership_chain_of_two_relations_is_refused() {
    let schema = document(vec![
        user(true),
        model(
            "Blog",
            json!({ "id": uuid_pk(false), "owner": belongs_to("User", "owner_id") }),
            json!({ "read": public(), "update": owner("owner") }),
        ),
        model(
            "Post",
            json!({ "id": uuid_pk(false), "blog": belongs_to("Blog", "blog_id") }),
            json!({ "read": public(), "update": owner("blog") }),
        ),
        comment(),
    ]);
    let message = parse_err(&schema);
    assert!(
        message.contains("Model 'Comment': Owner<\"post\"> is invalid"),
        "{message}"
    );
    assert!(message.contains("more than one relation"), "{message}");
    assert!(
        message.contains("Post") && message.contains("Blog"),
        "{message}"
    );
}

#[test]
fn a_chain_ending_at_a_user_model_after_one_relation_is_accepted() {
    let schema = document(vec![
        user(true),
        post(json!({ "read": public(), "update": owner("author") })),
        comment(),
    ]);
    parser::parse(&schema).expect("comment -> post -> user is one relation from the comment");
}

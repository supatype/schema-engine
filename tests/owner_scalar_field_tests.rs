//! `Owner<"f">` on a scalar UUID field (A7-N3, decision D11 (a)).
//!
//! An owner is `id`, a relation that holds its key on this model, or a field of type UUID or
//! SupatypeAuthUserId. Anything else is refused with a message that names the field, its type and
//! what is allowed. The same rules apply wherever an `Owner` can appear: the row clauses, the
//! update check, per-field rules and a membership filter, which is checked against its own table.

mod common;

use serde_json::{json, Value};
use supatype_engine::generator::sql::{field_views, rls};
use supatype_engine::parser::{self, ast::SchemaAst};
use supatype_engine::state::database_state::DatabaseState;

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

fn uuid_pk() -> Value {
    json!({ "kind": "uuid", "primaryKey": true, "required": true,
            "default": { "kind": "genRandomUuid" },
            "annotations": { "db": { "pgType": "UUID", "unique": false } } })
}

fn uuid(required: bool) -> Value {
    json!({ "kind": "uuid", "required": required,
            "annotations": { "db": { "pgType": "UUID", "unique": false } } })
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

fn model(name: &str, table: &str, fields: Value, access: Value) -> Value {
    json!({
        "name": name,
        "fields": fields,
        "options": { "timestamps": false, "softDelete": false },
        "annotations": {
            "db": { "tableName": table, "indexes": [] },
            "platform": { "access": access }
        }
    })
}

fn document(models: Vec<Value>) -> String {
    json!({ "astVersion": 2, "models": models }).to_string()
}

/// The A7-N3 reproduction: a note owned through a plain `owner_id: UUID` column.
fn note(access: Value) -> String {
    document(vec![model(
        "Note",
        "note",
        json!({ "id": uuid_pk(), "owner_id": uuid(true), "body": text() }),
        access,
    )])
}

fn note_owned_by(field: &str) -> String {
    note(json!({
        "read": owner(field), "create": owner(field),
        "update": owner(field), "delete": owner(field)
    }))
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

const OWNER_ID_EXPR: &str = "(SELECT _supatype.jwt_uid()) = \"owner_id\"";

// ---------------------------------------------------------------------------------------------
// Row rules
// ---------------------------------------------------------------------------------------------

#[test]
fn owner_on_a_declared_uuid_field_is_accepted() {
    let ast = parser::parse(&note_owned_by("owner_id")).expect("A7-N3 schema parses");
    let note = model_named(&ast, "Note");
    let access = note.access();
    for rule in [&access.read, &access.create, &access.update, &access.delete] {
        let rule = rule.as_ref().expect("rule kept");
        assert_eq!(
            serde_json::to_value(rule).unwrap(),
            owner("owner_id"),
            "a scalar owner field is kept as written"
        );
        assert_eq!(
            rls::access_rule_to_expr(&ast, note, rule, "public"),
            OWNER_ID_EXPR
        );
    }
}

#[test]
fn owner_policies_compare_the_uid_with_the_uuid_column() {
    let ast = parser::parse(&note_owned_by("owner_id")).expect("parses");
    let sql = rls::generate(&ast, "public").expect("policies render");
    assert_eq!(
        sql.matches(OWNER_ID_EXPR).count(),
        5,
        "select, insert, update USING and CHECK, delete all compare with owner_id:\n{sql}"
    );
}

#[test]
fn owner_on_a_text_field_names_the_field_its_type_and_what_is_allowed() {
    let message = parse_err(&note_owned_by("body"));
    assert!(
        message.contains("Model 'Note': Owner<\"body\"> is invalid"),
        "{message}"
    );
    assert!(
        message.contains("field 'body' is of type text"),
        "{message}"
    );
    assert!(
        message.contains(
            "An owner must be \"id\", a relation field, or a field of type UUID or SupatypeAuthUserId"
        ),
        "{message}"
    );
    assert!(message.contains("[id, owner_id]"), "{message}");
}

#[test]
fn owner_on_an_unknown_field_lists_what_is_allowed() {
    let message = parse_err(&note_owned_by("author_id"));
    assert!(
        message.contains(
            "Model 'Note': Owner<\"author_id\"> is invalid: there is no field 'author_id'"
        ),
        "{message}"
    );
    assert!(message.contains("[id, owner_id]"), "{message}");
    assert!(!message.contains("kernel field names"), "{message}");
}

#[test]
fn update_check_owner_on_a_text_field_is_refused() {
    let schema = note(json!({
        "read": owner("owner_id"),
        "update": owner("owner_id"),
        "updateCheck": owner("body")
    }));
    let message = parse_err(&schema);
    assert!(message.contains("Owner<\"body\"> is invalid"), "{message}");
}

#[test]
fn owner_nested_in_any_on_a_text_field_is_refused() {
    let schema = note(json!({
        "read": { "type": "any", "rules": [{ "type": "role", "roles": ["admin"] }, owner("body")] }
    }));
    let message = parse_err(&schema);
    assert!(message.contains("Owner<\"body\"> is invalid"), "{message}");
}

// ---------------------------------------------------------------------------------------------
// Field rules: predicates, tier 1 labels, tier 2 views
// ---------------------------------------------------------------------------------------------

fn note_with_field_rule(field: &str) -> String {
    note(json!({
        "read": { "type": "authenticated" },
        "update": { "type": "authenticated" },
        "fields": { "body": { "read": owner(field), "write": owner(field) } }
    }))
}

#[test]
fn field_owner_on_a_uuid_field_reaches_predicates_labels_and_views() {
    let ast = parser::parse(&note_with_field_rule("owner_id")).expect("parses");

    let functions = rls::generate_can_functions(&ast, "public");
    assert!(
        functions.contains(&format!("SELECT {OWNER_ID_EXPR}")),
        "the read predicate compares with owner_id:\n{functions}"
    );
    assert!(
        functions.contains(&format!("({OWNER_ID_EXPR}) AND ({OWNER_ID_EXPR})")),
        "the write predicate is conjoined with the read one:\n{functions}"
    );

    let labels = rls::field_labels(&ast, "public");
    assert_eq!(labels.len(), 1, "{labels:?}");
    assert_eq!(labels[0].column, "body");
    assert!(
        labels[0].label.contains("can_read_note__body"),
        "{labels:?}"
    );

    let plan = field_views::field_view_plan(&ast, &DatabaseState::default());
    let views = field_views::render_field_views(&ast, &plan, "public");
    assert!(
        views.contains(OWNER_ID_EXPR),
        "the tier 2 view masks with the same predicate:\n{views}"
    );
}

#[test]
fn field_owner_on_a_text_field_is_refused() {
    let message = parse_err(&note_with_field_rule("body"));
    assert!(message.contains("Owner<\"body\"> is invalid"), "{message}");
    assert!(
        message.contains("field 'body' is of type text"),
        "{message}"
    );
}

// ---------------------------------------------------------------------------------------------
// Relations keep their existing behaviour: the key compared directly, or ownership looked up
// ---------------------------------------------------------------------------------------------

fn post_by(target: Value) -> String {
    document(vec![
        target,
        model(
            "Post",
            "post",
            json!({ "id": uuid_pk(), "author": belongs_to("Author", "author_id") }),
            json!({ "read": owner("author"), "update": owner("author_id") }),
        ),
    ])
}

#[test]
fn owner_through_a_relation_to_a_model_owned_by_a_uuid_field_looks_ownership_up() {
    let author = model(
        "Author",
        "author",
        json!({ "id": uuid_pk(), "user_id": uuid(true) }),
        json!({ "read": owner("user_id") }),
    );
    let ast = parser::parse(&post_by(author)).expect("parses");
    let post = model_named(&ast, "Post");
    let rule = post.access().read.as_ref().unwrap();
    let expr = rls::access_rule_to_expr(&ast, post, rule, "public");
    assert!(
        expr.contains("EXISTS (SELECT 1 FROM \"public\".\"author\"")
            && expr.contains("\"author\".\"user_id\""),
        "ownership is looked up through the author row: {expr}"
    );
}

#[test]
fn owner_through_a_has_many_relation_is_refused() {
    let schema = document(vec![model(
        "Author",
        "author",
        json!({ "id": uuid_pk(), "posts": { "kind": "relation", "cardinality": "hasMany",
                                            "target": "Author" } }),
        json!({ "read": owner("posts") }),
    )]);
    let message = parse_err(&schema);
    assert!(
        message.contains("field 'posts' is a relation that keeps its key on the other model"),
        "{message}"
    );
}

#[test]
fn owner_through_a_relation_to_a_user_model_is_accepted() {
    // A user model is keyed by a `SupatypeAuthUserId`, which the CLI marks (O1).
    let profile = model(
        "Author",
        "author",
        json!({ "id": { "kind": "uuid", "primaryKey": true, "required": true,
                        "annotations": { "db": { "pgType": "UUID", "authUserId": true } } } }),
        json!({}),
    );
    let ast = parser::parse(&post_by(profile)).expect("parses");
    let post = model_named(&ast, "Post");
    let rule = post.access().update.as_ref().unwrap();
    assert_eq!(
        rls::access_rule_to_expr(&ast, post, rule, "public"),
        "(SELECT _supatype.jwt_uid()) = \"author_id\""
    );
}

#[test]
fn owner_through_a_relation_to_the_auth_user_is_accepted() {
    let schema = document(vec![model(
        "Post",
        "post",
        json!({ "id": uuid_pk(), "author": belongs_to("supatype:user", "author_id") }),
        json!({ "read": owner("author") }),
    )]);
    let ast = parser::parse(&schema).expect("parses");
    let post = model_named(&ast, "Post");
    let rule = post.access().read.as_ref().unwrap();
    assert_eq!(
        rls::access_rule_to_expr(&ast, post, rule, "public"),
        "(SELECT _supatype.jwt_uid()) = \"author_id\""
    );
}

// ---------------------------------------------------------------------------------------------
// Membership filters are checked against the table they read
// ---------------------------------------------------------------------------------------------

#[test]
fn owner_in_a_membership_filter_is_checked_against_the_source_model() {
    let member = model(
        "Member",
        "member",
        json!({ "id": uuid_pk(), "team_id": uuid(true), "user_id": uuid(true) }),
        json!({ "read": owner("user_id") }),
    );
    let in_my_teams = |filter_field: &str| {
        json!({ "type": "in", "column": "id", "source": {
            "kind": "rows", "table": "member", "column": "team_id", "where": owner(filter_field)
        } })
    };
    let team = |filter_field: &str| {
        model(
            "Team",
            "team",
            json!({ "id": uuid_pk(), "name": text() }),
            json!({ "read": in_my_teams(filter_field) }),
        )
    };

    let ast = parser::parse(&document(vec![member.clone(), team("user_id")]))
        .expect("Owner<\"user_id\"> names a column of member, not of team");
    let team_model = model_named(&ast, "Team");
    let expr = rls::access_rule_to_expr(
        &ast,
        team_model,
        team_model.access().read.as_ref().unwrap(),
        "public",
    );
    assert!(expr.contains("\"member\".\"user_id\""), "{expr}");

    let message = parse_err(&document(vec![member, team("name")]));
    assert!(
        message.contains("Model 'Member': Owner<\"name\"> is invalid"),
        "{message}"
    );
}

// ---------------------------------------------------------------------------------------------
// The policy against a real database: the owner reads and updates their row, nobody else does
// ---------------------------------------------------------------------------------------------

const ALICE: &str = "00000000-0000-0000-0000-00000000a11c";
const BOB: &str = "00000000-0000-0000-0000-000000000b0b";

/// Run `sql` as the signed-in user `uid` and return the rows it touched or read.
async fn as_user(pool: &sqlx::PgPool, uid: &str, sql: &str) -> u64 {
    let mut tx = pool.begin().await.expect("begin");
    let claims = format!(r#"{{"sub":"{uid}","role":"authenticated"}}"#);
    sqlx::raw_sql(&format!(
        "SET LOCAL request.jwt.claims = '{claims}'; SET LOCAL ROLE authenticated;"
    ))
    .execute(&mut *tx)
    .await
    .expect("assume the caller's identity");
    let affected = sqlx::query(sql)
        .execute(&mut *tx)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
        .rows_affected();
    tx.commit().await.expect("commit");
    affected
}

#[tokio::test]
async fn only_the_owner_reads_and_updates_a_row_owned_by_a_uuid_column() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(&note_owned_by("owner_id")).expect("parses");
        common::push(&pool, &ast)
            .await
            .expect("A7-N3 schema pushes");
        common::exec(
            &pool,
            &format!("INSERT INTO note (owner_id, body) VALUES ('{ALICE}', 'alice''s note')"),
        )
        .await
        .expect("seed");

        assert_eq!(as_user(&pool, ALICE, "SELECT * FROM note").await, 1);
        assert_eq!(as_user(&pool, BOB, "SELECT * FROM note").await, 0);
        assert_eq!(
            as_user(
                &pool,
                BOB,
                "UPDATE note SET body = 'bob was here' WHERE true"
            )
            .await,
            0,
            "another user cannot update the row"
        );
        assert_eq!(
            as_user(
                &pool,
                ALICE,
                "UPDATE note SET body = 'edited by alice' WHERE true"
            )
            .await,
            1,
            "the owner can update their row"
        );
        let body: String = sqlx::query_scalar("SELECT body FROM note")
            .fetch_one(&pool)
            .await
            .expect("read back");
        assert_eq!(body, "edited by alice");
    })
    .await;
}

//! What each API role may do on each model's table once a push applies, beside what it may do
//! now (issue 16): the block `supatype diff` prints, so an author sees at once that a rule meant to
//! be public gives `anon` nothing.
//!
//! The fixture is the formflow shape, extracted by the CLI from a TypeScript schema: `form` is
//! readable once published, `question` is readable by the form's owner or for a published form,
//! `response` may be created for a published form, `profile` needs a login and `notice` is public.

mod common;

use supatype_engine::access_summary::{summarize, RoleAccess};
use supatype_engine::introspector::catalog::{CatalogState, DbColumnGrant, DbTableGrant};
use supatype_engine::parser::{self, ast::SchemaAst};

const FIXTURE: &str = include_str!("fixtures/role_access.json");

fn ast() -> SchemaAst {
    parser::parse(FIXTURE).expect("fixture parses")
}

fn access(catalog: &CatalogState, table: &str, role: &str) -> RoleAccess {
    summarize(&ast(), catalog, "public")
        .into_iter()
        .find(|a| a.table == table && a.role == role)
        .unwrap_or_else(|| panic!("no access for {role} on {table}"))
}

fn after(table: &str, role: &str) -> Vec<&'static str> {
    access(&CatalogState::default(), table, role).after
}

#[test]
fn a_public_rule_gives_anon_read() {
    assert_eq!(after("notice", "anon"), ["read"]);
}

#[test]
fn a_login_free_rows_membership_gives_anon_what_it_governs() {
    assert_eq!(after("question", "anon"), ["read"]);
    assert_eq!(after("response", "anon"), ["create"]);
}

#[test]
fn an_owner_only_rule_gives_anon_nothing() {
    // `question` is written, and `response` read and deleted, by the form's owner only
    // (`OwnerFrom<"form">`), and `form` is written by its owner only (`Owner<"owner_id">`).
    for (table, owner_only) in [
        ("question", ["create", "update", "delete"].as_slice()),
        ("response", ["read", "delete"].as_slice()),
        ("form", ["create", "update", "delete"].as_slice()),
    ] {
        let anon = after(table, "anon");
        assert!(
            owner_only.iter().all(|verb| !anon.contains(verb)),
            "{table}: {anon:?}"
        );
    }
}

#[test]
fn a_logged_in_rule_gives_anon_nothing_and_authenticated_everything_declared() {
    assert!(after("profile", "anon").is_empty());
    assert_eq!(
        after("profile", "authenticated"),
        ["read", "create", "update", "delete"]
    );
    assert_eq!(
        after("response", "authenticated"),
        ["read", "create", "delete"]
    );
}

#[test]
fn every_model_has_one_entry_per_api_role_in_model_order() {
    let rows: Vec<(String, String)> = summarize(&ast(), &CatalogState::default(), "public")
        .into_iter()
        .map(|a| (a.table, a.role))
        .collect();
    let tables = ["profile", "notice", "form", "question", "response"];
    let expected: Vec<(String, String)> = tables
        .iter()
        .flat_map(|t| ["anon", "authenticated"].map(|r| (t.to_string(), r.to_string())))
        .collect();
    assert_eq!(rows, expected);
}

#[test]
fn the_model_name_is_carried_beside_the_table() {
    let a = access(&CatalogState::default(), "question", "anon");
    assert_eq!(a.model, "Question");
}

fn table_grant(schema: &str, table: &str, grantee: &str, privileges: &[&str]) -> DbTableGrant {
    DbTableGrant {
        schema: schema.into(),
        table: table.into(),
        grantee: grantee.into(),
        privileges: privileges.iter().map(|p| p.to_string()).collect(),
        held_with: Default::default(),
    }
}

#[test]
fn before_is_nothing_for_a_table_the_database_does_not_have() {
    assert!(access(&CatalogState::default(), "question", "anon")
        .before
        .is_empty());
}

#[test]
fn before_reads_the_live_table_privileges_as_rule_verbs() {
    let catalog = CatalogState {
        table_grants: vec![table_grant(
            "public",
            "form",
            "authenticated",
            &["DELETE", "INSERT", "SELECT", "TRUNCATE", "UPDATE"],
        )],
        ..Default::default()
    };
    let a = access(&catalog, "form", "authenticated");
    assert_eq!(a.before, ["read", "create", "update", "delete"]);
    assert!(access(&catalog, "form", "anon").before.is_empty());
}

#[test]
fn before_counts_a_grant_to_public_and_the_api_view_as_the_roles_own() {
    let catalog = CatalogState {
        table_grants: vec![
            table_grant("public", "notice", "PUBLIC", &["SELECT"]),
            table_grant("api", "question", "anon", &["SELECT"]),
            table_grant("other", "response", "anon", &["INSERT"]),
        ],
        ..Default::default()
    };
    assert_eq!(access(&catalog, "notice", "anon").before, ["read"]);
    assert_eq!(access(&catalog, "question", "anon").before, ["read"]);
    // Another schema's table of the same name is not what the API reads.
    assert!(access(&catalog, "response", "anon").before.is_empty());
}

#[test]
fn before_counts_a_column_privilege_as_the_operation() {
    let catalog = CatalogState {
        column_grants: vec![DbColumnGrant {
            schema: "public".into(),
            table: "response".into(),
            column: "answers".into(),
            grantee: "anon".into(),
            privileges: vec!["INSERT".into()],
            held_with: Default::default(),
        }],
        ..Default::default()
    };
    assert_eq!(access(&catalog, "response", "anon").before, ["create"]);
}

// The plan a push applies carries the same summary, before and after, as `diff` prints it.
#[tokio::test]
async fn the_plan_json_carries_each_roles_access_before_and_after() {
    use supatype_engine::push;
    common::with_integration_pool(|pool| async move {
        let ast = ast();
        // `form.owner_id` cascades from `auth.users`, which the auth server makes.
        common::exec(
            &pool,
            "CREATE SCHEMA IF NOT EXISTS auth;
             CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY);",
        )
        .await
        .unwrap();
        let fresh = push::plan(&pool, &ast, "public")
            .await
            .unwrap()
            .to_json()
            .unwrap();
        let question_anon = |json: &serde_json::Value| {
            json["access"]
                .as_array()
                .expect("access is an array")
                .iter()
                .find(|a| a["table"] == "question" && a["role"] == "anon")
                .cloned()
                .expect("question anon entry")
        };
        let entry = question_anon(&fresh);
        assert_eq!(entry["before"], serde_json::json!([]));
        assert_eq!(entry["after"], serde_json::json!(["read"]));
        assert_eq!(entry["model"], "Question");

        // The push's own answer carries what it changed, for `supatype dev` to print.
        let applied = common::push(&pool, &ast).await.unwrap().to_json();
        let entry = question_anon(&applied);
        assert_eq!(entry["before"], serde_json::json!([]));
        assert_eq!(entry["after"], serde_json::json!(["read"]));

        let again = push::plan(&pool, &ast, "public")
            .await
            .unwrap()
            .to_json()
            .unwrap();
        let entry = question_anon(&again);
        assert_eq!(entry["before"], serde_json::json!(["read"]));
        assert_eq!(entry["after"], serde_json::json!(["read"]));
    })
    .await;
}

// ─── Many-to-many links ─────────────────────────────────────────────────────

fn model(
    name: &str,
    table: &str,
    fields: serde_json::Value,
    access: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "fields": fields,
        "options": { "timestamps": false, "softDelete": false, "singleton": false },
        "annotations": { "db": { "tableName": table, "indexes": [] },
                         "platform": { "access": access } }
    })
}

fn uuid_key() -> serde_json::Value {
    serde_json::json!({ "kind": "uuid", "required": true, "primaryKey": true,
                        "annotations": { "db": { "pgType": "UUID", "unique": false } } })
}

fn links(models: Vec<serde_json::Value>) -> SchemaAst {
    let doc = serde_json::json!({ "astVersion": 2, "models": models });
    parser::parse(&doc.to_string()).expect("the link fixture parses")
}

/// Tags anyone may read and an admin may change; posts readable once published and edited by an
/// editor. `post_tags` follows its ends' rows: readable where both ends are, written by an editor.
fn blog() -> SchemaAst {
    let admin = serde_json::json!({ "type": "role", "roles": ["admin"] });
    let tag = model(
        "Tag",
        "tags",
        serde_json::json!({ "id": uuid_key() }),
        serde_json::json!({ "read": { "type": "public" }, "update": admin }),
    );
    let published = serde_json::json!({ "type": "nullCheck", "isNull": false,
        "operand": { "kind": "column", "name": "published_at" } });
    let post = model(
        "Post",
        "posts",
        serde_json::json!({
            "id": uuid_key(),
            "published_at": { "kind": "datetime", "required": false,
                              "annotations": { "db": { "pgType": "TIMESTAMPTZ", "unique": false } } },
            "tags": { "kind": "relation", "cardinality": "manyToMany", "target": "Tag",
                      "through": "post_tags" }
        }),
        serde_json::json!({ "read": published,
                            "update": { "type": "role", "roles": ["editor"] } }),
    );
    links(vec![tag, post])
}

/// A project read by its members through the junction: reading the ends would recurse, so the
/// junction keeps the intersection of its ends' rules, and the project's row-dependent read leaves
/// the link with no read it can decide.
fn membership() -> SchemaAst {
    let member = model(
        "Member",
        "members",
        serde_json::json!({ "id": uuid_key() }),
        serde_json::json!({ "read": { "type": "authenticated" } }),
    );
    let mine = serde_json::json!({
        "type": "in", "column": "id",
        "source": { "kind": "rows", "table": "project_members", "column": "project_id",
                    "where": { "type": "compare", "op": "eq",
                               "left": { "kind": "column", "name": "member_id" },
                               "right": { "kind": "authUid" } } }
    });
    let project = model(
        "Project",
        "projects",
        serde_json::json!({
            "id": uuid_key(),
            "members": { "kind": "relation", "cardinality": "manyToMany", "target": "Member",
                         "through": "project_members" }
        }),
        serde_json::json!({ "read": mine, "update": mine }),
    );
    links(vec![member, project])
}

fn link_access(ast: &SchemaAst, role: &str) -> RoleAccess {
    summarize(ast, &CatalogState::default(), "public")
        .into_iter()
        .find(|a| a.link && a.role == role)
        .unwrap_or_else(|| panic!("no link entry for {role}"))
}

#[test]
fn a_junction_is_listed_as_a_link_after_the_models() {
    let tables: Vec<(String, bool)> = summarize(&blog(), &CatalogState::default(), "public")
        .into_iter()
        .filter(|a| a.role == "anon")
        .map(|a| (a.table, a.link))
        .collect();
    assert_eq!(
        tables,
        [
            ("tags".into(), false),
            ("posts".into(), false),
            ("post_tags".into(), true)
        ]
    );
}

#[test]
fn a_linked_junction_gives_each_role_what_its_ends_allow() {
    let anon = link_access(&blog(), "anon");
    assert_eq!(anon.table, "post_tags");
    assert_eq!(anon.after, ["read"]);
    assert_eq!(anon.denied, None);
    let signed_in = link_access(&blog(), "authenticated");
    assert_eq!(signed_in.after, ["read", "create", "update", "delete"]);
}

#[test]
fn a_link_an_end_reads_says_what_it_denies_and_why() {
    for role in ["anon", "authenticated"] {
        let link = link_access(&membership(), role);
        // SELECT stays granted for the project's policy to read the junction, but no policy admits
        // a row of it: the role can read none.
        assert!(link.after.is_empty(), "{role}: {link:?}");
        let denied = link.denied.expect("the undecidable read is named");
        assert_eq!(denied.verbs, ["read"]);
        assert_eq!(denied.reason, "an end's read rule reads this link table");
    }
}

#[test]
fn the_json_marks_a_link_and_carries_its_denial() {
    let json = serde_json::to_value(summarize(&membership(), &CatalogState::default(), "public"))
        .expect("serializes");
    let link = json
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["table"] == "project_members" && a["role"] == "anon")
        .expect("the link entry");
    assert_eq!(link["link"], true);
    assert_eq!(
        link["denied"],
        serde_json::json!({ "verbs": ["read"], "reason": "an end's read rule reads this link table" })
    );
    let projects = json
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["table"] == "projects")
        .unwrap();
    assert_eq!(projects["link"], false);
    assert!(projects.get("denied").is_none(), "{projects}");
}

// The SELECT a recursive link keeps for its end's policy is not access the role has, before the
// push any more than after it: counted only after, every diff showed the link as `read -> none`.
#[test]
fn what_a_link_denies_is_left_out_of_before_too() {
    let catalog = CatalogState {
        table_grants: vec![table_grant(
            "public",
            "project_members",
            "anon",
            &["SELECT"],
        )],
        ..Default::default()
    };
    let link = summarize(&membership(), &catalog, "public")
        .into_iter()
        .find(|a| a.link && a.role == "anon")
        .expect("the link entry");
    assert!(link.before.is_empty(), "{link:?}");
}

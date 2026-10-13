//! A required column nobody can write is a table nobody can insert into.
//!
//! Without this check the developer meets `23502 not-null violation`, which names the NOT
//! NULL constraint, the one part of the picture that is not the problem. These tests pin
//! both halves: that the provable contradictions are named, and that everything undecidable
//! stays silent. A false refusal breaks a working schema, so silence is the default.

use supatype_engine::{
    differ,
    introspector::{tables::DbTable, triggers::DbTrigger},
    parser,
    state::database_state::DatabaseState,
};

/// A one-model schema: `posts` with a required `secret` column carrying a field write rule.
fn schema_with(write_rule: &str, create_rule: &str, extra_field: &str) -> String {
    format!(
        r#"{{
  "astVersion": 2,
  "models": [
    {{
      "name": "Post",
      "fields": {{
        "id": {{ "kind": "uuid", "primaryKey": true, "required": true,
                 "default": {{ "kind": "genRandomUuid" }},
                 "annotations": {{ "db": {{ "pgType": "UUID", "unique": false }} }} }},
        "secret": {{ "kind": "text", "required": true{extra_field},
                     "annotations": {{ "db": {{ "pgType": "TEXT", "unique": false }} }} }}
      }},
      "annotations": {{
        "db": {{ "tableName": "posts", "indexes": [] }},
        "platform": {{
          "access": {{
            "read": {{ "type": "public" }},
            "create": {create_rule},
            "fields": {{ "secret": {{ "write": {write_rule} }} }}
          }}
        }}
      }}
    }}
  ]
}}"#
    )
}

/// `db` with the table present, so a missing BEFORE INSERT trigger is a fact rather than an
/// unknown.
fn db_with_posts() -> DatabaseState {
    DatabaseState {
        schema: "public".into(),
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: Vec::new(),
        }],
        ..Default::default()
    }
}

fn diff_error(schema: &str, db: &DatabaseState) -> Option<String> {
    let ast = parser::parse(schema).expect("schema parses");
    match differ::diff(&ast, db) {
        Ok(_) => None,
        Err(e) => Some(e.to_string()),
    }
}

fn diff_warnings(schema: &str, db: &DatabaseState) -> Vec<String> {
    let ast = parser::parse(schema).expect("schema parses");
    differ::diff(&ast, db).expect("diff succeeds").warnings
}

// ─── The provable contradictions ─────────────────────────────────────────────

// The commonest case, and not a contradiction. `Owner<"id">` reads the row, and on INSERT a
// write rule judges the row being inserted (MASK-N1), so a user creating their own row
// supplies their own value. Refusing this, as when the rule was judged against a row of NULLs,
// would refuse the schema every sign-up flow writes.
#[test]
fn a_row_dependent_write_rule_on_a_required_column_is_not_refused() {
    let schema = schema_with(
        r#"{ "type": "owner", "field": "id" }"#,
        r#"{ "type": "owner", "field": "id" }"#,
        "",
    );
    assert_eq!(diff_error(&schema, &db_with_posts()), None);
}

// The same rule under a public create rule: a caller who may insert need not own the row, so
// the narrowing is named, for that reason and not for depending on the row.
#[test]
fn a_row_dependent_write_rule_narrower_than_a_public_create_rule_is_refused() {
    let schema = schema_with(
        r#"{ "type": "owner", "field": "id" }"#,
        r#"{ "type": "public" }"#,
        "",
    );
    let error = diff_error(&schema, &db_with_posts()).expect("expected a refusal");
    assert!(
        error.contains("narrower than the table's create rule"),
        "unexpected message: {error}"
    );
}

#[test]
fn a_write_rule_denying_everyone_is_refused() {
    let schema = schema_with(r#"{ "type": "private" }"#, r#"{ "type": "public" }"#, "");
    let error = diff_error(&schema, &db_with_posts()).expect("expected a refusal");
    assert!(
        error.contains("denies every caller"),
        "unexpected message: {error}"
    );
}

// Identity-only write rule, but the table's create rule admits everyone, so a caller who
// may insert cannot supply the column.
#[test]
fn a_write_rule_narrower_than_a_public_create_rule_is_refused() {
    let schema = schema_with(
        r#"{ "type": "role", "roles": ["admin"] }"#,
        r#"{ "type": "public" }"#,
        "",
    );
    let error = diff_error(&schema, &db_with_posts()).expect("expected a refusal");
    assert!(
        error.contains("narrower than the table's create rule"),
        "unexpected message: {error}"
    );
}

// ─── Everything undecidable stays silent ─────────────────────────────────────

#[test]
fn a_default_satisfies_the_check() {
    let schema = schema_with(
        r#"{ "type": "owner", "field": "id" }"#,
        r#"{ "type": "public" }"#,
        r#", "default": { "kind": "value", "value": "x" }"#,
    );
    assert!(diff_error(&schema, &db_with_posts()).is_none());
}

#[test]
fn an_optional_column_is_not_a_problem() {
    let schema = schema_with(
        r#"{ "type": "owner", "field": "id" }"#,
        r#"{ "type": "public" }"#,
        "",
    )
    .replace(
        r#""kind": "text", "required": true"#,
        r#""kind": "text", "required": false"#,
    );
    assert!(diff_error(&schema, &db_with_posts()).is_none());
}

// A BEFORE INSERT trigger is the fourth way a row acquires a value, and it is in the
// database rather than the AST.
#[test]
fn a_before_insert_trigger_satisfies_the_check() {
    let mut db = db_with_posts();
    db.triggers.push(DbTrigger {
        table: "posts".into(),
        name: "fill_secret".into(),
        event: "INSERT".into(),
        timing: "BEFORE".into(),
        function_name: "fill_secret".into(),
    });
    let schema = schema_with(
        r#"{ "type": "owner", "field": "id" }"#,
        r#"{ "type": "public" }"#,
        "",
    );
    assert!(diff_error(&schema, &db).is_none());
}

// An identity-only write rule with a create rule that is *not* public: whether the create
// rule admits anyone the write rule excludes is an implication between two arbitrary
// predicates, which is not decidable. Silence rather than a guess.
#[test]
fn an_undecidable_narrowing_is_not_refused() {
    let schema = schema_with(
        r#"{ "type": "role", "roles": ["admin"] }"#,
        r#"{ "type": "role", "roles": ["editor"] }"#,
        "",
    );
    assert!(diff_error(&schema, &db_with_posts()).is_none());
}

#[test]
fn a_public_write_rule_is_not_a_problem() {
    let schema = schema_with(r#"{ "type": "public" }"#, r#"{ "type": "public" }"#, "");
    assert!(diff_error(&schema, &db_with_posts()).is_none());
}

// A column with only a read rule says nothing about who may write it.
#[test]
fn a_read_only_field_rule_is_not_a_problem() {
    let schema = schema_with(r#"{ "type": "public" }"#, r#"{ "type": "public" }"#, "").replace(
        r#""write": { "type": "public" }"#,
        r#""read": { "type": "private" }"#,
    );
    assert!(diff_error(&schema, &db_with_posts()).is_none());
}

// ─── Offline / new table degrades to a warning ───────────────────────────────

// With the table absent from the introspected state (a brand new table, or a `diff` with no
// connection), a BEFORE INSERT trigger cannot be ruled out. Report it, never refuse it.
#[test]
fn an_unintrospected_table_warns_instead_of_refusing() {
    let schema = schema_with(r#"{ "type": "private" }"#, r#"{ "type": "public" }"#, "");
    let empty = DatabaseState::default();
    assert!(
        diff_error(&schema, &empty).is_none(),
        "a table we cannot see must not be refused"
    );
    let warnings = diff_warnings(&schema, &empty);
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("no caller can ever insert a row")),
        "expected a warning, got: {warnings:#?}"
    );
    assert!(
        warnings.iter().any(|w| w.contains("cannot be ruled out")),
        "the warning must say why it is not a refusal: {warnings:#?}"
    );
}

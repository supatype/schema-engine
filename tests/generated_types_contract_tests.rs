//! What `database.ts` promises about a column, against what the column actually is.
//!
//! Both cases here are the generated type contradicting the schema it was generated from, which is
//! the worst shape a type can take: it compiles, it looks considered, and it is wrong. Neither was
//! caught by the differ tests, because the differ was right both times. Only the generator lied.

use supatype_engine::generator::typescript::types;
use supatype_engine::parser;

/// A model with one required relation, one optional relation, and an enum carrying a default.
fn schema() -> &'static str {
    r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "author",
      "annotations": { "db": { "tableName": "author" } },
      "fields": { "id": { "kind": "uuid", "required": true } }
    },
    {
      "name": "post",
      "annotations": { "db": { "tableName": "post" } },
      "fields": {
        "id": { "kind": "uuid", "required": true },
        "author": {
          "kind": "relation",
          "cardinality": "belongsTo",
          "target": "author",
          "required": true
        },
        "editor": {
          "kind": "relation",
          "cardinality": "belongsTo",
          "target": "author",
          "required": false
        },
        "status": {
          "kind": "enum",
          "required": true,
          "values": ["draft", "published"],
          "default": { "kind": "value", "value": "draft" }
        },
        "views": {
          "kind": "integer",
          "required": true,
          "default": { "kind": "value", "value": 0 }
        }
      }
    }
  ]
}"#
}

fn generated() -> String {
    let ast = parser::parse(schema()).expect("schema parses");
    types::generate(&ast).expect("types generate")
}

/// The `Row` block of the `post` table, so an assertion cannot match `Insert` or `Update`.
fn row_block(src: &str) -> String {
    let start = src.find("      post: {").expect("post table in output");
    let rest = &src[start..];
    let row = rest.find("Row: {").expect("Row block");
    let end = rest[row..]
        .find("Insert: {")
        .expect("Insert block after Row");
    rest[row..row + end].to_string()
}

/// The `Insert` block of the `post` table.
fn insert_block(src: &str) -> String {
    let start = src.find("      post: {").expect("post table in output");
    let rest = &src[start..];
    let ins = rest.find("Insert: {").expect("Insert block");
    let end = rest[ins..]
        .find("Update: {")
        .expect("Update block after Insert");
    rest[ins..ins + end].to_string()
}

#[test]
fn a_required_relation_is_not_nullable() {
    // The FK column was emitted nullable whatever the relation said, so
    // `RelatedTo<X, { required: true }>` produced `author_id: string | null` over a column the
    // differ had made NOT NULL. Every caller was invited to write a null the database rejects.
    let row = row_block(&generated());
    assert!(
        row.contains("author_id: string\n"),
        "required relation should be non-nullable, got:\n{row}"
    );
    assert!(
        !row.contains("author_id: string | null"),
        "required relation must not be nullable, got:\n{row}"
    );
}

#[test]
fn an_optional_relation_is_still_nullable() {
    // The other half. A fix that made every FK non-nullable would pass the test above and be
    // just as wrong in the other direction.
    let row = row_block(&generated());
    assert!(
        row.contains("editor_id: string | null"),
        "optional relation should stay nullable, got:\n{row}"
    );
}

#[test]
fn an_enum_with_a_default_is_optional_on_insert() {
    // Every default arrives as an object, `{"kind":"value","value":"draft"}`, and the enum branch
    // read it with `.as_str()`, which is None for an object. So the default was discarded and the
    // field was emitted as required on Insert, asking callers for a value the database fills in.
    let insert = insert_block(&generated());
    assert!(
        insert.contains("status?:"),
        "enum with a default should be optional on Insert, got:\n{insert}"
    );
}

#[test]
fn a_scalar_with_a_default_is_optional_on_insert() {
    // The control. This one always worked, and is what made the enum case visible: two fields on
    // one model, both with defaults, disagreeing about whether Insert required them.
    let insert = insert_block(&generated());
    assert!(
        insert.contains("views?:"),
        "scalar with a default should be optional on Insert, got:\n{insert}"
    );
}

/// The AST publishes the Postgres type the engine actually creates.
///
/// `money` sat in the TEXT arm beside `email` and `url` while the differ emitted NUMERIC(19,4), so
/// every consumer of the AST was told the column was text. That is not cosmetic: it is the contract
/// code is generated from, and someone wrote a parser that rejected every value the column returns.
#[test]
fn the_ast_reports_the_type_the_column_is_given() {
    use supatype_engine::parser::v2::default_pg_type;

    assert_eq!(default_pg_type("money"), "NUMERIC(19,4)");
    assert_eq!(default_pg_type("decimal"), "NUMERIC");
    // The text-shaped kinds it used to be grouped with are untouched.
    assert_eq!(default_pg_type("text"), "TEXT");
    assert_eq!(default_pg_type("email"), "TEXT");
    assert_eq!(default_pg_type("enum"), "TEXT");
}

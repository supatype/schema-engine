//! Identity and generated columns (identity-contract): what the AST says, the DDL a push renders,
//! the differ's changes against a live column, and the generated client types. No database.

use std::collections::BTreeMap;

use serde_json::{json, Value};
use supatype_engine::{
    desired::{desired_objects_for, FieldEnforcement},
    differ::{self, Operation, Risk},
    generator::{sql::migration, typescript},
    introspector::{
        fingerprint::ObjectKind,
        tables::{DbColumn, DbTable},
    },
    parser::{
        self,
        ast::{FieldAst, IdentityGeneration, SchemaAst},
    },
    state::database_state::DatabaseState,
};

fn int(extra: Value) -> Value {
    let mut f = json!({ "kind": "integer", "required": true,
                        "annotations": { "db": { "pgType": "INTEGER" } } });
    f.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    f
}

fn text(extra: Value) -> Value {
    let mut f = json!({ "kind": "text", "required": false,
                        "annotations": { "db": { "pgType": "TEXT" } } });
    f.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    f
}

fn schema(fields: Value) -> Result<SchemaAst, anyhow::Error> {
    let doc = json!({
        "astVersion": 2,
        "models": [{
            "name": "Post",
            "fields": fields,
            "options": { "timestamps": false, "softDelete": false, "singleton": false },
            "annotations": { "db": { "tableName": "posts", "indexes": [] },
                             "platform": { "access": { "read": { "type": "public" } } } }
        }]
    });
    parser::parse(&doc.to_string())
}

fn posts(fields: Value) -> SchemaAst {
    schema(fields).expect("fixture parses")
}

fn identity_posts(how: &str) -> SchemaAst {
    posts(json!({
        "id": int(json!({ "primaryKey": true, "identity": how })),
        "title": text(json!({})),
    }))
}

fn generated_posts(expression: &str) -> SchemaAst {
    posts(json!({
        "id": int(json!({ "primaryKey": true, "identity": "always" })),
        "title": text(json!({})),
        "title_lower": text(json!({ "generated": { "expression": expression, "stored": true } })),
    }))
}

fn scalar<'a>(ast: &'a SchemaAst, field: &str) -> &'a supatype_engine::parser::ast::ScalarFieldAst {
    let field = &ast.models[0].fields[field];
    supatype_engine::parser::ast::scalar_of(field).expect("a scalar field")
}

fn column(name: &str, udt: &str) -> DbColumn {
    DbColumn {
        name: name.into(),
        data_type: udt.into(),
        udt_name: udt.into(),
        nullable: false,
        ordinal_position: 1,
        ..Default::default()
    }
}

/// A database holding `public.posts`, Supatype's, with these columns and these recorded column
/// statements.
fn db(columns: Vec<DbColumn>, recorded: &[(&str, &str)]) -> DatabaseState {
    let mut db = DatabaseState {
        schema: "public".into(),
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            columns,
            comment: None,
        }],
        ..Default::default()
    };
    db.table_ownership = BTreeMap::from([("posts".to_string(), true)]);
    db.recorded_columns = recorded
        .iter()
        .map(|(c, sql)| (("posts".to_string(), c.to_string()), sql.to_string()))
        .collect();
    db
}

fn title() -> DbColumn {
    let mut c = column("title", "text");
    c.nullable = true;
    c
}

fn sql_of(ast: &SchemaAst, db: &DatabaseState) -> (String, differ::DiffOutput) {
    let diff = differ::diff(ast, db).expect("diff");
    let sql = migration::generate(&diff, true, "public", ast).expect("render");
    (sql, diff)
}

fn column_ops<'a>(diff: &'a differ::DiffOutput, name: &str) -> Vec<&'a Operation> {
    diff.operations
        .iter()
        .filter(|op| {
            matches!(op, Operation::AlterColumn { column, .. } | Operation::RecreateColumn { column, .. }
                if column == name)
        })
        .collect()
}

// ─── parsing ────────────────────────────────────────────────────────────────

#[test]
fn identity_and_generated_parse_into_the_scalar_field() {
    let ast = identity_posts("byDefault");
    assert_eq!(
        scalar(&ast, "id").identity,
        Some(IdentityGeneration::ByDefault)
    );
    let ast = generated_posts("lower(title)");
    assert_eq!(
        scalar(&ast, "id").identity,
        Some(IdentityGeneration::Always)
    );
    let g = scalar(&ast, "title_lower").generated.as_ref().unwrap();
    assert_eq!(g.expression, "lower(title)");
    assert!(g.stored);
}

#[test]
fn an_identity_column_is_always_required() {
    let ast = posts(json!({
        "id": int(json!({ "primaryKey": true, "required": false, "identity": "always" })),
    }));
    assert!(scalar(&ast, "id").required);
}

#[test]
fn what_postgres_would_refuse_is_refused_when_parsed() {
    let refused = |fields: Value, says: &str| {
        let err = schema(fields).expect_err("refused");
        let message = format!("{err:#}");
        assert!(message.contains(says), "{message}");
        assert!(message.contains("field"), "names the field: {message}");
    };
    refused(
        json!({ "t": text(json!({ "identity": "always" })) }),
        "must be an integer",
    );
    refused(
        json!({ "n": int(json!({ "identity": "always",
                                 "generated": { "expression": "1", "stored": true } })) }),
        "not both",
    );
    refused(
        json!({ "n": int(json!({ "identity": "always",
                                 "default": { "kind": "value", "value": 1 } })) }),
        "cannot also have a default",
    );
    refused(
        json!({ "n": int(json!({ "generated": { "expression": "1", "stored": false } })) }),
        "only stored",
    );
    refused(
        json!({ "j": { "kind": "json", "required": false,
                       "generated": { "expression": "'{}'::jsonb", "stored": true },
                       "annotations": { "db": { "pgType": "JSONB" } } } }),
        "cannot be an identity or generated column",
    );
    refused(
        json!({ "s": { "kind": "serial", "required": true, "identity": "always",
                       "annotations": { "db": { "pgType": "SERIAL" } } } }),
        "must be an integer",
    );
    refused(
        json!({ "n": int(json!({ "identity": "sometimes" })) }),
        "\"always\" or \"byDefault\"",
    );
}

#[test]
fn a_field_without_either_serialises_as_before() {
    let ast = posts(json!({ "id": int(json!({ "primaryKey": true })) }));
    let value = serde_json::to_value(&ast.models[0].fields["id"]).unwrap();
    assert!(value.get("identity").is_none(), "{value}");
    assert!(value.get("generated").is_none(), "{value}");
}

// ─── DDL ────────────────────────────────────────────────────────────────────

#[test]
fn a_new_table_declares_identity_and_generated_columns() {
    let (sql, _) = sql_of(&generated_posts("lower(title)"), &DatabaseState::default());
    assert!(
        sql.contains(
            "\"id\" INTEGER GENERATED ALWAYS AS IDENTITY CONSTRAINT \"posts_pkey\" PRIMARY KEY"
        ),
        "{sql}"
    );
    assert!(
        sql.contains("\"title_lower\" TEXT GENERATED ALWAYS AS (lower(title)) STORED"),
        "{sql}"
    );
    let (sql, _) = sql_of(&identity_posts("byDefault"), &DatabaseState::default());
    assert!(sql.contains("GENERATED BY DEFAULT AS IDENTITY"), "{sql}");
}

#[test]
fn a_generated_search_vector_is_declared_with_its_expression() {
    let ast = posts(json!({
        "id": int(json!({ "primaryKey": true, "identity": "always" })),
        "body": text(json!({})),
        "search": { "kind": "tsVector", "required": false,
                    "generated": { "expression": "to_tsvector('english', coalesce(body, ''))", "stored": true },
                    "annotations": { "db": { "pgType": "TSVECTOR" } } },
    }));
    let (sql, _) = sql_of(&ast, &DatabaseState::default());
    assert!(
        sql.contains("\"search\" TSVECTOR GENERATED ALWAYS AS (to_tsvector('english', coalesce(body, ''))) STORED"),
        "{sql}"
    );
}

#[test]
fn an_identity_columns_sequence_is_desired_like_a_serials() {
    let objects = desired_objects_for(
        &identity_posts("always"),
        "public",
        FieldEnforcement::Labels,
    )
    .unwrap();
    let sequence = objects
        .iter()
        .find(|d| d.key.kind == ObjectKind::Sequence)
        .expect("the identity column's sequence is desired");
    assert_eq!(sequence.key.name, "posts_id_seq");
    assert_eq!(
        sequence.structure.get("owned_by").map(String::as_str),
        Some("posts.id")
    );
}

// ─── differ ─────────────────────────────────────────────────────────────────

#[test]
fn a_plain_integer_becomes_an_identity_numbered_past_its_rows() {
    let (sql, diff) = sql_of(
        &identity_posts("always"),
        &db(vec![column("id", "int4"), title()], &[]),
    );
    assert_eq!(column_ops(&diff, "id").len(), 1, "{:?}", diff.operations);
    assert!(
        sql.contains("ALTER TABLE \"public\".\"posts\" ALTER COLUMN \"id\" ADD GENERATED ALWAYS AS IDENTITY;"),
        "{sql}"
    );
    assert!(
        sql.contains("SELECT setval(pg_get_serial_sequence('\"public\".\"posts\"', 'id'), COALESCE(MAX(\"id\"), 0) + 1, false)"),
        "{sql}"
    );
    assert!(!sql.contains("DROP DEFAULT"), "{sql}");
}

#[test]
fn a_default_goes_before_identity_is_added() {
    let mut id = column("id", "int4");
    id.default = Some("0".into());
    let (sql, _) = sql_of(&identity_posts("byDefault"), &db(vec![id, title()], &[]));
    let drop = sql.find("ALTER COLUMN \"id\" DROP DEFAULT;").expect(&sql);
    let add = sql
        .find("ALTER COLUMN \"id\" ADD GENERATED BY DEFAULT AS IDENTITY;")
        .expect(&sql);
    assert!(drop < add, "{sql}");
}

#[test]
fn a_nullable_integer_is_made_not_null_before_it_becomes_an_identity() {
    let mut id = column("id", "int4");
    id.nullable = true;
    let (sql, _) = sql_of(&identity_posts("always"), &db(vec![id, title()], &[]));
    let not_null = sql.find("ALTER COLUMN \"id\" SET NOT NULL;").expect(&sql);
    let add = sql.find("ADD GENERATED ALWAYS AS IDENTITY").expect(&sql);
    assert!(not_null < add, "{sql}");
}

fn identity_column(how: &str) -> DbColumn {
    let mut id = column("id", "int4");
    id.is_identity = true;
    id.identity_generation = Some(how.into());
    id
}

#[test]
fn always_and_by_default_switch_in_place() {
    let (sql, diff) = sql_of(
        &identity_posts("always"),
        &db(vec![identity_column("BY DEFAULT"), title()], &[]),
    );
    assert!(
        sql.contains("ALTER TABLE \"public\".\"posts\" ALTER COLUMN \"id\" SET GENERATED ALWAYS;"),
        "{sql}"
    );
    assert!(
        diff.warnings
            .iter()
            .any(|w| w.contains("by default to generated always")),
        "{:?}",
        diff.warnings
    );
    let (sql, _) = sql_of(
        &identity_posts("byDefault"),
        &db(vec![identity_column("ALWAYS"), title()], &[]),
    );
    assert!(sql.contains("SET GENERATED BY DEFAULT;"), "{sql}");
}

#[test]
fn an_identity_the_schema_no_longer_declares_is_dropped() {
    let ast = posts(json!({ "id": int(json!({ "primaryKey": true })), "title": text(json!({})) }));
    let (sql, diff) = sql_of(&ast, &db(vec![identity_column("ALWAYS"), title()], &[]));
    assert!(
        sql.contains(
            "ALTER TABLE \"public\".\"posts\" ALTER COLUMN \"id\" DROP IDENTITY IF EXISTS;"
        ),
        "{sql}"
    );
    assert!(
        diff.warnings
            .iter()
            .any(|w| w.contains("no longer an identity")),
        "{:?}",
        diff.warnings
    );
}

#[test]
fn an_identity_that_matches_changes_nothing() {
    let diff = differ::diff(
        &identity_posts("always"),
        &db(vec![identity_column("ALWAYS"), title()], &[]),
    )
    .unwrap();
    assert!(column_ops(&diff, "id").is_empty(), "{:?}", diff.operations);
}

/// Converting a serial is a change to ask for: the push leaves it and says how.
#[test]
fn a_serial_declared_as_identity_is_left_and_explained() {
    let mut id = column("id", "int4");
    id.default = Some("nextval('posts_id_seq'::regclass)".into());
    let diff = differ::diff(&identity_posts("always"), &db(vec![id, title()], &[])).unwrap();
    assert!(column_ops(&diff, "id").is_empty(), "{:?}", diff.operations);
    let warning = diff
        .warnings
        .iter()
        .find(|w| w.contains("is a serial column"))
        .unwrap_or_else(|| panic!("{:?}", diff.warnings));
    assert!(warning.contains("DROP SEQUENCE posts_id_seq"), "{warning}");
    assert!(
        warning.contains("ADD GENERATED ALWAYS AS IDENTITY"),
        "{warning}"
    );
    assert!(warning.contains("setval"), "{warning}");
}

fn generated_column(expression: &str) -> DbColumn {
    let mut c = column("title_lower", "text");
    c.nullable = true;
    c.is_generated = true;
    c.generation_expression = Some(expression.into());
    c
}

const RECORDED_LOWER: &str =
    "ALTER TABLE \"public\".\"posts\" ADD COLUMN \"title_lower\" TEXT GENERATED ALWAYS AS (lower(title)) STORED;";

#[test]
fn a_generated_expression_is_compared_with_what_the_last_push_declared() {
    // Postgres deparses `lower(title)` as it likes; the record is what was declared.
    let live = db(
        vec![
            identity_column("ALWAYS"),
            title(),
            generated_column("lower(title::text)"),
        ],
        &[("title_lower", RECORDED_LOWER)],
    );
    let diff = differ::diff(&generated_posts("lower(title)"), &live).unwrap();
    assert!(
        column_ops(&diff, "title_lower").is_empty(),
        "{:?}",
        diff.operations
    );

    let (sql, diff) = sql_of(&generated_posts("upper(title)"), &live);
    let ops = column_ops(&diff, "title_lower");
    assert!(
        matches!(
            ops.as_slice(),
            [Operation::RecreateColumn {
                risk: Risk::Cautious,
                ..
            }]
        ),
        "{ops:?}"
    );
    assert!(
        sql.contains("current_setting('server_version_num')::int >= 170000"),
        "{sql}"
    );
    assert!(
        sql.contains("ALTER TABLE \"public\".\"posts\" ALTER COLUMN \"title_lower\" SET EXPRESSION AS (upper(title))"),
        "{sql}"
    );
    // Before 17, made again: dropped and added with the new expression, the tier-2 view that reads
    // it (made again later in the migration) out of the way first.
    let else_branch = &sql[sql.find("ELSE").expect(&sql)..];
    let view = else_branch
        .find("DROP VIEW IF EXISTS \"api\".\"posts\"")
        .expect(&sql);
    let drop = else_branch.find("DROP COLUMN").expect(&sql);
    assert!(view < drop, "{sql}");
    assert!(
        sql.contains("DROP COLUMN IF EXISTS \"title_lower\""),
        "{sql}"
    );
    assert!(
        sql.contains("ADD COLUMN \"title_lower\" TEXT GENERATED ALWAYS AS (upper(title)) STORED"),
        "{sql}"
    );
}

#[test]
fn without_a_record_the_live_expression_is_compared_loosely() {
    let live = db(
        vec![
            identity_column("ALWAYS"),
            title(),
            generated_column("(lower(title))"),
        ],
        &[],
    );
    let diff = differ::diff(&generated_posts("lower( title )"), &live).unwrap();
    assert!(
        column_ops(&diff, "title_lower").is_empty(),
        "{:?}",
        diff.operations
    );
    let diff = differ::diff(&generated_posts("upper(title)"), &live).unwrap();
    assert_eq!(
        column_ops(&diff, "title_lower").len(),
        1,
        "{:?}",
        diff.operations
    );
}

#[test]
fn a_plain_column_becoming_generated_is_made_again_and_says_so() {
    let mut plain = column("title_lower", "text");
    plain.nullable = true;
    let live = db(vec![identity_column("ALWAYS"), title(), plain], &[]);
    let (sql, diff) = sql_of(&generated_posts("lower(title)"), &live);
    let ops = column_ops(&diff, "title_lower");
    assert!(
        matches!(
            ops.as_slice(),
            [Operation::RecreateColumn {
                risk: Risk::Destructive,
                ..
            }]
        ),
        "{ops:?}"
    );
    assert!(!sql.contains("SET EXPRESSION"), "{sql}");
    assert!(
        sql.contains("DROP VIEW IF EXISTS \"api\".\"posts\";"),
        "{sql}"
    );
    assert!(
        diff.warnings
            .iter()
            .any(|w| w.contains("becomes a generated column")),
        "{:?}",
        diff.warnings
    );
}

#[test]
fn a_generated_column_becoming_plain_keeps_its_values() {
    let ast = posts(json!({
        "id": int(json!({ "primaryKey": true, "identity": "always" })),
        "title": text(json!({})),
        "title_lower": text(json!({})),
    }));
    let live = db(
        vec![
            identity_column("ALWAYS"),
            title(),
            generated_column("lower(title)"),
        ],
        &[("title_lower", RECORDED_LOWER)],
    );
    let (sql, _) = sql_of(&ast, &live);
    assert!(
        sql.contains("ALTER TABLE \"public\".\"posts\" ALTER COLUMN \"title_lower\" DROP EXPRESSION IF EXISTS;"),
        "{sql}"
    );
}

// ─── fingerprint and introspection shape ────────────────────────────────────

#[test]
fn how_the_database_fills_a_column_is_part_of_its_definition() {
    assert_eq!(
        identity_column("BY DEFAULT").generation().as_deref(),
        Some("GENERATED BY DEFAULT AS IDENTITY")
    );
    assert_eq!(
        generated_column("lower(title)").generation().as_deref(),
        Some("GENERATED ALWAYS AS (lower(title)) STORED")
    );
    assert_eq!(column("id", "int4").generation(), None);
    let value = serde_json::to_value(identity_column("ALWAYS")).unwrap();
    assert_eq!(value["isIdentity"], json!(true));
    assert_eq!(value["identityGeneration"], json!("ALWAYS"));
    // Unset ones are left out, so a plain column reads as it did before.
    assert!(value.get("isGenerated").is_none(), "{value}");
    let plain = serde_json::to_value(column("id", "int4")).unwrap();
    assert!(plain.get("isIdentity").is_none(), "{plain}");
    // A snapshot written before these were read still loads.
    let old: DbColumn = serde_json::from_value(json!({
        "name": "id", "dataType": "integer", "udtName": "int4", "nullable": false,
        "default": null, "ordinalPosition": 1
    }))
    .unwrap();
    assert!(!old.is_identity && !old.is_generated);
}

// ─── client types ───────────────────────────────────────────────────────────

fn table_types(ast: &SchemaAst) -> String {
    typescript::types::generate(ast).unwrap()
}

fn block<'a>(types: &'a str, name: &str) -> &'a str {
    let start = types.find(&format!("{name}: {{")).expect(types);
    let rest = &types[start..];
    &rest[..rest.find("        }").expect(types)]
}

#[test]
fn what_the_database_writes_is_read_only_in_the_client_types() {
    let types = table_types(&generated_posts("lower(title)"));
    let row = block(&types, "Row");
    assert!(row.contains("id: number"), "{row}");
    assert!(row.contains("title_lower: string | null"), "{row}");
    for mode in ["Insert", "Update"] {
        let b = block(&types, mode);
        assert!(b.contains("id?: never"), "{mode}: {b}");
        assert!(b.contains("title_lower?: never"), "{mode}: {b}");
        assert!(b.contains("title?: string | null"), "{mode}: {b}");
    }
}

#[test]
fn a_by_default_identity_is_optional_on_insert() {
    let types = table_types(&identity_posts("byDefault"));
    let insert = block(&types, "Insert");
    assert!(insert.contains("id?: number"), "{insert}");
    assert!(!insert.contains("never"), "{insert}");
}

#[test]
fn an_identity_field_is_a_scalar_integer_field() {
    let ast = identity_posts("always");
    assert!(matches!(ast.models[0].fields["id"], FieldAst::Integer(_)));
}

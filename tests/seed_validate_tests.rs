//! One case per check in the seed validator.
//!
//! Validation is a distinct phase because a dynamically typed SDK has no compile step, so
//! this is where its mistakes are caught. Each test names the mistake an author would make
//! rather than the branch it exercises, and asserts the message says something useful: a
//! validator that refuses correctly but explains nothing just moves the confusion.

use supatype_engine::parser::ast::SchemaAst;
use supatype_engine::seed::{validate::validate, SeedIr};

/// A small schema with the shapes the checks need: a unique natural key, a required field
/// with no default, one with a default, a relation, a timestamp, and a composite unique.
const SCHEMA: &str = r#"{
    "astVersion": 2,
    "models": [
        {
            "name": "Organiser",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {"kind": "genRandomUuid"},
                       "annotations": {"db": {"unique": true}}},
                "slug": {"kind": "text", "required": true, "annotations": {"db": {"unique": true}}},
                "name": {"kind": "text", "required": true},
                "website": {"kind": "text", "required": false},
                "events": {"kind": "relation", "cardinality": "hasMany", "target": "Event"}
            },
            "annotations": {"db": {"tableName": "organiser"}}
        },
        {
            "name": "Event",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {"kind": "genRandomUuid"},
                       "annotations": {"db": {"unique": true}}},
                "title": {"kind": "text", "required": true},
                "currency": {"kind": "text", "required": true, "default": {"kind": "value", "value": "GBP"}},
                "starts_at": {"kind": "datetime", "required": true},
                "organiser": {"kind": "relation", "cardinality": "belongsTo", "target": "Organiser",
                              "required": true, "annotations": {"db": {"foreignKey": "organiser_id"}}}
            },
            "annotations": {
                "db": {
                    "tableName": "event",
                    "indexes": [{"fields": ["organiser_id", "title"], "unique": true, "using": "btree"}]
                }
            }
        }
    ]
}"#;

const FINGERPRINT: &str = "sha256:test";

fn schema() -> SchemaAst {
    serde_json::from_str(SCHEMA).expect("the schema fixture parses")
}

/// Build an IR from just its operations, with a matching fingerprint.
fn ir(operations: &str) -> SeedIr {
    let document = format!(
        r#"{{"irVersion":1,"schemaFingerprint":"{FINGERPRINT}","operations":{operations}}}"#
    );
    serde_json::from_str(&document)
        .unwrap_or_else(|e| panic!("the IR fixture does not parse: {e}\n{document}"))
}

fn accepts(operations: &str) {
    let result = validate(&ir(operations), &schema(), FINGERPRINT);
    assert!(result.is_ok(), "expected valid, got: {:?}", result.err());
}

/// Assert the document is refused and the message mentions each of `expected`.
fn rejects(operations: &str, expected: &[&str]) -> String {
    let error = validate(&ir(operations), &schema(), FINGERPRINT)
        .expect_err("expected this document to be refused");
    let rendered = error.to_string();
    for fragment in expected {
        assert!(
            rendered.contains(fragment),
            "message should mention `{fragment}`, got: {rendered}"
        );
    }
    rendered
}

// --- The document itself ---

#[test]
fn it_accepts_a_well_formed_document() {
    accepts(
        r#"[
        {"op":"upsert","model":"Organiser","id":"northern","where":{"slug":"n"},
         "data":{"name":"Northern"}},
        {"op":"create","model":"Event",
         "data":{"title":"Conf","starts_at":{"kind":"now"},
                 "organiser":{"connect":{"slug":"n"}}}}
    ]"#,
    );
}

#[test]
fn it_refuses_an_unsupported_ir_version() {
    let document: SeedIr = serde_json::from_str(
        r#"{"irVersion":99,"schemaFingerprint":"sha256:test","operations":[]}"#,
    )
    .expect("parses");
    let error = validate(&document, &schema(), FINGERPRINT).expect_err("refused");
    assert!(error.to_string().contains("version 1"), "{error}");
    assert!(error.remedy.is_some(), "a version mismatch has a remedy");
}

// The most common seed failure there is: edit the schema, forget to push or generate.
#[test]
fn it_refuses_a_stale_fingerprint_and_names_the_remedy() {
    let document = ir("[]");
    let error = validate(&document, &schema(), "sha256:something-else").expect_err("refused");
    let remedy = error.remedy.expect("a drift error names the remedy");
    assert!(remedy.contains("supatype generate"), "{remedy}");
    assert!(remedy.contains("supatype push"), "{remedy}");
}

// --- Models and fields ---

#[test]
fn it_refuses_an_unknown_model_and_lists_the_known_ones() {
    rejects(
        r#"[{"op":"create","model":"Speaker","data":{}}]"#,
        &["Speaker", "Organiser", "Event"],
    );
}

#[test]
fn it_refuses_an_unknown_field_and_lists_the_known_ones() {
    rejects(
        r#"[{"op":"create","model":"Organiser","data":{"slug":"n","name":"N","nmae":"typo"}}]"#,
        &["nmae", "slug"],
    );
}

// The foreign-key column is writable as well as the relation, because an author may
// reasonably have the id already.
#[test]
fn it_accepts_a_foreign_key_column_written_directly() {
    accepts(
        r#"[{"op":"create","model":"Event",
             "data":{"title":"C","starts_at":{"kind":"now"},
                     "organiser_id":"1e9d2f00-0000-4000-8000-000000000001"}}]"#,
    );
}

#[test]
fn it_refuses_a_missing_required_field() {
    rejects(
        r#"[{"op":"create","model":"Organiser","data":{"slug":"n"}}]"#,
        &["name", "required"],
    );
}

// A column with a default is not missing when absent, which is what makes `id` omittable.
#[test]
fn it_does_not_require_a_column_that_has_a_default() {
    accepts(
        r#"[{"op":"create","model":"Event",
             "data":{"title":"C","starts_at":{"kind":"now"},
                     "organiser":{"connect":{"slug":"n"}}}}]"#,
    );
}

// --- Conflict targets ---

#[test]
fn it_refuses_an_upsert_on_a_column_that_is_not_unique() {
    let message = rejects(
        r#"[{"op":"upsert","model":"Organiser","where":{"name":"N"},"data":{"slug":"n"}}]"#,
        &["not unique", "conflict"],
    );
    assert!(
        message.contains("slug"),
        "the remedy should list what is unique: {message}"
    );
}

#[test]
fn it_accepts_an_upsert_on_a_unique_composite() {
    accepts(
        r#"[{"op":"upsert","model":"Event",
             "where":{"organiser_id":"1e9d2f00-0000-4000-8000-000000000001","title":"C"},
             "data":{"starts_at":{"kind":"now"}}}]"#,
    );
}

#[test]
fn it_refuses_an_upsert_with_no_where() {
    rejects(
        r#"[{"op":"upsert","model":"Organiser","where":{},"data":{"name":"N"}}]"#,
        &["where"],
    );
}

// A column named in `where` counts towards the insert, so this must not be reported as a
// missing required field.
#[test]
fn an_upsert_where_column_satisfies_the_insert() {
    accepts(r#"[{"op":"upsert","model":"Organiser","where":{"slug":"n"},"data":{"name":"N"}}]"#);
}

// --- References ---

#[test]
fn it_accepts_a_backwards_reference() {
    accepts(
        r#"[
        {"op":"create","model":"Organiser","id":"northern","data":{"slug":"n","name":"N"}},
        {"op":"create","model":"Event",
         "data":{"title":"C","starts_at":{"kind":"now"},"organiser_id":{"$ref":"northern.id"}}}
    ]"#,
    );
}

// The direction is the point: a reference resolved at execution must already exist.
#[test]
fn it_refuses_a_forward_reference() {
    let message = rejects(
        r#"[
        {"op":"create","model":"Event",
         "data":{"title":"C","starts_at":{"kind":"now"},"organiser_id":{"$ref":"northern.id"}}},
        {"op":"create","model":"Organiser","id":"northern","data":{"slug":"n","name":"N"}}
    ]"#,
        &["northern"],
    );
    assert!(message.contains("backwards"), "{message}");
}

#[test]
fn it_refuses_a_reference_to_a_field_that_does_not_exist() {
    rejects(
        r#"[
        {"op":"create","model":"Organiser","id":"northern","data":{"slug":"n","name":"N"}},
        {"op":"create","model":"Event",
         "data":{"title":"C","starts_at":{"kind":"now"},"organiser_id":{"$ref":"northern.nmae"}}}
    ]"#,
        &["nmae"],
    );
}

#[test]
fn it_refuses_a_malformed_reference() {
    rejects(
        r#"[{"op":"create","model":"Organiser","data":{"slug":{"$ref":"northern"},"name":"N"}}]"#,
        &["operation id"],
    );
}

// --- Connect and nesting ---

#[test]
fn it_refuses_a_connect_on_a_non_unique_key() {
    rejects(
        r#"[{"op":"create","model":"Event",
             "data":{"title":"C","starts_at":{"kind":"now"},
                     "organiser":{"connect":{"name":"Northern"}}}}]"#,
        &["unique", "Organiser"],
    );
}

#[test]
fn it_refuses_a_connect_on_something_that_is_not_a_relation() {
    rejects(
        r#"[{"op":"create","model":"Organiser",
             "data":{"slug":"n","name":{"connect":{"id":"x"}}}}]"#,
        &["not a relation"],
    );
}

#[test]
fn it_validates_rows_nested_inside_a_relation() {
    rejects(
        r#"[{"op":"create","model":"Organiser",
             "data":{"slug":"n","name":"N",
                     "events":{"create":[{"title":"C"}]}}}]"#,
        &["events"],
    );
}

// --- Values ---

#[test]
fn it_refuses_a_numeric_that_is_not_a_number() {
    rejects(
        r#"[{"op":"create","model":"Organiser",
             "data":{"slug":"n","name":{"$numeric":"not a number"}}}]"#,
        &["decimal"],
    );
}

#[test]
fn it_refuses_a_default_on_a_column_that_has_none() {
    rejects(
        r#"[{"op":"create","model":"Organiser","data":{"slug":"n","name":{"$default":true}}}]"#,
        &["no default"],
    );
}

#[test]
fn it_accepts_a_default_on_a_column_that_has_one() {
    accepts(
        r#"[{"op":"create","model":"Event",
             "data":{"title":"C","starts_at":{"kind":"now"},"currency":{"$default":true},
                     "organiser":{"connect":{"slug":"n"}}}}]"#,
    );
}

// A seed has no caller. These would compile to SQL evaluating to null, and null is a
// value, so nothing would fail: the row would just be wrong.
#[test]
fn it_refuses_caller_operands_outright() {
    for operand in [r#"{"kind":"authUid"}"#, r#"{"kind":"authRole"}"#] {
        let message = rejects(
            &format!(
                r#"[{{"op":"create","model":"Organiser","data":{{"slug":"n","name":{operand}}}}}]"#
            ),
            &["no caller"],
        );
        assert!(message.contains("seed is not a request"), "{message}");
    }
}

#[test]
fn it_refuses_a_time_operand_on_a_column_that_is_not_a_time() {
    rejects(
        r#"[{"op":"create","model":"Organiser","data":{"slug":"n","name":{"kind":"now"}}}]"#,
        &["not a date or timestamp"],
    );
}

#[test]
fn it_accepts_a_composed_time_operand_on_a_timestamp() {
    accepts(
        r#"[{"op":"create","model":"Event",
             "data":{"title":"C",
                     "starts_at":{"kind":"after","base":{"kind":"startOf","unit":"day"},
                                  "interval":{"days":30,"hours":9}},
                     "organiser":{"connect":{"slug":"n"}}}}]"#,
    );
}

// --- Conditions and groups ---

#[test]
fn it_accepts_a_bare_condition() {
    accepts(r#"[{"op":"group","if":{"kind":"notExists","model":"Organiser"},"operations":[]}]"#);
}

#[test]
fn it_refuses_a_condition_on_an_unknown_model() {
    rejects(
        r#"[{"op":"group","if":{"kind":"exists","model":"Speaker"},"operations":[]}]"#,
        &["Speaker"],
    );
}

#[test]
fn it_refuses_a_condition_filtering_on_an_unknown_column() {
    rejects(
        r#"[{"op":"group","if":{"kind":"exists","model":"Event","where":
             {"type":"compare","op":"eq","left":{"kind":"column","name":"nmae"},
              "right":{"kind":"literal","value":"x"}}},"operations":[]}]"#,
        &["nmae"],
    );
}

#[test]
fn it_refuses_a_caller_operand_in_a_condition() {
    rejects(
        r#"[{"op":"group","if":{"kind":"exists","model":"Event","where":
             {"type":"compare","op":"eq","left":{"kind":"column","name":"title"},
              "right":{"kind":"authUid"}}},"operations":[]}]"#,
        &["no caller"],
    );
}

#[test]
fn it_validates_operations_inside_a_group() {
    rejects(
        r#"[{"op":"group","operations":[{"op":"create","model":"Speaker","data":{}}]}]"#,
        &["Speaker"],
    );
}

// An IR arrives as JSON from outside, so unbounded nesting would be a stack overflow
// rather than an error.
#[test]
fn it_refuses_groups_nested_too_deeply() {
    let mut document = r#"{"op":"group","operations":[]}"#.to_string();
    for _ in 0..20 {
        document = format!(r#"{{"op":"group","operations":[{document}]}}"#);
    }
    rejects(&format!("[{document}]"), &["nested"]);
}

// --- Other operations ---

#[test]
fn it_refuses_an_empty_create_many() {
    rejects(
        r#"[{"op":"createMany","model":"Organiser","rows":[]}]"#,
        &["no rows"],
    );
}

#[test]
fn it_validates_every_row_of_a_create_many() {
    rejects(
        r#"[{"op":"createMany","model":"Organiser","rows":[
             {"slug":"a","name":"A"},
             {"slug":"b"}
        ]}]"#,
        &["rows[1]", "name"],
    );
}

#[test]
fn it_refuses_an_empty_sql_statement() {
    rejects(
        r#"[{"op":"sql","text":"   ","params":[]}]"#,
        &["empty statement"],
    );
}

/// Postgres refuses too few params but silently ignores extras, so both are caught here,
/// before anything runs, with the statement named.
#[test]
fn it_refuses_sql_params_that_do_not_match_the_placeholders() {
    let text = "INSERT INTO organiser (slug, name) VALUES ($1, $2)";
    rejects(
        &format!(r#"[{{"op":"sql","text":"{text}","params":["a"]}}]"#),
        &[
            "operations[0]",
            "takes 2 parameters but was given 1",
            "`INSERT INTO organiser",
        ],
    );
    rejects(
        &format!(r#"[{{"op":"sql","text":"{text}","params":["a","b","c"]}}]"#),
        &["takes 2 parameters but was given 3"],
    );
    rejects(
        r#"[{"op":"sql","text":"ANALYZE organiser","params":["a"]}]"#,
        &["takes no parameters but was given 1"],
    );
}

#[test]
fn it_accepts_sql_params_that_match_the_placeholders() {
    accepts(r#"[{"op":"sql","text":"SELECT '$9', $2::int, $1 -- $3","params":["a", 1]}]"#);
    accepts(r#"[{"op":"sql","text":"ANALYZE organiser","params":[]}]"#);
}

#[test]
fn it_refuses_an_expression_as_a_sql_param() {
    rejects(
        r#"[{"op":"sql","text":"SELECT $1","params":[{"kind":"now"}]}]"#,
        &["operations[0].params[0]", "must be a value", "now()"],
    );
}

#[test]
fn a_sql_param_can_reference_any_column_the_model_has() {
    accepts(
        r#"[
        {"op":"create","model":"Organiser","id":"o","data":{"slug":"a","name":"A"}},
        {"op":"sql","text":"SELECT $1::uuid, $2","params":[{"$ref":"o.id"},{"$ref":"o.slug"}]}
    ]"#,
    );
    rejects(
        r#"[
        {"op":"create","model":"Organiser","id":"o","data":{"slug":"a","name":"A"}},
        {"op":"sql","text":"SELECT $1","params":[{"$ref":"o.nickname"}]}
    ]"#,
        &["operations[1].params[0]", "`Organiser`", "`nickname`"],
    );
}

// --- The error itself ---

/// A failure inside a nested write has to say where it was, or the author is left
/// searching a document for a column name that appears several times.
#[test]
fn errors_carry_a_path_into_the_document() {
    let message = rejects(
        r#"[
        {"op":"create","model":"Organiser","data":{"slug":"a","name":"A"}},
        {"op":"createMany","model":"Organiser","rows":[{"slug":"b","name":"B"},{"slug":"c"}]}
    ]"#,
        &["operations[1].rows[1]"],
    );
    assert!(message.starts_with("operations[1].rows[1]"), "{message}");
}

/// And the author's own label, when they gave one, because that is what they can search
/// their seed file for.
#[test]
fn errors_name_the_operation_label() {
    let message = rejects(
        r#"[{"op":"upsert","model":"Organiser","id":"northern","where":{"name":"N"},
             "data":{"slug":"n"}}]"#,
        &["northern"],
    );
    assert!(message.contains("operation `northern`"), "{message}");
}

// --- Relation shapes the planner cannot lower ---

/// The inverse side is where a nested write belongs, because that is the side whose rows
/// carry the foreign key.
#[test]
fn a_nested_create_on_the_side_holding_the_key_is_refused() {
    rejects(
        r#"[{"op":"create","model":"Event","data":{
            "title":"Conf","starts_at":"2026-01-01T00:00:00Z",
            "organiser":{"create":[{"slug":"n","name":"N"}]}
        }}]"#,
        &["organiser", "foreign key", "connect"],
    );
}

/// And the same relation written the way it is meant to be is accepted, or the check above
/// would pass by refusing everything.
#[test]
fn a_connect_on_the_side_holding_the_key_is_accepted() {
    accepts(
        r#"[{"op":"create","model":"Event","data":{
            "title":"Conf","starts_at":"2026-01-01T00:00:00Z",
            "organiser":{"connect":{"slug":"n"}}
        }}]"#,
    );
}

/// A nested write under the inverse side is the whole point of nesting, so it must be
/// accepted. Without this the refusals above could be refusing the feature itself.
#[test]
fn a_nested_create_on_the_inverse_side_is_accepted() {
    accepts(
        r#"[{"op":"create","model":"Organiser","data":{
            "slug":"n","name":"N",
            "events":{"create":[{"title":"Conf","starts_at":"2026-01-01T00:00:00Z"}]}
        }}]"#,
    );
}

/// A composite key names a row with two columns, and one bound column cannot carry both.
/// Picking the first part would connect a row the author did not name.
#[test]
fn a_connect_on_a_composite_key_is_refused() {
    rejects(
        r#"[{"op":"create","model":"Event","data":{
            "title":"Conf","starts_at":"2026-01-01T00:00:00Z",
            "organiser":{"connect":{"organiser_id":"x","title":"y"}}
        }}]"#,
        &["connect"],
    );
}

/// Two relations back to the same model leave nothing to say which key a nested write
/// fills, and filling the wrong one would be silent.
#[test]
fn a_nested_create_with_an_ambiguous_back_reference_is_refused() {
    let ambiguous = SCHEMA.replace(
        r#""starts_at": {"kind": "datetime", "required": true},"#,
        r#""starts_at": {"kind": "datetime", "required": true},
           "co_organiser": {"kind": "relation", "cardinality": "belongsTo", "target": "Organiser",
                            "required": false,
                            "annotations": {"db": {"foreignKey": "co_organiser_id"}}},"#,
    );
    let ast: SchemaAst = serde_json::from_str(&ambiguous).expect("the fixture parses");
    let document = ir(r#"[{"op":"create","model":"Organiser","data":{
        "slug":"n","name":"N",
        "events":{"create":[{"title":"Conf","starts_at":"2026-01-01T00:00:00Z"}]}
    }}]"#);

    let error = validate(&document, &ast, FINGERPRINT)
        .expect_err("an ambiguous back reference cannot be nested");
    let rendered = error.to_string();
    assert!(
        rendered.contains("more than one relation"),
        "the message names the ambiguity: {rendered}"
    );
}

// --- Values that nearly parsed ---

/// `Value` is untagged, so anything that fails to read as an operand falls through to being a
/// plain value without a word said. A negative interval component does exactly that, because
/// the components are unsigned, and the expression then reached the database as JSON text in
/// a timestamp column: `invalid input syntax for type timestamp with time zone`, naming
/// neither the field nor the real mistake.
#[test]
fn an_expression_that_could_not_be_read_is_refused_by_name() {
    let error = rejects(
        r#"[{"op":"create","model":"Event","data":{
            "title":"Conf",
            "starts_at":{"kind":"after","base":{"kind":"now"},"interval":{"days":-20}}
        }}]"#,
        &["after", "written as text"],
    );
    assert!(
        error.contains("direction is in the"),
        "and it says what to do instead: {error}"
    );
}

/// A JSON column may legitimately hold an object with a `kind` in it, so only the kinds this
/// engine would have recognised are refused.
#[test]
fn a_json_value_that_happens_to_have_a_kind_is_left_alone() {
    accepts(
        r#"[{"op":"create","model":"Organiser","data":{
            "slug":"n","name":"N","website":"x"
        }}]"#,
    );
}

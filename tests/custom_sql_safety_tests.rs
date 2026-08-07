//! `Custom<>` is raw SQL the developer writes, interpolated into an *expression*
//! position — `USING ( … )` on a policy, and the body of a `can_*` function.
//!
//! It is not an injection vector in the usual sense: the string is a compile-time
//! literal from the developer's own source (the extractor refuses `Custom<string>`),
//! never runtime input, and anyone who can edit the schema can already write a
//! migration. The risk is narrower and more interesting — a string that *reads*
//! like a predicate in a schema diff can quietly stop being one, and then it runs
//! as statement text at push time with migration privileges.

use supatype_engine::parser;

/// Builds a one-model schema whose read rule is the given SQL.
///
/// The fixtures below deliberately contain no double quotes or backslashes, so the
/// SQL can be embedded in JSON without an escaping pass that could itself mask what
/// is being tested.
fn schema_with_custom(sql: &str) -> String {
    assert!(
        !sql.contains('"') && !sql.contains('\\'),
        "test fixture must not need JSON escaping: {sql}"
    );
    format!(
        r#"{{
  "astVersion": 2,
  "models": [{{
    "name": "Post",
    "fields": {{ "id": {{ "kind": "uuid", "primaryKey": true, "required": true,
                          "annotations": {{ "db": {{ "pgType": "UUID" }} }} }} }},
    "options": {{ "timestamps": false, "softDelete": false }},
    "annotations": {{
      "db": {{ "tableName": "posts", "indexes": [] }},
      "platform": {{ "access": {{ "read": {{ "type": "custom", "expression": "{sql}" }} }} }}
    }}
  }}]
}}"#
    )
}

fn rejects(sql: &str) -> String {
    match parser::parse(&schema_with_custom(sql)) {
        Ok(_) => panic!("Custom<\"{sql}\"> was accepted, but it escapes its expression"),
        Err(e) => e.to_string(),
    }
}

fn accepts(sql: &str) {
    if let Err(e) = parser::parse(&schema_with_custom(sql)) {
        panic!("Custom<\"{sql}\"> should be a valid predicate: {e}");
    }
}

// The whole point: a predicate stays a predicate.
#[test]
fn ordinary_predicates_are_accepted() {
    accepts("published_at <= now()");
    accepts("status = 'live'");
    accepts("(status = 'live' OR status = 'archived') AND deleted_at IS NULL");
    // Parentheses and quotes inside a string literal are text, not structure.
    accepts("label = 'a )( weird'' value'");
    accepts("owner_id = auth.uid()");
}

// A stray `)` closes `USING ( … )`, and everything after it becomes statement text
// executed when the migration runs.
#[test]
fn a_parenthesis_breakout_is_refused() {
    let err = rejects("true) ; DROP TABLE users; --");
    assert!(err.contains("closes a parenthesis"), "unhelpful error: {err}");
}

#[test]
fn a_statement_separator_is_refused() {
    let err = rejects("true; DROP TABLE users");
    assert!(err.contains("`;`"), "unhelpful error: {err}");
}

// A line comment swallows the rest of the generated statement, including the
// closing parenthesis of the clause the predicate sits in.
#[test]
fn a_comment_is_refused() {
    assert!(rejects("true -- rest of the statement").contains("comment"));
    assert!(rejects("true /* swallow").contains("comment"));
}

// The generated affordance function body is dollar-quoted, so a dollar quote in the
// predicate would end it early.
#[test]
fn dollar_quoting_is_refused() {
    let err = rejects("$can$ SELECT 1 $can$ = 'x'");
    assert!(err.contains("Dollar quoting"), "unhelpful error: {err}");
}

// An unterminated literal makes the generated SQL continue inside the string.
#[test]
fn an_unterminated_literal_is_refused() {
    assert!(rejects("status = 'live").contains("unterminated"));
}

#[test]
fn unbalanced_parentheses_are_refused() {
    assert!(rejects("(status = 'live'").contains("parenthesis"));
}

// Every error names the model and quotes the offending rule, because the point is
// to make this legible at review time rather than to be clever.
#[test]
fn errors_name_the_model_and_the_rule() {
    let err = rejects("true; DROP TABLE users");
    assert!(err.contains("Post"), "error does not name the model: {err}");
    assert!(
        err.contains("DROP TABLE users"),
        "error does not quote the rule: {err}"
    );
}

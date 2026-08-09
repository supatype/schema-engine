//! Per-column affordance functions.
//!
//! These are what the masking rewrite calls to decide whether a caller sees a
//! column, and what Studio calls to decide between a value, a lock and a disabled
//! input. One expression serving both is the point: a UI that renders from a
//! different rule than the database enforces is the lie this phase exists to remove.

use supatype_engine::{generator::sql::rls, parser};

const FIXTURE: &str = include_str!("fixtures/rls_access_rules.json");

fn can_functions() -> String {
    let ast = parser::parse(FIXTURE).expect("fixture parses");
    rls::generate_can_functions(&ast)
}

#[test]
fn a_field_read_rule_emits_a_read_affordance() {
    let sql = can_functions();
    assert!(
        sql.contains(r#"FUNCTION "public"."can_read_users__email""#),
        "no read affordance for a column with a read rule:\n{sql}"
    );
}

// Write is conjoined with read rather than checked against it. Without this a
// caller could hold write on a column they cannot see, round-trip the value they
// were never shown, and destroy it -- silently, with a 200.
#[test]
fn a_field_write_rule_is_conjoined_with_its_read_rule() {
    let sql = can_functions();
    let body = sql
        .split(r#"FUNCTION "public"."can_write_users__name""#)
        .nth(1)
        .expect("no write affordance emitted");
    let body = body.split("$can$;").next().unwrap();
    assert!(
        body.contains(" AND "),
        "write rule was not conjoined with the read rule:\n{body}"
    );
    assert!(
        body.contains("auth.role()"),
        "the read rule did not reach the write body:\n{body}"
    );
}

// A column with only a write rule is as readable as the table, so the read
// affordance is unconditionally true rather than missing -- a UI should never have
// to tell "allowed" apart from "no function".
#[test]
fn a_column_without_a_read_rule_still_gets_a_read_affordance() {
    let sql = can_functions();
    let body = sql
        .split(r#"FUNCTION "public"."can_read_users__id""#)
        .nth(1)
        .expect("no read affordance for a write-only field rule");
    assert!(
        body.split("$can$;").next().unwrap().contains("TRUE"),
        "expected an unconditional read affordance"
    );
}

// `can_read_posts__salary` must not collide with a table literally named
// `posts_salary`, hence the doubled separator.
#[test]
fn table_and_column_are_separated_unambiguously() {
    let sql = can_functions();
    assert!(sql.contains("can_read_users__email"), "separator changed");
    assert!(
        !sql.contains("can_read_users_email\""),
        "single-underscore form would collide with a table of that name"
    );
}

// Models without field rules are untouched.
#[test]
fn a_model_with_no_field_rules_emits_no_field_functions() {
    let sql = can_functions();
    assert!(
        !sql.contains("can_read_posts__"),
        "emitted field affordances for a model that declared none"
    );
}

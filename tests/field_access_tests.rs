//! Per-column affordance functions.
//!
//! These are what the masking rewrite calls to decide whether a caller sees a
//! column, and what Studio calls to decide between a value, a lock and a disabled
//! input. One expression serving both is the point: a UI that renders from a
//! different rule than the database enforces is the lie this phase exists to remove.

use supatype_engine::{generator::sql::rls, parser};

const FIXTURE: &str = include_str!("fixtures/rls_field_rules.json");

fn can_functions() -> String {
    let ast = parser::parse(FIXTURE).expect("fixture parses");
    rls::generate_can_functions(&ast, "public")
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

// ─── Security labels ─────────────────────────────────────────────────────────
//
// The labels are what makes a field rule enforced rather than merely described:
// `supatype_mask` reads them to decide which columns to rewrite. A generated
// affordance function nobody points the extension at changes nothing.

fn security_labels() -> String {
    let ast = parser::parse(FIXTURE).expect("fixture parses");
    rls::generate_security_labels(&ast, "public")
}

#[test]
fn a_read_rule_is_named_in_the_label() {
    let sql = security_labels();
    assert!(
        sql.contains(r#"SECURITY LABEL FOR supatype ON COLUMN "public"."users"."email""#),
        "no label for a column with a read rule:\n{sql}"
    );
    assert!(
        sql.contains(r#"IS 'MASK READ public."can_read_users__email"';"#),
        "label did not point at the generated read predicate:\n{sql}"
    );
}

#[test]
fn a_read_and_write_rule_names_both_predicates() {
    let sql = security_labels();
    assert!(
        sql.contains(
            r#"IS 'MASK READ public."can_read_users__name" WRITE public."can_write_users__name"';"#
        ),
        "label did not carry both predicates:\n{sql}"
    );
}

// A write-only rule leaves reads alone. The read affordance function still exists for
// Studio, but naming it here would make every read of the column call a predicate that
// always answers true.
#[test]
fn a_write_only_rule_does_not_name_a_read_predicate() {
    let sql = security_labels();
    let label = sql
        .split(r#"ON COLUMN "public"."users"."id""#)
        .nth(1)
        .expect("no label for a write-only field rule")
        .split(';')
        .next()
        .unwrap();
    assert!(
        label.contains(r#"WRITE public."can_write_users__id""#),
        "write-only rule lost its write predicate:\n{label}"
    );
    assert!(
        !label.contains("READ"),
        "write-only rule was given a read predicate:\n{label}"
    );
}

// Tier 3 of the field-access plan: never silently unmask. A schema that declares a
// masked column, applied to a database that cannot mask it, must fail rather than apply.
#[test]
fn field_rules_refuse_to_apply_without_the_extension() {
    let sql = security_labels();
    assert!(
        sql.contains("RAISE EXCEPTION 'field-level access requires the supatype_mask extension'"),
        "no capability probe:\n{sql}"
    );
    assert!(
        sql.contains("feature_not_supported"),
        "probe did not raise a typed error:\n{sql}"
    );
}

// A schema with no field rules sets no label and probes for nothing: every such schema would
// otherwise refuse to apply to a database without the extension. Taking off the labels a removed
// rule left is the reconcile's (`tests/label_ledger_tests.rs`).
#[test]
fn a_schema_with_no_field_rules_neither_labels_nor_probes() {
    let mut ast = parser::parse(FIXTURE).expect("fixture parses");
    for model in &mut ast.models {
        supatype_engine::parser::accessors::platform_access_mut(model)
            .fields
            .clear();
    }
    let sql = rls::generate_security_labels(&ast, "public");
    assert!(
        sql.trim().is_empty(),
        "a schema with no field rules emitted label SQL:\n{sql}"
    );
}

// The predicates in those labels call `auth.role()` from the query itself, not from a policy, so
// the caller needs USAGE on the auth schema. Postgres runs a policy's USING clause with the table
// owner's privileges, which is why row-level security never needed this and masking does.
//
// The privilege is granted in the auth preamble, which a push emits before the labels, and the
// labels carry only the probe that proves it landed. That split is deliberate: a GRANT issued by a
// role that does not own the schema is a WARNING, not an error, so granting proves nothing on its
// own. This asserts both halves, each in the artefact that actually carries it, because an earlier
// version of this test looked for the grant in the labels alone and failed for that reason rather
// than because the privilege was missing.
#[test]
fn field_rules_grant_usage_on_the_auth_schema() {
    let preamble = rls::generate_auth_helpers();
    assert!(
        preamble.contains("GRANT USAGE ON SCHEMA \"auth\" TO authenticated"),
        "the preamble did not grant the privilege the predicates need:\n{preamble}"
    );
    assert!(
        preamble.contains("IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated')"),
        "the grant was not guarded on the role existing:\n{preamble}"
    );

    let labels = security_labels();
    assert!(
        labels.contains("has_schema_privilege('authenticated', 'auth', 'USAGE')"),
        "the labels did not check that the grant landed:\n{labels}"
    );
}

// Issuing that grant proves nothing: a role that does not own the schema cannot grant on it,
// and Postgres answers with a WARNING rather than an error. So the push checks, and refuses,
// rather than succeeding and leaving every authenticated read of a masked column at 42501.
#[test]
fn field_rules_refuse_to_apply_without_usage_on_the_auth_schema() {
    let sql = security_labels();
    assert!(
        sql.contains("has_schema_privilege('authenticated', 'auth', 'USAGE')"),
        "no privilege probe, so a no-op grant would pass unnoticed:\n{sql}"
    );
    assert!(
        sql.contains("RAISE EXCEPTION 'field-level access requires USAGE on schema auth'"),
        "the probe did not refuse the push:\n{sql}"
    );
    assert!(
        sql.contains("pg_get_userbyid(nspowner)"),
        "the refusal must name the owner who can grant it:\n{sql}"
    );
}

// Same reasoning as the extension probe: a schema with no field rules must not start demanding
// a privilege it does not use, or every such push would refuse on a database that never had it.
#[test]
fn a_schema_with_no_field_rules_neither_grants_nor_probes() {
    let mut ast = parser::parse(FIXTURE).expect("fixture parses");
    for model in &mut ast.models {
        supatype_engine::parser::accessors::platform_access_mut(model)
            .fields
            .clear();
    }
    let sql = rls::generate_security_labels(&ast, "public");

    assert!(
        !sql.contains("GRANT USAGE ON SCHEMA"),
        "granted a privilege for rules that do not exist:\n{sql}"
    );
    assert!(
        !sql.contains("has_schema_privilege"),
        "probed a privilege the schema does not need:\n{sql}"
    );
}

//! Regression tests for bugs found while building the "standup" app:
//!   1. A primary-key column flagged `unique` must NOT generate a `<table>_id_key`
//!      UNIQUE constraint / managed COMMENT (Postgres: "constraint does not exist").
//!   2. A `belongsTo` relation plus an explicitly-declared `<rel>_id` scalar must
//!      emit the FK column only ONCE ("column specified more than once").
//!   3. The generated TypeScript types must not contain a duplicate FK column key.
//!   4. `push` must install slug / updated_at triggers (with the `_platform` schema
//!      created and granted), otherwise NOT NULL `Slug<…>` columns fail on insert.

use supatype_engine::{
    differ,
    generator::sql::{migration, triggers},
    generator::typescript::types,
    parser,
    state::database_state::DatabaseState,
};

const FIXTURE: &str = include_str!("fixtures/standup_relations.json");

fn forward_sql() -> String {
    let ast = parser::parse(FIXTURE).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    migration::forward_sql(&diff, false, "public", &ast).unwrap()
}

// ── Bug 1: PK column flagged unique ───────────────────────────────────────────

#[test]
fn pk_column_does_not_emit_id_key_unique_constraint() {
    let sql = forward_sql();
    assert!(
        !sql.contains("profile_id_key"),
        "PK `id` must not produce a profile_id_key UNIQUE constraint:\n{sql}"
    );
    assert!(
        !sql.contains("team_id_key"),
        "PK `id` must not produce a team_id_key UNIQUE constraint:\n{sql}"
    );
    // A genuine non-PK unique (slug) should still be managed.
    assert!(
        sql.contains("team_slug_key"),
        "non-PK unique `slug` should still get its UNIQUE constraint"
    );
}

// ── Bug 2: relation + explicit FK scalar => single column ─────────────────────

#[test]
fn relation_and_explicit_fk_scalar_emit_column_once() {
    let sql = forward_sql();
    let start = sql
        .find("CREATE TABLE IF NOT EXISTS \"public\".\"team\"")
        .unwrap();
    let end = sql[start..].find(");").unwrap() + start;
    let create_team = &sql[start..end];
    let occurrences = create_team.matches("\"owner_id\"").count();
    assert_eq!(
        occurrences, 1,
        "owner_id must appear exactly once in the team CREATE TABLE, got {occurrences}:\n{create_team}"
    );
}

// ── Bug 3: TypeScript types must not duplicate the FK column ──────────────────

#[test]
fn generated_types_do_not_duplicate_fk_column() {
    let ast = parser::parse(FIXTURE).unwrap();
    let ts = types::generate(&ast).unwrap();
    // owner_id is declared once each in Row / Insert / Update: three times total. Counted as a
    // property, because the table's `Relationships` also names it as the key's column.
    let occurrences = ts.matches("owner_id:").count() + ts.matches("owner_id?:").count();
    assert_eq!(
        occurrences, 3,
        "owner_id should appear 3x (Row/Insert/Update), got {occurrences}:\n{ts}"
    );
}

// ── Bug 4: triggers generated, scoped, and applied during push ────────────────

#[test]
fn triggers_create_platform_schema_with_grants_and_slug_trigger() {
    let ast = parser::parse(FIXTURE).unwrap();
    let sql = triggers::generate(&ast, "public").unwrap();
    assert!(sql.contains("CREATE SCHEMA IF NOT EXISTS _platform"));
    assert!(sql.contains("GRANT USAGE ON SCHEMA _platform TO PUBLIC"));
    assert!(sql.contains("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA _platform TO PUBLIC"));
    assert!(
        sql.contains("\"team_slug_trigger\""),
        "expected a slug trigger for team.slug:\n{sql}"
    );
}

#[test]
fn push_apply_body_includes_slug_trigger() {
    let ast = parser::parse(FIXTURE).unwrap();
    // The migration a push applies, the trigger layer included: triggers are the reconcile's
    // creations since Phase 4.2, so a diff alone no longer carries them.
    let body = supatype_engine::push::fresh_migration(&ast, "public", false)
        .unwrap()
        .apply_body();
    assert!(
        body.contains("CREATE SCHEMA IF NOT EXISTS _platform"),
        "push apply body must ensure the _platform schema"
    );
    assert!(
        body.contains("\"team_slug_trigger\""),
        "push apply body must install the slug trigger so NOT NULL slug inserts succeed"
    );
}

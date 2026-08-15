//! Column write privileges derived from `fields.write` — defence in depth under the masking
//! extension.
//!
//! The interesting content is what this *refuses* to revoke. A column privilege belongs to a
//! database role, and every signed-in caller is `authenticated`, so revoking on the strength
//! of an application-role rule would lock out the very callers the rule admits. Enforcement
//! is the query rewrite; this is only a second layer for what a database role provably can
//! never write.

use supatype_engine::{generator::sql::grants, parser};

/// `docs`, writable by everyone at table level, with one column per interesting write rule.
///
/// Purpose-built rather than the shared access fixture: that one declares no `create` rule and
/// an ownership `update` rule, so nothing is provably unwritable and it correctly emits
/// nothing — exercising none of the branches below.
const SCHEMA: &str = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Doc",
      "fields": {
        "id":         { "kind": "uuid", "primaryKey": true, "required": true,
                        "default": { "kind": "genRandomUuid" },
                        "annotations": { "db": { "pgType": "UUID", "unique": false } } },
        "open":       { "kind": "text", "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
        "locked":     { "kind": "text", "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
        "mine":       { "kind": "text", "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
        "admin_only": { "kind": "text", "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
      },
      "annotations": {
        "db": { "tableName": "docs", "indexes": [] },
        "platform": {
          "access": {
            "read":   { "type": "public" },
            "create": { "type": "public" },
            "update": { "type": "public" },
            "fields": {
              "open":       { "write": { "type": "public" } },
              "locked":     { "write": { "type": "private" } },
              "mine":       { "write": { "type": "owner", "field": "id" } },
              "admin_only": { "write": { "type": "role", "roles": ["admin"] } }
            }
          }
        }
      }
    }
  ]
}"#;

fn column_grants() -> String {
    let ast = parser::parse(SCHEMA).expect("schema parses");
    grants::generate_column_grants(&ast, "public", &[])
}

/// The excluded-column list for one (operation, role) pair.
fn excluded_for(sql: &str, op: &str, role: &str) -> Vec<String> {
    let needle = format!("REVOKE {op} ");
    let block = sql
        .split("IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ")
        .skip(1)
        .map(|b| b.split("END IF;").next().unwrap_or("").to_string())
        .find(|b| b.starts_with(&format!("'{role}'")) && b.contains(&needle))
        .unwrap_or_else(|| panic!("no {op} block for {role} in:\n{sql}"));

    let list = block
        .split("column_name NOT IN (")
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .unwrap_or("");

    list.split(',')
        .map(|item| item.trim().trim_matches('\'').to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

fn has(list: &[String], column: &str) -> bool {
    list.iter().any(|c| c == column)
}

// An anonymous caller has no `auth.uid()` and no app role, so ownership and role rules are
// both unreachable for `anon` — those columns can never be written as that role.
#[test]
fn anon_loses_every_column_it_can_never_write() {
    let sql = column_grants();
    for op in ["INSERT", "UPDATE"] {
        let excluded = excluded_for(&sql, op, "anon");
        assert!(has(&excluded, "locked"), "{op}: {excluded:?}");
        assert!(has(&excluded, "mine"), "{op}: {excluded:?}");
        assert!(has(&excluded, "admin_only"), "{op}: {excluded:?}");
        assert!(
            !has(&excluded, "open"),
            "{op}: a public write rule is reachable by anon and must stay granted: {excluded:?}"
        );
    }
}

// The heart of it. `authenticated` is every signed-in caller, so a rule naming an application
// role is satisfiable by some of them — revoking would lock out the admins the rule exists to
// admit. On the UPDATE path only `Private` is provable.
#[test]
fn authenticated_keeps_columns_some_caller_can_write() {
    let sql = column_grants();
    let excluded = excluded_for(&sql, "UPDATE", "authenticated");

    assert!(
        has(&excluded, "locked"),
        "a private write rule denies every caller: {excluded:?}"
    );
    assert!(
        !has(&excluded, "admin_only"),
        "an admin connects as `authenticated`; revoking would lock them out: {excluded:?}"
    );
    assert!(
        !has(&excluded, "mine"),
        "the owner can write their own row on UPDATE: {excluded:?}"
    );
    assert!(!has(&excluded, "open"), "{excluded:?}");
}

// On INSERT there is no row, so the extension evaluates a row-dependent write predicate
// against `NULL::t` and it yields NULL for every caller. Nobody can write the column on that
// path, which makes the privilege provably unusable — unlike on UPDATE.
#[test]
fn authenticated_loses_row_dependent_columns_on_insert_only() {
    let sql = column_grants();
    let insert = excluded_for(&sql, "INSERT", "authenticated");
    let update = excluded_for(&sql, "UPDATE", "authenticated");

    assert!(
        has(&insert, "mine"),
        "a row-dependent rule is unsatisfiable on INSERT: {insert:?}"
    );
    assert!(
        !has(&update, "mine"),
        "the same rule is satisfiable on UPDATE, so the privilege must stay: {update:?}"
    );
    assert!(
        !has(&insert, "admin_only"),
        "an identity-only rule is satisfiable on INSERT too: {insert:?}"
    );
}

// The complement has to come from the live catalog, not the AST: a column this generator never
// saw must still be granted, or a defence-in-depth layer becomes the thing that breaks writes.
#[test]
fn the_granted_column_list_is_read_from_the_catalog() {
    let sql = column_grants();
    assert!(sql.contains("FROM information_schema.columns"), "{sql}");
    assert!(
        sql.contains("quote_ident(column_name)"),
        "column names must be quoted by the database, not by string building:\n{sql}"
    );
}

// Reads are never restricted this way: a column REVOKE makes `GET /table` with no `select`
// return 403 for the whole table, which is the break the field-access design exists to avoid.
#[test]
fn reads_are_never_restricted_by_privilege() {
    let sql = column_grants();
    assert!(!sql.contains("REVOKE SELECT"), "{sql}");
    assert!(
        !sql.contains("GRANT SELECT"),
        "reads are the extension's job:\n{sql}"
    );
}

// A GRANT to a missing role aborts the transaction, and this is defence in depth — it must
// never take the migration down with it.
#[test]
fn column_grants_are_guarded_on_the_role_existing() {
    assert!(column_grants().contains("FROM pg_roles WHERE rolname ="));
}

// No table-level write rule means the table grants revoked the operation from both roles.
// Granting a column complement back would widen what they just closed.
#[test]
fn a_table_with_no_write_rule_gets_no_column_grants() {
    let schema = SCHEMA
        .replace("\"create\": { \"type\": \"public\" },", "")
        .replace("\"update\": { \"type\": \"public\" },", "");
    let ast = parser::parse(&schema).expect("schema parses");
    assert!(
        grants::generate_column_grants(&ast, "public", &[])
            .trim()
            .is_empty(),
        "nothing may be granted where the table rules granted nothing"
    );
}

#[test]
fn no_field_rules_means_no_column_grants() {
    let mut ast = parser::parse(SCHEMA).expect("schema parses");
    for model in &mut ast.models {
        supatype_engine::parser::accessors::platform_access_mut(model)
            .fields
            .clear();
    }
    assert!(grants::generate_column_grants(&ast, "public", &[])
        .trim()
        .is_empty());
}

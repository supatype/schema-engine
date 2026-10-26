//! Phase 2c of the managed-object ownership plan: every statement of a push belongs to an object.
//!
//! The generator renders a push as blobs. `desired::statements` splits them and attributes each
//! statement to the object key it creates, drops, comments on or grants on. Three things are
//! proved here, per fixture:
//!
//! - the split loses nothing: joining the statements back reproduces the push byte for byte;
//! - no statement is left unattributed, and the objects the desired set names are the objects
//!   the statements name (the set and the attribution cannot disagree);
//! - after a real push, every object a creating statement named exists under that key in the
//!   live fingerprints, which is what the ledger will record against.

mod common;

use std::collections::BTreeSet;

use supatype_engine::{
    desired::{
        desired_objects,
        statements::{attribute_all, head, split_statements, Attribution, Statement},
        ObjectKey,
    },
    differ,
    generator::sql::{migration, triggers},
    introspector::{
        self,
        catalog::ENGINE_SCHEMAS,
        fingerprint::{fingerprints, ObjectKind},
    },
    parser,
    parser::accessors::versions_table_name,
    parser::ast::SchemaAst,
};

/// Every fixture the parser accepts. The ones a database refuses still render, and the split and
/// attribution must hold for what they render.
const RENDERABLE: &[&str] = &[
    "basic_blog",
    "cms_content",
    "conformance_matrix",
    "ecommerce",
    "five_model_blog",
    "geospatial",
    "kitchen_sink",
    "kitchen_sink_example",
    "many_to_many",
    "rls_access_rules",
    "rls_field_rules",
    "self_referential",
    "standup_relations",
    "vector_search",
    "versioned_blog",
];

/// The fixtures a real database accepts (see `golden_tests.rs` for why the rest do not).
const PUSHABLE: &[&str] = &[
    "ecommerce",
    "five_model_blog",
    "geospatial",
    "kitchen_sink_example",
    "many_to_many",
    "rls_access_rules",
    "rls_field_rules",
    "self_referential",
    "standup_relations",
    "versioned_blog",
];

fn fixture(name: &str) -> SchemaAst {
    let path = format!("{}/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    parser::parse(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

/// The whole push against an empty database, assembled as the golden harness assembles it.
fn push_sql(ast: &SchemaAst) -> String {
    let diff = differ::diff(ast, &Default::default()).unwrap();
    let sql = migration::forward_sql(&diff, false, "public", ast).unwrap();
    let trigger_sql = triggers::generate(ast, "public").unwrap();
    format!("{sql}\n\n-- triggers\n{trigger_sql}")
}

fn attributed(ast: &SchemaAst) -> Vec<Statement> {
    attribute_all("public", split_statements(&push_sql(ast)))
}

fn keys_of(statement: &Statement) -> Vec<&ObjectKey> {
    match &statement.attribution {
        Attribution::Object(k) => vec![k],
        Attribution::Shared(keys) => keys.iter().collect(),
        Attribution::Ignored(_) | Attribution::Unknown => Vec::new(),
    }
}

fn first_line(statement: &Statement) -> String {
    head(&statement.sql)
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(120)
        .collect()
}

#[test]
fn rejoining_the_statements_reproduces_the_push() {
    for name in RENDERABLE {
        let sql = push_sql(&fixture(name));
        let parts = split_statements(&sql);
        assert!(
            parts.len() > 40,
            "{name}: only {} statements, the split is not splitting",
            parts.len()
        );
        assert_eq!(
            parts.concat(),
            sql,
            "{name}: the split lost or altered bytes"
        );
        for part in &parts {
            let count = split_statements(part).len();
            assert_eq!(
                count, 1,
                "{name}: a statement split again into {count}:\n{part}"
            );
        }
    }
}

#[test]
fn every_statement_is_attributed() {
    for name in RENDERABLE {
        let unknown: Vec<String> = attributed(&fixture(name))
            .iter()
            .filter(|s| s.attribution == Attribution::Unknown)
            .map(first_line)
            .collect();
        assert!(
            unknown.is_empty(),
            "{name}: {} statements belong to no object:\n  {}",
            unknown.len(),
            unknown.join("\n  ")
        );
    }
}

fn kinds_in_set() -> &'static [ObjectKind] {
    &[
        ObjectKind::PrimaryKey,
        ObjectKind::Unique,
        ObjectKind::ForeignKey,
        ObjectKind::Check,
        ObjectKind::Index,
        ObjectKind::Policy,
    ]
}

/// The versions layer's policies are not in the desired set yet (its tables' keys and indexes
/// are), so they are the one thing the statements name that the set does not.
fn versions_layer_policy(ast: &SchemaAst, key: &ObjectKey) -> bool {
    key.kind == ObjectKind::Policy
        && (key.name.ends_with("_draft_select")
            || ast
                .models
                .iter()
                .any(|m| versions_table_name(m.table_name()) == key.parent))
}

#[test]
fn the_desired_set_and_the_statements_name_the_same_objects() {
    for name in RENDERABLE {
        let ast = fixture(name);
        let in_set: BTreeSet<ObjectKey> = desired_objects(&ast, "public")
            .unwrap()
            .into_iter()
            .map(|o| o.key)
            .filter(|k| kinds_in_set().contains(&k.kind))
            .collect();
        let in_statements: BTreeSet<ObjectKey> = attributed(&ast)
            .iter()
            .flat_map(keys_of)
            .filter(|k| {
                kinds_in_set().contains(&k.kind)
                    && k.schema == "public"
                    && !versions_layer_policy(&ast, k)
            })
            .cloned()
            .collect();
        let only_set: Vec<_> = in_set.difference(&in_statements).collect();
        let only_statements: Vec<_> = in_statements.difference(&in_set).collect();
        assert!(
            only_set.is_empty() && only_statements.is_empty(),
            "{name}: the set and the statements disagree.\n  desired but no statement: {only_set:#?}\n  statement but not desired: {only_statements:#?}"
        );
    }
}

/// Whether a statement brings its object into being, as opposed to dropping, revoking or
/// annotating it. Only these have to leave a live row behind.
fn creates(statement: &Statement) -> bool {
    let h = head(&statement.sql);
    let u = h.to_ascii_uppercase();
    (u.starts_with("CREATE ") && !u.starts_with("CREATE EXTENSION"))
        || u.starts_with("ALTER TABLE ")
        || u.starts_with("SECURITY LABEL ")
        || u.starts_with("GRANT ")
}

/// Tables, their constraints and their indexes are read from the project schema only
/// (`introspector::introspect`); the catalog sweep covers the engine schemas for every other
/// kind. So the engine's own tables (`_supatype.preview_links` and friends) have no live row yet,
/// and the ledger cannot record them until that sweep widens. Named here so the gap is visible,
/// not quietly passed over.
fn outside_live_coverage(key: &ObjectKey) -> bool {
    matches!(
        key.kind,
        ObjectKind::Table
            | ObjectKind::PrimaryKey
            | ObjectKind::ForeignKey
            | ObjectKind::Unique
            | ObjectKind::Check
            | ObjectKind::Index
    ) && ENGINE_SCHEMAS.contains(&key.schema.as_str())
}

/// Function keys carry the declared argument list; the live key carries what
/// `pg_get_function_identity_arguments` reports. Phase 3 canonicalises the declared side, so
/// until then a function is matched on schema and name.
fn exists_live(key: &ObjectKey, live: &BTreeSet<ObjectKey>) -> bool {
    if outside_live_coverage(key) {
        return true;
    }
    if key.kind == ObjectKind::Function {
        let bare = key.name.split('(').next().unwrap_or("");
        return live.iter().any(|l| {
            l.kind == ObjectKind::Function
                && l.schema == key.schema
                && l.name.split('(').next() == Some(bare)
        });
    }
    live.contains(key)
}

#[tokio::test]
async fn after_a_push_every_created_object_exists_under_its_key() {
    for name in PUSHABLE {
        common::with_integration_pool(|pool| async move {
            let ast = fixture(name);
            sqlx::raw_sql(
                "CREATE SCHEMA IF NOT EXISTS auth;
                 CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT UNIQUE);",
            )
            .execute(&pool)
            .await
            .unwrap();
            let empty = introspector::introspect(&pool, "public").await.unwrap();
            let diff = differ::diff(&ast, &empty).unwrap();
            let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
            let trigger_sql = triggers::generate(&ast, "public").unwrap();
            sqlx::raw_sql(&sql)
                .execute(&pool)
                .await
                .unwrap_or_else(|e| panic!("{name}: applies: {e}"));
            sqlx::raw_sql(&trigger_sql).execute(&pool).await.unwrap();

            let db = introspector::introspect(&pool, "public").await.unwrap();
            let catalog = introspector::introspect_catalog(&pool, "public").await.unwrap();
            let live: BTreeSet<ObjectKey> = fingerprints(&db, &catalog)
                .into_iter()
                .map(|f| ObjectKey {
                    kind: f.kind,
                    schema: f.schema,
                    parent: f.parent,
                    name: f.name,
                })
                .collect();

            let statements =
                attribute_all("public", split_statements(&format!("{sql}\n\n-- triggers\n{trigger_sql}")));
            // A table grant that a later statement of the same push revokes (the field views grant
            // the API roles everything, then the per-table block takes back what the rules do not
            // allow) legitimately leaves no row.
            let revoked: BTreeSet<&ObjectKey> = statements
                .iter()
                .filter(|s| s.sql.contains("REVOKE"))
                .flat_map(keys_of)
                .filter(|k| k.kind == ObjectKind::TableGrant)
                .collect();
            let mut missing = Vec::new();
            for statement in statements.iter().filter(|s| creates(s)) {
                for key in keys_of(statement) {
                    if revoked.contains(key) {
                        continue;
                    }
                    if !exists_live(key, &live) {
                        missing.push(format!("{key:?}\n    from: {}", first_line(statement)));
                    }
                }
            }
            assert!(
                missing.is_empty(),
                "{name}: {} created objects have no live row under their key:\n  {}",
                missing.len(),
                missing.join("\n  ")
            );
        })
        .await;
    }
}

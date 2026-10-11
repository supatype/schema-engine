//! Phase 2c of the managed-object ownership plan: every statement of a push against an empty
//! database belongs to an object. (The incremental statements of a later push are not covered;
//! see `desired::statements`.)
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
        desired_objects, desired_objects_for,
        statements::{attribute_all, head, split_statements, Attribution, Statement},
        DesiredObject, FieldEnforcement, ObjectKey,
    },
    differ::{self, FieldMaskingTier},
    introspector::fingerprint::ObjectKind,
    parser,
    parser::ast::SchemaAst,
    push,
    state::database_state::DatabaseState,
};

/// Every fixture the parser accepts. The ones a database refuses still render, and the split and
/// attribution must hold for what they render.
const RENDERABLE: &[&str] = &[
    "awkward_names",
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
    "awkward_names",
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

/// The whole push against an empty database: the migration, which since Phase 4.2 carries the
/// trigger functions and triggers as the reconcile's creations.
fn push_sql(ast: &SchemaAst) -> String {
    push::fresh_migration(ast, "public", false)
        .unwrap()
        .up_script()
}

/// The desired set for the masking tier that push chooses: an empty database has no
/// `supatype_mask`, so a schema with field rules gets tier 2's views and their policies.
fn desired_for_a_fresh_push(ast: &SchemaAst) -> Vec<DesiredObject> {
    let diff = differ::diff(ast, &DatabaseState::default()).unwrap();
    match diff.field_masking {
        FieldMaskingTier::Views => desired_objects_for(
            ast,
            "public",
            FieldEnforcement::Views(&diff.field_view_plan),
        ),
        _ => desired_objects(ast, "public"),
    }
    .unwrap()
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

/// Both sides read in the project schema: the engine's own schemas hold objects the set lists
/// (the layer's tables, their indexes and policies) that the scan does not look for.
#[test]
fn the_desired_set_and_the_statements_name_the_same_objects() {
    for name in RENDERABLE {
        let ast = fixture(name);
        let in_set: BTreeSet<ObjectKey> = desired_for_a_fresh_push(&ast)
            .into_iter()
            .map(|o| o.key)
            .filter(|k| kinds_in_set().contains(&k.kind) && k.schema == "public")
            .collect();
        // Creating statements only: the layer also drops what a model no longer asks for (the
        // write policies of a history-only table), and those name nothing the set wants.
        let in_statements: BTreeSet<ObjectKey> = attributed(&ast)
            .iter()
            .filter(|s| creates(s))
            .flat_map(keys_of)
            .filter(|k| kinds_in_set().contains(&k.kind) && k.schema == "public")
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

/// Exact key equality, every kind, every schema: the engine's own tables are introspected like a
/// model's, and a function's declared signature is canonicalised to the catalog's
/// `identity_types`, so there is no kind matched loosely.
fn exists_live(key: &ObjectKey, live: &BTreeSet<ObjectKey>) -> bool {
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
            // The push a user gets, and the statements it ran.
            let plan = push::prepare(&pool, &ast, "public").await.unwrap();
            let sql = plan.migration(false).unwrap().up_script();
            push::apply(&pool, plan, push::ApplyOptions::default())
                .await
                .unwrap_or_else(|e| panic!("{name}: applies: {e}"));

            let live: BTreeSet<ObjectKey> = common::live_state(&pool)
                .await
                .fingerprints
                .into_iter()
                .map(|f| f.key())
                .collect();

            let statements = attribute_all("public", split_statements(&sql));
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

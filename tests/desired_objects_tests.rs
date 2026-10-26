//! Phase 2b of the managed-object ownership plan: the desired object set describes what a push
//! emits, and what a push leaves behind.
//!
//! Two checks, per fixture, both directions:
//!
//! - every constraint, index and policy name in the generated migration is in the set, and every
//!   name in the set is in the migration (the generator and the set cannot disagree about what a
//!   push creates);
//! - after a real push, every desired object exists under its key, and the structural parts the
//!   set predicts equal what the catalog reports (desired-versus-live is trustworthy, which is
//!   what auto-adopt relies on).
//!
//! The versions layer's policies and the draft views are not in the set yet (Phase 2c), so the
//! migration scan leaves them out explicitly rather than quietly.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use supatype_engine::{
    desired::{desired_objects, DesiredObject},
    differ,
    generator::sql::{migration, triggers},
    introspector::{
        self,
        fingerprint::{fingerprints, ObjectKind},
    },
    parser,
    parser::accessors::versions_table_name,
    parser::ast::SchemaAst,
};

/// The fixtures a real database accepts (see `golden_tests.rs` for the ones it does not).
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

/// Every `CONSTRAINT "x"`, `INDEX IF NOT EXISTS "x"` and `CREATE POLICY "x"` in statements that
/// touch the project schema. Statements against `_supatype`, `draft`, `api` and `supatype` are the
/// versions layer and the field views, which are not in the set yet.
fn names_in_sql(sql: &str, ast: &SchemaAst) -> BTreeSet<String> {
    let versions_tables: BTreeSet<String> = ast
        .models
        .iter()
        .map(|m| versions_table_name(m.table_name()))
        .collect();
    let mut out = BTreeSet::new();
    for statement in sql.split(';') {
        if !statement.contains("\"public\".") {
            continue;
        }
        // Policies on a versions table, and the draft-select policy, come from the versions
        // layer (2c). Their table's own keys and indexes are in the set.
        if statement.contains("CREATE POLICY")
            && (versions_tables
                .iter()
                .any(|vt| statement.contains(&format!("ON \"public\".\"{vt}\"")))
                || statement.contains("_draft_select\""))
        {
            continue;
        }
        for marker in [
            "CONSTRAINT \"",
            "INDEX IF NOT EXISTS \"",
            "CREATE POLICY \"",
        ] {
            let mut rest = statement;
            while let Some(i) = rest.find(marker) {
                let after = &rest[i + marker.len()..];
                if let Some(end) = after.find('"') {
                    out.insert(after[..end].to_string());
                    rest = &after[end..];
                } else {
                    break;
                }
            }
        }
    }
    out
}

fn names_in_set(set: &[DesiredObject]) -> BTreeSet<String> {
    set.iter()
        .filter(|o| kinds_in_set().contains(&o.key.kind))
        .map(|o| o.key.name.clone())
        .collect()
}

#[test]
fn the_set_and_the_migration_name_the_same_objects() {
    for name in PUSHABLE {
        let ast = fixture(name);
        let diff = differ::diff(&ast, &Default::default()).unwrap();
        let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
        let set = desired_objects(&ast, "public").unwrap();

        let in_sql = names_in_sql(&sql, &ast);
        let in_set = names_in_set(&set);
        let only_sql: Vec<_> = in_sql.difference(&in_set).collect();
        let only_set: Vec<_> = in_set.difference(&in_sql).collect();
        assert!(
            only_sql.is_empty() && only_set.is_empty(),
            "{name}: the generator and the set disagree.\n  emitted but not desired: {only_sql:?}\n  desired but not emitted: {only_set:?}"
        );
    }
}

#[test]
fn no_drop_cascades_and_the_set_is_deterministic() {
    for name in PUSHABLE {
        let ast = fixture(name);
        let a = desired_objects(&ast, "public").unwrap();
        let b = desired_objects(&ast, "public").unwrap();
        assert_eq!(
            a.iter().map(|o| &o.key).collect::<Vec<_>>(),
            b.iter().map(|o| &o.key).collect::<Vec<_>>(),
            "{name}: two builds differ"
        );
        for o in &a {
            assert!(
                !o.drop_sql.contains("CASCADE"),
                "{name}: {} cascades",
                o.key.name
            );
            assert!(
                !o.create_sql.trim().is_empty(),
                "{name}: {} has no create",
                o.key.name
            );
        }
        let mut keys: Vec<_> = a.iter().map(|o| &o.key).collect();
        let unsorted = keys.clone();
        keys.sort();
        assert_eq!(keys, unsorted, "{name}: not sorted");
    }
}

#[tokio::test]
async fn after_a_push_every_desired_object_exists_with_the_structure_it_predicted() {
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
            sqlx::raw_sql(&migration::forward_sql(&diff, false, "public", &ast).unwrap())
                .execute(&pool)
                .await
                .unwrap_or_else(|e| panic!("{name}: applies: {e}"));
            sqlx::raw_sql(&triggers::generate(&ast, "public").unwrap())
                .execute(&pool)
                .await
                .unwrap();

            let db = introspector::introspect(&pool, "public").await.unwrap();
            let catalog = introspector::introspect_catalog(&pool, "public").await.unwrap();
            let live: BTreeMap<(ObjectKind, String, String, String), BTreeMap<String, String>> =
                fingerprints(&db, &catalog)
                    .into_iter()
                    .map(|f| {
                        let parts = f
                            .definition
                            .lines()
                            .filter_map(|l| l.split_once('='))
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                            .collect();
                        ((f.kind, f.schema, f.parent, f.name), parts)
                    })
                    .collect();

            let mut problems = Vec::new();
            for o in desired_objects(&ast, "public").unwrap() {
                let key = (
                    o.key.kind,
                    o.key.schema.clone(),
                    o.key.parent.clone(),
                    o.key.name.clone(),
                );
                let Some(parts) = live.get(&key) else {
                    problems.push(format!("missing after push: {key:?}"));
                    continue;
                };
                for (label, want) in &o.structure {
                    match parts.get(*label) {
                        Some(got) if got == want => {}
                        other => problems.push(format!(
                            "{key:?}: {label} predicted {want:?}, live {other:?}"
                        )),
                    }
                }
            }
            assert!(problems.is_empty(), "{name}:\n{}", problems.join("\n"));
        })
        .await;
    }
}

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
//! The scan reads statements against the project schema and compares them with the set's objects
//! there; the engine's own schemas (`_supatype`, `draft`, `supatype`) are the ledger's to account
//! for, and the cron jobs exist only where `pg_cron` does.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use supatype_engine::{
    desired::{desired_objects, desired_objects_for, DesiredObject, FieldEnforcement},
    differ::FieldMaskingTier,
    introspector::fingerprint::ObjectKind,
    parser,
    parser::ast::SchemaAst,
    push,
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
/// touch the project schema.
fn names_in_sql(sql: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for statement in sql.split(';') {
        if !statement.contains("\"public\".") {
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
        .filter(|o| kinds_in_set().contains(&o.key.kind) && o.key.schema == "public")
        .map(|o| o.key.name.clone())
        .collect()
}

/// The migration a push of `ast` would apply to an empty database (the differ's operations and
/// the reconcile's creations, as one body), and the desired set for the masking tier it chose.
async fn first_push(pool: &sqlx::PgPool, ast: &SchemaAst) -> (String, Vec<DesiredObject>) {
    let plan = push::prepare(pool, ast, "public").await.unwrap();
    let set = match plan.diff.field_masking {
        FieldMaskingTier::Views => desired_objects_for(
            ast,
            "public",
            FieldEnforcement::Views(&plan.diff.field_view_plan),
        ),
        _ => desired_objects(ast, "public"),
    }
    .unwrap();
    (plan.migration(false).unwrap().up(), set)
}

#[tokio::test]
async fn the_set_and_the_migration_name_the_same_objects() {
    for name in PUSHABLE {
        common::with_integration_pool(|pool| async move {
            let ast = fixture(name);
            let (sql, set) = first_push(&pool, &ast).await;

            let in_sql = names_in_sql(&sql);
            let in_set = names_in_set(&set);
            let only_sql: Vec<_> = in_sql.difference(&in_set).collect();
            let only_set: Vec<_> = in_set.difference(&in_sql).collect();
            assert!(
                only_sql.is_empty() && only_set.is_empty(),
                "{name}: the generator and the set disagree.\n  emitted but not desired: {only_sql:?}\n  desired but not emitted: {only_set:?}"
            );
        })
        .await;
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

/// Every desired object of `kinds` (all of them for `None`) whose predicted structure differs from
/// the live one after the push, or that is missing.
async fn structure_problems(
    pool: &sqlx::PgPool,
    ast: &SchemaAst,
    kinds: Option<&[ObjectKind]>,
) -> Vec<String> {
    let push::State {
        catalog,
        fingerprints,
        ..
    } = common::live_state(pool).await;
    let live: BTreeMap<(ObjectKind, String, String, String), BTreeMap<String, String>> =
        fingerprints
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
    for o in desired_objects(ast, "public").unwrap() {
        if kinds.is_some_and(|kinds| !kinds.contains(&o.key.kind)) {
            continue;
        }
        // Where `pg_cron` is absent the layer says so and schedules nothing.
        if o.key.kind == ObjectKind::CronJob && !catalog.cron_available {
            continue;
        }
        // A role the rules allow nothing holds nothing, which the catalog has no row for:
        // the ledger records it as `holding_nothing`.
        let holds_nothing = o.structure.get("privileges").is_some_and(String::is_empty);
        if o.key.kind == ObjectKind::TableGrant && holds_nothing {
            continue;
        }
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
    problems
}

async fn auth_users(pool: &sqlx::PgPool) {
    sqlx::raw_sql(
        "CREATE SCHEMA IF NOT EXISTS auth;
         CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT UNIQUE);",
    )
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn after_a_push_every_desired_object_exists_with_the_structure_it_predicted() {
    for name in PUSHABLE {
        common::with_integration_pool(|pool| async move {
            let ast = fixture(name);
            auth_users(&pool).await;
            // `desired_objects` describes a database that enforces field rules with labels, so
            // the extension is installed: without it the push would choose the `api` views.
            assert!(common::mask_extension_available(&pool).await);
            common::push(&pool, &ast)
                .await
                .unwrap_or_else(|e| panic!("{name}: applies: {e}"));
            let problems = structure_problems(&pool, &ast, None).await;
            assert!(problems.is_empty(), "{name}:\n{}", problems.join("\n"));
        })
        .await;
    }
}

/// Adoption compares a same-named live object with its prediction, so every function and foreign
/// key a push creates has to match its own, options and all (`SET search_path`, `STRICT`,
/// `ON UPDATE`, `DEFERRABLE`, ...): one that did not would read as a user's object on a database
/// with no record of it. Neither kind depends on how field rules are enforced, so this runs
/// without `supatype_mask` too, over the fixtures that declare no field rules and need no
/// extension beyond the image's defaults.
#[tokio::test]
async fn every_function_and_foreign_key_a_push_creates_matches_its_prediction() {
    for name in [
        "ecommerce",
        "five_model_blog",
        "many_to_many",
        "rls_access_rules",
        "self_referential",
        "standup_relations",
        "versioned_blog",
    ] {
        common::with_integration_pool(|pool| async move {
            let ast = fixture(name);
            auth_users(&pool).await;
            common::push(&pool, &ast)
                .await
                .unwrap_or_else(|e| panic!("{name}: applies: {e}"));
            let kinds = [ObjectKind::Function, ObjectKind::ForeignKey];
            let problems = structure_problems(&pool, &ast, Some(&kinds)).await;
            assert!(problems.is_empty(), "{name}:\n{}", problems.join("\n"));
            let desired = desired_objects(&ast, "public").unwrap();
            assert!(
                desired.iter().any(|o| kinds.contains(&o.key.kind)),
                "{name}: nothing to compare"
            );
            if name == "versioned_blog" {
                // The options were compared, not left out: the versions layer pins its path.
                assert!(
                    desired.iter().any(|o| o.key.kind == ObjectKind::Function
                        && o.structure
                            .get("config")
                            .is_some_and(|c| c == "search_path=\"\"")),
                    "no function predicted SET search_path = ''"
                );
            }
        })
        .await;
    }
}

/// With no record that the engine made it (no row, no previous schema naming it), a function in
/// the project schema that is exactly what we would create is adopted. The same function with a
/// `SET search_path` of its own is not: pushes were applied here and their schema is gone, so
/// nothing says whether it was changed by hand, and the push refuses and names it (F16, fail
/// closed) until it is overwritten with consent.
#[tokio::test]
async fn a_function_differing_from_ours_only_in_its_search_path_refuses_the_push() {
    common::with_integration_pool(|pool| async move {
        let ast = fixture("five_model_blog");
        auth_users(&pool).await;
        common::push(&pool, &ast).await.unwrap();
        let forget = "DELETE FROM _supatype.managed_objects WHERE kind = 'function';
                      UPDATE _supatype.migrations SET schema_snapshot = NULL WHERE true;
                      UPDATE _supatype.schema_state SET ast_snapshot = NULL WHERE true;";

        sqlx::raw_sql(forget).execute(&pool).await.unwrap();
        common::push(&pool, &ast)
            .await
            .expect("every function of ours matches its prediction, so it is adopted");

        sqlx::raw_sql(&format!(
            "ALTER FUNCTION public.can_read_posts(public.posts, boolean) SET search_path = public; {forget}"
        ))
        .execute(&pool)
        .await
        .unwrap();
        let refused = common::push(&pool, &ast)
            .await
            .expect_err("a function with a search_path of its own is not adopted");
        let message = format!("{refused:#}");
        assert!(
            message.contains("can_read_posts") && message.contains("not checked"),
            "{message}"
        );
    })
    .await;
}

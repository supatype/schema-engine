//! Phase 1c of the managed-object ownership plan: the fingerprints hold still when nothing changed,
//! and move for exactly the object that did.
//!
//! The first property is the one a ledger lives or dies by. Every push re-asserts triggers,
//! functions, grants and the versions layer with `CREATE OR REPLACE`; if that moved a fingerprint,
//! every owned object would read as hand-edited after every push.

mod common;

use std::collections::BTreeMap;

use supatype_engine::{
    differ,
    generator::sql::{migration, triggers},
    introspector::{
        self,
        fingerprint::{fingerprints, ObjectFingerprint, ObjectKind},
    },
    parser,
    parser::ast::SchemaAst,
};

async fn exec(pool: &sqlx::PgPool, sql: &str) {
    sqlx::raw_sql(sql).execute(pool).await.expect("sql applies");
}

/// The full push the CLI runs: forward migration (versions layer included), then the trigger SQL.
async fn push(pool: &sqlx::PgPool, ast: &SchemaAst) {
    let db = introspector::introspect(pool, "public").await.unwrap();
    let diff = differ::diff(ast, &db).unwrap();
    exec(
        pool,
        &migration::forward_sql(&diff, false, "public", ast).unwrap(),
    )
    .await;
    exec(pool, &triggers::generate(ast, "public").unwrap()).await;
}

type Key = (ObjectKind, String, String, String);

/// Fingerprint and definition per object key.
async fn snapshot(pool: &sqlx::PgPool) -> BTreeMap<Key, (String, String)> {
    let db = introspector::introspect(pool, "public").await.unwrap();
    let catalog = introspector::introspect_catalog(pool, "public")
        .await
        .unwrap();
    fingerprints(&db, &catalog)
        .into_iter()
        .map(
            |ObjectFingerprint {
                 kind,
                 schema,
                 parent,
                 name,
                 fingerprint,
                 definition,
             }| { ((kind, schema, parent, name), (fingerprint, definition)) },
        )
        .collect()
}

fn moved(
    before: &BTreeMap<Key, (String, String)>,
    after: &BTreeMap<Key, (String, String)>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (key, (fp, _)) in after {
        match before.get(key) {
            Some((old, _)) if old == fp => {}
            Some(_) => out.push(format!("changed {key:?}")),
            None => out.push(format!("added {key:?}")),
        }
    }
    for key in before.keys() {
        if !after.contains_key(key) {
            out.push(format!("removed {key:?}"));
        }
    }
    out
}

#[tokio::test]
async fn a_second_push_of_the_same_schema_moves_no_fingerprint() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(include_str!("fixtures/versioned_blog.json")).unwrap();
        push(&pool, &ast).await;
        let before = snapshot(&pool).await;
        assert!(
            before.len() > 50,
            "the versioned fixture produces a lot of objects: {}",
            before.len()
        );
        assert!(before
            .keys()
            .any(|k| k.0 == ObjectKind::Function && k.1 == "supatype"));
        assert!(before
            .keys()
            .any(|k| k.0 == ObjectKind::View && k.1 == "draft"));
        assert!(before.keys().any(|k| k.0 == ObjectKind::Policy));
        assert!(before.keys().any(|k| k.0 == ObjectKind::TableGrant));

        push(&pool, &ast).await;
        let after = snapshot(&pool).await;

        let diff = moved(&before, &after);
        assert!(
            diff.is_empty(),
            "re-asserting an unchanged schema moved fingerprints:\n{}",
            diff.join("\n")
        );
    })
    .await;
}

#[tokio::test]
async fn a_hand_edit_moves_exactly_the_objects_it_touched() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(include_str!("fixtures/five_model_blog.json")).unwrap();
        push(&pool, &ast).await;
        let before = snapshot(&pool).await;

        // A default on one column: the column and its table change, nothing else does.
        let table = before
            .keys()
            .find(|k| k.0 == ObjectKind::Column && k.3 == "title")
            .map(|k| k.2.clone())
            .expect("a model with a title column");
        exec(
            &pool,
            &format!("ALTER TABLE public.\"{table}\" ALTER COLUMN title SET DEFAULT 'untitled'"),
        )
        .await;

        let after = snapshot(&pool).await;
        let mut diff = moved(&before, &after);
        diff.sort();
        assert_eq!(
            diff,
            vec![
                format!(
                    "changed {:?}",
                    (
                        ObjectKind::Column,
                        "public".to_string(),
                        table.clone(),
                        "title".to_string()
                    )
                ),
                format!(
                    "changed {:?}",
                    (
                        ObjectKind::Table,
                        "public".to_string(),
                        String::new(),
                        table.clone()
                    )
                ),
            ]
        );

        // The stored definition is what a ledger shows beside the live one.
        let key = (
            ObjectKind::Column,
            "public".to_string(),
            table,
            "title".to_string(),
        );
        assert!(!before[&key].1.contains("untitled"));
        assert!(
            after[&key].1.contains("default='untitled'::text"),
            "the definition names the change: {}",
            after[&key].1
        );
    })
    .await;
}

#[tokio::test]
async fn a_rewritten_policy_or_function_body_is_a_moved_fingerprint() {
    common::with_integration_pool(|pool| async move {
        exec(
            &pool,
            "CREATE TABLE public.docs (id int PRIMARY KEY, owner text);
             ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
             CREATE POLICY docs_select ON public.docs FOR SELECT USING (owner = current_user);
             CREATE FUNCTION public.answer() RETURNS int LANGUAGE sql AS $$ SELECT 41 $$;",
        )
        .await;
        let before = snapshot(&pool).await;

        exec(
            &pool,
            "DROP POLICY docs_select ON public.docs;
             CREATE POLICY docs_select ON public.docs FOR SELECT USING (true);
             CREATE OR REPLACE FUNCTION public.answer() RETURNS int LANGUAGE sql AS $$ SELECT 42 $$;",
        )
        .await;
        let after = snapshot(&pool).await;

        let mut diff = moved(&before, &after);
        diff.sort();
        assert_eq!(diff.len(), 2, "{diff:?}");
        assert!(diff[0].contains("Function") && diff[0].contains("answer()"), "{diff:?}");
        assert!(diff[1].contains("Policy") && diff[1].contains("docs_select"), "{diff:?}");
    })
    .await;
}

#[tokio::test]
async fn column_order_does_not_enter_a_table_fingerprint() {
    common::with_integration_pool(|pool| async move {
        exec(
            &pool,
            "CREATE TABLE public.a (x int, y text); CREATE TABLE public.b (y text, x int);",
        )
        .await;
        let snap = snapshot(&pool).await;
        let fp =
            |t: &str| snap[&(ObjectKind::Table, "public".into(), String::new(), t.into())].clone();
        assert_eq!(
            fp("a"),
            fp("b"),
            "the same columns in a different order are the same table"
        );
    })
    .await;
}

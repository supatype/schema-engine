//! Phase 1a of the managed-object ownership plan: introspection sees every constraint, and sees
//! the indexes it used to miss.
//!
//! Read-only by intent. The differ must plan exactly what it planned before, so the last test here
//! is the idempotency invariant with the new rows present: primary keys now in `constraints`, and
//! expression-only indexes in `CatalogState` rather than `DatabaseState::indexes`, where a managed
//! index nothing expects would be dropped.

mod common;

use supatype_engine::{
    differ,
    generator::sql::migration,
    introspector::{self, constraints::DbConstraintType},
    parser,
};

async fn exec(pool: &sqlx::PgPool, sql: &str) {
    sqlx::raw_sql(sql)
        .execute(pool)
        .await
        .expect("fixture applies");
}

#[tokio::test]
async fn primary_keys_are_read_with_their_columns_in_order() {
    common::with_integration_pool(|pool| async move {
        exec(
            &pool,
            "CREATE TABLE public.pairs (b int, a int, PRIMARY KEY (b, a))",
        )
        .await;

        let db = introspector::introspect(&pool, "public").await.unwrap();
        let pk = db
            .constraints
            .iter()
            .find(|c| c.table == "pairs" && c.constraint_type == DbConstraintType::PrimaryKey)
            .expect("the primary key is now a constraint the engine can see");

        assert_eq!(pk.name, "pairs_pkey");
        assert_eq!(pk.columns, vec!["b", "a"], "key order, not column order");
        assert!(pk.comment.is_none());
    })
    .await;
}

#[tokio::test]
async fn a_foreign_key_carries_its_comment_and_delete_rule() {
    common::with_integration_pool(|pool| async move {
        exec(
            &pool,
            "CREATE TABLE public.parents (id int PRIMARY KEY);
             CREATE TABLE public.children (id int PRIMARY KEY, parent_id int,
               CONSTRAINT children_parent_id_fkey FOREIGN KEY (parent_id)
                 REFERENCES public.parents (id) ON DELETE SET NULL);
             COMMENT ON CONSTRAINT children_parent_id_fkey ON public.children IS 'theirs';",
        )
        .await;

        let db = introspector::introspect(&pool, "public").await.unwrap();
        let fk = db
            .constraints
            .iter()
            .find(|c| c.name == "children_parent_id_fkey")
            .expect("foreign key read");

        assert_eq!(fk.constraint_type, DbConstraintType::ForeignKey);
        assert_eq!(fk.columns, vec!["parent_id"]);
        assert_eq!(fk.foreign_table.as_deref(), Some("parents"));
        assert_eq!(fk.foreign_columns.as_deref(), Some(&["id".to_string()][..]));
        assert_eq!(fk.on_delete.as_deref(), Some("SET NULL"));
        assert_eq!(
            fk.comment.as_deref(),
            Some("theirs"),
            "the comment used to be hard-coded to None"
        );
    })
    .await;
}

#[tokio::test]
async fn unique_and_check_constraints_keep_their_shape() {
    common::with_integration_pool(|pool| async move {
        exec(
            &pool,
            "CREATE TABLE public.things (id int PRIMARY KEY, code text,
               CONSTRAINT things_code_key UNIQUE (code),
               CONSTRAINT things_code_bounds CHECK (length(code) < 10));
             COMMENT ON CONSTRAINT things_code_key ON public.things IS 'u';
             COMMENT ON CONSTRAINT things_code_bounds ON public.things IS 'c';",
        )
        .await;

        let db = introspector::introspect(&pool, "public").await.unwrap();
        let unique = db
            .constraints
            .iter()
            .find(|c| c.name == "things_code_key")
            .unwrap();
        let check = db
            .constraints
            .iter()
            .find(|c| c.name == "things_code_bounds")
            .unwrap();

        assert_eq!(unique.constraint_type, DbConstraintType::Unique);
        assert_eq!(unique.columns, vec!["code"]);
        assert_eq!(unique.comment.as_deref(), Some("u"));

        assert_eq!(check.constraint_type, DbConstraintType::Check);
        assert!(
            check.columns.is_empty(),
            "check constraints keep an empty column list"
        );
        assert!(check
            .check_expression
            .as_deref()
            .unwrap_or("")
            .contains("length(code)"));
        assert_eq!(check.comment.as_deref(), Some("c"));
    })
    .await;
}

#[tokio::test]
async fn an_expression_only_index_is_read_apart_from_column_indexes() {
    common::with_integration_pool(|pool| async move {
        exec(
            &pool,
            "CREATE TABLE public.settings (id int PRIMARY KEY, site text);
             CREATE UNIQUE INDEX settings_singleton_idx ON public.settings ((TRUE));
             CREATE INDEX settings_site_idx ON public.settings (site);
             CREATE INDEX settings_mixed_idx ON public.settings (site, lower(site));",
        )
        .await;

        let db = introspector::introspect(&pool, "public").await.unwrap();
        let names: Vec<&str> = db.indexes.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains(&"settings_site_idx"));
        assert!(
            names.contains(&"settings_mixed_idx"),
            "an index with a column key still reads as before, columns only"
        );
        assert!(
            !names.contains(&"settings_singleton_idx"),
            "an expression-only index must not reach the differ yet; it would be dropped"
        );

        let catalog = introspector::introspect_catalog(&pool, "public")
            .await
            .unwrap();
        let singleton = catalog
            .expression_indexes
            .iter()
            .find(|i| i.name == "settings_singleton_idx")
            .expect("the expression-only index is visible in the catalog state");
        assert!(singleton.unique);
        assert_eq!(singleton.table, "settings");
        assert!(
            singleton
                .expressions
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .contains("true"),
            "{:?}",
            singleton.expressions
        );
        assert!(singleton
            .definition
            .as_deref()
            .unwrap_or("")
            .contains("CREATE UNIQUE INDEX"));
        assert_eq!(
            catalog.expression_indexes.len(),
            1,
            "only the expression-only one lands here"
        );
    })
    .await;
}

#[tokio::test]
async fn delete_rules_are_spelled_as_information_schema_spells_them() {
    common::with_integration_pool(|pool| async move {
        exec(
            &pool,
            "CREATE TABLE public.p (id int PRIMARY KEY);
             CREATE TABLE public.c (
               id int PRIMARY KEY,
               a int REFERENCES public.p (id) ON DELETE CASCADE,
               b int REFERENCES public.p (id) ON DELETE SET NULL,
               c int REFERENCES public.p (id) ON DELETE SET DEFAULT,
               d int REFERENCES public.p (id) ON DELETE RESTRICT,
               e int REFERENCES public.p (id));",
        )
        .await;

        let db = introspector::introspect(&pool, "public").await.unwrap();
        let expected: Vec<(String, String)> = sqlx::query_as(
            "SELECT constraint_name::text, delete_rule::text
             FROM information_schema.referential_constraints
             WHERE constraint_schema = 'public' ORDER BY 1",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(expected.len(), 5);

        for (name, rule) in expected {
            let fk = db.constraints.iter().find(|k| k.name == name).unwrap();
            assert_eq!(fk.on_delete.as_deref(), Some(rule.as_str()), "{name}");
        }
    })
    .await;
}

#[tokio::test]
async fn a_fresh_push_is_still_up_to_date_with_primary_keys_in_the_state() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(include_str!("fixtures/five_model_blog.json")).unwrap();
        let empty = introspector::introspect(&pool, "public").await.unwrap();
        let diff = differ::diff(&ast, &empty).unwrap();
        let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
        exec(&pool, &sql).await;

        let after = introspector::introspect(&pool, "public").await.unwrap();
        let pks = after
            .constraints
            .iter()
            .filter(|c| c.constraint_type == DbConstraintType::PrimaryKey)
            .count();
        assert!(pks > 0, "the new rows are present");

        let second = differ::diff(&ast, &after).unwrap();
        assert!(
            second.operations.is_empty(),
            "the differ must plan nothing new because of rows it never used to see: {:?}",
            second.operations
        );
    })
    .await;
}

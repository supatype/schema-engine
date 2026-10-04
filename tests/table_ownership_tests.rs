//! Never destroy a table Supatype did not create.
//!
//! Indexes, constraints and RLS policies have been gated on an ownership comment for a long time.
//! Tables were not, so any table in the managed schema that was absent from `schema/index.ts`
//! became `DropTable`, and on a database Supatype did not create, that is someone else's data.
//! This is the case that matters for bring-your-own-Postgres, where `public` is full of tables the
//! schema has never heard of.
//!
//! The gate covers destructive operations only. An unowned table may gain a column (intrusive but
//! recoverable) and may not lose one, be renamed into a model, or be dropped.

mod common;

use sqlx::Row;
use supatype_engine::{
    differ, generator::sql::migration, introspector, parser, state::database_state::DatabaseState,
};

/// One model, so a diff has something to converge towards.
const ONE_MODEL: &str = r#"{
  "astVersion": 2,
  "models": [{
    "name": "Widget",
    "fields": {
      "id": { "kind": "integer", "primaryKey": true, "required": true,
              "annotations": { "db": { "pgType": "INTEGER", "unique": false } } }
    },
    "options": {},
    "annotations": { "db": { "tableName": "widget", "indexes": [] }, "platform": {} }
  }]
}"#;

const NO_MODELS: &str = r#"{ "astVersion": 2, "models": [] }"#;

fn op_names(ops: &[differ::Operation]) -> Vec<String> {
    ops.iter()
        .map(|op| format!("{op:?}").chars().take(140).collect())
        .collect()
}

#[tokio::test]
async fn an_unmanaged_table_survives_a_push_that_would_drop_it() {
    common::with_integration_pool(|pool| async move {
        // A table Supatype created (stamped) beside one it merely found (unstamped).
        sqlx::raw_sql(
            r#"
            CREATE TABLE public.ours (id int primary key, kept text);
            COMMENT ON TABLE public.ours IS 'supatype:managed;kind=table;table=ours;fields=;v=1';
            CREATE TABLE public.theirs (id int primary key, precious text);
            INSERT INTO public.theirs VALUES (1, 'do not lose me');
            "#,
        )
        .execute(&pool)
        .await
        .expect("ownership fixture applies");

        let ast = parser::parse(ONE_MODEL).expect("fixture parses");
        let db = introspector::introspect(&pool, "public").await.unwrap();
        let diff = differ::diff(&ast, &db).unwrap();
        let ops = op_names(&diff.operations);

        // Ours left the schema, so it is fair game.
        assert!(
            ops.iter().any(|o| o.contains("DropTable") && o.contains("ours")),
            "a table Supatype created and that left the schema should still be dropped; ops: {ops:?}"
        );

        // Theirs is not ours to destroy.
        assert!(
            !ops.iter().any(|o| o.contains("DropTable") && o.contains("theirs")),
            "an unmanaged table was scheduled for destruction: {ops:?}"
        );

        // And the refusal is reported. A silent skip is how an operator concludes push is broken.
        assert!(
            diff.warnings.iter().any(|w| w.contains("theirs") && w.contains("adopt")),
            "skipping an unmanaged table must say so, and say how to adopt it; warnings: {:?}",
            diff.warnings
        );

        // Applying the migration must leave their data alone: the assertion the rest is for.
        // Forced, because dropping `ours` is a genuine destructive operation and the point is that
        // even a forced push does not reach `theirs`.
        let sql = migration::forward_sql(&diff, true, "public", &ast).unwrap();
        sqlx::raw_sql(&sql).execute(&pool).await.expect("migration applies");

        let row = sqlx::query("SELECT precious FROM public.theirs WHERE id = 1")
            .fetch_one(&pool)
            .await
            .expect("their table still exists after the push");
        assert_eq!(row.get::<String, _>("precious"), "do not lose me");
    })
    .await;
}

#[tokio::test]
async fn an_unmanaged_table_is_not_renamed_into_a_model() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql(
            r#"
            CREATE TABLE public.widgets_old (id int primary key, name text);
            INSERT INTO public.widgets_old VALUES (1, 'theirs');
            "#,
        )
        .execute(&pool)
        .await
        .expect("fixture applies");

        // `widgets_old` is similar enough to `widget` to trip the rename heuristic
        // (jaro-winkler >= 0.7). Renaming would take over their table *and* its data, while looking
        // like a successful migration.
        let ast = parser::parse(ONE_MODEL).expect("fixture parses");
        let db = introspector::introspect(&pool, "public").await.unwrap();
        let diff = differ::diff(&ast, &db).unwrap();
        let ops = op_names(&diff.operations);

        assert!(
            !ops.iter().any(|o| o.contains("RenameTable")),
            "an unmanaged table was renamed into a model: {ops:?}"
        );

        let still_there: i64 = sqlx::query_scalar("SELECT count(*) FROM public.widgets_old")
            .fetch_one(&pool)
            .await
            .expect("their table still exists under its own name");
        assert_eq!(still_there, 1, "their table or its rows went missing");
    })
    .await;
}

#[tokio::test]
async fn a_column_is_not_dropped_from_an_unmanaged_table() {
    common::with_integration_pool(|pool| async move {
        // Same table name as the model, so the differ treats it as this model's table, but the
        // table is unstamped, so a column the schema no longer declares must survive.
        sqlx::raw_sql(
            r#"
            CREATE TABLE public.widget (id int primary key, their_column text);
            INSERT INTO public.widget VALUES (1, 'their data');
            "#,
        )
        .execute(&pool)
        .await
        .expect("fixture applies");

        let ast = parser::parse(ONE_MODEL).expect("fixture parses");
        let db = introspector::introspect(&pool, "public").await.unwrap();
        let diff = differ::diff(&ast, &db).unwrap();
        let ops = op_names(&diff.operations);

        assert!(
            !ops.iter().any(|o| o.contains("DropColumn")),
            "a column was dropped from a table Supatype does not own: {ops:?}"
        );
        assert!(
            diff.warnings.iter().any(|w| w.contains("their_column")),
            "the skipped column drop must be reported; warnings: {:?}",
            diff.warnings
        );
    })
    .await;
}

#[tokio::test]
async fn a_table_the_engine_creates_is_stamped() {
    common::with_integration_pool(|pool| async move {
        // The gate is only safe if the engine marks what it makes. Otherwise every table becomes
        // permanently undroppable and the differ can never converge.
        let ast = parser::parse(ONE_MODEL).expect("fixture parses");
        let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
        let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
        sqlx::raw_sql(&sql)
            .execute(&pool)
            .await
            .expect("migration applies");

        let comment: Option<String> =
            sqlx::query_scalar("SELECT obj_description('public.widget'::regclass, 'pg_class')")
                .fetch_one(&pool)
                .await
                .expect("the table exists");

        assert!(
            comment
                .as_deref()
                .unwrap_or("")
                .starts_with("supatype:managed"),
            "a table the engine created carries no ownership marker, so it could never be dropped \
             again; comment was {comment:?}"
        );

        // And the round trip: with the stamp in place, removing it from the schema drops it.
        let empty = parser::parse(NO_MODELS).expect("empty schema parses");
        let db = introspector::introspect(&pool, "public").await.unwrap();
        let second = differ::diff(&empty, &db).unwrap();
        assert!(
            op_names(&second.operations)
                .iter()
                .any(|o| o.contains("DropTable") && o.contains("widget")),
            "the gate must not make our own tables undroppable; ops: {:?}",
            op_names(&second.operations)
        );
    })
    .await;
}

#[tokio::test]
async fn a_column_is_not_retyped_on_an_unmanaged_table() {
    common::with_integration_pool(|pool| async move {
        // Their table, under the name a model declares, with an incompatible column type: `id serial`
        // where the model says UUID. Modifying it is the same class of loss as dropping it:
        // `RecreateColumn` literally drops and re-adds the column, and an `AlterColumn` type change
        // rewrites their data or fails outright. This was found by rehearsing a push against a real
        // external Postgres: the migration aborted with `cannot cast type integer to uuid`, from a
        // table the gate was supposed to be protecting.
        sqlx::raw_sql(
            r#"
            CREATE TABLE public.widget (id serial PRIMARY KEY, name text);
            INSERT INTO public.widget (name) VALUES ('theirs');
            "#,
        )
        .execute(&pool)
        .await
        .expect("fixture applies");

        const UUID_ID: &str = r#"{
          "astVersion": 2,
          "models": [{
            "name": "Widget",
            "fields": {
              "id": { "kind": "uuid", "primaryKey": true, "required": true,
                      "default": { "kind": "genRandomUuid" },
                      "annotations": { "db": { "pgType": "UUID", "unique": false } } },
              "name": { "kind": "text",
                      "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
            },
            "options": {},
            "annotations": { "db": { "tableName": "widget", "indexes": [] }, "platform": {} }
          }]
        }"#;

        let ast = parser::parse(UUID_ID).expect("fixture parses");
        let db = introspector::introspect(&pool, "public").await.unwrap();
        let diff = differ::diff(&ast, &db).unwrap();
        let ops = op_names(&diff.operations);

        assert!(
            !ops.iter().any(|o| o.contains("RecreateColumn")),
            "a column was scheduled for drop-and-recreate on a table Supatype does not own: {ops:?}"
        );
        assert!(
            !ops.iter().any(|o| o.contains("AlterColumn")),
            "a column type change was scheduled on a table Supatype does not own: {ops:?}"
        );
        assert!(
            diff.warnings.iter().any(|w| w.contains("widget") && w.contains("adopt")),
            "the skipped column change must be reported, and say how to opt in; warnings: {:?}",
            diff.warnings
        );

        // And the push refuses outright, naming the table. Applying the rest while silently leaving
        // their column behind would put the schema and the database permanently out of step, and
        // `--force` must not buy its way past this: forcing is for data loss you understand, not for
        // taking ownership of someone else's table.
        let refusal = migration::forward_sql(&diff, true, "public", &ast)
            .expect_err("a push over an unmanaged model table must refuse");
        let message = format!("{refusal:#}");
        assert!(
            message.contains("widget") && message.contains("adopt"),
            "the refusal must name the table and the way out: {message}"
        );

        let kind: String = sqlx::query_scalar(
            "SELECT data_type FROM information_schema.columns              WHERE table_schema = 'public' AND table_name = 'widget' AND column_name = 'id'",
        )
        .fetch_one(&pool)
        .await
        .expect("their column still exists");
        assert_eq!(kind, "integer", "their column type was changed underneath them");

        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM public.widget")
            .fetch_one(&pool)
            .await
            .expect("their rows survive");
        assert_eq!(rows, 1, "their data went missing");
    })
    .await;
}

#[tokio::test]
async fn access_rules_are_not_applied_to_an_unowned_table() {
    common::with_integration_pool(|pool| async move {
        // Declaring a model for a table that already exists is not permission to change it.
        // `ENABLE ROW LEVEL SECURITY` on someone else's table changes what every role except its
        // owner can read (an existing application can stop seeing its own rows) and revoking or
        // granting privileges on it is the same intrusion by another route.
        //
        // Skipping is also fail-closed for Supatype: without the grants, the API has no access to the
        // table, so nothing is served under rules that were never applied.
        sqlx::raw_sql(
            r#"
            CREATE TABLE public.widget (id int primary key, name text);
            GRANT SELECT ON public.widget TO PUBLIC;
            INSERT INTO public.widget VALUES (1, 'theirs');
            "#,
        )
        .execute(&pool)
        .await
        .expect("fixture applies");

        const WITH_RULES: &str = r#"{
          "astVersion": 2,
          "models": [{
            "name": "Widget",
            "fields": {
              "id": { "kind": "integer", "primaryKey": true, "required": true,
                      "annotations": { "db": { "pgType": "INTEGER", "unique": false } } },
              "name": { "kind": "text",
                      "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
            },
            "options": {},
            "annotations": {
              "db": { "tableName": "widget", "indexes": [] },
              "platform": { "access": { "read": { "type": "authenticated" },
                                        "create": { "type": "authenticated" } } }
            }
          }]
        }"#;

        let ast = parser::parse(WITH_RULES).expect("fixture parses");
        let db = introspector::introspect(&pool, "public").await.unwrap();
        let diff = differ::diff(&ast, &db).unwrap();

        assert_eq!(
            diff.unmanaged_model_tables,
            vec!["widget".to_string()],
            "the differ must tell the generators which declared tables are not ours"
        );
        let ops = op_names(&diff.operations);
        assert!(
            !ops.iter().any(|o| o.contains("EnableRls") || o.contains("Rls")),
            "row level security was scheduled on a table Supatype does not own: {ops:?}"
        );
        assert!(
            diff.warnings.iter().any(|w| w.contains("widget") && w.contains("adopt")),
            "the skipped rules must be reported, and say how to opt in; warnings: {:?}",
            diff.warnings
        );

        // The push refuses. Skipping the rules alone is not enough: PostgREST serves any table in
        // an exposed schema that the request role can already read, so a table the operator had
        // granted to PUBLIC would get an endpoint with none of the declared rules applied. Measured
        // on a rehearsal: `GET /rest/v1/post` returned their rows as `anon`.
        let refusal = migration::forward_sql(&diff, true, "public", &ast)
            .expect_err("a push over an unmanaged model table must refuse");
        let message = format!("{refusal:#}");
        assert!(
            message.contains("widget") && message.contains("adopt"),
            "the refusal must name the table and the way out: {message}"
        );

        // Their table is exactly as they left it.
        let rls: bool = sqlx::query_scalar(
            "SELECT relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace              WHERE n.nspname = 'public' AND c.relname = 'widget'",
        )
        .fetch_one(&pool)
        .await
        .expect("their table still exists");
        assert!(!rls, "row level security was forced on a table Supatype does not own");

        let policies: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_policies WHERE schemaname = 'public' AND tablename = 'widget'",
        )
        .fetch_one(&pool)
        .await
        .expect("count policies");
        assert_eq!(policies, 0, "policies were attached to a table Supatype does not own");

        // And after adoption the rules do apply: the gate must be an opt-in, not a dead end.
        for statement in supatype_engine::differ::doctor::adopt_stamp_sql(&ast, &db, &supatype_engine::introspector::catalog::CatalogState::default(), "public").unwrap() {
            sqlx::raw_sql(&statement).execute(&pool).await.expect("stamp applies");
        }
        let adopted_db = introspector::introspect(&pool, "public").await.unwrap();
        let adopted = differ::diff(&ast, &adopted_db).unwrap();
        assert!(
            adopted.unmanaged_model_tables.is_empty(),
            "the table is still reported as unowned after adoption"
        );
        let sql = migration::forward_sql(&adopted, true, "public", &ast).unwrap();
        sqlx::raw_sql(&sql).execute(&pool).await.expect("migration applies after adoption");

        let rls: bool = sqlx::query_scalar(
            "SELECT relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace              WHERE n.nspname = 'public' AND c.relname = 'widget'",
        )
        .fetch_one(&pool)
        .await
        .expect("read rls flag");
        assert!(rls, "adoption did not make the access rules apply");
    })
    .await;
}

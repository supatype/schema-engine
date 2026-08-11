//! Never destroy a table Supatype did not create.
//!
//! Indexes, constraints and RLS policies have been gated on an ownership comment for a long time.
//! Tables were not, so any table in the managed schema that was absent from `schema/index.ts`
//! became `DropTable` — and on a database Supatype did not create, that is someone else's data.
//! This is the case that matters for bring-your-own-Postgres, where `public` is full of tables the
//! schema has never heard of.
//!
//! The gate covers destructive operations only. An unowned table may gain a column — intrusive but
//! recoverable — and may not lose one, be renamed into a model, or be dropped.

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
    ops.iter().map(|op| format!("{op:?}").chars().take(140).collect()).collect()
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

        // Applying the migration must leave their data alone — the assertion the rest is for.
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
        // Same table name as the model, so the differ treats it as this model's table — but the
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
        sqlx::raw_sql(&sql).execute(&pool).await.expect("migration applies");

        let comment: Option<String> =
            sqlx::query_scalar("SELECT obj_description('public.widget'::regclass, 'pg_class')")
                .fetch_one(&pool)
                .await
                .expect("the table exists");

        assert!(
            comment.as_deref().unwrap_or("").starts_with("supatype:managed"),
            "a table the engine created carries no ownership marker, so it could never be dropped \
             again; comment was {comment:?}"
        );

        // And the round trip: with the stamp in place, removing it from the schema drops it.
        let empty = parser::parse(NO_MODELS).expect("empty schema parses");
        let db = introspector::introspect(&pool, "public").await.unwrap();
        let second = differ::diff(&empty, &db).unwrap();
        assert!(
            op_names(&second.operations).iter().any(|o| o.contains("DropTable") && o.contains("widget")),
            "the gate must not make our own tables undroppable; ops: {:?}",
            op_names(&second.operations)
        );
    })
    .await;
}

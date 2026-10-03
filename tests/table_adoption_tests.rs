//! Reporting an unmanaged table, and adopting one deliberately.
//!
//! The ownership gate stops push destroying a table Supatype did not create. That leaves two holes,
//! and this file is about both:
//!
//! * **Silence.** `doctor` reported unmanaged indexes and constraints but never tables, so the gate
//!   could decline to drop a table and nothing said so. An operator reading a clean report and
//!   watching push leave a table behind concludes push is broken.
//! * **No way in.** Without adoption there was no supported way to say "this table is mine now", a
//!   table that arrived by hand could never be managed, and its columns were permanently exempt from
//!   the diff.
//!
//! The round trip is the assertion that matters: stamp, then confirm push manages it thereafter. A
//! marker that adoption writes in a different shape from `CREATE TABLE` would leave the table
//! undroppable forever and the differ unable to converge.

mod common;

use supatype_engine::{
    differ::{self, doctor},
    generator::sql::migration,
    introspector, parser,
    state::database_state::DatabaseState,
};

const ONE_MODEL: &str = r#"{
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
    "annotations": { "db": { "tableName": "widget", "indexes": [] }, "platform": {} }
  }]
}"#;

const NO_MODELS: &str = r#"{ "astVersion": 2, "models": [] }"#;

fn messages(items: &[doctor::DoctorItem]) -> Vec<String> {
    items.iter().map(|i| i.message.clone()).collect()
}

#[tokio::test]
async fn doctor_reports_an_unmanaged_table_absent_from_the_schema() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql(
            r#"
            CREATE TABLE public.widget (id int primary key, name text);
            COMMENT ON TABLE public.widget IS 'supatype:managed;kind=table;table=widget;fields=;v=1';
            CREATE TABLE public.theirs (id int primary key, note text);
            CREATE TABLE public.ours_but_gone (id int primary key);
            COMMENT ON TABLE public.ours_but_gone IS 'supatype:managed;kind=table;table=ours_but_gone;fields=;v=1';
            "#,
        )
        .execute(&pool)
        .await
        .expect("fixture applies");

        let ast = parser::parse(ONE_MODEL).expect("fixture parses");
        let db = introspector::introspect(&pool, "public").await.expect("introspect");
        let report = doctor::report(&ast, &db, &[]);

        // Not ours, not in the schema: push will leave it, and the report says so in the same words
        // the index and constraint cases use.
        let unmanaged = messages(&report.unmanaged_drift);
        assert!(
            unmanaged.iter().any(|m| m.contains("Unmanaged table theirs")
                && m.contains("push will not drop; manual decision required")),
            "an unmanaged table was not reported: {unmanaged:?}"
        );

        // Ours, but no longer in the schema: push *will* drop it, which is a different fact and
        // belongs in the bucket `--strict` fails on.
        let stale = messages(&report.stale_managed);
        assert!(
            stale.iter().any(|m| m.contains("Managed table ours_but_gone")),
            "a managed table absent from the schema was not reported as stale: {stale:?}"
        );
        assert!(
            doctor::has_strict_issues(&report),
            "a managed table that push will drop must fail --strict"
        );

        // And the table that is both ours and in the schema is not mentioned at all.
        for message in unmanaged.iter().chain(stale.iter()) {
            assert!(
                !message.contains("widget"),
                "a healthy managed table should not appear in the report: {message}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn doctor_explains_why_columns_survive_on_an_unstamped_model_table() {
    common::with_integration_pool(|pool| async move {
        // The table the schema declares, but created by hand, so the column gate declines to drop
        // `their_column`. Without this row in the report, that refusal has no explanation anywhere.
        sqlx::raw_sql(
            "CREATE TABLE public.widget (id int primary key, name text, their_column text)",
        )
        .execute(&pool)
        .await
        .expect("fixture applies");

        let ast = parser::parse(ONE_MODEL).expect("fixture parses");
        let db = introspector::introspect(&pool, "public")
            .await
            .expect("introspect");
        let report = doctor::report(&ast, &db, &[]);

        let unmanaged = messages(&report.unmanaged_drift);
        assert!(
            unmanaged.iter().any(
                |m| m.contains("Table widget matches a model but is not managed")
                    && m.contains("supatype adopt")
            ),
            "the report does not explain why columns survive on an unstamped table: {unmanaged:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn adopting_a_table_makes_push_manage_it_thereafter() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql("CREATE TABLE public.widget (id int primary key, name text)")
            .execute(&pool)
            .await
            .expect("fixture applies");

        let ast = parser::parse(ONE_MODEL).expect("fixture parses");
        let before = introspector::introspect(&pool, "public")
            .await
            .expect("introspect");

        // Before adoption the table is not droppable, so removing it from the schema does nothing.
        let empty = parser::parse(NO_MODELS).expect("empty schema parses");
        let diff = differ::diff(&empty, &before).expect("diff");
        let ops: Vec<String> = diff.operations.iter().map(|o| format!("{o:?}")).collect();
        assert!(
            !ops.iter().any(|o| o.contains("DropTable")),
            "an unadopted table must not be droppable: {ops:?}"
        );

        // Adopt it.
        let stamps = doctor::adopt_stamp_sql(&ast, &before, "public");
        assert!(
            stamps
                .iter()
                .any(|s| s.contains("COMMENT ON TABLE") && s.contains("widget")),
            "adoption emitted no table stamp: {stamps:?}"
        );
        for statement in &stamps {
            sqlx::raw_sql(statement)
                .execute(&pool)
                .await
                .expect("stamp applies");
        }

        // The marker must match what CREATE TABLE writes, or the differ can never converge.
        let engine_marker = {
            let fresh = differ::diff(&ast, &DatabaseState::default()).expect("diff against empty");
            let sql =
                migration::forward_sql(&fresh, false, "public", &ast).expect("script renders");
            let line = sql
                .lines()
                .find(|l| l.contains("COMMENT ON TABLE") && l.contains("widget"))
                .expect("the engine stamps tables it creates")
                .to_string();
            line
        };
        let adopted_marker = stamps
            .iter()
            .find(|s| s.contains("widget"))
            .expect("the adoption stamp exists")
            .clone();
        assert_eq!(
            adopted_marker.trim(),
            engine_marker.trim(),
            "adoption writes a different marker from CREATE TABLE, so an adopted table would never \
             behave like a created one"
        );

        // After adoption, removing the model drops the table: the round trip that makes adoption
        // meaningful rather than a comment nobody reads.
        let after = introspector::introspect(&pool, "public")
            .await
            .expect("re-introspect");
        let diff = differ::diff(&empty, &after).expect("diff after adoption");
        let ops: Vec<String> = diff.operations.iter().map(|o| format!("{o:?}")).collect();
        assert!(
            ops.iter()
                .any(|o| o.contains("DropTable") && o.contains("widget")),
            "an adopted table is still not managed: {ops:?}"
        );

        // And doctor stops complaining about it.
        let report = doctor::report(&ast, &after, &[]);
        assert!(
            !messages(&report.unmanaged_drift)
                .iter()
                .any(|m| m.contains("widget")),
            "doctor still reports an adopted table as unmanaged: {:?}",
            report.unmanaged_drift
        );
    })
    .await;
}

#[tokio::test]
async fn adoption_never_stamps_a_table_the_schema_does_not_declare() {
    common::with_integration_pool(|pool| async move {
        // The whole point of the gate is the first run on someone else's database. Stamping whatever
        // happens to be in the schema would hand Supatype every table on that first run.
        sqlx::raw_sql(
            r#"
            CREATE TABLE public.widget (id int primary key, name text);
            CREATE TABLE public.theirs (id int primary key, precious text);
            "#,
        )
        .execute(&pool)
        .await
        .expect("fixture applies");

        let ast = parser::parse(ONE_MODEL).expect("fixture parses");
        let db = introspector::introspect(&pool, "public")
            .await
            .expect("introspect");
        let stamps = doctor::adopt_stamp_sql(&ast, &db, "public");

        assert!(
            !stamps.iter().any(|s| s.contains("theirs")),
            "adoption stamped a table the schema never mentions: {stamps:?}"
        );

        for statement in &stamps {
            sqlx::raw_sql(statement)
                .execute(&pool)
                .await
                .expect("stamp applies");
        }
        let comment: Option<String> =
            sqlx::query_scalar("SELECT obj_description('public.theirs'::regclass, 'pg_class')")
                .fetch_one(&pool)
                .await
                .expect("their table still exists");
        assert!(
            comment.is_none(),
            "their table was marked as Supatype-managed: {comment:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn adoption_is_idempotent() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql("CREATE TABLE public.widget (id int primary key, name text)")
            .execute(&pool)
            .await
            .expect("fixture applies");

        let ast = parser::parse(ONE_MODEL).expect("fixture parses");
        let db = introspector::introspect(&pool, "public")
            .await
            .expect("introspect");
        for statement in doctor::adopt_stamp_sql(&ast, &db, "public") {
            sqlx::raw_sql(&statement)
                .execute(&pool)
                .await
                .expect("stamp applies");
        }

        // Running it again must be a no-op, not a second stamp: `supatype adopt` is a command an
        // operator will run twice, and an emitted statement reads as "there is still work to do".
        let after = introspector::introspect(&pool, "public")
            .await
            .expect("re-introspect");
        let second = doctor::adopt_stamp_sql(&ast, &after, "public");
        assert!(
            second.iter().all(|s| !s.contains("COMMENT ON TABLE")),
            "adoption re-stamps an already-managed table: {second:?}"
        );
    })
    .await;
}

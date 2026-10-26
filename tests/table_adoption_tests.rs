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
//! The round trip is the assertion that matters: adopt, then confirm push manages it thereafter.
//! Adopting writes a ledger row and nothing else (plan section 8): the table's comment is its
//! owner's, and `--release` hands an object back for good.

mod common;

use supatype_engine::{
    adopt, differ::doctor, introspector::fingerprint::ObjectKind, ledger, parser, push,
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
        let report = common::doctor(&pool, &ast).await;

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
        let report = common::doctor(&pool, &ast).await;

        // A declared table that is not ours is the reconcile's conflict (Phase 4.11): the push
        // refuses until it is adopted, which is also why its columns survive.
        let conflicting = messages(&report.conflicting);
        assert!(
            conflicting
                .iter()
                .any(|m| m.contains("Table widget") && m.contains("supatype adopt")),
            "the report does not explain why columns survive on an unstamped table: {conflicting:?}"
        );
        assert!(doctor::has_strict_issues(&report));
    })
    .await;
}

/// The table's comment, which adopting must never write (plan section 6).
async fn table_comment(pool: &sqlx::PgPool, table: &str) -> Option<String> {
    sqlx::query_scalar("SELECT obj_description(to_regclass($1), 'pg_class')")
        .bind(format!("public.{table}"))
        .fetch_one(pool)
        .await
        .expect("comment reads")
}

/// The tables the ledger records, with their status.
async fn recorded_tables(pool: &sqlx::PgPool) -> Vec<String> {
    let mut conn = pool.acquire().await.unwrap();
    let mut rows: Vec<String> = ledger::load(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.key.kind == ObjectKind::Table && r.key.schema == "public")
        .map(|r| format!("{} {}", r.key.name, r.status.as_str()))
        .collect();
    rows.sort();
    rows
}

fn forced() -> push::ApplyOptions {
    push::ApplyOptions {
        force: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn adopting_a_table_makes_push_manage_it_thereafter() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql("CREATE TABLE public.widget (id int primary key, name text)")
            .execute(&pool)
            .await
            .expect("fixture applies");
        let ast = parser::parse(ONE_MODEL).expect("fixture parses");
        let empty = parser::parse(NO_MODELS).expect("empty schema parses");

        // Before adoption a push refuses the table, and removing it from the schema keeps it.
        assert!(common::push(&pool, &ast).await.is_err());
        common::push_with(&pool, &empty, forced()).await.unwrap();
        assert!(table_comment(&pool, "widget").await.is_none());
        assert!(recorded_tables(&pool).await.is_empty());

        // The preview names it and writes nothing; applying records it and edits nothing.
        let preview = adopt::run(&pool, &ast, "public", adopt::Request::default())
            .await
            .unwrap();
        assert_eq!(preview.status, "preview");
        assert!(preview
            .adopt
            .iter()
            .any(|i| i.kind == "table" && i.name == "widget"));
        assert!(
            recorded_tables(&pool).await.is_empty(),
            "a preview wrote rows"
        );
        let applied = adopt::run(
            &pool,
            &ast,
            "public",
            adopt::Request {
                apply: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(applied.status, "adopted");
        assert_eq!(recorded_tables(&pool).await, ["widget adopted"]);
        assert!(
            table_comment(&pool, "widget").await.is_none(),
            "adopt wrote a comment"
        );

        // Push now manages it, and removing the model drops it: the round trip that makes adoption
        // mean something.
        common::push(&pool, &ast).await.unwrap();
        let report = doctor_of(&pool, &ast).await;
        assert!(!doctor::has_strict_issues(&report), "{report:#?}");
        common::push_with(&pool, &empty, forced()).await.unwrap();
        let gone: bool = sqlx::query_scalar("SELECT to_regclass('public.widget') IS NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(gone, "an adopted table is still not managed");
    })
    .await;
}

async fn doctor_of(
    pool: &sqlx::PgPool,
    ast: &supatype_engine::parser::ast::SchemaAst,
) -> doctor::DoctorReport {
    common::doctor(pool, ast).await
}

#[tokio::test]
async fn adoption_never_takes_a_table_the_schema_does_not_declare() {
    common::with_integration_pool(|pool| async move {
        // The whole point of the gate is the first run on someone else's database. Taking whatever
        // happens to be there would hand Supatype every table on that first run.
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
        let outcome = adopt::run(
            &pool,
            &ast,
            "public",
            adopt::Request {
                apply: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(
            !outcome.adopt.iter().any(|i| i.name == "theirs"),
            "adoption took a table the schema never mentions: {:?}",
            outcome.adopt
        );
        assert_eq!(recorded_tables(&pool).await, ["widget adopted"]);
        assert!(table_comment(&pool, "theirs").await.is_none());
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
        adopt::run(
            &pool,
            &ast,
            "public",
            adopt::Request {
                apply: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // Running it again must be a no-op: `supatype adopt` is a command an operator will run
        // twice, and anything listed reads as "there is still work to do".
        let second = adopt::run(
            &pool,
            &ast,
            "public",
            adopt::Request {
                apply: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(second.status, "nothing_to_adopt", "{:?}", second.adopt);
        assert_eq!(recorded_tables(&pool).await, ["widget adopted"]);
    })
    .await;
}

#[tokio::test]
async fn a_released_object_is_left_alone_by_every_push() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(ONE_MODEL).expect("fixture parses");
        common::push(&pool, &ast).await.unwrap();

        // Kept by hand: released, so the push neither puts it back nor drops it (plan 3.5).
        let release = ["table:widget".to_string()];
        let preview = adopt::run(
            &pool,
            &ast,
            "public",
            adopt::Request {
                release: &release,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(preview.release.iter().any(|i| i.name == "widget"));
        adopt::run(
            &pool,
            &ast,
            "public",
            adopt::Request {
                release: &release,
                apply: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(recorded_tables(&pool).await, ["widget released"]);

        let empty = parser::parse(NO_MODELS).expect("empty schema parses");
        common::push_with(&pool, &empty, forced()).await.unwrap();
        let kept: bool = sqlx::query_scalar("SELECT to_regclass('public.widget') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(kept, "a released table was dropped");
        let report = doctor_of(&pool, &ast).await;
        assert!(
            report.released.iter().any(|i| i.name == "widget"),
            "{report:#?}"
        );

        // A name that is not an object says so, and writes nothing.
        let wrong = adopt::run(
            &pool,
            &ast,
            "public",
            adopt::Request {
                release: &["table:nope".to_string()],
                apply: true,
                ..Default::default()
            },
        )
        .await;
        assert!(format!("{:#}", wrong.unwrap_err()).contains("supatype doctor"));
    })
    .await;
}

#[tokio::test]
async fn releasing_a_conflict_takes_it_back_instead_of_adopting_it() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql("CREATE TABLE public.widget (id int primary key, name text)")
            .execute(&pool)
            .await
            .expect("fixture applies");
        let ast = parser::parse(ONE_MODEL).expect("fixture parses");

        // Named twice, and also a conflict adopt would take: released, once.
        let release = ["table:widget".to_string(), "table:widget".to_string()];
        let outcome = adopt::run(
            &pool,
            &ast,
            "public",
            adopt::Request {
                release: &release,
                apply: true,
                ..Default::default()
            },
        )
        .await
        .expect("one row per object, whoever names it");
        assert!(outcome.adopt.is_empty(), "{:?}", outcome.adopt);
        assert_eq!(outcome.release.len(), 1);
        assert_eq!(recorded_tables(&pool).await, ["widget released"]);
    })
    .await;
}

#[tokio::test]
async fn a_reclaimed_object_is_supatypes_again() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(ONE_MODEL).expect("fixture parses");
        let empty = parser::parse(NO_MODELS).expect("empty schema parses");
        common::push(&pool, &ast).await.unwrap();
        let widget = ["table:widget".to_string()];
        let release = adopt::Request {
            release: &widget,
            apply: true,
            ..Default::default()
        };
        adopt::run(&pool, &ast, "public", release).await.unwrap();

        // Not released: nothing to reclaim, and a name cannot be both.
        let both = adopt::Request {
            release: &widget,
            reclaim: &widget,
            apply: true,
            ..Default::default()
        };
        let refused = adopt::run(&pool, &ast, "public", both).await.unwrap_err();
        assert!(format!("{refused:#}").contains("both to release and to reclaim"));
        let other = ["index:widget.nope".to_string()];
        let not_released = adopt::Request {
            reclaim: &other,
            apply: true,
            ..Default::default()
        };
        let refused = adopt::run(&pool, &ast, "public", not_released)
            .await
            .unwrap_err();
        assert!(
            format!("{refused:#}").contains("nothing released"),
            "{refused:#}"
        );

        let reclaim = adopt::Request {
            reclaim: &widget,
            apply: true,
            ..Default::default()
        };
        let outcome = adopt::run(&pool, &ast, "public", reclaim).await.unwrap();
        assert!(outcome.reclaim.iter().any(|i| i.name == "widget"));
        assert_eq!(recorded_tables(&pool).await, ["widget adopted"]);

        // Ours again: a push that no longer declares it drops it.
        common::push_with(&pool, &empty, forced()).await.unwrap();
        let gone: bool = sqlx::query_scalar("SELECT to_regclass('public.widget') IS NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(gone, "a reclaimed table is still left alone");
    })
    .await;
}

/// The first thing a project on an existing database does: its first push refuses a table that is
/// already there, and the refusal says to run `adopt`. Adopt then has to work on a database
/// Supatype has never written to. The CLI subcommand checked the project schema before anything
/// had created `_supatype.schema_state`, and failed with `relation "_supatype.schema_state" does
/// not exist`.
#[tokio::test]
async fn adoption_works_on_a_database_supatype_has_never_pushed_to() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql("CREATE TABLE public.widget (id int primary key, name text)")
            .execute(&pool)
            .await
            .expect("fixture applies");
        let ast = parser::parse(ONE_MODEL).expect("fixture parses");

        let applied = adopt::run(
            &pool,
            &ast,
            "public",
            adopt::Request {
                apply: true,
                ..Default::default()
            },
        )
        .await
        .expect("adopt on a never-pushed database");
        assert_eq!(applied.status, "adopted");
        assert_eq!(recorded_tables(&pool).await, ["widget adopted"]);
        common::push(&pool, &ast)
            .await
            .expect("the push it unblocks");
    })
    .await;
}

/// One project per database holds for adopt as it does for push, whichever way adopt is called:
/// the HTTP route never checked, and the CLI subcommand checked before the table existed.
#[tokio::test]
async fn adoption_refuses_a_database_that_holds_another_project_schema() {
    common::with_integration_pool(|pool| async move {
        let empty = parser::parse(NO_MODELS).expect("empty schema parses");
        common::push(&pool, &empty)
            .await
            .expect("bootstraps the engine tables");
        sqlx::raw_sql(
            "UPDATE _supatype.schema_state SET project_schema = 'tenant_other' WHERE id = 1",
        )
        .execute(&pool)
        .await
        .expect("records another project");
        let ast = parser::parse(ONE_MODEL).expect("fixture parses");

        let refused = adopt::run(&pool, &ast, "public", adopt::Request::default()).await;
        let message = format!(
            "{:#}",
            refused.expect_err("adopt into another project's database")
        );
        assert!(message.contains("tenant_other"), "{message}");
    })
    .await;
}

#[tokio::test]
async fn adopting_with_keys_takes_only_what_was_previewed() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql("CREATE TABLE public.widget (id int primary key, name text);")
            .execute(&pool)
            .await
            .expect("fixture applies");
        let ast = parser::parse(ONE_MODEL).expect("fixture parses");
        let preview = adopt::run(&pool, &ast, "public", adopt::Request::default())
            .await
            .unwrap();
        assert!(preview
            .adopt
            .iter()
            .any(|i| i.kind == "table" && i.name == "widget"));
        let keys = ["table:widget".to_string()];

        // The database changed after the preview: the previewed conflict is gone (and back as a
        // different table would be just as wrong to take). Nothing is written.
        sqlx::raw_sql("DROP TABLE public.widget;")
            .execute(&pool)
            .await
            .unwrap();
        let refused = adopt::run(
            &pool,
            &ast,
            "public",
            adopt::Request {
                apply: true,
                keys: Some(&keys),
                ..Default::default()
            },
        )
        .await
        .expect_err("adopted something other than what was previewed");
        let message = format!("{refused:#}");
        assert!(message.contains("table:widget"), "{message}");
        assert!(message.contains("since the preview"), "{message}");
        assert!(recorded_tables(&pool).await.is_empty());

        // As previewed: adopted.
        sqlx::raw_sql("CREATE TABLE public.widget (id int primary key, name text);")
            .execute(&pool)
            .await
            .unwrap();
        let applied = adopt::run(
            &pool,
            &ast,
            "public",
            adopt::Request {
                apply: true,
                keys: Some(&keys),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(applied.status, "adopted");
        assert_eq!(recorded_tables(&pool).await, ["widget adopted"]);
    })
    .await;
}

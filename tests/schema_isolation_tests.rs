//! A push into a non-`public` schema must put **everything** there.
//!
//! `schema.pg_schema` was honoured by the table DDL and by nothing else. Policies, table and column
//! grants, `can_*` affordance functions, security labels, membership subqueries and the
//! `updated_at`/slug triggers were all generated against a literal `"public"`. On a database
//! Supatype created that was merely wrong-looking; on a database it did not create — the whole point
//! of bring-your-own-Postgres — `public` holds someone else's tables, so:
//!
//! * a policy's `EXISTS (SELECT 1 FROM "public"."team_member" ...)` reads *their* table and decides
//!   access from it,
//! * `GRANT`/`REVOKE` lands on their table,
//! * a `BEFORE UPDATE` trigger attaches to their table,
//!
//! and each of those either errors or, worse, succeeds against the wrong object. The tests here
//! assert the qualification rather than the absence of an error, because the dangerous case is the
//! one that applies cleanly.

mod common;

use sqlx::Row;
use supatype_engine::{
    differ,
    generator::sql::{grants, migration, rls, triggers},
    introspector, parser,
    state::database_state::DatabaseState,
};

const MANAGED: &str = "app";

/// Two models with a membership rule between them, so the generated policy contains a subquery
/// against a second table — the case that silently reads the wrong object.
const SCHEMA: &str = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "TeamMember",
      "fields": {
        "id": { "kind": "uuid", "primaryKey": true, "required": true,
                "default": { "kind": "genRandomUuid" },
                "annotations": { "db": { "pgType": "UUID", "unique": false } } },
        "userId": { "kind": "uuid", "required": true,
                "annotations": { "db": { "pgType": "UUID", "unique": false } } },
        "teamId": { "kind": "text", "required": true,
                "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
      },
      "annotations": { "db": { "tableName": "team_member", "indexes": [] }, "platform": {} }
    },
    {
      "name": "Doc",
      "fields": {
        "id": { "kind": "uuid", "primaryKey": true, "required": true,
                "default": { "kind": "genRandomUuid" },
                "annotations": { "db": { "pgType": "UUID", "unique": false } } },
        "teamId": { "kind": "text", "required": true,
                "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
        "title": { "kind": "text",
                "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
        "updatedAt": { "kind": "datetime",
                "annotations": { "db": { "pgType": "TIMESTAMPTZ", "unique": false } } }
      },
      "annotations": {
        "db": { "tableName": "doc", "indexes": [] },
        "platform": {
          "access": {
            "read": { "type": "in", "column": "teamId",
                      "source": { "kind": "rows", "table": "team_member", "column": "teamId",
                                  "where": { "type": "owner", "field": "id" } } },
            "create": { "type": "authenticated" },
            "update": { "type": "authenticated" },
            "delete": { "type": "authenticated" },
            "fields": {
              "title": { "write": { "type": "private" } }
            }
          }
        }
      }
    }
  ]
}"#;

/// The same schema without the field rule.
///
/// A schema declaring `fields` refuses to apply without `supatype_mask`, which the published
/// `supatype/postgres` image does not yet carry — gating the database test on the extension made it
/// skip silently, which is indistinguishable from passing. Label placement is asserted against the
/// generator instead, where no database is involved.
const SCHEMA_WITHOUT_FIELD_RULES: &str = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "TeamMember",
      "fields": {
        "id": { "kind": "uuid", "primaryKey": true, "required": true,
                "default": { "kind": "genRandomUuid" },
                "annotations": { "db": { "pgType": "UUID", "unique": false } } },
        "userId": { "kind": "uuid", "required": true,
                "annotations": { "db": { "pgType": "UUID", "unique": false } } },
        "teamId": { "kind": "text", "required": true,
                "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
      },
      "annotations": { "db": { "tableName": "team_member", "indexes": [] }, "platform": {} }
    },
    {
      "name": "Doc",
      "fields": {
        "id": { "kind": "uuid", "primaryKey": true, "required": true,
                "default": { "kind": "genRandomUuid" },
                "annotations": { "db": { "pgType": "UUID", "unique": false } } },
        "teamId": { "kind": "text", "required": true,
                "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
        "title": { "kind": "text",
                "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
        "updatedAt": { "kind": "datetime",
                "annotations": { "db": { "pgType": "TIMESTAMPTZ", "unique": false } } }
      },
      "annotations": {
        "db": { "tableName": "doc", "indexes": [] },
        "platform": {
          "access": {
            "read": { "type": "in", "column": "teamId",
                      "source": { "kind": "rows", "table": "team_member", "column": "teamId",
                                  "where": { "type": "owner", "field": "id" } } },
            "create": { "type": "authenticated" },
            "update": { "type": "authenticated" },
            "delete": { "type": "authenticated" }
          }
        }
      }
    }
  ]
}"#;

fn ast() -> supatype_engine::parser::ast::SchemaAst {
    parser::parse(SCHEMA).expect("fixture parses")
}

fn ast_without_field_rules() -> supatype_engine::parser::ast::SchemaAst {
    parser::parse(SCHEMA_WITHOUT_FIELD_RULES).expect("field-rule-free fixture parses")
}

#[test]
fn policies_grants_labels_and_triggers_all_name_the_managed_schema() {
    let ast = ast();

    let policies = rls::generate(&ast, MANAGED).expect("policies render");
    let can = rls::generate_can_functions(&ast, MANAGED);
    let labels = rls::generate_security_labels(&ast, MANAGED);
    let table_grants = grants::generate_table_grants(&ast, MANAGED);
    let column_grants = grants::generate_column_grants(&ast, MANAGED);
    let trigger_sql = triggers::generate(&ast, MANAGED).expect("triggers render");

    for (what, sql) in [
        ("policies", &policies),
        ("can_* functions", &can),
        ("security labels", &labels),
        ("table grants", &table_grants),
        ("column grants", &column_grants),
        ("triggers", &trigger_sql),
    ] {
        assert!(
            !sql.is_empty(),
            "{what} produced nothing, so this test would pass vacuously"
        );
        assert!(
            !sql.contains("\"public\"."),
            "{what} still qualifies an object with \"public\" while the managed schema is \
             \"{MANAGED}\":\n{sql}"
        );
        assert!(
            sql.contains(&format!("\"{MANAGED}\".")),
            "{what} never names the managed schema \"{MANAGED}\":\n{sql}"
        );
    }

    // The membership subquery is the dangerous one: unqualified or mis-qualified, the policy decides
    // access by reading a table that belongs to whoever else is in `public`.
    assert!(
        policies.contains(&format!("FROM \"{MANAGED}\".\"team_member\"")),
        "the membership subquery does not read the managed schema:\n{policies}"
    );
}

#[test]
fn a_full_migration_script_never_mentions_public() {
    // The assembled script is what actually runs, and it stitches together six generators. Checking
    // the pieces individually would miss one that was wired up with the wrong argument.
    let ast = ast();
    let diff = differ::diff(&ast, &DatabaseState::default()).expect("diff against empty db");
    // The batch path, because it is the one a push runs — `forward_sql` emits only a comment where
    // the trigger SQL goes, so a trigger qualified with `public` would slip past this check.
    let storage_sql =
        supatype_engine::generator::sql::storage::generate(&ast).expect("storage sql renders");
    let sql = migration::push_storage_and_model_batch_sql(&storage_sql, &diff, false, MANAGED, &ast)
        .expect("script renders");

    // `public` legitimately appears in `GRANT USAGE ... TO PUBLIC` (the role) and in the realtime
    // drop's legacy-name cleanup, so match the qualified-identifier form only.
    assert!(
        !sql.contains("\"public\"."),
        "the migration script qualifies an object with \"public\":\n{sql}"
    );
}

/// Privileges the API roles hold on tables in `public`.
async fn public_api_grants(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.role_table_grants          WHERE table_schema = 'public' AND grantee IN ('anon', 'authenticated')",
    )
    .fetch_one(pool)
    .await
    .expect("count public grants")
}

#[tokio::test]
async fn a_push_into_a_non_public_schema_leaves_public_untouched() {
    common::with_integration_pool(|pool| async move {
        // Someone else's tables, under the same names the schema uses. This is what a bring-your-own
        // database looks like, and it is why "it applied without error" is not evidence of anything.
        sqlx::raw_sql(
            r#"
            CREATE SCHEMA app;
            CREATE TABLE public.doc (id int primary key, title text, theirs text);
            CREATE TABLE public.team_member (id int primary key, note text);
            INSERT INTO public.doc VALUES (1, 'their title', 'their data');
            "#,
        )
        .execute(&pool)
        .await
        .expect("decoy fixture applies");

        // `supatype/postgres` sets default privileges on `public` for the API roles, so their tables
        // already carry grants that have nothing to do with this push. Compare the delta, not the
        // total — an absolute assertion here measures the image, not the migration.
        let grants_before = public_api_grants(&pool).await;

        let ast = ast_without_field_rules();
        let db = introspector::introspect(&pool, MANAGED).await.expect("introspect app");
        let diff = differ::diff(&ast, &db).expect("diff");
        // The real push path, not `forward_sql`: only this one appends the trigger SQL, and triggers
        // are one of the things that used to attach to `public`.
        let storage_sql = supatype_engine::generator::sql::storage::generate(&ast)
            .expect("storage sql renders");
        let sql = migration::push_storage_and_model_batch_sql(&storage_sql, &diff, false, MANAGED, &ast)
            .expect("script renders");
        sqlx::raw_sql(&sql).execute(&pool).await.expect("migration applies");

        // Policies on the managed table, none on theirs.
        let managed_policies: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_policies WHERE schemaname = 'app' AND tablename = 'doc'",
        )
        .fetch_one(&pool)
        .await
        .expect("count app policies");
        assert!(managed_policies > 0, "no policies were created on app.doc");

        let their_policies: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_policies WHERE schemaname = 'public'",
        )
        .fetch_one(&pool)
        .await
        .expect("count public policies");
        assert_eq!(their_policies, 0, "policies were attached to tables in public");

        // Triggers likewise: `updated_at` belongs to app.doc, not to theirs.
        let their_triggers: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_trigger t \
             JOIN pg_class c ON c.oid = t.tgrelid \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'public' AND NOT t.tgisinternal",
        )
        .fetch_one(&pool)
        .await
        .expect("count public triggers");
        assert_eq!(their_triggers, 0, "a trigger was attached to a table in public");

        let managed_triggers: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_trigger t \
             JOIN pg_class c ON c.oid = t.tgrelid \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'app' AND c.relname = 'doc' AND NOT t.tgisinternal",
        )
        .fetch_one(&pool)
        .await
        .expect("count app triggers");
        assert!(
            managed_triggers > 0,
            "the updated_at trigger was not attached to app.doc, so the assertion above is vacuous"
        );

        // Privileges are the other half: the generated GRANT/REVOKE pairs name a table, and pointed
        // at `public` they hand the API roles access to someone else's — or take it away.
        assert_eq!(
            public_api_grants(&pool).await,
            grants_before,
            "the push changed the API roles' privileges on tables in public"
        );

        let managed_grants: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM information_schema.role_table_grants              WHERE table_schema = 'app' AND grantee IN ('anon', 'authenticated')",
        )
        .fetch_one(&pool)
        .await
        .expect("count app grants");
        assert!(
            managed_grants > 0,
            "no privileges were granted on app tables, so the assertion above is vacuous"
        );

        // RLS was not switched on over their table — that alone would break their application.
        let their_rls: bool = sqlx::query_scalar(
            "SELECT relrowsecurity FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'public' AND c.relname = 'doc'",
        )
        .fetch_one(&pool)
        .await
        .expect("read public.doc rls flag");
        assert!(!their_rls, "row level security was forced on a table in public");

        // And their data is still there, with its columns intact.
        let row = sqlx::query("SELECT title, theirs FROM public.doc WHERE id = 1")
            .fetch_one(&pool)
            .await
            .expect("their table survived");
        assert_eq!(row.get::<String, _>("title"), "their title");
        assert_eq!(row.get::<String, _>("theirs"), "their data");
    })
    .await;
}

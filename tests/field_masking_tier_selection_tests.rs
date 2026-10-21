//! Which mechanism a push chooses to enforce field rules, and whether the choice is a real boundary.
//!
//! Before tier 2 existed, a schema declaring `access.fields` against a database without
//! `supatype_mask` **refused to apply**. That was correct at the time, since a push must never
//! silently unmask, and it was the reason field rules could not follow anyone to their own
//! Postgres. Now the same push generates `api` views.
//!
//! These tests never create the masking extension, except the one that reads tier 1's record, so
//! they run tier 2 on any image, including `supatype/postgres`, which only provides it. They used to ask the image whether it could, and
//! that question created the extension, so on CI's image every one of them skipped and tier 2 went
//! untested (A3-N3).

mod common;

use supatype_engine::{
    differ::{self, FieldMaskingTier},
    parser,
};

/// One masked column with a row-dependent read rule, and one ordinary table with no field rules.
/// The second must still get a view, or it would vanish from an API that only exposes `api`.
const SCHEMA: &str = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Employee",
      "fields": {
        "id":        { "kind": "integer", "primaryKey": true, "required": true,
                       "annotations": { "db": { "pgType": "INTEGER", "unique": false } } },
        "name":      { "kind": "text",
                       "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
        "salary":    { "kind": "decimal",
                       "annotations": { "db": { "pgType": "NUMERIC", "unique": false } } },
        "user_id":   { "kind": "text", "required": true,
                       "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
      },
      "annotations": {
        "db": { "tableName": "tier_employee", "indexes": [] },
        "platform": { "access": {
          "read": { "type": "public" },
          "update": { "type": "public" },
          "fields": {
            "salary": { "read": { "type": "compare",
                                  "left":  { "kind": "column", "name": "user_id" },
                                  "op":    "eq",
                                  "right": { "kind": "claim", "path": "uid" } } }
          }
        } }
      }
    },
    {
      "name": "Office",
      "fields": {
        "id":   { "kind": "integer", "primaryKey": true, "required": true,
                  "annotations": { "db": { "pgType": "INTEGER", "unique": false } } },
        "city": { "kind": "text",
                  "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
      },
      "annotations": {
        "db": { "tableName": "tier_office", "indexes": [] },
        "platform": { "access": { "read": { "type": "public" } } }
      }
    }
  ]
}"#;

/// Everything a push needs to exist before the model migration runs.
async fn prepare(pool: &sqlx::PgPool) {
    sqlx::raw_sql(
        "CREATE SCHEMA IF NOT EXISTS auth; \
         DO $$ BEGIN \
           BEGIN CREATE ROLE anon NOLOGIN NOINHERIT; \
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END; \
           BEGIN CREATE ROLE authenticated NOLOGIN NOINHERIT; \
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END; \
           BEGIN CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS; \
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END; \
         END $$;",
    )
    .execute(pool)
    .await
    .expect("roles and auth schema");
    sqlx::raw_sql(&supatype_engine::generator::sql::rls::generate_auth_helpers())
        .execute(pool)
        .await
        .expect("auth helpers");
}

/// Apply the schema with the push a user runs, returning the diff that produced it.
async fn push(pool: &sqlx::PgPool) -> differ::DiffOutput {
    let ast = parser::parse(SCHEMA).expect("schema parses");
    let plan = supatype_engine::push::prepare(pool, &ast, "public")
        .await
        .expect("the push plans");
    let diff = plan.diff.clone();
    supatype_engine::push::apply(
        pool,
        plan,
        supatype_engine::push::ApplyOptions {
            force: true,
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|e| panic!("push does not apply: {e}"));
    diff
}

#[tokio::test]
async fn a_database_without_the_extension_gets_views_instead_of_a_refusal() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;

        let diff = push(&pool).await;
        assert_eq!(
            diff.field_masking,
            FieldMaskingTier::Views,
            "a database with no masking extension must select tier 2"
        );

        // The masked table's view masks; the unmasked table's view passes through. Both must exist,
        // because under tier 2 the API is pointed at `api` and nothing else.
        let views: Vec<String> = sqlx::query_scalar(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = 'api' AND c.relkind = 'v' ORDER BY c.relname",
        )
        .fetch_all(&pool)
        .await
        .expect("list api views");
        assert_eq!(
            views,
            vec!["tier_employee".to_string(), "tier_office".to_string()],
            "every model needs a view under tier 2, not only the masked ones"
        );

        // And the masking is in the definition, not merely implied.
        let def: String =
            sqlx::query_scalar("SELECT pg_get_viewdef('api.tier_employee'::regclass)")
                .fetch_one(&pool)
                .await
                .expect("read the view definition");
        assert!(
            def.contains("CASE") && def.contains("_supatype.can_read_tier_employee__"),
            "the masked column is not masked in the view: {def}"
        );
    })
    .await;
}

#[tokio::test]
async fn tier_two_takes_the_api_roles_off_the_base_tables() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;
        // What `supatype/postgres` gives every new table, so the push has something to take away.
        sqlx::raw_sql(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public \
             GRANT ALL ON TABLES TO anon, authenticated, service_role",
        )
        .execute(&pool)
        .await
        .expect("the image's default privileges");
        push(&pool).await;

        // The whole point. Schema exposure is PostgREST configuration, not a boundary: a client picks
        // its schema per request with `Accept-Profile`, so if `anon` can still read the base table the
        // mask is opt-out. Verified as a privilege, which no gateway setting can undo.
        for role in ["anon", "authenticated"] {
            let base: bool = sqlx::query_scalar(
                "SELECT has_table_privilege($1, 'public.tier_employee', 'SELECT')",
            )
            .bind(role)
            .fetch_one(&pool)
            .await
            .expect("read base privilege");
            assert!(
                !base,
                "{role} can still read the unmasked table behind the view, so the mask is only as \
                 strong as PGRST_DB_SCHEMA"
            );

            let view: bool =
                sqlx::query_scalar("SELECT has_table_privilege($1, 'api.tier_employee', 'SELECT')")
                    .bind(role)
                    .fetch_one(&pool)
                    .await
                    .expect("read view privilege");
            assert!(
                view,
                "{role} cannot read the view, so the API would serve nothing"
            );
        }

        // `service_role` keeps its base access by standing policy: it is the escape hatch, and the
        // engine never touches its privileges. Through the API it reads the views, which exempt it
        // from every mask, as the extension exempts it in tier 1.
        let escape: bool = sqlx::query_scalar(
            "SELECT has_table_privilege('service_role', 'public.tier_employee', 'SELECT')",
        )
        .fetch_one(&pool)
        .await
        .expect("read service_role privilege");
        assert!(escape, "service_role lost its base-table access");
    })
    .await;
}

#[tokio::test]
async fn the_capability_record_says_views_not_broken() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;
        // The engine's own bookkeeping, which a real push creates before it migrates.
        for sql in [
            supatype_engine::state::migration_history::create_internal_schema_sql().to_string(),
            supatype_engine::state::migration_history::create_schema_state_table_sql(),
            supatype_engine::state::migration_history::ensure_schema_state_capabilities_column_sql(),
        ] {
            sqlx::raw_sql(&sql).execute(&pool).await.expect("internal schema");
        }
        // The row `record_field_enforcement` updates. A real push writes it when it saves the schema
        // snapshot; this test only cares about the capability field on it.
        sqlx::raw_sql(
            "INSERT INTO _supatype.schema_state (id, db_state, engine_version) \
             VALUES (1, '{}'::jsonb, 'test') ON CONFLICT (id) DO NOTHING",
        )
        .execute(&pool)
        .await
        .expect("schema_state row");
        push(&pool).await;

        // Studio and `doctor` read this. Before tier 2 existed the same state was recorded as
        // `broken`, which would now describe a database that is enforcing its rules perfectly well.
        let mut conn = pool.acquire().await.expect("connection");
        supatype_engine::state::migration_history::record_field_enforcement(
            &mut conn,
            &parser::parse(SCHEMA).expect("schema parses"),
            "public",
        )
        .await
        .expect("record the capability");
        drop(conn);

        let tier: String = sqlx::query_scalar(
            "SELECT capabilities #>> '{fieldMasking,tier}' FROM _supatype.schema_state WHERE id = 1",
        )
        .fetch_one(&pool)
        .await
        .expect("read the recorded tier");
        assert_eq!(tier, "views");

        // Which predicate decides each masked column, as a label would say under tier 1: the one
        // place a tier 2 reader (realtime) can learn it without rebuilding the naming rule.
        let columns: serde_json::Value = sqlx::query_scalar(
            "SELECT capabilities #> '{fieldMasking,columns}' FROM _supatype.schema_state WHERE id = 1",
        )
        .fetch_one(&pool)
        .await
        .expect("read the recorded predicates");
        assert_eq!(
            columns,
            serde_json::json!([{
                "schema": "public",
                "table": "tier_employee",
                "column": "salary",
                "read": "public.\"can_read_tier_employee__salary\"",
                "write": null
            }])
        );
    })
    .await;
}

/// The recorded predicates name each column's schema under tier 1 too, so a reader never infers it
/// from the predicate's qualifier (RT-W3).
#[tokio::test]
async fn the_tier_one_record_names_each_columns_schema() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            return;
        }
        prepare(&pool).await;
        push(&pool).await;
        let recorded: serde_json::Value = sqlx::query_scalar(
            "SELECT capabilities -> 'fieldMasking' FROM _supatype.schema_state WHERE id = 1",
        )
        .fetch_one(&pool)
        .await
        .expect("read the recorded enforcement");
        assert_eq!(recorded["tier"], "extension", "{recorded}");
        assert_eq!(
            recorded["columns"],
            serde_json::json!([{
                "schema": "public",
                "table": "tier_employee",
                "column": "salary",
                "read": "public.\"can_read_tier_employee__salary\"",
                "write": null
            }])
        );
    })
    .await;
}

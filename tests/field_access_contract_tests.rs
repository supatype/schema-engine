//! The observable contract of a masked column, asserted identically against every tier.
//!
//! Field masking has two intended implementations: **tier 1**, the `supatype_mask` planner
//! rewrite, and **tier 2**, generated `api`-schema views for databases that cannot load an
//! extension. The plan's whole case for calling tier 2 *redundancy* rather than a second product
//! rests on one claim, namely that both produce the same observable behaviour for the same schema
//! and caller. A claim like that decays silently unless something checks it.
//!
//! So this suite is written once and run per tier. Every assertion is phrased in terms a client
//! can see: what comes back in the row, what happens on a round-trip write, what happens to an
//! aggregate. Nothing here inspects *how* the masking was achieved, which is the only way the
//! same test can be honest about both.
//!
//! Tier 2 does not exist yet. Its cases skip with a message rather than passing vacuously, so
//! this file is the parity gate the generator will be built against. The day the generator
//! lands, drift between the tiers becomes a test failure rather than a discovery.

mod common;

use sqlx::Row;
use supatype_engine::{
    generator::sql::{field_views, rls},
    introspector, parser,
};

/// The same table and rules as [`SETUP`], expressed as a schema so that tier 2 is built by the
/// generator rather than by hand.
///
/// The write rule mirrors tier 1's hand-written function exactly, including the second clause on a
/// claim that the caller may not have. That matters: with a simpler `private` rule the predicate
/// compiles to `FALSE`, and the NULL case (a rule keyed on an absent claim) is never reached. Tier
/// 1's predicate *is* NULL for a caller who can read but has no `writer` claim, and it refuses; tier
/// 2 has to refuse for the same reason rather than a different one.
///
/// Hand-writing the views would test the *idea* of tier 2 and not the thing that ships. The read
/// rule compares a column to a JWT claim, which is what makes `as_caller` set
/// `request.jwt.claims` as well as `contract.uid`.
const CONTRACT_SCHEMA: &str = r#"{
  "astVersion": 2,
  "models": [{
    "name": "ContractPosts",
    "fields": {
      "id":       { "kind": "integer", "primaryKey": true, "required": true,
                    "annotations": { "db": { "pgType": "INTEGER", "unique": false } } },
      "title":    { "kind": "text",
                    "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
      "salary":   { "kind": "decimal",
                    "annotations": { "db": { "pgType": "NUMERIC", "unique": false } } },
      "author_id": { "kind": "text", "required": true,
                    "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
    },
    "annotations": {
      "db": { "tableName": "contract_posts", "indexes": [] },
      "platform": { "access": {
        "read":   { "type": "public" },
        "update": { "type": "public" },
        "fields": {
          "salary": {
            "read":  { "type": "compare",
                       "left":  { "kind": "column", "name": "author_id" },
                       "op":    "eq",
                       "right": { "kind": "claim", "path": "uid" } },
            "write": { "type": "all", "rules": [
                       { "type": "compare",
                         "left":  { "kind": "column", "name": "author_id" },
                         "op":    "eq",
                         "right": { "kind": "claim", "path": "uid" } },
                       { "type": "compare",
                         "left":  { "kind": "claim", "path": "writer" },
                         "op":    "eq",
                         "right": { "kind": "literal", "value": "on" } }
                     ] }
          }
        }
      } }
    }
  }]
}"#;

/// Build tier 2 for the fixture table using the shipping generator.
async fn install_tier_two(pool: &sqlx::PgPool) {
    let ast = parser::parse(CONTRACT_SCHEMA).expect("contract schema parses");

    // The generated predicate calls `_supatype.jwt_claim_text`, so the readers have to exist.
    sqlx::raw_sql("CREATE SCHEMA IF NOT EXISTS auth")
        .execute(pool)
        .await
        .expect("auth schema");
    sqlx::raw_sql(&rls::generate_auth_helpers())
        .execute(pool)
        .await
        .expect("auth helpers");

    let db = introspector::introspect(pool, "public")
        .await
        .expect("introspect for the view generator");
    let sql =
        field_views::render_field_views(&ast, &field_views::field_view_plan(&ast, &db), "public");
    assert!(
        !sql.is_empty(),
        "the generator produced nothing for a schema that masks a column"
    );
    sqlx::raw_sql(&sql)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("tier 2 SQL does not apply: {e}\n\n{sql}"));

    // The generator grants to the real API roles (anon / authenticated / service_role). This suite
    // uses a role of its own so that identity is explicit in every assertion, so it grants what that
    // role needs, exactly as `SETUP` already does for the base table.
    // `_supatype` too: the generated predicate calls `_supatype.jwt_claim_text`, both when the view
    // inlines it and when the write trigger calls it. The push grants this to the API roles.
    sqlx::raw_sql(
        "GRANT USAGE ON SCHEMA api TO contract_app; \
         GRANT USAGE ON SCHEMA _supatype TO contract_app; \
         GRANT SELECT, INSERT, UPDATE, DELETE ON api.contract_posts TO contract_app;",
    )
    .execute(pool)
    .await
    .expect("grant the suite's role access to the views");
}

/// Where a tier serves its rows from. The only thing that differs between them.
#[derive(Clone, Copy, Debug)]
enum Tier {
    /// `supatype_mask` rewrites references to the base table in the planner.
    Extension,
    /// A generated `api`-schema view carries the masking expression in its definition.
    Views,
}

impl Tier {
    fn relation(self) -> &'static str {
        match self {
            Tier::Extension => "\"public\".\"contract_posts\"",
            Tier::Views => "\"api\".\"contract_posts\"",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Tier::Extension => "tier 1 (extension)",
            Tier::Views => "tier 2 (views)",
        }
    }
}

/// The schema both tiers are tested against: one masked column with an ownership read rule and a
/// stricter write rule, which is the shape that exercises every branch of the contract.
const SETUP: &str = r#"
CREATE TABLE public.contract_posts (
  id        int primary key,
  title     text,
  salary    numeric,
  author_id text
);

INSERT INTO public.contract_posts VALUES
  (1, 'alice post', 100, 'alice'),
  (2, 'bob post',   200, 'bob');

CREATE FUNCTION public.can_read_contract_posts__salary(contract_posts public.contract_posts)
  RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT author_id = current_setting('contract.uid', true)
      FROM (SELECT ($1).*) AS contract_posts;
  $$;

CREATE FUNCTION public.can_write_contract_posts__salary(contract_posts public.contract_posts)
  RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT author_id = current_setting('contract.uid', true)
       AND current_setting('contract.writer', true) = 'on'
      FROM (SELECT ($1).*) AS contract_posts;
  $$;

SECURITY LABEL FOR supatype ON COLUMN public.contract_posts.salary
  IS 'MASK READ public."can_read_contract_posts__salary" WRITE public."can_write_contract_posts__salary"';

-- Created by whichever test in this suite gets here first. An IF NOT EXISTS pre-check is not
-- enough: roles are cluster-wide, so the loser of the race gets 23505, not 42710.
DO $$ BEGIN
  BEGIN
    CREATE ROLE contract_app;
  EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
  END;
END $$;
GRANT SELECT, UPDATE ON public.contract_posts TO contract_app;
"#;

/// Run one statement as the application role with a given identity, returning the error if any.
async fn as_caller(pool: &sqlx::PgPool, uid: &str, sql: &str) -> Result<(), String> {
    let mut tx = pool.begin().await.expect("begin");
    // Two settings, one identity. Tier 1's fixture is hand-written and reads `contract.uid`
    // directly; tier 2 is produced by the generator, so its predicate is whatever the AST compiles
    // to: `_supatype.jwt_claim_text('uid')`, which reads `request.jwt.claims`. Setting both is what lets the
    // assertions below be written once.
    let prelude = format!(
        "SET LOCAL contract.uid = '{uid}'; \
         SET LOCAL \"request.jwt.claims\" = '{{\"uid\": \"{uid}\"}}'; \
         SET LOCAL ROLE contract_app;"
    );
    sqlx::raw_sql(&prelude)
        .execute(&mut *tx)
        .await
        .expect("assume identity");

    let result = sqlx::raw_sql(sql).execute(&mut *tx).await;
    let answer = match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    };
    let _ = tx.rollback().await;
    answer
}

/// Read one row's `salary` as a given identity. `None` means the column came back NULL.
async fn read_salary(pool: &sqlx::PgPool, tier: Tier, uid: &str, id: i32) -> Option<String> {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::raw_sql(&format!(
        "SET LOCAL contract.uid = '{uid}'; \
         SET LOCAL \"request.jwt.claims\" = '{{\"uid\": \"{uid}\"}}'; \
         SET LOCAL ROLE contract_app;"
    ))
    .execute(&mut *tx)
    .await
    .expect("assume identity");

    let row = sqlx::query(&format!(
        "SELECT salary::text AS salary FROM {} WHERE id = {id}",
        tier.relation()
    ))
    .fetch_one(&mut *tx)
    .await
    .expect("the row is visible");

    let salary: Option<String> = row.get("salary");
    let _ = tx.rollback().await;
    salary
}

/// The value actually in the table, read with no tier in the way.
async fn stored_salary(pool: &sqlx::PgPool, id: i32) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(&format!(
        "SELECT salary::text FROM public.contract_posts WHERE id = {id}"
    ))
    .fetch_one(pool)
    .await
    .expect("read the stored value")
}

/// Whether this tier is available in the database yet.
async fn tier_available(pool: &sqlx::PgPool, tier: Tier) -> bool {
    match tier {
        Tier::Extension => true,
        Tier::Views => sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM pg_class c
               JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = 'api' AND c.relname = 'contract_posts' AND c.relkind = 'v')",
        )
        .fetch_one(pool)
        .await
        .unwrap_or(false),
    }
}

/// The contract, in full, for one tier.
async fn assert_contract(pool: &sqlx::PgPool, tier: Tier) {
    let where_ = tier.label();

    // 1. The owner reads the real value.
    assert_eq!(
        read_salary(pool, tier, "alice", 1).await.as_deref(),
        Some("100"),
        "{where_}: the owner must read their own value"
    );

    // 2. Everyone else gets NULL: present, not an error, because `SELECT *` must keep working.
    assert_eq!(
        read_salary(pool, tier, "bob", 1).await,
        None,
        "{where_}: a non-owner must get NULL, not a value and not an error"
    );

    // 3. `SELECT *` with no column list is the request PostgREST sends by default. A tier that
    //    403s here has broken the API rather than restricted a column.
    assert!(
        as_caller(pool, "bob", &format!("SELECT * FROM {}", tier.relation()))
            .await
            .is_ok(),
        "{where_}: SELECT * must not fail"
    );

    // 4. The round-trip. A client GETs a row, `salary` comes back NULL because it is masked, the
    //    user edits the title, and the client PATCHes the whole object back including
    //    `salary: null`. The real value must survive, silently. This is the case the whole
    //    coercion design exists for, and the one most likely to differ between tiers.
    let round_trip = as_caller(
        pool,
        "bob",
        &format!("UPDATE {} SET salary = NULL WHERE id = 1", tier.relation()),
    )
    .await;
    assert!(
        round_trip.is_ok(),
        "{where_}: a round-tripped null from a caller who never saw the value must not error: {round_trip:?}"
    );

    // 5. Saw it and tried to change it, without the write rule: rejected loudly. The distinction
    //    from (4) is the point, since collapsing them either destroys data or breaks
    //    whole-object clients.
    let refused = as_caller(
        pool,
        "alice",
        &format!("UPDATE {} SET salary = 999 WHERE id = 1", tier.relation()),
    )
    .await;
    assert!(
        refused.is_err(),
        "{where_}: a caller who can read but not write the column must be refused"
    );

    // 7. A caller with no identity at all. The `uid` claim is NULL for them, so a rule comparing
    //    a column to it is NULL, not FALSE. `NOT NULL` is NULL and `IF NULL THEN RAISE` does not
    //    raise, so a predicate written as a comparison would silently *permit* the write.
    //
    //    What tier 1 guarantees here is not an error. Measured, it reports `UPDATE 1` and leaves the
    //    stored value alone, discarding the new one. So the assertion is about the data, which is the
    //    property that actually matters and the one a NULL-logic bug would break.
    let before = stored_salary(pool, 1).await;
    let _ = as_caller(
        pool,
        "",
        &format!("UPDATE {} SET salary = 777 WHERE id = 1", tier.relation()),
    )
    .await;
    assert_eq!(
        stored_salary(pool, 1).await,
        before,
        "{where_}: a caller with no identity changed a masked column"
    );

    // 6. Aggregates: **the one place the tiers differ**, deliberately and by decision.
    //
    // Tier 1 raises `column … is masked for this role and cannot be aggregated`, because the planner
    // knows the column appears inside an aggregate. A view cannot: requirement 2 above demands that
    // `SELECT salary` yield NULL rather than an error, and one expression cannot answer differently
    // inside `sum()` than in a projection.
    //
    // Decided 2026-08-12 to accept it, because the divergence is unreachable through the API:
    // PostgREST ships `db-aggregates-enabled = false` and Supatype never sets it, so only direct SQL
    // against the `api` views can see it. Asserted per tier so that neither can change quietly: if
    // tier 1 ever stops raising, or tier 2 ever starts, this fails.
    let aggregate = as_caller(
        pool,
        "bob",
        &format!("SELECT sum(salary) FROM {}", tier.relation()),
    )
    .await;
    match tier {
        Tier::Extension => assert!(
            aggregate.is_err(),
            "{where_}: an aggregate over a column the caller cannot read must error, not undercount"
        ),
        Tier::Views => assert!(
            aggregate.is_ok(),
            "{where_}: views cannot raise here (see the comment above); if this now errors, the \
             divergence is gone and the comment and docs are stale: {aggregate:?}"
        ),
    }
}

#[tokio::test]
async fn both_tiers_present_the_same_contract() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            return;
        }
        sqlx::raw_sql(SETUP)
            .execute(&pool)
            .await
            .expect("contract fixture applies");

        assert_contract(&pool, Tier::Extension).await;

        // Tier 2 is asserted with tier 1 switched **off**, which is the configuration it ships in:
        // it exists precisely for databases that cannot load the extension.
        //
        // Not a tidiness point. With the label in place the extension also guards the base table, so
        // a write the view wrongly permitted was refused by the extension instead. That was
        // measured by mutating the view's write guard and watching the suite still pass. Tier 2 has to be tested
        // alone or it is not being tested at all.
        sqlx::raw_sql("SECURITY LABEL FOR supatype ON COLUMN public.contract_posts.salary IS NULL")
            .execute(&pool)
            .await
            .expect("drop tier 1's label before asserting tier 2");

        install_tier_two(&pool).await;

        if tier_available(&pool, Tier::Views).await {
            assert_contract(&pool, Tier::Views).await;
        } else {
            // Not a pass. Tier 2's generator does not exist yet, and this suite is the gate it
            // will be built against.
            eprintln!(
                "SKIP {}: no `api` view for the fixture table. This is the parity gate for B9; \
                 when the view generator lands, remove nothing here and it becomes the check that \
                 the two tiers cannot drift.",
                Tier::Views.label()
            );
        }
    })
    .await;
}

/// A masked view must not become a row-level-security bypass.
///
/// Views run as their *owner* unless created `WITH (security_invoker = true)`, and the owner here is
/// the migrating superuser. Without that option every caller would read every row through the `api`
/// schema while the base table's policies applied only to callers who went around it, masking a
/// column while handing over the whole table.
///
/// Its own test because the shared contract fixture deliberately has no policies: several of those
/// assertions read another caller's row, which a policy would hide. Nothing in that suite noticed
/// `security_invoker` being removed, which was measured by mutating the generator and watching it
/// pass.
#[tokio::test]
async fn a_masked_view_does_not_bypass_row_level_security() {
    common::with_integration_pool(|pool| async move {
        // The policy calls auth.claim_text, so the helpers come first.
        sqlx::raw_sql("CREATE SCHEMA IF NOT EXISTS auth")
            .execute(&pool)
            .await
            .expect("auth schema");
        sqlx::raw_sql(&rls::generate_auth_helpers())
            .execute(&pool)
            .await
            .expect("auth helpers");

        sqlx::raw_sql(
            r#"
            CREATE TABLE public.rls_view_posts (
              id        int primary key,
              secret    text,
              author_id text
            );
            INSERT INTO public.rls_view_posts VALUES (1, 'alice secret', 'alice'), (2, 'bob secret', 'bob');

            ALTER TABLE public.rls_view_posts ENABLE ROW LEVEL SECURITY;
            CREATE POLICY own_rows ON public.rls_view_posts FOR SELECT
              USING (author_id = auth.claim_text('uid'));

            -- Cluster-wide role, so this races with the rest of the suite; catch both the
            -- sequential (42710) and concurrent (23505) forms of "it already exists".
            DO $$ BEGIN
              BEGIN
                CREATE ROLE rls_view_app;
              EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
              END;
            END $$;
            GRANT SELECT ON public.rls_view_posts TO rls_view_app;
            "#,
        )
        .execute(&pool)
        .await
        .expect("rls fixture applies");

        let ast = parser::parse(
            r#"{
              "astVersion": 2,
              "models": [{
                "name": "RlsViewPosts",
                "fields": {
                  "id":        { "kind": "integer", "primaryKey": true, "required": true,
                                 "annotations": { "db": { "pgType": "INTEGER", "unique": false } } },
                  "secret":    { "kind": "text",
                                 "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
                  "author_id": { "kind": "text", "required": true,
                                 "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
                },
                "annotations": {
                  "db": { "tableName": "rls_view_posts", "indexes": [] },
                  "platform": { "access": { "read": { "type": "public" }, "fields": {
                    "secret": { "read": { "type": "compare",
                                          "left":  { "kind": "column", "name": "author_id" },
                                          "op":    "eq",
                                          "right": { "kind": "claim", "path": "uid" } } }
                  } } }
                }
              }]
            }"#,
        )
        .expect("rls view schema parses");

        let db = introspector::introspect(&pool, "public").await.expect("introspect");
        let sql = field_views::render_field_views(&ast, &field_views::field_view_plan(&ast, &db), "public");
        sqlx::raw_sql(&sql)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("view SQL does not apply: {e}\n\n{sql}"));
        sqlx::raw_sql(
            "GRANT USAGE ON SCHEMA api, auth, _supatype TO rls_view_app; \
             GRANT SELECT ON api.rls_view_posts TO rls_view_app;",
        )
        .execute(&pool)
        .await
        .expect("grant the suite's role access");

        let mut tx = pool.begin().await.expect("begin");
        sqlx::raw_sql(
            "SET LOCAL \"request.jwt.claims\" = '{\"uid\": \"alice\"}'; SET LOCAL ROLE rls_view_app;",
        )
        .execute(&mut *tx)
        .await
        .expect("assume identity");

        let visible: Vec<String> = sqlx::query_scalar("SELECT author_id FROM api.rls_view_posts ORDER BY id")
            .fetch_all(&mut *tx)
            .await
            .expect("read through the view");
        let _ = tx.rollback().await;

        assert_eq!(
            visible,
            vec!["alice".to_string()],
            "the view exposed rows the base table's policy hides: it is missing \
             `security_invoker`, so it ran as its owner"
        );
    })
    .await;
}

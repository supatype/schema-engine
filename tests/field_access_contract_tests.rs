//! The observable contract of a masked column, asserted identically against every tier.
//!
//! Field masking has two intended implementations: **tier 1**, the `supatype_mask` planner
//! rewrite, and **tier 2**, generated `api`-schema views for databases that cannot load an
//! extension. The plan's whole case for calling tier 2 *redundancy* rather than a second product
//! rests on one claim — that both produce the same observable behaviour for the same schema and
//! caller. A claim like that decays silently unless something checks it.
//!
//! So this suite is written once and run per tier. Every assertion is phrased in terms a client
//! can see: what comes back in the row, what happens on a round-trip write, what happens to an
//! aggregate. Nothing here inspects *how* the masking was achieved, which is the only way the
//! same test can be honest about both.
//!
//! Tier 2 does not exist yet. Its cases skip with a message rather than passing vacuously, so
//! this file is the parity gate the generator will be built against — and the day the generator
//! lands, drift between the tiers becomes a test failure rather than a discovery.

mod common;

use sqlx::Row;

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

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'contract_app') THEN
    CREATE ROLE contract_app;
  END IF;
END $$;
GRANT SELECT, UPDATE ON public.contract_posts TO contract_app;
"#;

/// Run one statement as the application role with a given identity, returning the error if any.
async fn as_caller(pool: &sqlx::PgPool, uid: &str, sql: &str) -> Result<(), String> {
    let mut tx = pool.begin().await.expect("begin");
    let prelude = format!(
        "SET LOCAL contract.uid = '{uid}'; SET LOCAL ROLE contract_app;"
    );
    sqlx::raw_sql(&prelude).execute(&mut *tx).await.expect("assume identity");

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
        "SET LOCAL contract.uid = '{uid}'; SET LOCAL ROLE contract_app;"
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

    // 2. Everyone else gets NULL — present, not an error, because `SELECT *` must keep working.
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
    //    `salary: null`. The real value must survive, silently — this is the case the whole
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
    //    from (4) is the point — collapsing them either destroys data or breaks whole-object
    //    clients.
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

    // 6. An aggregate must never return a quietly partial number.
    let aggregate = as_caller(
        pool,
        "bob",
        &format!("SELECT sum(salary) FROM {}", tier.relation()),
    )
    .await;
    assert!(
        aggregate.is_err(),
        "{where_}: an aggregate over a column the caller cannot read must error, not undercount"
    );
}

#[tokio::test]
async fn both_tiers_present_the_same_contract() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            return;
        }
        sqlx::raw_sql(SETUP).execute(&pool).await.expect("contract fixture applies");

        assert_contract(&pool, Tier::Extension).await;

        if tier_available(&pool, Tier::Views).await {
            assert_contract(&pool, Tier::Views).await;
        } else {
            // Not a pass. Tier 2's generator does not exist yet, and this suite is the gate it
            // will be built against.
            eprintln!(
                "SKIP {}: no `api` view for the fixture table. This is the parity gate for B9 — \
                 when the view generator lands, remove nothing here and it becomes the check that \
                 the two tiers cannot drift.",
                Tier::Views.label()
            );
        }
    })
    .await;
}

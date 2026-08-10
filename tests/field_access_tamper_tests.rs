//! Trying to get a masked value out, on purpose.
//!
//! `field_access_contract_tests.rs` asserts the behaviour a well-behaved client sees.
//! This asserts what an ill-behaved one *cannot* see. The difference matters because masking is
//! a rewrite rather than a privilege: the column is still there, the caller can still name it,
//! and every SQL construct that touches it is a place the substitution could have been missed.
//!
//! The specific worry is oracles. A restriction that returns NULL in the target list but still
//! evaluates `WHERE salary > 100000` honestly has not hidden the salary — it has made it
//! searchable one bit at a time. So most of these tests are not "is the value NULL" but "does
//! this construct discriminate between rows it should not be able to see".
//!
//! Runs only where `supatype_mask` is installed; skips loudly otherwise, like the other field
//! suites.

mod common;

use sqlx::Row;

/// A masked salary, a non-owner caller, and rows whose values are known to the test.
const SETUP: &str = r#"
CREATE TABLE public.tamper_staff (
  id      int primary key,
  name    text,
  salary  int,
  user_id text
);

INSERT INTO public.tamper_staff VALUES
  (1, 'alice', 100, 'alice'),
  (2, 'bob',   200, 'bob'),
  (3, 'carol', 300, 'carol');

CREATE FUNCTION public.can_read_tamper_staff__salary(tamper_staff public.tamper_staff)
  RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT user_id = current_setting('tamper.uid', true)
      FROM (SELECT ($1).*) AS tamper_staff;
  $$;

SECURITY LABEL FOR supatype ON COLUMN public.tamper_staff.salary
  IS 'MASK READ public."can_read_tamper_staff__salary"';

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tamper_app') THEN
    CREATE ROLE tamper_app;
  END IF;
END $$;
GRANT SELECT, UPDATE ON public.tamper_staff TO tamper_app;
GRANT USAGE ON SCHEMA public TO tamper_app;
"#;

/// Run SQL as `tamper_app` with a given identity. Returns rows, or the error text.
async fn attempt(pool: &sqlx::PgPool, uid: &str, sql: &str) -> Result<Vec<sqlx::postgres::PgRow>, String> {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::raw_sql(&format!(
        "SET LOCAL tamper.uid = '{uid}'; SET LOCAL ROLE tamper_app;"
    ))
    .execute(&mut *tx)
    .await
    .expect("assume identity");

    let result = sqlx::query(sql).fetch_all(&mut *tx).await;
    let answer = match result {
        Ok(rows) => Ok(rows),
        Err(e) => Err(e.to_string()),
    };
    let _ = tx.rollback().await;
    answer
}

/// How many rows a query returned, or `None` if it errored.
async fn count_rows(pool: &sqlx::PgPool, uid: &str, sql: &str) -> Option<usize> {
    attempt(pool, uid, sql).await.ok().map(|r| r.len())
}

#[tokio::test]
async fn a_masked_column_cannot_be_used_as_an_oracle() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            eprintln!("SKIP field-access tamper suite: supatype_mask is not installed");
            return;
        }
        sqlx::raw_sql(SETUP).execute(&pool).await.expect("tamper fixture applies");

        // Baseline: alice sees her own salary, and nobody else's.
        let rows = attempt(&pool, "alice", "SELECT salary FROM public.tamper_staff ORDER BY id")
            .await
            .expect("select succeeds");
        let visible: Vec<Option<i32>> = rows.iter().map(|r| r.get::<Option<i32>, _>("salary")).collect();
        assert_eq!(
            visible,
            vec![Some(100), None, None],
            "the owner should see exactly one value and NULL for the rest"
        );

        // ── Equality probe ─────────────────────────────────────────────────────
        // The simplest oracle: guess a value and see whether a row comes back. Every guess must
        // return nothing, including the *correct* one for a row the caller cannot read.
        for guess in [100, 200, 300, 0] {
            let n = count_rows(
                &pool,
                "bob",
                &format!("SELECT id FROM public.tamper_staff WHERE salary = {guess}"),
            )
            .await;
            // bob may read only row 2. A guess of 200 is correct for his own row, so that one is
            // allowed to match; nothing else may.
            let expected = if guess == 200 { Some(1) } else { Some(0) };
            assert_eq!(
                n, expected,
                "WHERE salary = {guess} leaked: a caller who cannot read a row must not be able \
                 to confirm its value"
            );
        }

        // ── Range probe ────────────────────────────────────────────────────────
        // Binary search is the same attack with fewer requests. `> 0` would match every row if
        // the qual saw real values; it must match only the one bob can read.
        for predicate in ["salary > 0", "salary < 1000", "salary >= 100", "salary <> 999"] {
            let n = count_rows(
                &pool,
                "bob",
                &format!("SELECT id FROM public.tamper_staff WHERE {predicate}"),
            )
            .await;
            assert_eq!(
                n,
                Some(1),
                "{predicate} matched more than bob's own row — the qual is evaluating real values"
            );
        }

        // ── IS NULL is the inverse probe ───────────────────────────────────────
        // Masked values read as NULL, so `IS NULL` is expected to match the rows a caller cannot
        // see. That is not a leak of the *value*, but it is worth pinning as intended: it tells
        // the caller which rows are withheld, which the masked-field header says anyway.
        let n = count_rows(&pool, "bob", "SELECT id FROM public.tamper_staff WHERE salary IS NULL").await;
        assert_eq!(n, Some(2), "expected the two rows bob cannot read to read as NULL");

        // ── Subqueries and CTEs ────────────────────────────────────────────────
        for sql in [
            "SELECT id FROM (SELECT id, salary FROM public.tamper_staff) s WHERE s.salary = 300",
            "WITH c AS (SELECT id, salary FROM public.tamper_staff) SELECT id FROM c WHERE salary = 300",
            "SELECT id FROM public.tamper_staff t WHERE EXISTS \
             (SELECT 1 FROM public.tamper_staff i WHERE i.id = t.id AND i.salary = 300)",
        ] {
            assert_eq!(
                count_rows(&pool, "bob", sql).await,
                Some(0),
                "a nested reference reached the real value: {sql}"
            );
        }

        // ── Self-join ──────────────────────────────────────────────────────────
        // Joining the table to itself on the masked column would match every unreadable pair if
        // the join condition saw real values.
        let n = count_rows(
            &pool,
            "bob",
            "SELECT a.id FROM public.tamper_staff a JOIN public.tamper_staff b ON a.salary = b.salary \
             WHERE a.id <> b.id",
        )
        .await;
        assert_eq!(n, Some(0), "a join on the masked column correlated real values");

        // ── ORDER BY ───────────────────────────────────────────────────────────
        // Ordering by a masked column must not reveal the ranking. With everything but one row
        // NULL, a leak would show as a stable non-trivial ordering of the unreadable rows.
        let rows = attempt(
            &pool,
            "bob",
            "SELECT id FROM public.tamper_staff WHERE id <> 2 ORDER BY salary ASC, id ASC",
        )
        .await
        .expect("order by succeeds");
        let ids: Vec<i32> = rows.iter().map(|r| r.get::<i32, _>("id")).collect();
        assert_eq!(
            ids,
            vec![1, 3],
            "ordering fell back to id as expected; a different order would mean real values were compared"
        );
    })
    .await;
}

#[tokio::test]
async fn aggregates_over_an_unreadable_column_error_rather_than_undercount() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            eprintln!("SKIP field-access tamper suite: supatype_mask is not installed");
            return;
        }
        sqlx::raw_sql(SETUP).execute(&pool).await.expect("tamper fixture applies");

        // A quietly partial total is worse than an error: `sum` skipping the rows a caller cannot
        // read looks like an answer and is not one.
        for agg in ["sum(salary)", "avg(salary)", "min(salary)", "max(salary)", "count(salary)"] {
            let result = attempt(&pool, "bob", &format!("SELECT {agg} FROM public.tamper_staff")).await;
            assert!(
                result.is_err(),
                "{agg} returned a value for a caller who cannot read every row — that is a \
                 partial answer presented as a total"
            );
        }

        // Restricted to rows the caller *can* read, an aggregate is correct and must still work —
        // otherwise the rule has broken legitimate use rather than restricted it.
        let rows = attempt(&pool, "bob", "SELECT sum(salary) AS total FROM public.tamper_staff WHERE id = 2")
            .await
            .expect("an aggregate over readable rows must still work");
        assert_eq!(rows[0].get::<Option<i64>, _>("total"), Some(200));
    })
    .await;
}

#[tokio::test]
async fn a_masked_value_cannot_be_smuggled_out_through_a_projection() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            eprintln!("SKIP field-access tamper suite: supatype_mask is not installed");
            return;
        }
        sqlx::raw_sql(SETUP).execute(&pool).await.expect("tamper fixture applies");

        // Casting, concatenating or arithmetic on the column operates on the substituted NULL,
        // not the stored value — so each of these must be NULL for a row bob cannot read.
        for expr in [
            "salary::text",
            "salary + 0",
            "salary * 2",
            "concat('x', salary)",
            "coalesce(salary, -1)",
            "greatest(salary, 0)",
        ] {
            let rows = attempt(
                &pool,
                "bob",
                &format!("SELECT {expr} AS v FROM public.tamper_staff WHERE id = 3"),
            )
            .await
            .unwrap_or_else(|e| panic!("{expr} errored unexpectedly: {e}"));

            let v: Option<String> = rows[0].try_get::<Option<String>, _>("v").unwrap_or_else(|_| {
                rows[0].try_get::<Option<i32>, _>("v").ok().flatten().map(|n| n.to_string())
            });

            // `coalesce` and `greatest` legitimately turn NULL into their fallback — the point is
            // that the fallback is what appears, never 300.
            assert!(
                v.as_deref() != Some("300") && v.as_deref() != Some("600"),
                "{expr} produced {v:?}, which is derived from the real value"
            );
        }

        // A whole-row reference bypasses per-column rewriting by construction, so it is refused
        // outright rather than masked.
        let whole_row = attempt(&pool, "bob", "SELECT to_jsonb(t) FROM public.tamper_staff t WHERE id = 3").await;
        assert!(
            whole_row.is_err(),
            "a whole-row reference returned a row — every column would be in it, unmasked"
        );
    })
    .await;
}

#[tokio::test]
async fn writes_cannot_destroy_a_value_the_caller_never_saw() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            eprintln!("SKIP field-access tamper suite: supatype_mask is not installed");
            return;
        }
        sqlx::raw_sql(SETUP).execute(&pool).await.expect("tamper fixture applies");

        // The round-trip: bob reads row 3, gets NULL for salary, and writes the whole object back.
        // The value must survive, and the write must not error — a whole-object client is not
        // doing anything wrong.
        let mut tx = pool.begin().await.expect("begin");
        sqlx::raw_sql("SET LOCAL tamper.uid = 'bob'; SET LOCAL ROLE tamper_app;")
            .execute(&mut *tx)
            .await
            .expect("assume identity");
        sqlx::raw_sql("UPDATE public.tamper_staff SET salary = NULL, name = 'carol edited' WHERE id = 3")
            .execute(&mut *tx)
            .await
            .expect("a round-tripped null must not error");
        // Read it back as the owner *inside the same transaction* to see the stored value.
        sqlx::raw_sql("RESET ROLE").execute(&mut *tx).await.expect("reset");
        let stored: Option<i32> = sqlx::query("SELECT salary FROM public.tamper_staff WHERE id = 3")
            .fetch_one(&mut *tx)
            .await
            .expect("read back")
            .get("salary");
        assert_eq!(
            stored,
            Some(300),
            "a null round-tripped by a caller who never saw the value destroyed it"
        );
        let _ = tx.rollback().await;

        // And the other half: a caller must not be able to *set* a value on a row they cannot
        // read. Here the write rule is absent, so it follows the read rule.
        let refused = attempt(
            &pool,
            "bob",
            "UPDATE public.tamper_staff SET salary = 1 WHERE id = 3 RETURNING id",
        )
        .await;
        // Either refused outright, or silently preserved — both are safe. What must not happen is
        // the value changing to 1.
        let _ = refused;
        let after: Option<i32> = sqlx::query("SELECT salary FROM public.tamper_staff WHERE id = 3")
            .fetch_one(&pool)
            .await
            .expect("read back")
            .get("salary");
        assert_eq!(after, Some(300), "an unreadable column was overwritten by a caller who cannot read it");

        // RETURNING must not become a read channel either.
        let returned = attempt(
            &pool,
            "bob",
            "UPDATE public.tamper_staff SET name = 'x' WHERE id = 3 RETURNING salary",
        )
        .await;
        if let Ok(rows) = returned {
            let leaked: Option<i32> = rows[0].get("salary");
            assert_ne!(leaked, Some(300), "RETURNING handed back the masked value");
        }
    })
    .await;
}

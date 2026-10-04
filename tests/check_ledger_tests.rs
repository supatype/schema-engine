//! Phase 3d of the managed-object ownership plan: check constraints on the ledger.
//!
//! The six live tests every kind gets (plan section 11), for the first kind to move: created and
//! recorded; untouched on a second push; replaced when its definition changes; recreated when
//! dropped by hand; dropped when the schema stops asking; never touched when it was never ours.
//! Then the ways an object with no row is claimed (section 7): a stamp from an older engine, moved
//! into the ledger and out of the comment; a same-named check the database deparses to ours,
//! adopted; and the one way it is not: a same-named check that means something else, which refuses
//! the push and names itself.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{
    introspector::fingerprint::ObjectKind,
    ledger::{self, LedgerRow, Status},
    parser,
    parser::ast::SchemaAst,
    push,
};

fn schema(name_max: Option<u32>, price_rule: Option<Value>) -> SchemaAst {
    let mut name = json!({ "kind": "text", "required": true,
                           "annotations": { "db": { "pgType": "TEXT", "unique": false } } });
    if let Some(n) = name_max {
        // The CLI writes both: the bound for the SDKs and the check the generator renders.
        name["validation"] = json!({ "maxLength": n });
        name["check"] = json!(format!("char_length(\"{{name}}\") <= {n}"));
    }
    let doc = json!({
        "astVersion": 2,
        "locales": ["en"],
        "defaultLocale": "en",
        "publishing": {
            "draftVisibility": ["admin", "developer", "editor"],
            "previewDefaultTtl": 900,
            "previewMaxRecordTtl": 604800,
            "previewMaxProjectTtl": 86400,
            "previewAllowProjectScope": true
        },
        "models": [{
            "name": "Product",
            "fields": {
                "id": { "kind": "integer", "primaryKey": true, "required": true,
                        "annotations": { "db": { "pgType": "INTEGER", "unique": false } } },
                "name": name,
                "price": { "kind": "integer", "required": true,
                           "annotations": { "db": { "pgType": "INTEGER", "unique": false } } }
            },
            "options": { "timestamps": false, "softDelete": false },
            "annotations": {
                "db": {
                    "tableName": "products",
                    "indexes": [],
                    "constraints": price_rule.into_iter().collect::<Vec<_>>()
                },
                "platform": {}
            }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

fn price_at_least(n: i64) -> Value {
    json!({ "type": "compare", "op": "gte",
            "left": { "kind": "column", "name": "price" }, "right": { "kind": "literal", "value": n } })
}

use common::{exec, push};

async fn check_rows(pool: &PgPool) -> Vec<LedgerRow> {
    let mut conn = pool.acquire().await.unwrap();
    ledger::load(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.key.kind == ObjectKind::Check)
        .collect()
}

/// `(name, definition, comment)` of every check on `products`.
async fn live_checks(pool: &PgPool) -> Vec<(String, String, Option<String>)> {
    sqlx::query_as(
        "SELECT conname::text, pg_get_constraintdef(oid), obj_description(oid, 'pg_constraint')
         FROM pg_constraint
         WHERE conrelid = 'public.products'::regclass AND contype = 'c' ORDER BY conname",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

fn applied(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::Applied { .. })
}

fn up_to_date(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::UpToDate { .. })
}

#[tokio::test]
async fn checks_are_recorded_on_creation_and_left_alone_on_a_second_push() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(Some(10), Some(price_at_least(0)));
        assert!(applied(&push(&pool, &ast).await.unwrap()));

        let rows = check_rows(&pool).await;
        let names: Vec<&str> = rows.iter().map(|r| r.key.name.as_str()).collect();
        assert_eq!(
            names,
            ["products_check_1", "products_name_bounds"],
            "the inline bound and the model rule are both recorded"
        );
        assert!(rows.iter().all(|r| r.status == Status::Managed));
        assert!(rows.iter().all(|r| r.migration_id.is_some()));
        assert!(rows
            .iter()
            .all(|r| r.desired_sql.contains("ADD CONSTRAINT")));
        assert!(rows.iter().all(|r| r.live_def.starts_with("expression=")));
        // Checks carry no stamp any more: the comment is the user's.
        assert!(live_checks(&pool).await.iter().all(|(_, _, c)| c.is_none()));

        let again = push(&pool, &ast).await.unwrap();
        assert!(up_to_date(&again), "{again:?}");
        assert_eq!(
            check_rows(&pool).await,
            rows,
            "an up-to-date push changes no row"
        );
    })
    .await;
}

#[tokio::test]
async fn a_changed_bound_is_replaced_and_the_database_enforces_the_new_one() {
    common::with_integration_pool(|pool| async move {
        assert!(applied(
            &push(&pool, &schema(Some(10), None)).await.unwrap()
        ));
        exec(&pool, "INSERT INTO public.products VALUES (1, 'short', 5)")
            .await
            .unwrap();
        let before = check_rows(&pool).await;

        // The row breaches the tightened bound, so the push refuses rather than skips it, and
        // nothing changes: not the constraint, not the ledger.
        let refused = push(&pool, &schema(Some(3), None))
            .await
            .expect_err("tightening a bound past existing data fails the push");
        assert!(
            format!("{refused:#}").contains("products_name_bounds"),
            "{refused:#}"
        );
        assert_eq!(check_rows(&pool).await, before);
        assert!(live_checks(&pool).await[0].1.contains("<= 10"));

        exec(&pool, "DELETE FROM public.products WHERE true")
            .await
            .unwrap();
        assert!(applied(&push(&pool, &schema(Some(3), None)).await.unwrap()));
        assert!(live_checks(&pool).await[0].1.contains("<= 3"));
        exec(
            &pool,
            "INSERT INTO public.products VALUES (2, 'long name', 5)",
        )
        .await
        .expect_err("the tightened bound is enforced");
        exec(&pool, "INSERT INTO public.products VALUES (3, 'ok', 5)")
            .await
            .unwrap();

        let after = check_rows(&pool).await;
        assert_eq!(after.len(), 1);
        assert_ne!(
            after[0].desired_fp, before[0].desired_fp,
            "the intent changed"
        );
        assert_ne!(
            after[0].live_fp, before[0].live_fp,
            "and so did the catalog"
        );
        assert!(up_to_date(
            &push(&pool, &schema(Some(3), None)).await.unwrap()
        ));
    })
    .await;
}

#[tokio::test]
async fn a_rule_added_to_an_existing_table_is_created_and_one_removed_is_dropped() {
    common::with_integration_pool(|pool| async move {
        assert!(applied(&push(&pool, &schema(None, None)).await.unwrap()));
        assert!(check_rows(&pool).await.is_empty());

        // A model rule on a table that already exists: no inline statement creates it, so the
        // reconcile does.
        let outcome = push(&pool, &schema(None, Some(price_at_least(0))))
            .await
            .unwrap();
        assert!(applied(&outcome), "{outcome:?}");
        assert_eq!(
            check_rows(&pool)
                .await
                .iter()
                .map(|r| r.key.name.as_str())
                .collect::<Vec<_>>(),
            ["products_check_1"]
        );
        exec(&pool, "INSERT INTO public.products VALUES (1, 'a', -1)")
            .await
            .expect_err("the new rule is enforced");

        // The schema stops asking: the owned constraint goes, and so does its row.
        assert!(applied(&push(&pool, &schema(None, None)).await.unwrap()));
        assert!(check_rows(&pool).await.is_empty());
        assert!(live_checks(&pool).await.is_empty());
        exec(&pool, "INSERT INTO public.products VALUES (1, 'a', -1)")
            .await
            .expect("without the rule a negative price is accepted");
    })
    .await;
}

#[tokio::test]
async fn an_owned_check_dropped_by_hand_is_recreated() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(Some(10), None);
        assert!(applied(&push(&pool, &ast).await.unwrap()));
        exec(
            &pool,
            "ALTER TABLE public.products DROP CONSTRAINT products_name_bounds",
        )
        .await
        .unwrap();
        assert!(live_checks(&pool).await.is_empty());

        let outcome = push(&pool, &ast).await.unwrap();
        assert!(
            applied(&outcome),
            "a missing owned object is a change: {outcome:?}"
        );
        assert_eq!(live_checks(&pool).await.len(), 1);
        exec(
            &pool,
            "INSERT INTO public.products VALUES (1, 'far too long', 1)",
        )
        .await
        .expect_err("the recreated bound is enforced");
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
    })
    .await;
}

#[tokio::test]
async fn a_check_the_user_added_is_never_ours() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(None, None);
        assert!(applied(&push(&pool, &ast).await.unwrap()));
        exec(
            &pool,
            "ALTER TABLE public.products ADD CONSTRAINT products_price_positive CHECK (price > 0)",
        )
        .await
        .unwrap();

        // Pushed twice: once with nothing else to do, once with a change elsewhere, and the
        // user's constraint survives both with no ledger row.
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
        assert!(applied(
            &push(&pool, &schema(Some(10), None)).await.unwrap()
        ));
        let live = live_checks(&pool).await;
        assert!(
            live.iter().any(|(n, _, _)| n == "products_price_positive"),
            "{live:?}"
        );
        assert!(check_rows(&pool)
            .await
            .iter()
            .all(|r| r.key.name != "products_price_positive"));
    })
    .await;
}

#[tokio::test]
async fn a_check_stamped_by_an_older_engine_moves_into_the_ledger_and_out_of_its_comment() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(Some(10), None);
        assert!(applied(&push(&pool, &ast).await.unwrap()));
        // What a pre-ledger engine left behind: a stamped constraint and no ledger row. A user
        // line beside the stamp must survive the move.
        common::as_an_older_engine_left_it(&pool).await.unwrap();
        exec(
            &pool,
            "COMMENT ON CONSTRAINT products_name_bounds ON public.products IS
               E'supatype:managed;kind=check;table=products;fields=name;v=1\\nkeep this line';",
        )
        .await
        .unwrap();

        let outcome = push(&pool, &ast).await.unwrap();
        assert!(applied(&outcome), "{outcome:?}");
        let rows = check_rows(&pool).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].status,
            Status::Managed,
            "stamped means ours by record"
        );
        assert_eq!(
            live_checks(&pool).await[0].2.as_deref(),
            Some("keep this line"),
            "the stamp is gone and the user's line stays"
        );
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
    })
    .await;
}

#[tokio::test]
async fn a_same_named_check_is_adopted_when_the_database_deparses_it_to_ours_and_refused_otherwise()
{
    common::with_integration_pool(|pool| async move {
        let ast = schema(Some(10), None);
        // The table as a hand-written migration might have left it: our name, no stamp, no row.
        exec(
            &pool,
            "CREATE TABLE public.products (
               id integer PRIMARY KEY, name text NOT NULL, price integer NOT NULL,
               CONSTRAINT products_name_bounds CHECK (char_length(name) <= 10));
             COMMENT ON TABLE public.products IS 'supatype:managed;kind=table;table=products;fields=;v=1';",
        )
        .await
        .unwrap();

        let outcome = push(&pool, &ast).await.unwrap();
        assert!(applied(&outcome), "{outcome:?}");
        let rows = check_rows(&pool).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].status,
            Status::Adopted,
            "the database deparses the user's check to ours, so it is adopted, not duplicated"
        );
        assert_eq!(live_checks(&pool).await.len(), 1);
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));

        // The same name meaning something else is refused, by name, before anything is written.
        // Only the check's row goes: the table is the ledger's since the first push took it over by
        // its stamp and removed the stamp (Phase 4.11, section 6).
        exec(
            &pool,
            "DELETE FROM _supatype.managed_objects WHERE kind = 'check';
             ALTER TABLE public.products DROP CONSTRAINT products_name_bounds;
             ALTER TABLE public.products ADD CONSTRAINT products_name_bounds CHECK (char_length(name) <= 99);",
        )
        .await
        .unwrap();
        let refused = push(&pool, &ast)
            .await
            .expect_err("a different check under our name is not ours to replace");
        let message = format!("{refused:#}");
        assert!(message.contains("products_name_bounds"), "{message}");
        assert!(message.contains("supatype adopt"), "{message}");
        assert!(live_checks(&pool).await[0].1.contains("<= 99"), "nothing was changed");
        assert!(check_rows(&pool).await.is_empty());
    })
    .await;
}

#[tokio::test]
async fn an_owned_check_edited_by_hand_is_drift_and_is_put_back() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(Some(10), None);
        assert!(applied(&push(&pool, &ast).await.unwrap()));
        exec(
            &pool,
            "ALTER TABLE public.products DROP CONSTRAINT products_name_bounds;
             ALTER TABLE public.products ADD CONSTRAINT products_name_bounds CHECK (char_length(name) <= 99);",
        )
        .await
        .unwrap();

        // The diff shows it as drift: the recorded definition against the live one.
        let plan = push::plan(&pool, &ast, "public").await.unwrap();
        let drift: Vec<_> = plan
            .reconcile
            .actions
            .iter()
            .filter(|a| matches!(a, supatype_engine::ledger::reconcile::Action::Drift { .. }))
            .collect();
        assert_eq!(drift.len(), 1, "{:?}", plan.reconcile.actions);

        // And the push puts the declared bound back (O1: shown, then updated).
        let outcome = push(&pool, &ast).await.unwrap();
        assert!(applied(&outcome), "{outcome:?}");
        assert!(live_checks(&pool).await[0].1.contains("<= 10"));
        exec(&pool, "INSERT INTO public.products VALUES (1, 'far too long a name', 1)")
            .await
            .expect_err("the declared bound is enforced again");
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
    })
    .await;
}

/// Doctor and push decide the same way (one planner): a same-named check the database deparses to
/// ours is one a push adopts, so doctor must not call it a conflict.
#[tokio::test]
async fn doctor_agrees_with_push_about_a_check_the_database_proves_ours() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(Some(10), None);
        exec(
            &pool,
            "CREATE TABLE public.products (
               id integer PRIMARY KEY, name text NOT NULL, price integer NOT NULL,
               CONSTRAINT products_name_bounds CHECK (char_length(name) <= 10));
             COMMENT ON TABLE public.products IS 'supatype:managed;kind=table;table=products;fields=;v=1';",
        )
        .await
        .unwrap();

        let report = supatype_engine::inspect::doctor(&pool, &ast, "public", false)
            .await
            .unwrap();
        assert!(
            !report.conflicting.iter().any(|i| i.name == "products_name_bounds"),
            "doctor calls a check a push would adopt a conflict: {:#?}",
            report.conflicting
        );
    })
    .await;
}

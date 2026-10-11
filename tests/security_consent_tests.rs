//! Access a push would take over, drop or overwrite without a person's consent (F15, F16, F10).
//!
//! Each test is one reproduction from the pre-launch verification (A1, A2 and A3): a same-named
//! object the user made (E22), a label the user set (E23), a hand edit on an object the schema
//! drops (E24), a grant to `PUBLIC` (E25), a junction table's privileges (E27), an affordance
//! function edited by hand (E31, A2-N3), a grant option or a second grantor (E16), and the first
//! push after an upgrade that cannot compare what an older engine made (E09, E29, E11).

mod common;

use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{
    adopt,
    differ::doctor::{DoctorItem, DoctorReport},
    ledger::drift::SecurityDrift,
    parser,
    parser::ast::SchemaAst,
    push::ApplyOptions,
};

use common::{exec, push, push_with};

fn column(kind: &str, pg_type: &str, required: bool) -> Value {
    json!({ "kind": kind, "required": required,
            "annotations": { "db": { "pgType": pg_type, "unique": false } } })
}

fn model(name: &str, table: &str, access: Value) -> Value {
    let mut id = column("integer", "INTEGER", true);
    id["primaryKey"] = json!(true);
    json!({
        "name": name,
        "fields": {
            "id": id,
            "title": column("text", "TEXT", true),
            "author_id": column("uuid", "UUID", false)
        },
        "options": { "timestamps": false, "softDelete": false, "singleton": false },
        "annotations": { "db": { "tableName": table, "indexes": [] },
                         "platform": { "access": access } }
    })
}

fn schema(models: Vec<Value>) -> SchemaAst {
    let doc = json!({ "astVersion": 2, "models": models });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

fn public() -> Value {
    json!({ "type": "public" })
}

/// `author_id` is the caller: what reads the claims through the engine's readers.
fn owner() -> Value {
    json!({ "type": "compare",
            "left": { "kind": "column", "name": "author_id" },
            "op": "eq",
            "right": { "kind": "authUid" } })
}

fn posts(access: Value) -> SchemaAst {
    schema(vec![model("Post", "posts", access)])
}

fn names(items: &[DoctorItem]) -> Vec<String> {
    items
        .iter()
        .map(|i| format!("{} {}.{}", i.kind, i.table, i.name))
        .collect()
}

fn has(items: &[DoctorItem], name: &str) -> bool {
    names(items).iter().any(|n| n == name)
}

async fn doctor(pool: &PgPool, ast: &SchemaAst) -> DoctorReport {
    common::doctor(pool, ast).await
}

fn consented() -> ApplyOptions {
    ApplyOptions {
        overwrite_drift: true,
        ..Default::default()
    }
}

/// The keys of the objects a refused push named as changed outside Supatype.
fn refused_for(result: anyhow::Result<supatype_engine::push::Outcome>) -> Vec<String> {
    let e = result.expect_err("applied without consent");
    let drift = e
        .downcast_ref::<SecurityDrift>()
        .unwrap_or_else(|| panic!("refused for another reason: {e:#}"));
    drift.objects.iter().map(|o| o.key.to_string()).collect()
}

async fn using_of(pool: &PgPool, table: &str, policy: &str) -> Option<String> {
    sqlx::query_scalar(
        "SELECT pg_get_expr(polqual, polrelid) FROM pg_policy
         WHERE polrelid = to_regclass($1) AND polname = $2",
    )
    .bind(format!("public.{table}"))
    .bind(policy)
    .fetch_optional(pool)
    .await
    .unwrap()
}

async fn privilege(pool: &PgPool, role: &str, table: &str, privilege: &str) -> bool {
    sqlx::query_scalar("SELECT has_table_privilege($1, $2, $3)")
        .bind(role)
        .bind(format!("public.{table}"))
        .bind(privilege)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn adopt_keys(pool: &PgPool, ast: &SchemaAst, keys: &[&str]) {
    let keys: Vec<String> = keys.iter().map(|k| k.to_string()).collect();
    adopt::run(
        pool,
        ast,
        "public",
        adopt::Request {
            apply: true,
            keys: Some(&keys),
            ..Default::default()
        },
    )
    .await
    .expect("adopt");
}

/// What an older engine leaves of access: its policies, grants, RLS and functions with no row.
const FORGET_THE_ACCESS_ROWS: &str = "DELETE FROM _supatype.managed_objects
    WHERE kind IN ('policy', 'table_grant', 'rls_attributes', 'function', 'security_label')";

/// F15 (a), E22: a policy the user wrote under the name the schema's policy takes is compared, and
/// one that differs is a conflict `adopt` resolves, never replaced without a word.
#[tokio::test]
async fn a_users_policy_under_a_name_the_schema_needs_is_a_conflict() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!({ "read": public() }));
        exec(
            &pool,
            "CREATE TABLE public.posts (id integer PRIMARY KEY, title text NOT NULL, author_id uuid);
             ALTER TABLE public.posts ENABLE ROW LEVEL SECURITY;
             CREATE POLICY posts_select ON public.posts FOR SELECT USING (title = 'only-this');",
        )
        .await
        .unwrap();
        // The table is handed over, and nothing else, as `supatype adopt` first offers.
        adopt_keys(&pool, &ast, &["table:posts"]).await;

        let report = doctor(&pool, &ast).await;
        assert!(
            has(&report.conflicting, "policy posts.posts_select"),
            "{report:#?}"
        );
        assert!(!has(&report.claimed, "policy posts.posts_select"));
        let refused = push(&pool, &ast).await.expect_err("replaced the user's policy");
        assert!(
            format!("{refused:#}").contains("policy public.posts.posts_select"),
            "{refused:#}"
        );
        assert_eq!(
            using_of(&pool, "posts", "posts_select").await.as_deref(),
            Some("(title = 'only-this'::text)")
        );

        // Handed over with consent, the next push brings it to the schema.
        adopt_keys(&pool, &ast, &["policy:posts.posts_select"]).await;
        push(&pool, &ast).await.expect("adopted, then replaced");
        assert_eq!(
            using_of(&pool, "posts", "posts_select").await.as_deref(),
            Some("true")
        );
    })
    .await;
}

/// F15 (a), E22 on a database already pushed: a table made by hand later, then modelled and
/// adopted, keeps its own policy until that is adopted too.
#[tokio::test]
async fn a_users_policy_on_a_table_modelled_later_is_a_conflict() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts(json!({ "read": public() })))
            .await
            .unwrap();
        exec(
            &pool,
            "CREATE TABLE public.gadgets (id integer PRIMARY KEY, title text NOT NULL, author_id uuid);
             ALTER TABLE public.gadgets ENABLE ROW LEVEL SECURITY;
             CREATE POLICY gadgets_select ON public.gadgets FOR SELECT USING (title = 'only-this');",
        )
        .await
        .unwrap();
        let both = schema(vec![
            model("Post", "posts", json!({ "read": public() })),
            model("Gadget", "gadgets", json!({ "read": public() })),
        ]);
        adopt_keys(&pool, &both, &["table:gadgets"]).await;

        let report = doctor(&pool, &both).await;
        assert!(
            has(&report.conflicting, "policy gadgets.gadgets_select"),
            "{report:#?}"
        );
        assert!(push(&pool, &both).await.is_err(), "replaced the user's policy");
        assert_eq!(
            using_of(&pool, "gadgets", "gadgets_select").await.as_deref(),
            Some("(title = 'only-this'::text)")
        );
    })
    .await;
}

/// F15 (b), E23: a label someone set under the masking provider, with no row, is theirs: on a table
/// Supatype does not manage and on a model column no field rule names, a push leaves it.
#[tokio::test]
async fn a_label_set_by_hand_is_left_alone() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            return;
        }
        let ast = posts(json!({ "read": public() }));
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            r#"CREATE TABLE public.payroll (id int PRIMARY KEY, salary int);
               CREATE FUNCTION public.mine_can_read_salary(r public.payroll) RETURNS boolean
                 LANGUAGE sql STABLE AS $$ SELECT false $$;
               CREATE FUNCTION public.mine_can_read_title(r public.posts) RETURNS boolean
                 LANGUAGE sql STABLE AS $$ SELECT false $$;
               SECURITY LABEL FOR supatype ON COLUMN public.payroll.salary
                 IS 'MASK READ public."mine_can_read_salary"';
               SECURITY LABEL FOR supatype ON COLUMN public.posts.title
                 IS 'MASK READ public."mine_can_read_title"';"#,
        )
        .await
        .unwrap();

        let report = doctor(&pool, &ast).await;
        assert!(
            !report
                .stale_managed
                .iter()
                .any(|i| i.kind == "security_label"),
            "{report:#?}"
        );
        push(&pool, &ast).await.unwrap();
        let labels: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_seclabel WHERE provider = 'supatype' AND objsubid > 0
               AND objoid IN ('public.payroll'::regclass, 'public.posts'::regclass)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(labels, 2, "a push took a label someone set off");
    })
    .await;
}

/// F15 (c), E24: dropping an access rule edited by hand needs the consent putting it back does, as
/// a rule removed from the schema and as a model removed with its table.
#[tokio::test]
async fn dropping_a_policy_edited_by_hand_needs_consent() {
    common::with_integration_pool(|pool| async move {
        let editable = posts(json!({ "read": public(), "update": public() }));
        push(&pool, &editable).await.unwrap();
        exec(
            &pool,
            "ALTER POLICY posts_update ON public.posts USING (title = 'hand-edited')",
        )
        .await
        .unwrap();
        let read_only = posts(json!({ "read": public() }));
        assert_eq!(
            refused_for(push(&pool, &read_only).await),
            ["policy public.posts.posts_update"]
        );
        assert!(using_of(&pool, "posts", "posts_update").await.is_some());
        push_with(&pool, &read_only, consented()).await.unwrap();
        assert!(using_of(&pool, "posts", "posts_update").await.is_none());

        let both = schema(vec![
            model("Post", "posts", json!({ "read": public() })),
            model("Gadget", "gadgets", json!({ "read": public() })),
        ]);
        push(&pool, &both).await.unwrap();
        exec(
            &pool,
            "ALTER POLICY gadgets_select ON public.gadgets USING (title = 'hand-edited')",
        )
        .await
        .unwrap();
        let forced = ApplyOptions {
            force: true,
            ..Default::default()
        };
        assert_eq!(
            refused_for(push_with(&pool, &read_only, forced).await),
            ["policy public.gadgets.gadgets_select"]
        );
        let forced_with_consent = ApplyOptions {
            force: true,
            overwrite_drift: true,
            ..Default::default()
        };
        push_with(&pool, &read_only, forced_with_consent)
            .await
            .unwrap();
    })
    .await;
}

/// F15 (d), E25: a grant to `PUBLIC` on a model table is read, reported and put back only with
/// consent.
#[tokio::test]
async fn a_grant_to_public_is_reported_and_needs_consent() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!({ "read": public() }));
        push(&pool, &ast).await.unwrap();
        exec(&pool, "GRANT ALL ON public.posts TO PUBLIC")
            .await
            .unwrap();
        assert!(privilege(&pool, "anon", "posts", "INSERT").await);

        let report = doctor(&pool, &ast).await;
        assert!(
            has(&report.drifted, "table_grant posts.PUBLIC"),
            "{report:#?}"
        );
        assert!(report.blocking);
        assert_eq!(
            refused_for(push(&pool, &ast).await),
            ["table_grant public.posts.PUBLIC"]
        );
        push_with(&pool, &ast, consented()).await.unwrap();
        assert!(!privilege(&pool, "anon", "posts", "INSERT").await);
        assert!(!privilege(&pool, "anon", "posts", "TRUNCATE").await);
    })
    .await;
}

/// F15 (e), E27: a junction table holds what the intersection of its parents' rules allows, and
/// nothing the database's default privileges handed out.
#[tokio::test]
async fn a_junction_table_holds_exactly_what_its_rules_allow() {
    common::with_integration_pool(|pool| async move {
        let mut student = model("Student", "students", json!({ "read": public() }));
        student["fields"]["courses"] = json!({ "kind": "relation", "cardinality": "manyToMany",
                                               "target": "Course", "through": "enrollments" });
        let ast = schema(vec![
            student,
            model("Course", "courses", json!({ "read": public() })),
        ]);
        assert_eq!(ast.junction_tables.len(), 1, "{:?}", ast.junction_tables);
        // As the supatype image's project database is provisioned.
        exec(
            &pool,
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated",
        )
        .await
        .unwrap();
        push(&pool, &ast).await.unwrap();

        for role in ["anon", "authenticated"] {
            assert!(
                privilege(&pool, role, "enrollments", "SELECT").await,
                "{role}"
            );
            for denied in [
                "INSERT",
                "UPDATE",
                "DELETE",
                "TRUNCATE",
                "REFERENCES",
                "TRIGGER",
            ] {
                assert!(
                    !privilege(&pool, role, "enrollments", denied).await,
                    "{role} holds {denied} on the junction table"
                );
            }
        }
        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM _supatype.managed_objects
              WHERE kind = 'table_grant' AND parent = 'enrollments'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            rows >= 2,
            "the junction table's grants are not on the ledger"
        );
        let report = doctor(&pool, &ast).await;
        assert!(!report.blocking, "{report:#?}");
    })
    .await;
}

const CAN_READ_POSTS_FALSE: &str =
    "CREATE OR REPLACE FUNCTION public.can_read_posts(posts public.posts)
     RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT false $$";

/// F15 (f), E31: an affordance function decides access as its policy does, so a hand edit to it
/// is put back only with consent.
#[tokio::test]
async fn an_affordance_function_edited_by_hand_needs_consent() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!({ "read": public() }));
        push(&pool, &ast).await.unwrap();
        exec(&pool, CAN_READ_POSTS_FALSE).await.unwrap();

        let report = doctor(&pool, &ast).await;
        let item = report
            .drifted
            .iter()
            .find(|i| i.kind == "function" && i.name.starts_with("can_read_posts"))
            .unwrap_or_else(|| panic!("{report:#?}"));
        assert!(item.message.contains("after asking"), "{item:?}");
        let refused = refused_for(push(&pool, &ast).await);
        assert!(
            refused.iter().any(|k| k.contains("can_read_posts")),
            "{refused:?}"
        );
        push_with(&pool, &ast, consented()).await.unwrap();
    })
    .await;
}

/// F15 (f), A2-N3: the same edit made under an older engine, which recorded nothing, is compared
/// with what the last push's schema makes and refused the same way.
#[tokio::test]
async fn an_affordance_function_edited_under_an_older_engine_needs_consent() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!({ "read": public() }));
        push(&pool, &ast).await.unwrap();
        exec(&pool, FORGET_THE_ACCESS_ROWS).await.unwrap();
        exec(&pool, CAN_READ_POSTS_FALSE).await.unwrap();

        let refused = refused_for(push(&pool, &ast).await);
        assert!(
            refused.iter().any(|k| k.contains("can_read_posts")),
            "{refused:?}"
        );
    })
    .await;
}

/// F15 (g), E16: holding a privilege with the grant option, or from a second grantor, is a change
/// to what a role may do.
#[tokio::test]
async fn a_grant_option_or_a_second_grantor_is_drift() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!({ "read": public() }));
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            "GRANT SELECT ON public.posts TO anon WITH GRANT OPTION",
        )
        .await
        .unwrap();
        let report = doctor(&pool, &ast).await;
        assert!(
            has(&report.drifted, "table_grant posts.anon"),
            "{report:#?}"
        );
        push_with(&pool, &ast, consented()).await.unwrap();
        assert!(doctor(&pool, &ast).await.drifted.is_empty());

        // `anon` hands its SELECT on: `authenticated` now holds it from a second grantor too.
        exec(
            &pool,
            "GRANT SELECT ON public.posts TO anon WITH GRANT OPTION;
             SET ROLE anon; GRANT SELECT ON public.posts TO authenticated; RESET ROLE;",
        )
        .await
        .unwrap();
        let report = doctor(&pool, &ast).await;
        assert!(
            has(&report.drifted, "table_grant posts.authenticated"),
            "{report:#?}"
        );
    })
    .await;
}

/// Holds ACCESS SHARE on `public.posts` from another session, as an application's read does,
/// until the returned sender is dropped or fired.
async fn reading_posts(pool: &PgPool) -> tokio::sync::oneshot::Sender<()> {
    let (done, wait) = tokio::sync::oneshot::channel::<()>();
    let (held, started) = tokio::sync::oneshot::channel::<()>();
    let mut conn = pool.acquire().await.unwrap().detach();
    tokio::spawn(async move {
        use sqlx::Connection;
        let mut tx = conn.begin().await.unwrap();
        sqlx::query("SELECT count(*) FROM public.posts")
            .execute(&mut *tx)
            .await
            .unwrap();
        let _ = held.send(());
        let _ = tokio::time::timeout(Duration::from_secs(30), wait).await;
        let _ = tx.commit().await;
    });
    started.await.unwrap();
    done
}

/// Every lock stronger than a reader's that anyone holds or waits for on a permanent relation of
/// this database.
async fn strong_locks(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT c.relname::text || ' ' || l.mode FROM pg_locks l
           JOIN pg_class c ON c.oid = l.relation
          WHERE l.database = (SELECT oid FROM pg_database WHERE datname = current_database())
            AND c.relpersistence = 'p'
            AND l.mode IN ('AccessExclusiveLock', 'ExclusiveLock', 'ShareRowExclusiveLock')",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// F16, E09: doctor on a database an older engine left reads it; it never takes a lock that would
/// stop an application, and an application's read does not stop it.
#[tokio::test]
async fn doctor_after_an_upgrade_takes_no_lock_an_application_waits_on() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!({ "read": public(), "update": owner() }));
        push(&pool, &ast).await.unwrap();
        exec(&pool, FORGET_THE_ACCESS_ROWS).await.unwrap();
        let reader = reading_posts(&pool).await;

        let started = Instant::now();
        let doctor_run = tokio::spawn({
            let (pool, ast) = (pool.clone(), ast.clone());
            async move { doctor(&pool, &ast).await }
        });
        let mut seen = Vec::new();
        while !doctor_run.is_finished() {
            seen.extend(strong_locks(&pool).await);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let report = doctor_run.await.unwrap();
        drop(reader);
        assert!(seen.is_empty(), "doctor took or waited on {seen:?}");
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "doctor waited on an application's read: {:?}",
            started.elapsed()
        );
        assert!(report.drifted.is_empty(), "{report:#?}");
        assert!(
            has(&report.claimed, "policy posts.posts_select"),
            "{report:#?}"
        );
    })
    .await;
}

/// F16, E29: an older engine's policy edited by hand is found while an application reads the
/// table, rather than replaced unchecked.
#[tokio::test]
async fn an_upgrade_finds_a_hand_edit_while_the_table_is_in_use() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!({ "read": public() }));
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            &format!(
                "{FORGET_THE_ACCESS_ROWS};
                 ALTER POLICY posts_select ON public.posts USING (false);"
            ),
        )
        .await
        .unwrap();
        let reader = reading_posts(&pool).await;
        let pushed = tokio::time::timeout(Duration::from_secs(20), push(&pool, &ast)).await;
        drop(reader);
        let pushed = pushed.expect("the push waited on the application's read");
        assert_eq!(refused_for(pushed), ["policy public.posts.posts_select"]);
        assert_eq!(
            using_of(&pool, "posts", "posts_select").await.as_deref(),
            Some("false")
        );
    })
    .await;
}

/// F16, E29: with the last push's schema gone there is nothing to compare an older engine's
/// objects with, so each counts as changed: a push asks, and doctor says which were not checked.
#[tokio::test]
async fn an_upgrade_with_no_snapshot_fails_closed() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!({ "read": public() }));
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            &format!(
                "{FORGET_THE_ACCESS_ROWS};
                 ALTER POLICY posts_select ON public.posts USING (false);
                 UPDATE _supatype.migrations SET schema_snapshot = NULL WHERE true;
                 UPDATE _supatype.schema_state SET ast_snapshot = NULL WHERE true;"
            ),
        )
        .await
        .unwrap();

        let report = doctor(&pool, &ast).await;
        let item = report
            .drifted
            .iter()
            .find(|i| i.name == "posts_select")
            .unwrap_or_else(|| panic!("{report:#?}"));
        assert!(item.message.contains("not checked"), "{item:?}");
        assert!(report.blocking);
        let refused = refused_for(push(&pool, &ast).await);
        assert!(
            refused.contains(&"policy public.posts.posts_select".to_string()),
            "{refused:?}"
        );
        assert_eq!(
            using_of(&pool, "posts", "posts_select").await.as_deref(),
            Some("false")
        );
        push_with(&pool, &ast, consented()).await.unwrap();
        assert_eq!(
            using_of(&pool, "posts", "posts_select").await.as_deref(),
            Some("true")
        );
    })
    .await;
}

/// F10, E11: a snapshot that cannot be read is not "no earlier schema": the push says it could
/// not read it, and fails closed as with none.
#[tokio::test]
async fn an_unreadable_snapshot_is_said_and_fails_closed() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!({ "read": public() }));
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            &format!(
                r#"{FORGET_THE_ACCESS_ROWS};
                   ALTER TABLE public.posts DISABLE ROW LEVEL SECURITY;
                   UPDATE _supatype.migrations
                      SET schema_snapshot = jsonb_set(schema_snapshot, '{{models,0,fields}}', '"not-an-object"')
                    WHERE schema_snapshot IS NOT NULL;
                   UPDATE _supatype.schema_state SET ast_snapshot = NULL WHERE true;"#
            ),
        )
        .await
        .unwrap();

        let report = doctor(&pool, &ast).await;
        let item = report
            .drifted
            .iter()
            .find(|i| i.kind == "rls_attributes")
            .unwrap_or_else(|| panic!("{report:#?}"));
        assert!(
            item.message
                .contains("the last push's schema could not be read"),
            "{item:?}"
        );
        let refused = refused_for(push(&pool, &ast).await);
        assert!(
            refused.contains(&"rls_attributes public.posts.rls".to_string()),
            "{refused:?}"
        );
        let enabled: bool = sqlx::query_scalar(
            "SELECT relrowsecurity FROM pg_class WHERE oid = 'public.posts'::regclass",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!enabled, "the hand edit was put back without consent");
    })
    .await;
}

/// An older engine's rules read the claims through `auth.uid()` and `auth.role()`, where this
/// engine reads them through its own readers: that is the engine's change, not a hand edit, so a
/// clean upgrade asks nothing.
#[tokio::test]
async fn an_older_engines_rules_reading_the_claims_through_auth_are_not_hand_edits() {
    common::with_integration_pool(|pool| async move {
        let ast = posts(json!({ "read": owner() }));
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            &format!(
                "{FORGET_THE_ACCESS_ROWS};
                 ALTER POLICY posts_select ON public.posts
                   USING (author_id = (SELECT auth.uid()));
                 CREATE OR REPLACE FUNCTION public.can_read_posts(posts public.posts)
                   RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT \"author_id\" = (SELECT auth.uid())
      FROM (SELECT ($1).*) AS \"posts\";
  $can$;"
            ),
        )
        .await
        .unwrap();

        let report = doctor(&pool, &ast).await;
        assert!(report.drifted.is_empty(), "{report:#?}");
        assert!(
            has(&report.claimed, "policy posts.posts_select"),
            "{report:#?}"
        );
        push(&pool, &ast)
            .await
            .expect("a clean upgrade asks nothing");
        let using = using_of(&pool, "posts", "posts_select").await.unwrap();
        assert!(using.contains("jwt_uid"), "{using}");
    })
    .await;
}

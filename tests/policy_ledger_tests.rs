//! Phase 4.7b of the managed-object ownership plan: policies on the ledger.
//!
//! The policy differ compared our policy text with Postgres's deparse of it, through a normaliser
//! that had to learn every rewrite Postgres applies, and recognised its own policies by a comment
//! stamp. Each policy is a ledger object now: created by the reconcile, recorded, replaced when
//! its rule changes, put back when it is dropped by hand, and dropped when the schema stops asking.
//! A same-named policy with no row (an older engine's, stamped or not) is replaced, as the differ
//! rewrote it; a policy the developer wrote is never touched.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{
    introspector::fingerprint::ObjectKind,
    ledger::{self, reconcile::Action},
    parser,
    parser::ast::SchemaAst,
    push,
};

use common::{exec, push};

fn posts(access: Value) -> SchemaAst {
    let doc = json!({
        "astVersion": 2,
        "models": [{
            "name": "Post",
            "fields": {
                "id": { "kind": "integer", "primaryKey": true, "required": true,
                        "annotations": { "db": { "pgType": "INTEGER", "unique": false } } },
                "title": { "kind": "text", "required": true,
                           "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
            },
            "options": { "timestamps": false, "softDelete": false, "singleton": false },
            "annotations": { "db": { "tableName": "posts", "indexes": [] },
                             "platform": { "access": access } }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

fn public_read() -> SchemaAst {
    posts(json!({ "read": { "type": "public" } }))
}

async fn recorded(pool: &PgPool) -> Vec<String> {
    let mut conn = pool.acquire().await.unwrap();
    ledger::load(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.key.kind == ObjectKind::Policy && r.key.parent == "posts")
        .map(|r| r.key.name)
        .collect()
}

/// `USING` of the named policy on `public.posts`, as Postgres deparses it.
async fn using_of(pool: &PgPool, policy: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT pg_get_expr(polqual, polrelid) FROM pg_policy
          WHERE polrelid = 'public.posts'::regclass AND polname = $1",
    )
    .bind(policy)
    .fetch_optional(pool)
    .await
    .unwrap()
    .flatten()
}

fn up_to_date(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::UpToDate { .. })
}

fn policy_actions(plan: &push::Plan<'_>) -> Vec<Action> {
    plan.reconcile
        .actions
        .iter()
        .filter(|a| a.key().kind == ObjectKind::Policy && a.key().parent == "posts")
        .cloned()
        .collect()
}

#[tokio::test]
async fn a_policy_is_recorded_replaced_when_its_rule_changes_and_dropped_when_it_goes() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &public_read()).await.unwrap();
        assert_eq!(recorded(&pool).await, ["posts_select"]);
        assert_eq!(
            using_of(&pool, "posts_select").await.as_deref(),
            Some("true")
        );
        assert!(up_to_date(&push(&pool, &public_read()).await.unwrap()));

        let signed_in = posts(json!({ "read": { "type": "authenticated" } }));
        push(&pool, &signed_in).await.unwrap();
        let using = using_of(&pool, "posts_select").await.unwrap_or_default();
        assert!(using.contains("uid()"), "the old rule stayed: {using}");
        assert!(up_to_date(&push(&pool, &signed_in).await.unwrap()));

        push(&pool, &posts(json!({}))).await.unwrap();
        assert_eq!(using_of(&pool, "posts_select").await, None);
        assert!(recorded(&pool).await.is_empty());
    })
    .await;
}

#[tokio::test]
async fn a_policy_dropped_by_hand_is_put_back() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &public_read()).await.unwrap();
        exec(&pool, "DROP POLICY posts_select ON public.posts")
            .await
            .unwrap();

        let ast = public_read();
        let plan = push::prepare(&pool, &ast, "public").await.unwrap();
        let actions = policy_actions(&plan);
        assert!(
            matches!(actions[..], [Action::Recreate { .. }]),
            "{actions:?}"
        );
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap();
        assert_eq!(
            using_of(&pool, "posts_select").await.as_deref(),
            Some("true")
        );
    })
    .await;
}

#[tokio::test]
async fn a_hand_written_policy_on_a_model_table_is_never_ours() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &public_read()).await.unwrap();
        exec(
            &pool,
            "CREATE POLICY team_rule ON public.posts FOR SELECT USING (false)",
        )
        .await
        .unwrap();

        let ast = posts(json!({}));
        let plan = push::prepare(&pool, &ast, "public").await.unwrap();
        assert!(
            plan.diff
                .warnings
                .iter()
                .any(|w| w.contains("posts.team_rule")),
            "the hand-written policy is reported: {:?}",
            plan.diff.warnings
        );
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap();
        assert_eq!(using_of(&pool, "team_rule").await.as_deref(), Some("false"));
        assert!(recorded(&pool).await.is_empty());
    })
    .await;
}

/// What an older engine left: its policies stamped, one with a rule the schema has since
/// changed, and one for an operation the schema no longer declares, all with no rows. The first
/// is replaced, since the name says it is ours and its expression cannot be compared with our
/// text; the second is dropped, as the stamp says it is ours.
#[tokio::test]
async fn an_older_engines_policies_are_brought_up_to_date() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &public_read()).await.unwrap();
        exec(
            &pool,
            "DELETE FROM _supatype.managed_objects WHERE kind = 'policy';
             DROP POLICY posts_select ON public.posts;
             CREATE POLICY posts_select ON public.posts FOR SELECT USING (false);
             COMMENT ON POLICY posts_select ON public.posts
               IS 'supatype:managed;kind=rls_policy;table=posts;fields=select;v=1';
             CREATE POLICY posts_delete ON public.posts FOR DELETE USING (true);
             COMMENT ON POLICY posts_delete ON public.posts
               IS 'supatype:managed;kind=rls_policy;table=posts;fields=delete;v=1';",
        )
        .await
        .unwrap();

        let ast = public_read();
        let plan = push::prepare(&pool, &ast, "public").await.unwrap();
        let actions = policy_actions(&plan);
        let select = actions.iter().find(|a| a.key().name == "posts_select");
        assert!(
            matches!(select, Some(Action::Replace { .. })),
            "{actions:?}"
        );
        let delete = actions.iter().find(|a| a.key().name == "posts_delete");
        assert!(matches!(delete, Some(Action::Drop { .. })), "{actions:?}");

        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap();
        assert_eq!(
            using_of(&pool, "posts_select").await.as_deref(),
            Some("true")
        );
        assert_eq!(using_of(&pool, "posts_delete").await, None);
        assert_eq!(recorded(&pool).await, ["posts_select"]);
        assert!(up_to_date(&push(&pool, &public_read()).await.unwrap()));
    })
    .await;
}

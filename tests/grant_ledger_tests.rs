//! Phase 4.7c of the managed-object ownership plan: grants on the ledger (D7).
//!
//! Each API role's privileges on a model table are one ledger object: the exact set the rules
//! allow, table and column privileges together, applied as `REVOKE ALL` and then the grants. The
//! revoke-then-grant blocks re-asserted on every push touched only the four privileges the rules
//! govern, so the image's defaults (`TRUNCATE`, `REFERENCES`, `TRIGGER`, `MAINTAIN`) survived on
//! every model table. A grant to any other role is never the engine's.

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
                           "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
                "locked": { "kind": "text",
                            "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
            },
            "options": { "timestamps": false, "softDelete": false, "singleton": false },
            "annotations": { "db": { "tableName": "posts", "indexes": [] },
                             "platform": { "access": access } }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// Anyone reads; signed-in callers write.
fn readable() -> SchemaAst {
    posts(json!({
        "read": { "type": "public" },
        "create": { "type": "authenticated" },
        "update": { "type": "authenticated" }
    }))
}

/// The privileges `role` holds on `public.posts`, sorted, table-level only.
async fn held(pool: &PgPool, role: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT g.privilege_type::text
           FROM pg_class c, aclexplode(c.relacl) g
          WHERE c.oid = 'public.posts'::regclass AND g.grantee = $1::regrole
          ORDER BY 1",
    )
    .bind(role)
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The columns of `public.posts` on which `role` holds `privilege`, sorted.
async fn columns_with(pool: &PgPool, role: &str, privilege: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT a.attname::text
           FROM pg_attribute a, aclexplode(a.attacl) g
          WHERE a.attrelid = 'public.posts'::regclass AND a.attnum > 0
            AND g.grantee = $1::regrole AND g.privilege_type = $2
          ORDER BY 1",
    )
    .bind(role)
    .bind(privilege)
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn recorded(pool: &PgPool) -> Vec<String> {
    let mut conn = pool.acquire().await.unwrap();
    ledger::load(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.key.kind == ObjectKind::TableGrant && r.key.parent == "posts")
        .map(|r| r.key.name)
        .collect()
}

fn up_to_date(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::UpToDate { .. })
}

fn grant_actions(plan: &push::Plan<'_>) -> Vec<Action> {
    plan.reconcile
        .actions
        .iter()
        .filter(|a| a.key().kind == ObjectKind::TableGrant && a.key().parent == "posts")
        .cloned()
        .collect()
}

#[tokio::test]
async fn each_role_holds_exactly_what_the_rules_allow_and_nothing_else() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &readable()).await.unwrap();
        assert_eq!(held(&pool, "anon").await, ["SELECT"]);
        assert_eq!(
            held(&pool, "authenticated").await,
            ["INSERT", "SELECT", "UPDATE"]
        );
        assert_eq!(recorded(&pool).await, ["anon", "authenticated"]);
        assert!(up_to_date(&push(&pool, &readable()).await.unwrap()));

        // Nothing declared: both roles hold nothing, which is recorded and stays up to date.
        let closed = posts(json!({}));
        push(&pool, &closed).await.unwrap();
        assert!(held(&pool, "anon").await.is_empty());
        assert!(held(&pool, "authenticated").await.is_empty());
        assert_eq!(recorded(&pool).await, ["anon", "authenticated"]);
        let again = push(&pool, &closed).await.unwrap();
        assert!(up_to_date(&again), "{again:?}");
    })
    .await;
}

#[tokio::test]
async fn a_privilege_granted_by_hand_is_taken_back() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &readable()).await.unwrap();
        exec(&pool, "GRANT TRUNCATE ON public.posts TO anon")
            .await
            .unwrap();

        let ast = readable();
        let plan = push::prepare(&pool, &ast, "public").await.unwrap();
        let actions = grant_actions(&plan);
        assert!(
            matches!(
                actions.iter().find(|a| a.key().name == "anon"),
                Some(Action::Drift { .. })
            ),
            "{actions:?}"
        );
        common::apply_with_consent(&pool, plan, &ast).await;
        assert_eq!(held(&pool, "anon").await, ["SELECT"]);
    })
    .await;
}

#[tokio::test]
async fn a_grant_to_another_role_is_never_ours() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &readable()).await.unwrap();
        exec(
            &pool,
            "DO $$ BEGIN CREATE ROLE report_reader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
             GRANT SELECT ON public.posts TO report_reader;",
        )
        .await
        .unwrap();

        push(&pool, &posts(json!({}))).await.unwrap();
        assert_eq!(held(&pool, "report_reader").await, ["SELECT"]);
        assert_eq!(recorded(&pool).await, ["anon", "authenticated"]);
    })
    .await;
}

/// What an older engine left: the image's default privileges, minus what its four-privilege
/// block revoked, and no rows. The push takes the API roles' grants over and leaves them holding
/// the exact set; the rollback would restore what they held.
#[tokio::test]
async fn an_upgrade_takes_the_api_roles_grants_over() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &readable()).await.unwrap();
        exec(
            &pool,
            "DELETE FROM _supatype.managed_objects WHERE kind = 'table_grant';
             GRANT ALL ON public.posts TO anon;",
        )
        .await
        .unwrap();

        let ast = readable();
        let plan = push::prepare(&pool, &ast, "public").await.unwrap();
        let actions = grant_actions(&plan);
        let anon = actions.iter().find(|a| a.key().name == "anon").unwrap();
        assert!(matches!(anon, Action::Replace { .. }), "{actions:?}");
        assert!(
            anon.rollback_sql().iter().any(|s| s.contains("TRUNCATE")),
            "the rollback restores what anon held: {:?}",
            anon.rollback_sql()
        );
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap();
        assert_eq!(held(&pool, "anon").await, ["SELECT"]);
        assert!(up_to_date(&push(&pool, &readable()).await.unwrap()));
    })
    .await;
}

/// A column no caller may write narrows the write privilege to the other columns, in the same
/// object as the table privileges, since revoking the table privilege revokes the columns' too.
#[tokio::test]
async fn a_field_write_rule_narrows_the_write_privilege_to_columns() {
    common::with_integration_pool(|pool| async move {
        let narrowed = posts(json!({
            "read": { "type": "public" },
            "update": { "type": "authenticated" },
            "fields": { "locked": { "write": { "type": "private" } } }
        }));
        if !common::mask_extension_available(&pool).await {
            return;
        }
        push(&pool, &narrowed).await.unwrap();
        assert_eq!(held(&pool, "authenticated").await, ["SELECT"]);
        assert_eq!(
            columns_with(&pool, "authenticated", "UPDATE").await,
            ["id", "title"]
        );
        assert!(up_to_date(&push(&pool, &narrowed).await.unwrap()));

        // The rule goes: the table privilege comes back whole.
        push(&pool, &readable()).await.unwrap();
        assert_eq!(
            held(&pool, "authenticated").await,
            ["INSERT", "SELECT", "UPDATE"]
        );
        assert!(columns_with(&pool, "authenticated", "UPDATE")
            .await
            .is_empty());
    })
    .await;
}

/// A narrowed write privilege names the declared columns the role may write, so declaring a column
/// changes the grant and the push applies it again: the new column is writable like its siblings.
/// Dropping a column from the schema changes it the same way, so the column privilege going with
/// the column is the push's own change, not access changed outside Supatype.
#[tokio::test]
async fn a_narrowed_grant_follows_the_declared_columns() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            return;
        }
        let narrowed = |extra: bool| {
            let mut ast = posts(json!({
                "read": { "type": "public" },
                "update": { "type": "authenticated" },
                "fields": { "locked": { "write": { "type": "private" } } }
            }));
            if extra {
                let title = ast.models[0].fields["title"].clone();
                ast.models[0].fields.insert("summary".into(), title);
            }
            ast
        };
        push(&pool, &narrowed(false)).await.unwrap();
        assert_eq!(
            columns_with(&pool, "authenticated", "UPDATE").await,
            ["id", "title"]
        );

        push(&pool, &narrowed(true)).await.unwrap();
        assert_eq!(
            columns_with(&pool, "authenticated", "UPDATE").await,
            ["id", "summary", "title"],
            "the new column has no write privilege"
        );
        assert!(up_to_date(&push(&pool, &narrowed(true)).await.unwrap()));

        // Without consent to overwrite drift: the push's own column drop is not drift.
        common::push_with(
            &pool,
            &narrowed(false),
            push::ApplyOptions {
                force: true,
                ..Default::default()
            },
        )
        .await
        .expect("dropping a declared column is not access changed outside Supatype");
        assert_eq!(
            columns_with(&pool, "authenticated", "UPDATE").await,
            ["id", "title"]
        );
        assert!(up_to_date(&push(&pool, &narrowed(false)).await.unwrap()));
    })
    .await;
}

/// #63: a narrowed write grant names the declared columns, so a column someone adds outside the
/// schema gets no write privilege from it. Push and doctor say so and how to include it; once
/// `supatype adopt --key column:<table>.<column>` records it, the grant includes it and the warning stops.
#[tokio::test]
async fn a_column_added_outside_supatype_is_granted_once_adopted() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            return;
        }
        let ast = posts(json!({
            "read": { "type": "public" },
            "update": { "type": "authenticated" },
            "fields": { "locked": { "write": { "type": "private" } } }
        }));
        push(&pool, &ast).await.unwrap();
        exec(&pool, "ALTER TABLE public.posts ADD COLUMN extra TEXT")
            .await
            .unwrap();

        let flag = "column posts.extra was added outside Supatype and has no write grant for \
                    authenticated; run `supatype adopt --key column:posts.extra` to include it";
        let plan = push::plan(&pool, &ast, "public").await.unwrap();
        assert!(
            plan.diff.warnings.iter().any(|w| w == flag),
            "{:?}",
            plan.diff.warnings
        );
        let report = supatype_engine::inspect::doctor(&pool, &ast, "public", false)
            .await
            .unwrap();
        assert!(
            report
                .unmanaged_drift
                .iter()
                .any(|i| i.name == "extra" && i.message == flag),
            "{report:#?}"
        );
        // A warning, not a refusal.
        push(&pool, &ast).await.unwrap();
        assert_eq!(
            columns_with(&pool, "authenticated", "UPDATE").await,
            ["id", "title"]
        );

        let extra = ["column:posts.extra".to_string()];
        supatype_engine::adopt::run(
            &pool,
            &ast,
            "public",
            supatype_engine::adopt::Request {
                apply: true,
                keys: Some(&extra),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let plan = push::plan(&pool, &ast, "public").await.unwrap();
        assert!(
            !plan.diff.warnings.iter().any(|w| w.contains("posts.extra")),
            "{:?}",
            plan.diff.warnings
        );
        push(&pool, &ast).await.unwrap();
        assert_eq!(
            columns_with(&pool, "authenticated", "UPDATE").await,
            ["extra", "id", "title"]
        );
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
    })
    .await;
}

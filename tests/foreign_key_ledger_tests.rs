//! Phase 4.1 of the managed-object ownership plan: foreign keys on the ledger.
//!
//! The six live tests every kind gets (plan section 11): created and recorded; untouched on a
//! second push; replaced when the relation changes; recreated when dropped by hand; dropped when
//! the schema stops asking; never touched when it was never ours (D3: the gate the name-derived
//! differ did not have). Then what the ledger adds for this kind: a foreign key on a surviving
//! table that points at a table the push drops is dropped first, so the drop needs no `CASCADE`;
//! an existing foreign key that matches what we would create is adopted (an upgrade from the
//! engine that created it by name alone); one that differs refuses the push and names itself; and
//! rolling the push back restores the previous foreign key.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{
    introspector::fingerprint::ObjectKind,
    ledger::{self, LedgerRow, Status},
    parser,
    parser::ast::SchemaAst,
    push,
    state::migration_history,
};

fn int_pk() -> Value {
    json!({ "kind": "integer", "primaryKey": true, "required": true,
            "annotations": { "db": { "pgType": "INTEGER", "unique": false } } })
}

fn integer() -> Value {
    json!({ "kind": "integer", "required": false,
            "annotations": { "db": { "pgType": "INTEGER", "unique": false } } })
}

fn belongs_to(target: &str, column: &str) -> Value {
    json!({ "kind": "relation", "cardinality": "belongsTo", "target": target,
            "annotations": { "db": { "foreignKey": column } } })
}

fn model(name: &str, table: &str, fields: Value) -> Value {
    json!({
        "name": name,
        "fields": fields,
        "options": { "timestamps": false, "softDelete": false, "singleton": false },
        "annotations": { "db": { "tableName": table, "indexes": [] }, "platform": {} }
    })
}

fn schema(models: Vec<Value>) -> SchemaAst {
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
        "models": models
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

fn users() -> Value {
    model("User", "users", json!({ "id": int_pk() }))
}

fn accounts() -> Value {
    model("Account", "accounts", json!({ "id": int_pk() }))
}

/// `posts.author_id` pointing at `target`. `reviewer_id` is a plain column the schema declares
/// and attaches nothing to, for the operator to add their own foreign key on.
fn posts_by(target: &str) -> Value {
    model(
        "Post",
        "posts",
        json!({ "id": int_pk(), "author": belongs_to(target, "author_id"),
                "reviewer_id": integer() }),
    )
}

/// `posts` with the column and no relation: the schema stopped asking for the foreign key.
fn posts_unrelated() -> Value {
    model(
        "Post",
        "posts",
        json!({ "id": int_pk(), "author_id": integer(), "reviewer_id": integer() }),
    )
}

use common::{exec, push, push_with};

async fn fk_rows(pool: &PgPool) -> Vec<LedgerRow> {
    let mut conn = pool.acquire().await.unwrap();
    ledger::load(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.key.kind == ObjectKind::ForeignKey)
        .collect()
}

/// The table a foreign key points at, or None when the constraint is gone.
async fn fk_target(pool: &PgPool, table: &str, constraint: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT r.relname::text FROM pg_constraint k \
         JOIN pg_class c ON c.oid = k.conrelid JOIN pg_class r ON r.oid = k.confrelid \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname = $1 AND k.conname = $2 AND k.contype = 'f'",
    )
    .bind(table)
    .bind(constraint)
    .fetch_optional(pool)
    .await
    .unwrap()
}

async fn table_exists(pool: &PgPool, table: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'public' AND tablename = $1)",
    )
    .bind(table)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn applied(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::Applied { .. })
}

fn up_to_date(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::UpToDate { .. })
}

async fn force_push(pool: &PgPool, ast: &SchemaAst) -> push::Outcome {
    push_with(
        pool,
        ast,
        push::ApplyOptions {
            force: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn foreign_keys_are_recorded_on_creation_and_left_alone_on_a_second_push() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(vec![users(), posts_by("User")]);

        // The migration creates the tables first and the reconcile's foreign key after them.
        let plan = push::prepare(&pool, &ast, "public").await.unwrap();
        let file = plan.migration(false).unwrap().file();
        let last_table = file.rfind("CREATE TABLE").expect("tables are created");
        let first_fk = file
            .find("FOREIGN KEY")
            .expect("the foreign key is created");
        assert!(last_table < first_fk, "{file}");
        assert!(applied(
            &push::apply(&pool, plan, push::ApplyOptions::default())
                .await
                .unwrap()
        ));

        let rows = fk_rows(&pool).await;
        let names: Vec<&str> = rows.iter().map(|r| r.key.name.as_str()).collect();
        assert_eq!(names, ["posts_author_id_fkey"]);
        assert_eq!(rows[0].key.parent, "posts");
        assert_eq!(rows[0].status, Status::Managed);
        assert!(rows[0].migration_id.is_some());
        assert!(rows[0].desired_sql.contains("FOREIGN KEY"));
        assert!(
            rows[0].live_def.contains("references=public.users\n"),
            "{}",
            rows[0].live_def
        );
        assert_eq!(
            fk_target(&pool, "posts", "posts_author_id_fkey")
                .await
                .as_deref(),
            Some("users")
        );

        let again = push(&pool, &ast).await.unwrap();
        assert!(up_to_date(&again), "{again:?}");
        assert_eq!(
            fk_rows(&pool).await,
            rows,
            "an up-to-date push changes no row"
        );
    })
    .await;
}

#[tokio::test]
async fn retargeting_a_relation_replaces_the_foreign_key_and_rolling_back_restores_it() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(vec![users(), accounts(), posts_by("User")]))
            .await
            .unwrap();
        let before = fk_rows(&pool).await;

        let outcome = force_push(
            &pool,
            &schema(vec![users(), accounts(), posts_by("Account")]),
        )
        .await;
        assert!(applied(&outcome), "{outcome:?}");
        assert_eq!(
            fk_target(&pool, "posts", "posts_author_id_fkey")
                .await
                .as_deref(),
            Some("accounts"),
            "the foreign key follows the relation, not its name"
        );
        let after = fk_rows(&pool).await;
        assert_eq!(after.len(), 1);
        assert_ne!(
            after[0].desired_fp, before[0].desired_fp,
            "the intent changed"
        );
        assert_ne!(
            after[0].live_fp, before[0].live_fp,
            "and so did the catalog"
        );

        migration_history::apply_rollback(&pool, "public")
            .await
            .unwrap();
        assert_eq!(
            fk_target(&pool, "posts", "posts_author_id_fkey")
                .await
                .as_deref(),
            Some("users"),
            "rolling back restores the previous foreign key"
        );
    })
    .await;
}

#[tokio::test]
async fn a_removed_relation_drops_its_foreign_key_and_a_hand_added_one_survives() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(vec![users(), posts_by("User")]))
            .await
            .unwrap();
        exec(
            &pool,
            "ALTER TABLE public.posts ADD CONSTRAINT posts_reviewer_id_fkey \
             FOREIGN KEY (reviewer_id) REFERENCES public.users (id)",
        )
        .await
        .unwrap();

        let outcome = force_push(&pool, &schema(vec![users(), posts_unrelated()])).await;
        assert!(applied(&outcome), "{outcome:?}");
        assert_eq!(
            fk_target(&pool, "posts", "posts_author_id_fkey").await,
            None,
            "the foreign key the schema stopped asking for is gone"
        );
        assert_eq!(
            fk_target(&pool, "posts", "posts_reviewer_id_fkey")
                .await
                .as_deref(),
            Some("users"),
            "a foreign key Supatype did not create is never dropped (D3)"
        );
        assert!(fk_rows(&pool).await.is_empty(), "and never recorded");
    })
    .await;
}

#[tokio::test]
async fn an_owned_foreign_key_dropped_by_hand_is_recreated() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(vec![users(), posts_by("User")]);
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            "ALTER TABLE public.posts DROP CONSTRAINT posts_author_id_fkey",
        )
        .await
        .unwrap();

        let outcome = push(&pool, &ast).await.unwrap();
        assert!(applied(&outcome), "{outcome:?}");
        assert_eq!(
            fk_target(&pool, "posts", "posts_author_id_fkey")
                .await
                .as_deref(),
            Some("users")
        );
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
    })
    .await;
}

#[tokio::test]
async fn a_foreign_key_pointing_at_a_table_the_push_drops_is_dropped_before_the_table() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(vec![users(), posts_by("User")]))
            .await
            .unwrap();

        // `users` goes and `posts` keeps its column. Without the reconcile's drop running first,
        // `DROP TABLE users` fails on the dependent constraint, since nothing ever cascades.
        let outcome = force_push(&pool, &schema(vec![posts_unrelated()])).await;
        assert!(applied(&outcome), "{outcome:?}");
        assert!(!table_exists(&pool, "users").await);
        assert_eq!(
            fk_target(&pool, "posts", "posts_author_id_fkey").await,
            None
        );
        assert!(fk_rows(&pool).await.is_empty());
    })
    .await;
}

#[tokio::test]
async fn an_existing_matching_foreign_key_is_adopted_and_a_different_one_refuses_the_push() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(vec![users(), accounts(), posts_by("User")]);
        push(&pool, &ast).await.unwrap();

        // An engine before the ledger created this foreign key by name alone: no row, no stamp.
        exec(
            &pool,
            "DELETE FROM _supatype.managed_objects WHERE kind = 'foreign_key'",
        )
        .await
        .unwrap();
        assert!(applied(&push(&pool, &ast).await.unwrap()));
        let rows = fk_rows(&pool).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, Status::Adopted, "{rows:?}");
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));

        // The same name, pointing somewhere else: not ours to replace.
        exec(
            &pool,
            "DELETE FROM _supatype.managed_objects WHERE kind = 'foreign_key';
             ALTER TABLE public.posts DROP CONSTRAINT posts_author_id_fkey;
             ALTER TABLE public.posts ADD CONSTRAINT posts_author_id_fkey \
             FOREIGN KEY (author_id) REFERENCES public.accounts (id)",
        )
        .await
        .unwrap();
        let refused = push(&pool, &ast)
            .await
            .expect_err("a same-named foreign key that means something else refuses the push");
        let message = format!("{refused:#}");
        assert!(message.contains("posts_author_id_fkey"), "{message}");
        assert!(message.contains("supatype adopt"), "{message}");
        assert_eq!(
            fk_target(&pool, "posts", "posts_author_id_fkey")
                .await
                .as_deref(),
            Some("accounts"),
            "and leaves it alone"
        );
    })
    .await;
}

/// A key that differs from ours only in `ON UPDATE` or in being `DEFERRABLE` does something else
/// when a row changes or a transaction commits, so it is the user's, not ours to adopt.
#[tokio::test]
async fn a_foreign_key_differing_only_in_on_update_or_deferral_refuses_the_push() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(vec![users(), accounts(), posts_by("User")]);
        push(&pool, &ast).await.unwrap();
        for options in [
            "ON DELETE RESTRICT",
            "ON DELETE RESTRICT ON UPDATE CASCADE DEFERRABLE",
        ] {
            exec(
                &pool,
                &format!(
                    "DELETE FROM _supatype.managed_objects WHERE kind = 'foreign_key';
                     ALTER TABLE public.posts DROP CONSTRAINT posts_author_id_fkey;
                     ALTER TABLE public.posts ADD CONSTRAINT posts_author_id_fkey \
                     FOREIGN KEY (author_id) REFERENCES public.users (id) {options}"
                ),
            )
            .await
            .unwrap();
            let refused = push(&pool, &ast)
                .await
                .expect_err("a key that behaves differently is not adopted");
            let message = format!("{refused:#}");
            assert!(
                message.contains("posts_author_id_fkey") && message.contains("supatype adopt"),
                "{options}: {message}"
            );
            assert!(fk_rows(&pool).await.is_empty(), "{options}");
        }
    })
    .await;
}

#[tokio::test]
async fn junction_and_versions_foreign_keys_are_recorded_from_their_tables_create() {
    common::with_integration_pool(|pool| async move {
        for fixture in [
            include_str!("fixtures/many_to_many.json"),
            include_str!("fixtures/versioned_blog.json"),
        ] {
            let ast = parser::parse(fixture).unwrap();
            exec(
                &pool,
                "CREATE SCHEMA IF NOT EXISTS auth;
                 CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT UNIQUE);",
            )
            .await
            .unwrap();
            assert!(applied(&force_push(&pool, &ast).await));
            let rows = fk_rows(&pool).await;
            assert!(!rows.is_empty(), "the fixture's foreign keys are recorded");
            assert!(rows.iter().all(|r| r.migration_id.is_some()), "{rows:#?}");
            let again = push(&pool, &ast).await.unwrap();
            assert!(up_to_date(&again), "{again:?}");
        }
    })
    .await;
}

/// `posts.author_id` to `users`, its relation declaring `onUpdate`.
fn posts_on_update(on_update: &str) -> Value {
    let mut author = belongs_to("User", "author_id");
    author["onUpdate"] = on_update.into();
    model(
        "Post",
        "posts",
        json!({ "id": int_pk(), "author": author, "reviewer_id": integer() }),
    )
}

/// `pg_constraint.confupdtype` of `posts_author_id_fkey` (`r` restrict, `c` cascade, ...) and
/// whether the key is validated.
async fn posts_author_on_update(pool: &PgPool) -> (String, bool) {
    sqlx::query_as::<_, (String, bool)>(
        "SELECT k.confupdtype::text, k.convalidated FROM pg_constraint k \
         JOIN pg_class c ON c.oid = k.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname = 'posts' AND k.conname = 'posts_author_id_fkey'",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

/// A relation's `onUpdate` is applied, reads back equal on the next push, and a change to it
/// replaces the key, online on a table with rows; leaving it out keeps the `ON UPDATE CASCADE`
/// every key had before.
#[tokio::test]
async fn a_relations_on_update_is_applied_kept_and_changed() {
    common::with_integration_pool(|pool| async move {
        let restrict = schema(vec![users(), posts_on_update("restrict")]);
        assert!(applied(&push(&pool, &restrict).await.unwrap()));
        assert_eq!(posts_author_on_update(&pool).await, ("r".into(), true));
        let again = push(&pool, &restrict).await.unwrap();
        assert!(up_to_date(&again), "no perpetual diff: {again:?}");

        exec(
            &pool,
            "INSERT INTO public.users (id) VALUES (1);
             INSERT INTO public.posts (id, author_id) VALUES (1, 1);",
        )
        .await
        .unwrap();
        let cascade = schema(vec![users(), posts_on_update("cascade")]);
        let plan = push::prepare(&pool, &cascade, "public").await.unwrap();
        let file = plan.migration(false).unwrap().file();
        assert!(
            file.contains("ON DELETE RESTRICT ON UPDATE CASCADE NOT VALID;"),
            "the key is replaced, added NOT VALID on a table with rows:\n{file}"
        );
        let outcome = push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap();
        assert!(applied(&outcome), "{outcome:?}");
        assert_eq!(posts_author_on_update(&pool).await, ("c".into(), true));
        assert!(up_to_date(&push(&pool, &cascade).await.unwrap()));

        // Omitted is `CASCADE`, so the same key: nothing to do.
        let omitted = schema(vec![users(), posts_by("User")]);
        let outcome = push(&pool, &omitted).await.unwrap();
        assert!(up_to_date(&outcome), "{outcome:?}");
    })
    .await;
}

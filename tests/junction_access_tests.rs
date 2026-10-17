//! Who may read and write a many-to-many link (DR1).
//!
//! A link row is readable when both of its ends are readable to the caller, and writable when the
//! caller may also update at least one end: tagging a post is an edit of the post. The fixture is
//! the marketing site's: tags anyone may read and only an admin may change, and posts readable
//! once published and editable by an editor. Before the fix the junction had no read policy (the
//! post's read rule depends on the row) and no grants, so an anonymous read of a published post's
//! tags failed with "permission denied", and an editor could not tag a post.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::parser::{self, ast::SchemaAst};

const PUBLISHED: &str = "11111111-1111-1111-1111-111111111111";
const UNPUBLISHED: &str = "22222222-2222-2222-2222-222222222222";
const RUST: &str = "33333333-3333-3333-3333-333333333333";
const SQL: &str = "44444444-4444-4444-4444-444444444444";

fn column(kind: &str, pg_type: &str, required: bool) -> Value {
    json!({ "kind": kind, "required": required,
            "annotations": { "db": { "pgType": pg_type, "unique": false } } })
}

fn uuid_key() -> Value {
    let mut id = column("uuid", "UUID", true);
    id["primaryKey"] = json!(true);
    id
}

fn model(name: &str, table: &str, fields: Value, access: Value) -> Value {
    json!({
        "name": name,
        "fields": fields,
        "options": { "timestamps": false, "softDelete": false, "singleton": false },
        "annotations": { "db": { "tableName": table, "indexes": [] },
                         "platform": { "access": access } }
    })
}

fn role(name: &str) -> Value {
    json!({ "type": "role", "roles": [name] })
}

/// `published_at <= now()`, the rule that left the junction with no read policy.
fn published() -> Value {
    json!({ "type": "compare", "op": "lte",
            "left": { "kind": "column", "name": "published_at" },
            "right": { "kind": "now" } })
}

fn blog() -> SchemaAst {
    let tag = model(
        "Tag",
        "tags",
        json!({ "id": uuid_key(), "label": column("text", "TEXT", true) }),
        json!({ "read": { "type": "public" }, "create": role("admin"),
                "update": role("admin"), "delete": role("admin") }),
    );
    let post = model(
        "BlogPost",
        "blog_posts",
        json!({
            "id": uuid_key(),
            "title": column("text", "TEXT", true),
            "published_at": column("timestamp", "TIMESTAMPTZ", false),
            "tags": { "kind": "relation", "cardinality": "manyToMany", "target": "Tag",
                      "through": "blog_post_tags" }
        }),
        json!({ "read": published(), "create": role("editor"),
                "update": role("editor"), "delete": role("admin") }),
    );
    let doc = json!({ "astVersion": 2, "models": [tag, post] });
    parser::parse(&doc.to_string()).expect("the blog fixture parses")
}

/// The API roles and the claim readers, as a provisioned project has them.
async fn prepare(pool: &PgPool) {
    common::exec(
        pool,
        "CREATE SCHEMA IF NOT EXISTS auth;
         DO $$ BEGIN
           BEGIN CREATE ROLE anon NOLOGIN NOINHERIT;
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
           BEGIN CREATE ROLE authenticated NOLOGIN NOINHERIT;
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
           BEGIN CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS;
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
         END $$;",
    )
    .await
    .expect("roles and auth schema");
    common::exec(
        pool,
        &supatype_engine::generator::sql::rls::generate_auth_helpers(),
    )
    .await
    .expect("auth helpers");
}

/// Two posts, one published, and both tagged `rust`.
async fn seed(pool: &PgPool) {
    common::exec(
        pool,
        &format!(
            "INSERT INTO public.tags (id, label) VALUES ('{RUST}', 'rust'), ('{SQL}', 'sql');
             INSERT INTO public.blog_posts (id, title, published_at) VALUES
               ('{PUBLISHED}', 'Out', now() - interval '1 day'),
               ('{UNPUBLISHED}', 'Not yet', NULL);
             INSERT INTO public.blog_post_tags (blog_post_id, tag_id) VALUES
               ('{PUBLISHED}', '{RUST}'), ('{UNPUBLISHED}', '{RUST}');"
        ),
    )
    .await
    .expect("seed");
}

#[derive(Clone, Copy, Debug)]
enum Caller {
    Anon,
    Reader,
    Editor,
}

impl Caller {
    fn role(self) -> &'static str {
        match self {
            Caller::Anon => "anon",
            _ => "authenticated",
        }
    }

    fn claims(self) -> Value {
        let sub = "55555555-5555-5555-5555-555555555555";
        match self {
            Caller::Anon => json!({ "role": "anon" }),
            Caller::Reader => json!({ "role": "authenticated", "sub": sub }),
            Caller::Editor => json!({ "role": "authenticated", "sub": sub,
                                      "app_metadata": { "role": "editor" } }),
        }
    }
}

/// Runs `sql` as `caller` the way PostgREST does, in a transaction rolled back afterwards, and
/// answers the `line` column of the rows it returned, or the error.
async fn as_caller(pool: &PgPool, caller: Caller, sql: &str) -> Result<Vec<String>, String> {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('request.jwt.claims', $1, true)")
        .bind(caller.claims().to_string())
        .execute(&mut *tx)
        .await
        .expect("set the claims");
    sqlx::raw_sql(&format!("SET LOCAL ROLE {}", caller.role()))
        .execute(&mut *tx)
        .await
        .expect("assume the API role");
    let wrapped = format!("WITH q AS ({sql}) SELECT line FROM q ORDER BY 1");
    let rows = sqlx::query_scalar::<_, String>(&wrapped)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| e.to_string());
    let _ = tx.rollback().await;
    rows
}

fn link(post: &str, tag: &str) -> String {
    format!("{post}|{tag}")
}

/// A link as `post|tag`, the `line` [`as_caller`] reads.
const LINE: &str = "blog_post_id::text || '|' || tag_id::text AS line";

fn read_links() -> String {
    format!("SELECT {LINE} FROM public.blog_post_tags")
}

#[tokio::test]
async fn a_link_is_readable_when_both_of_its_ends_are() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;
        common::push(&pool, &blog()).await.expect("push");
        seed(&pool).await;

        for caller in [Caller::Anon, Caller::Reader] {
            let rows = as_caller(&pool, caller, &read_links()).await;
            assert_eq!(
                rows,
                Ok(vec![link(PUBLISHED, RUST)]),
                "{caller:?} reads the published post's tag and nothing of the unpublished one"
            );
        }
    })
    .await;
}

fn insert_link(post: &str, tag: &str) -> String {
    format!(
        "INSERT INTO public.blog_post_tags (blog_post_id, tag_id) VALUES ('{post}', '{tag}') \
         RETURNING {LINE}"
    )
}

fn delete_link(post: &str, tag: &str) -> String {
    format!(
        "DELETE FROM public.blog_post_tags WHERE blog_post_id = '{post}' AND tag_id = '{tag}' \
         RETURNING {LINE}"
    )
}

#[tokio::test]
async fn a_caller_who_may_update_a_post_may_tag_it() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;
        common::push(&pool, &blog()).await.expect("push");
        seed(&pool).await;

        let tagged = as_caller(&pool, Caller::Editor, &insert_link(PUBLISHED, SQL)).await;
        assert_eq!(tagged, Ok(vec![link(PUBLISHED, SQL)]));
        let untagged = as_caller(&pool, Caller::Editor, &delete_link(PUBLISHED, RUST)).await;
        assert_eq!(untagged, Ok(vec![link(PUBLISHED, RUST)]));

        // Neither end is theirs to edit.
        let refused = as_caller(&pool, Caller::Reader, &insert_link(PUBLISHED, SQL)).await;
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.contains("row-level security")),
            "{refused:?}"
        );
        let untouched = as_caller(&pool, Caller::Reader, &delete_link(PUBLISHED, RUST)).await;
        assert_eq!(untouched, Ok(Vec::new()));
        let anon = as_caller(&pool, Caller::Anon, &insert_link(PUBLISHED, SQL)).await;
        assert!(
            anon.as_ref()
                .is_err_and(|e| e.contains("permission denied")),
            "{anon:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_post_the_caller_cannot_read_cannot_be_tagged() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;
        common::push(&pool, &blog()).await.expect("push");
        seed(&pool).await;

        let refused = as_caller(&pool, Caller::Editor, &insert_link(UNPUBLISHED, SQL)).await;
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.contains("row-level security")),
            "{refused:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn the_link_policies_are_stable_across_pushes() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;
        common::push(&pool, &blog()).await.expect("push");
        let again = common::push(&pool, &blog()).await.expect("second push");
        assert!(
            matches!(again, supatype_engine::push::Outcome::UpToDate { .. }),
            "{again:?}"
        );
        let report = common::doctor(&pool, &blog()).await;
        assert!(!report.blocking, "{report:#?}");
    })
    .await;
}

/// `Project` is read by its members, through the junction that links it to `Member`. Reading a
/// project then reads the junction, so a junction policy that read the project back would recurse
/// and Postgres would refuse every read of either table. Such a junction keeps the intersection of
/// its ends' rules instead.
fn membership() -> SchemaAst {
    let member = model(
        "Member",
        "members",
        json!({ "id": uuid_key() }),
        json!({ "read": { "type": "authenticated" } }),
    );
    let mine = json!({
        "type": "in", "column": "id",
        "source": { "kind": "rows", "table": "project_members", "column": "project_id",
                    "where": { "type": "compare", "op": "eq",
                               "left": { "kind": "column", "name": "member_id" },
                               "right": { "kind": "authUid" } } }
    });
    let project = model(
        "Project",
        "projects",
        json!({
            "id": uuid_key(),
            "members": { "kind": "relation", "cardinality": "manyToMany", "target": "Member",
                         "through": "project_members" }
        }),
        json!({ "read": mine, "update": mine }),
    );
    let doc = json!({ "astVersion": 2, "models": [member, project] });
    parser::parse(&doc.to_string()).expect("the membership fixture parses")
}

#[tokio::test]
async fn a_junction_its_end_reads_as_membership_does_not_recurse() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;
        common::push(&pool, &membership()).await.expect("push");
        let read = "SELECT id::text AS line FROM public.projects";
        let rows = as_caller(&pool, Caller::Reader, read).await;
        assert!(rows.is_ok(), "{rows:?}");
    })
    .await;
}

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

// ─── Posts owned by their authors (Step 1 of the parent-driven junction rule) ────────────────

const ALICE: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const BOB: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const ALICE_PUBLISHED: &str = "a1a1a1a1-0000-0000-0000-000000000001";
const ALICE_DRAFT: &str = "a1a1a1a1-0000-0000-0000-000000000002";
const BOB_PUBLISHED: &str = "b1b1b1b1-0000-0000-0000-000000000001";
const BOB_DRAFT: &str = "b1b1b1b1-0000-0000-0000-000000000002";

/// Posts readable by their author or once published, and written by their author only. Tags are
/// readable by anyone and written by an admin only, so no caller here may update a tag.
fn authored() -> SchemaAst {
    let tag = model(
        "Tag",
        "tags",
        json!({ "id": uuid_key(), "label": column("text", "TEXT", true) }),
        json!({ "read": { "type": "public" }, "create": role("admin"),
                "update": role("admin"), "delete": role("admin") }),
    );
    let owner = json!({ "type": "owner", "field": "author_id" });
    let readable = json!({ "type": "any", "rules": [
        owner,
        { "type": "nullCheck", "operand": { "kind": "column", "name": "published_at" },
          "isNull": false }
    ] });
    let post = model(
        "Post",
        "posts",
        json!({
            "id": uuid_key(),
            "author_id": column("uuid", "UUID", true),
            "published_at": column("timestamp", "TIMESTAMPTZ", false),
            "tags": { "kind": "relation", "cardinality": "manyToMany", "target": "Tag",
                      "through": "post_tags" }
        }),
        json!({ "read": readable, "create": owner, "update": owner, "delete": owner }),
    );
    let doc = json!({ "astVersion": 2, "models": [tag, post] });
    parser::parse(&doc.to_string()).expect("the authored fixture parses")
}

/// Each author has a published post and a draft, and every post is tagged `rust`.
async fn seed_authored(pool: &PgPool) {
    let posts = [
        (ALICE_PUBLISHED, ALICE, "now()"),
        (ALICE_DRAFT, ALICE, "NULL"),
        (BOB_PUBLISHED, BOB, "now()"),
        (BOB_DRAFT, BOB, "NULL"),
    ];
    let values = posts
        .iter()
        .map(|(id, author, at)| format!("('{id}', '{author}', {at})"))
        .collect::<Vec<_>>()
        .join(", ");
    let links = posts
        .iter()
        .map(|(id, _, _)| format!("('{id}', '{RUST}')"))
        .collect::<Vec<_>>()
        .join(", ");
    common::exec(
        pool,
        &format!(
            "INSERT INTO public.tags (id, label) VALUES ('{RUST}', 'rust'), ('{SQL}', 'sql');
             INSERT INTO public.posts (id, author_id, published_at) VALUES {values};
             INSERT INTO public.post_tags (post_id, tag_id) VALUES {links};"
        ),
    )
    .await
    .expect("seed the authored posts");
}

/// Runs `sql` as `role` with `claims`, rolled back afterwards: the rows' `line`, or the error.
async fn as_claims(
    pool: &PgPool,
    role: &str,
    claims: Value,
    sql: &str,
) -> Result<Vec<String>, String> {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('request.jwt.claims', $1, true)")
        .bind(claims.to_string())
        .execute(&mut *tx)
        .await
        .expect("set the claims");
    sqlx::raw_sql(&format!("SET LOCAL ROLE {role}"))
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

const POST_LINE: &str = "post_id::text || '|' || tag_id::text AS line";

fn post_link(post: &str) -> String {
    format!("{post}|{RUST}")
}

#[tokio::test]
async fn an_authored_posts_links_follow_the_post_and_the_tag() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;
        common::push(&pool, &authored()).await.expect("push");
        seed_authored(&pool).await;

        let anon = ("anon", json!({ "role": "anon" }));
        let alice = (
            "authenticated",
            json!({ "role": "authenticated", "sub": ALICE }),
        );
        let bob = (
            "authenticated",
            json!({ "role": "authenticated", "sub": BOB }),
        );
        let read = format!("SELECT {POST_LINE} FROM public.post_tags");
        let insert = |post: &str| {
            format!(
                "INSERT INTO public.post_tags (post_id, tag_id) VALUES ('{post}', '{SQL}') \
                 RETURNING {POST_LINE}"
            )
        };
        let delete = |post: &str| {
            format!(
                "DELETE FROM public.post_tags WHERE post_id = '{post}' AND tag_id = '{RUST}' \
                 RETURNING {POST_LINE}"
            )
        };
        let run = |(role, claims): &(&str, Value), sql: String| {
            let (pool, role, claims) = (pool.clone(), role.to_string(), claims.clone());
            async move { as_claims(&pool, &role, claims, &sql).await }
        };

        // Reads: the published posts' links for everyone, and an author's own draft's for them.
        assert_eq!(
            run(&anon, read.clone()).await,
            Ok(vec![post_link(ALICE_PUBLISHED), post_link(BOB_PUBLISHED)]),
            "anon reads the published posts' links only"
        );
        let mut alices = vec![
            post_link(ALICE_PUBLISHED),
            post_link(ALICE_DRAFT),
            post_link(BOB_PUBLISHED),
        ];
        alices.sort();
        assert_eq!(
            run(&alice, read.clone()).await,
            Ok(alices),
            "alice adds her draft's link"
        );
        let mut bobs = vec![
            post_link(ALICE_PUBLISHED),
            post_link(BOB_PUBLISHED),
            post_link(BOB_DRAFT),
        ];
        bobs.sort();
        assert_eq!(
            run(&bob, read.clone()).await,
            Ok(bobs),
            "bob adds his draft's link"
        );

        // Writes on her own posts, published and draft, with a tag she may read but not edit.
        for post in [ALICE_PUBLISHED, ALICE_DRAFT] {
            let added = run(&alice, insert(post)).await;
            assert_eq!(
                added,
                Ok(vec![format!("{post}|{SQL}")]),
                "alice tags her own post"
            );
            let removed = run(&alice, delete(post)).await;
            assert_eq!(
                removed,
                Ok(vec![post_link(post)]),
                "alice untags her own post"
            );
        }

        // Writes on someone else's posts: a published one she can read, and a draft she cannot.
        for post in [BOB_PUBLISHED, BOB_DRAFT] {
            let added = run(&alice, insert(post)).await;
            assert!(
                added
                    .as_ref()
                    .is_err_and(|e| e.contains("row-level security")),
                "alice may not tag bob's post {post}: {added:?}"
            );
            let removed = run(&alice, delete(post)).await;
            assert_eq!(
                removed,
                Ok(Vec::new()),
                "alice may not untag bob's post {post}"
            );
        }

        // Anon holds no write privilege at all: every end's update rule needs a login.
        let anon_added = run(&anon, insert(ALICE_PUBLISHED)).await;
        assert!(
            anon_added
                .as_ref()
                .is_err_and(|e| e.contains("permission denied")),
            "{anon_added:?}"
        );
    })
    .await;
}

/// `membership()` with the project read through `Exists<Rows<"project_members", ...>>` rather than
/// `In<"id", Rows<...>>`: a rule that reaches the junction only through `Exists`.
fn membership_by_exists() -> SchemaAst {
    let mut doc: Value = serde_json::to_value(membership()).expect("the fixture serializes");
    let mine = json!({
        "type": "exists",
        "source": { "kind": "rows", "table": "project_members", "column": "project_id",
                    "where": { "type": "compare", "op": "eq",
                               "left": { "kind": "column", "name": "member_id" },
                               "right": { "kind": "authUid" } } }
    });
    let project = &mut doc["models"][1]["annotations"]["platform"]["access"];
    project["read"] = mine.clone();
    project["update"] = mine;
    parser::parse(&doc.to_string()).expect("the Exists fixture parses")
}

// The project's read policy reads the junction as the caller, so the junction keeps SELECT for
// both API roles however it is reached: without it every read of a project fails with
// "permission denied for table project_members" instead of finding no rows.
#[test]
fn a_junction_read_only_through_exists_keeps_select() {
    let ast = membership_by_exists();
    for role in supatype_engine::generator::sql::grants::GRANTED_ROLES {
        let grant = supatype_engine::generator::sql::grants::table_grants(&ast, false)
            .into_iter()
            .find(|g| g.table == "project_members" && g.role == role)
            .expect("a grant for the junction");
        assert!(grant.privileges.contains(&"SELECT"), "{grant:?}");
    }
}

#[tokio::test]
async fn a_project_read_through_exists_on_its_junction_is_not_refused() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;
        common::push(&pool, &membership_by_exists())
            .await
            .expect("push");
        let read = "SELECT id::text AS line FROM public.projects";
        let rows = as_caller(&pool, Caller::Reader, read).await;
        assert!(rows.is_ok(), "{rows:?}");
    })
    .await;
}

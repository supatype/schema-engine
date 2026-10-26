//! On a model with drafts, the live row changes only by publishing.
//!
//! An ordinary edit used to write the live row directly: the table's UPDATE policy is the model's
//! own `update` rule, so a signed-in editor's `PATCH /posts` (or a GraphQL update mutation) went
//! live at once, recorded no version, and a later publish answered "version 1 ... is already live".
//! Each drafts model's table now carries a `BEFORE UPDATE` trigger refusing a direct update from
//! `anon` or `authenticated`, unless one of the publishing functions is making it. The service
//! role, the table's owner (the scheduler, a push, a cascade) and a Studio editor still write it.
//!
//! Everything a caller does here runs as `authenticated` in a transaction of its own, as PostgREST
//! runs a request, on one connection: `request.jwt.claims` is a session setting.

mod common;

use sqlx::pool::PoolConnection;
use sqlx::{PgConnection, Postgres};
use supatype_engine::parser::{self, ast::SchemaAst};

const EDITOR: &str = "11111111-1111-1111-1111-111111111111";

/// What the refusal says, in part: the model, that it has drafts, and the way to change it.
const REFUSAL: &str = "posts has drafts: save a draft with supatype.create_draft or the client's update, then publish";

/// The versioned blog, editable by an `editor` and readable by anyone.
fn blog() -> SchemaAst {
    let mut doc: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/versioned_blog.json")).expect("fixture");
    doc["models"][0]["annotations"]["platform"]["access"] = serde_json::json!({
        "read": { "type": "public" },
        "create": { "type": "role", "roles": ["editor"] },
        "update": { "type": "role", "roles": ["editor"] }
    });
    parser::parse(&doc.to_string()).expect("the blog parses")
}

/// Claims as the auth server issues them to an editor, plus Studio's claim when `studio` is set.
async fn become_editor(db: &mut PgConnection, studio: Option<&str>) {
    let mut claims = serde_json::json!({
        "sub": EDITOR, "role": "authenticated", "app_metadata": { "role": "editor" }
    });
    if let Some(level) = studio {
        claims["supatype_studio"] = serde_json::json!(level);
    }
    sqlx::query("SELECT set_config('request.jwt.claims', $1, false)")
        .bind(claims.to_string())
        .execute(db)
        .await
        .expect("set claims");
}

/// `sql` as `role`, in a transaction of its own, committed when it succeeds.
async fn as_role(db: &mut PgConnection, role: &str, sql: &str) -> Result<(), sqlx::Error> {
    sqlx::raw_sql("BEGIN").execute(&mut *db).await?;
    sqlx::raw_sql(&format!("SET LOCAL ROLE {role}"))
        .execute(&mut *db)
        .await?;
    let result = sqlx::raw_sql(sql).execute(&mut *db).await.map(|_| ());
    sqlx::raw_sql(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })
        .execute(&mut *db)
        .await?;
    result
}

/// One JSON answer of `sql`, run as `authenticated` in a transaction of its own.
async fn answer(db: &mut PgConnection, sql: &str) -> Result<serde_json::Value, sqlx::Error> {
    sqlx::raw_sql("BEGIN").execute(&mut *db).await?;
    sqlx::raw_sql("SET LOCAL ROLE authenticated")
        .execute(&mut *db)
        .await?;
    let result = sqlx::query_scalar::<_, serde_json::Value>(sql)
        .fetch_one(&mut *db)
        .await;
    sqlx::raw_sql(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })
        .execute(&mut *db)
        .await?;
    result
}

/// The live title of `id`, read as the owner.
async fn live_title(db: &mut PgConnection, id: &str) -> String {
    sqlx::query_scalar("SELECT title FROM public.posts WHERE id = $1::uuid")
        .bind(id)
        .fetch_one(db)
        .await
        .expect("read the live row")
}

/// How many versions `id` has, counted as the owner.
async fn versions(db: &mut PgConnection, id: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM public.posts_versions WHERE record_id = $1::uuid")
        .bind(id)
        .fetch_one(db)
        .await
        .expect("count versions")
}

/// The blog pushed and one post published by the editor: one connection, as the editor, and its id.
async fn published_post(pool: &sqlx::PgPool) -> (PoolConnection<Postgres>, String) {
    common::push(pool, &blog()).await.expect("the blog pushes");
    let mut conn = pool.acquire().await.expect("acquire one connection");
    become_editor(&mut conn, None).await;
    let created = answer(
        &mut conn,
        r#"SELECT supatype.create_record('posts', '{"title": "First cut"}')"#,
    )
    .await
    .expect("an editor creates a post");
    let id = created["record_id"].as_str().expect("its id").to_string();
    answer(
        &mut conn,
        &format!("SELECT supatype.publish('posts', '{id}')"),
    )
    .await
    .expect("an editor publishes it");
    (conn, id)
}

fn update(id: &str, title: &str) -> String {
    format!("UPDATE public.posts SET title = '{title}' WHERE id = '{id}'")
}

#[tokio::test]
async fn a_signed_in_editors_direct_update_is_refused_naming_drafts_and_publish() {
    common::with_integration_pool(|pool| async move {
        let (mut conn, id) = published_post(&pool).await;
        let db = &mut *conn;
        let refused = as_role(db, "authenticated", &update(&id, "Straight to live"))
            .await
            .expect_err("a direct update of a drafts model must be refused");
        assert!(refused.to_string().contains(REFUSAL), "{refused}");
        let code = refused.as_database_error().and_then(|e| e.code());
        assert_eq!(code.as_deref(), Some("42501"), "{refused}");
        assert_eq!(live_title(db, &id).await, "First cut");
        assert_eq!(versions(db, &id).await, 1, "nothing was recorded either");
    })
    .await;
}

#[tokio::test]
async fn the_publishing_functions_still_write_the_live_row_for_a_signed_in_editor() {
    common::with_integration_pool(|pool| async move {
        let (mut conn, id) = published_post(&pool).await;
        let db = &mut *conn;
        let draft = format!(
            r#"SELECT supatype.create_draft('posts', '{id}', '{{"title": "Through drafts"}}')"#
        );
        answer(db, &draft).await.expect("save a draft");
        assert_eq!(live_title(db, &id).await, "First cut");
        let publish = format!("SELECT supatype.publish('posts', '{id}')");
        answer(db, &publish).await.expect("publish");
        assert_eq!(live_title(db, &id).await, "Through drafts");

        answer(db, &format!("SELECT supatype.unpublish('posts', '{id}')"))
            .await
            .expect("unpublish");
        let hidden: bool =
            sqlx::query_scalar("SELECT published_at IS NULL FROM public.posts WHERE id = $1::uuid")
                .bind(&id)
                .fetch_one(&mut *db)
                .await
                .expect("read published_at");
        assert!(hidden, "unpublishing cleared published_at");

        answer(
            db,
            &format!("SELECT supatype.restore_version('posts', '{id}', 1)"),
        )
        .await
        .expect("restore version 1 as a draft");
        answer(db, &publish)
            .await
            .expect("publish the restored version");
        assert_eq!(live_title(db, &id).await, "First cut");
    })
    .await;
}

#[tokio::test]
async fn publishing_does_not_leave_the_live_row_open_for_the_rest_of_the_transaction() {
    common::with_integration_pool(|pool| async move {
        let (mut conn, id) = published_post(&pool).await;
        let db = &mut *conn;
        let sql = format!(
            r#"SELECT supatype.create_draft('posts', '{id}', '{{"title": "Drafted"}}');
                   SELECT supatype.publish('posts', '{id}');
                   {}"#,
            update(&id, "Piggybacked")
        );
        let refused = as_role(db, "authenticated", &sql)
            .await
            .expect_err("an update after a publish in the same transaction is still direct");
        assert!(refused.to_string().contains(REFUSAL), "{refused}");
        assert_eq!(
            live_title(db, &id).await,
            "First cut",
            "all of it rolled back"
        );
    })
    .await;
}

#[tokio::test]
async fn the_service_role_and_the_owner_still_write_the_live_row() {
    common::with_integration_pool(|pool| async move {
        let (mut conn, id) = published_post(&pool).await;
        let db = &mut *conn;
        // The platform grants the service role every table; a fresh test database has not.
        sqlx::raw_sql("GRANT ALL ON public.posts TO service_role")
            .execute(&mut *db)
            .await
            .expect("grant as the platform does");
        as_role(db, "service_role", &update(&id, "By the service"))
            .await
            .expect("the service role writes the live row");
        assert_eq!(live_title(db, &id).await, "By the service");
        sqlx::raw_sql(&update(&id, "By the owner"))
            .execute(&mut *db)
            .await
            .expect("the owner writes the live row");
        assert_eq!(live_title(db, &id).await, "By the owner");
    })
    .await;
}

#[tokio::test]
async fn a_studio_editor_drafts_and_publishes_and_may_still_edit_a_row_directly() {
    common::with_integration_pool(|pool| async move {
        let (mut conn, id) = published_post(&pool).await;
        let db = &mut *conn;
        become_editor(db, Some("write")).await;
        let draft =
            format!(r#"SELECT supatype.create_draft('posts', '{id}', '{{"title": "In Studio"}}')"#);
        answer(db, &draft).await.expect("Studio saves a draft");
        assert_eq!(live_title(db, &id).await, "First cut");
        answer(db, &format!("SELECT supatype.publish('posts', '{id}')"))
            .await
            .expect("Studio publishes");
        assert_eq!(live_title(db, &id).await, "In Studio");

        // Studio's data browser edits a cell with a direct update, and keeps doing so.
        as_role(db, "authenticated", &update(&id, "Cell edit"))
            .await
            .expect("a Studio editor's direct update is admitted");
        assert_eq!(live_title(db, &id).await, "Cell edit");

        become_editor(db, Some("read")).await;
        let refused = as_role(db, "authenticated", &update(&id, "Reader"))
            .await
            .expect_err("Studio's read level is no exemption");
        assert!(refused.to_string().contains(REFUSAL), "{refused}");
    })
    .await;
}

#[tokio::test]
async fn save_drafts_saves_one_per_record_and_leaves_the_live_rows() {
    common::with_integration_pool(|pool| async move {
        let (mut conn, id) = published_post(&pool).await;
        let db = &mut *conn;
        let saved = answer(
            db,
            &format!(r#"SELECT supatype.save_drafts('posts', '["{id}"]', '{{"title": "Saved"}}')"#),
        )
        .await
        .expect("save a draft through save_drafts");
        let answers = saved.as_array().expect("one answer per record");
        assert_eq!(answers.len(), 1, "{saved}");
        assert_eq!(answers[0]["record_id"], id.as_str(), "{saved}");
        assert_eq!(answers[0]["version"], 2, "{saved}");
        assert_eq!(answers[0]["status"], "draft", "{saved}");
        assert_eq!(live_title(db, &id).await, "First cut");
        assert_eq!(versions(db, &id).await, 2);
    })
    .await;
}

#[tokio::test]
async fn save_drafts_with_publish_puts_the_new_version_live_in_the_same_call() {
    common::with_integration_pool(|pool| async move {
        let (mut conn, id) = published_post(&pool).await;
        let db = &mut *conn;
            let saved = answer(
                db,
                &format!(
                    r#"SELECT supatype.save_drafts('posts', '["{id}"]', '{{"title": "Live now"}}', true)"#
                ),
            )
            .await
            .expect("save and publish");
            assert_eq!(saved[0]["status"], "published", "{saved}");
            assert_eq!(saved[0]["version"], 2, "{saved}");
            assert_eq!(live_title(db, &id).await, "Live now");
            let live_version: i32 = sqlx::query_scalar(
                "SELECT version FROM public.posts_versions
                  WHERE record_id = $1::uuid AND status = 'published'",
            )
            .bind(&id)
            .fetch_one(&mut *db)
            .await
            .expect("exactly one version is live");
            assert_eq!(live_version, 2, "history records what went live");
    })
    .await;
}

#[tokio::test]
async fn save_drafts_is_all_or_none() {
    common::with_integration_pool(|pool| async move {
        let (mut conn, id) = published_post(&pool).await;
        let db = &mut *conn;
            let missing = "99999999-9999-9999-9999-999999999999";
            let refused = answer(
                db,
                &format!(
                    r#"SELECT supatype.save_drafts('posts', '["{id}", "{missing}"]', '{{"title": "Half"}}')"#
                ),
            )
            .await
            .expect_err("a record that does not exist refuses the call");
            assert!(refused.to_string().contains("no such record"), "{refused}");
            assert_eq!(versions(db, &id).await, 1, "the first record's draft went with it");
    })
    .await;
}

/// The mutation's answer, or the error it reports. pg_graphql reports errors in its answer
/// rather than raising them.
async fn graphql(db: &mut PgConnection, query: &str) -> serde_json::Value {
    answer(db, &format!("SELECT graphql.resolve($q${query}$q$)"))
        .await
        .expect("graphql.resolve answers")
}

#[tokio::test]
async fn a_graphql_update_mutation_is_refused_the_same_way() {
    common::with_integration_pool(|pool| async move {
        let (mut conn, id) = published_post(&pool).await;
        let db = &mut *conn;
        // As the platform sets it up: the extension, and the API roles allowed to call it.
        sqlx::raw_sql(
            "CREATE EXTENSION IF NOT EXISTS pg_graphql;
             GRANT USAGE ON SCHEMA graphql TO anon, authenticated, service_role;",
        )
        .execute(&mut *db)
        .await
        .expect("pg_graphql is in the image");
        let mutation = format!(
            r#"mutation {{ updatepostsCollection(set: {{title: "By GraphQL"}},
                     filter: {{id: {{eq: "{id}"}}}}) {{ affectedCount }} }}"#
        );
        let answered = graphql(db, &mutation).await;
        let message = answered["errors"][0]["message"]
            .as_str()
            .unwrap_or_default();
        assert!(message.contains(REFUSAL), "{answered}");
        assert_eq!(live_title(db, &id).await, "First cut");
    })
    .await;
}

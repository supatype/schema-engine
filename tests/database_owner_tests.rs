//! SEC-SQL (SQ1a): what a push makes in the project schema belongs to the database's owner.
//!
//! A project database is owned by a role that is not a superuser (the demoted `postgres` on
//! self-host, `<ref>_owner` on Cloud), and Studio's SQL editor connects as a member of that owner.
//! The engine still connects as a superuser, which it needs for the extensions it installs, so the
//! relations it creates in the project schema are handed to the database's owner
//! (`pg_database.datdba`) inside the push's own transaction. Left with the superuser, they could be
//! neither altered nor read by the owner's members.

mod common;

use serde_json::json;
use sqlx::PgPool;
use supatype_engine::{parser, parser::ast::SchemaAst, push::Outcome};

use common::{exec, push};

fn posts() -> SchemaAst {
    let doc = json!({ "astVersion": 2, "models": [{
        "name": "Post",
        "fields": {
            "id": { "kind": "serial", "primaryKey": true, "required": true,
                    "annotations": { "db": { "pgType": "SERIAL" } } },
            "title": { "kind": "text", "required": false,
                       "annotations": { "db": { "pgType": "TEXT" } } }
        },
        "options": { "timestamps": false, "softDelete": false },
        "annotations": { "db": { "tableName": "posts", "indexes": [] },
                         "platform": { "access": {} } }
    }]});
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// A login-less role that is not a superuser, made the owner of this database, as the provisioner
/// and the self-host image leave it. Roles are the server's, so the name is unique to this test.
async fn hand_database_to_new_owner(pool: &PgPool) -> String {
    let role = common::ephemeral_name("st_owner");
    exec(
        pool,
        &format!(
            "CREATE ROLE {role} NOLOGIN NOSUPERUSER;
             DO $$ BEGIN
               EXECUTE format('ALTER DATABASE %I OWNER TO {role}', current_database());
             END $$;"
        ),
    )
    .await
    .expect("make the database's owner");
    role
}

/// Gives the database and everything of `role`'s back to the connecting superuser and drops it.
async fn drop_owner(pool: &PgPool, role: &str) {
    exec(
        pool,
        &format!(
            "DO $$ BEGIN
               EXECUTE format('ALTER DATABASE %I OWNER TO %I', current_database(), current_user);
             END $$;
             REASSIGN OWNED BY {role} TO current_user;
             DROP OWNED BY {role};
             DROP ROLE {role};"
        ),
    )
    .await
    .expect("drop the test's owner role");
}

/// Who owns each relation in `public`, by name: the push makes the table and its serial's sequence.
async fn owners(pool: &PgPool) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT relname::text, pg_get_userbyid(relowner)::text FROM pg_class
          WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
          ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .expect("read the owners")
}

/// SQ1a: pushed as a superuser into a database a non-superuser owns, every object the push made in
/// the project schema is the owner's, and a second push finds nothing to change.
#[tokio::test(flavor = "multi_thread")]
async fn a_push_hands_what_it_makes_to_the_databases_owner() {
    common::with_integration_pool(|pool| async move {
        let owner = hand_database_to_new_owner(&pool).await;
        let first = push(&pool, &posts()).await;
        let found = owners(&pool).await;
        let again = push(&pool, &posts()).await;
        drop_owner(&pool, &owner).await;

        first.expect("first push");
        let names: Vec<&str> = found.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["posts", "posts_id_seq"], "{found:?}");
        for (object, held_by) in &found {
            assert_eq!(held_by, &owner, "{object} belongs to the database's owner");
        }
        let again = again.expect("second push");
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}

/// SQ1a for a project an older engine pushed: its relations are the superuser's, and the next push,
/// with nothing to change, hands them to the database's owner.
#[tokio::test(flavor = "multi_thread")]
async fn a_push_with_nothing_to_change_hands_an_older_project_to_its_owner() {
    common::with_integration_pool(|pool| async move {
        let first = push(&pool, &posts()).await;
        let owner = hand_database_to_new_owner(&pool).await;
        let before = owners(&pool).await;
        let again = push(&pool, &posts()).await;
        let after = owners(&pool).await;
        drop_owner(&pool, &owner).await;

        first.expect("first push");
        assert!(
            before.iter().all(|(_, held_by)| held_by != &owner),
            "{before:?}"
        );
        let again = again.expect("second push");
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");
        assert_eq!(after.len(), 2, "{after:?}");
        for (object, held_by) in &after {
            assert_eq!(held_by, &owner, "{object} belongs to the database's owner");
        }
    })
    .await;
}

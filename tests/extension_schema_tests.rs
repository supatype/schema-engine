//! Where a push installs the extensions it needs, and what it does about ones already in `public`.
//!
//! A push used to create `postgis`, `vector`, `unaccent` and `pgcrypto` with no schema, so they
//! landed in `public`: about 940 functions, a third of them served as `/rest/v1/rpc/*`, and a
//! function listing PostgREST 14 plans badly on the stale catalog statistics a push leaves behind,
//! so `GET /rest/v1/` timed out for 30 to 60 seconds after every first push. Extensions now go in
//! `extensions`, as Supabase puts them, and a push moves the relocatable ones it finds in `public`
//! there as an operation of its own, shown and consented to like any other. PostGIS cannot be moved
//! by `ALTER EXTENSION`; a push finds it, says so, and keeps working with it where it is.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{parser, parser::ast::SchemaAst, push};

use common::{exec, push};

/// One model with every field that needs an extension: a geography point and a vector (PostGIS and
/// pgvector), a slug (`unaccent`, through `_platform.slugify`) and a generated UUID key.
fn places() -> SchemaAst {
    places_with(json!({ "fields": ["embedding"], "unique": false, "using": "hnsw" }))
}

/// [`places`] with `vector_index` as the index on `embedding`.
fn places_with(vector_index: Value) -> SchemaAst {
    let doc = json!({
        "astVersion": 2,
        "models": [{
            "name": "Place",
            "fields": {
                "id": { "kind": "uuid", "primaryKey": true, "required": true,
                        "default": { "kind": "genRandomUuid" },
                        "annotations": { "db": { "pgType": "UUID", "unique": false } } },
                "name": { "kind": "text", "required": true,
                          "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
                "slug": { "kind": "slug", "required": false, "from": "name",
                          "annotations": { "db": { "pgType": "TEXT", "unique": true } } },
                "point": { "kind": "geo", "required": false, "geoType": "point", "srid": 4326,
                           "annotations": { "db": { "pgType": "GEOGRAPHY(POINT,4326)" } } },
                "embedding": { "kind": "vector", "required": false, "dimensions": 3,
                               "annotations": { "db": { "pgType": "vector(3)" } } }
            },
            "options": { "timestamps": false, "softDelete": false },
            "annotations": {
                "db": { "tableName": "places", "indexes": [
                    { "fields": ["point"], "unique": false, "using": "gist" },
                    vector_index
                ] },
                "platform": { "access": { "read": { "type": "public" } } }
            }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// The schema each extension a push needs is installed in, by name.
async fn placement(pool: &PgPool) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT e.extname::text, n.nspname::text FROM pg_extension e
         JOIN pg_namespace n ON n.oid = e.extnamespace
         WHERE e.extname IN ('postgis', 'vector', 'unaccent', 'pgcrypto')
         ORDER BY e.extname",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

fn pairs(expected: &[(&str, &str)]) -> Vec<(String, String)> {
    expected
        .iter()
        .map(|(e, s)| (e.to_string(), s.to_string()))
        .collect()
}

/// Functions in `public` that belong to an extension: what PostgREST lists as `/rpc/*`.
async fn extension_functions_in_public(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_proc p
         JOIN pg_depend d ON d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e'
         WHERE p.pronamespace = 'public'::regnamespace",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn create_auth_users(pool: &PgPool) {
    exec(
        pool,
        "CREATE SCHEMA IF NOT EXISTS auth;
         CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT UNIQUE);",
    )
    .await
    .unwrap();
}

/// One row written with every extension type, as the API writes them: text in, cast by the column.
async fn insert_place(pool: &PgPool) {
    exec(
        pool,
        "INSERT INTO public.places (name, point, embedding)
         VALUES ('Café Zoë', 'SRID=4326;POINT(-0.1276 51.5072)', '[1,2,3]')",
    )
    .await
    .unwrap();
}

/// The row back, through the extensions' own output functions and an operator of each.
async fn read_place(pool: &PgPool) -> (String, String, String, bool) {
    sqlx::query_as(
        "SELECT slug, point::text, embedding::text, embedding = '[1,2,3]' FROM public.places",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_push_installs_its_extensions_in_the_extensions_schema() {
    common::with_integration_pool(|pool| async move {
        create_auth_users(&pool).await;
        push(&pool, &places()).await.expect("the push applies");

        assert_eq!(
            placement(&pool).await,
            pairs(&[
                ("pgcrypto", "extensions"),
                ("postgis", "extensions"),
                ("unaccent", "extensions"),
                ("vector", "extensions"),
            ]),
            "every extension a push creates goes in `extensions`"
        );
        assert_eq!(
            extension_functions_in_public(&pool).await,
            0,
            "no extension function is left in `public`, where PostgREST serves it as an RPC"
        );
        let usage: Vec<(String, bool)> = sqlx::query_as(
            "SELECT r, has_schema_privilege(r, 'extensions', 'USAGE')
             FROM unnest(ARRAY['anon', 'authenticated', 'service_role']) AS r
             WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) ORDER BY r",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(
            usage.iter().all(|(_, granted)| *granted),
            "the API roles can reach the extensions' types and operators: {usage:?}"
        );

        insert_place(&pool).await;
        let (slug, _, embedding, same_vector) = read_place(&pool).await;
        assert_eq!(slug, "cafe-zoe");
        assert_eq!(embedding, "[1,2,3]");
        assert!(same_vector);
        assert!(
            matches!(
                push(&pool, &places()).await.unwrap(),
                push::Outcome::UpToDate { .. }
            ),
            "a second push of the same schema has nothing to do"
        );
    })
    .await;
}

/// The plan a push of [`places`] makes, as the CLI and the server serialise it.
async fn planned(pool: &PgPool) -> Value {
    let ast = places();
    let plan = push::prepare(pool, &ast, "public").await.unwrap();
    serde_json::to_value(&plan.diff).unwrap()
}

fn relocations(diff: &Value) -> Vec<(String, String, String, String)> {
    diff["operations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|op| op["type"] == "relocate_extension")
        .map(|op| {
            let s = |k: &str| op[k].as_str().unwrap_or_default().to_string();
            (s("name"), s("from"), s("to"), s("risk"))
        })
        .collect()
}

#[tokio::test]
async fn a_push_plans_the_move_out_of_public_as_an_operation_that_needs_consent() {
    common::with_integration_pool(|pool| async move {
        create_auth_users(&pool).await;
        exec(
            &pool,
            "CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;
             CREATE EXTENSION IF NOT EXISTS unaccent WITH SCHEMA public;
             CREATE EXTENSION IF NOT EXISTS postgis WITH SCHEMA public;",
        )
        .await
        .unwrap();

        let diff = planned(&pool).await;
        assert_eq!(
            relocations(&diff),
            vec![
                (
                    "unaccent".to_string(),
                    "public".to_string(),
                    "extensions".to_string(),
                    "cautious".to_string()
                ),
                (
                    "vector".to_string(),
                    "public".to_string(),
                    "extensions".to_string(),
                    "cautious".to_string()
                ),
            ],
            "vector and unaccent are moved, with consent; postgis cannot be: {diff:#}"
        );
        let warnings = diff["warnings"].to_string();
        assert!(
            warnings.contains("postgis") && warnings.contains("UPGRADING.md"),
            "PostGIS in `public` is named, with where to read how to move it: {warnings}"
        );
    })
    .await;
}

/// An older engine's project: the extensions in `public`, and a ledger that recorded the columns
/// with their types qualified by `public`. Built from a current push by moving the relocatable
/// extensions back and accepting the result as the baseline; PostGIS cannot move, so it is put in
/// `public` before the first push, as an older engine would have.
async fn as_an_older_engine_placed_them(pool: &PgPool, ast: &SchemaAst) {
    exec(
        pool,
        "CREATE EXTENSION IF NOT EXISTS postgis WITH SCHEMA public;",
    )
    .await
    .unwrap();
    push(pool, ast).await.expect("the first push applies");
    insert_place(pool).await;
    exec(
        pool,
        "DO $older$ DECLARE e text; BEGIN
           FOREACH e IN ARRAY ARRAY['vector', 'unaccent', 'pgcrypto'] LOOP
             IF EXISTS (SELECT 1 FROM pg_extension
                        WHERE extname = e AND extnamespace <> 'public'::regnamespace) THEN
               EXECUTE format('ALTER EXTENSION %I SET SCHEMA public', e);
             END IF;
           END LOOP;
         END $older$;",
    )
    .await
    .unwrap();
    supatype_engine::inspect::rebaseline(pool, ast, "public", true)
        .await
        .expect("the older placement recorded as the baseline");
}

#[tokio::test]
async fn an_existing_project_has_vector_and_unaccent_moved_and_keeps_postgis_and_its_data() {
    common::with_integration_pool(|pool| async move {
        create_auth_users(&pool).await;
        let ast = places();
        as_an_older_engine_placed_them(&pool, &ast).await;
        let before = read_place(&pool).await;

        let moved = push(&pool, &ast).await.expect("the upgrade push applies");
        assert!(
            matches!(moved, push::Outcome::Applied { .. }),
            "moving the extensions is a migration of its own: {moved:?}"
        );
        assert_eq!(
            placement(&pool).await,
            pairs(&[
                ("pgcrypto", "extensions"),
                ("postgis", "public"),
                ("unaccent", "extensions"),
                ("vector", "extensions"),
            ]),
            "the relocatable extensions are moved, and PostGIS is left where it is"
        );
        assert_eq!(
            read_place(&pool).await,
            before,
            "the row reads back the same: nothing holding data was dropped or rewritten"
        );
        let recorded: String =
            sqlx::query_scalar("SELECT sql_up FROM _supatype.migrations ORDER BY id DESC LIMIT 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            recorded.contains("ALTER EXTENSION \"vector\" SET SCHEMA \"extensions\""),
            "the move is recorded in the history like any other statement:\n{recorded}"
        );

        insert_place_again(&pool).await;
        assert!(
            matches!(
                push(&pool, &ast).await.unwrap(),
                push::Outcome::UpToDate { .. }
            ),
            "the push after the move has nothing to do: no column or index is replaced for it"
        );
    })
    .await;
}

/// A second row after the move, with a name that needs `unaccent`, through PostGIS still in
/// `public` and pgvector now in `extensions`.
async fn insert_place_again(pool: &PgPool) {
    exec(
        pool,
        "INSERT INTO public.places (name, point, embedding)
         VALUES ('Señor Ñandú', 'SRID=4326;POINT(2.35 48.85)', '[3,2,1]')",
    )
    .await
    .unwrap();
    let slug: String =
        sqlx::query_scalar("SELECT slug FROM public.places WHERE name = 'Señor Ñandú'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(slug, "senor-nandu");
}

#[tokio::test]
async fn a_slug_is_made_whatever_search_path_the_writer_has() {
    common::with_integration_pool(|pool| async move {
        create_auth_users(&pool).await;
        push(&pool, &places()).await.expect("the push applies");
        // A writer whose path reaches neither `public` nor `extensions`: psql as a role with its
        // own `search_path`, or a function pinned to `pg_catalog`.
        let slug: String = sqlx::query_scalar(
            "WITH path AS (SELECT set_config('search_path', 'pg_catalog', true)),
                  written AS (
                    INSERT INTO public.places (name) SELECT 'Crème Brûlée' FROM path RETURNING slug
                  )
             SELECT slug FROM written",
        )
        .fetch_one(&pool)
        .await
        .expect("the slug trigger finds unaccent wherever it is installed");
        assert_eq!(slug, "creme-brulee");
    })
    .await;
}

/// The `hnsw` index on `embedding`, as the catalog renders it.
async fn vector_index_definition(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT pg_get_indexdef(i.indexrelid) FROM pg_index i
         JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_am am ON am.oid = c.relam
         WHERE i.indrelid = 'public.places'::regclass AND am.amname = 'hnsw'",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

/// pgvector has no default operator class for `hnsw`, so the index names one: cosine distance
/// unless the schema asks for L2 or inner product. A change of distance builds the index again.
#[tokio::test]
async fn a_vector_index_uses_the_distance_the_schema_names() {
    common::with_integration_pool(|pool| async move {
        create_auth_users(&pool).await;
        push(&pool, &places())
            .await
            .expect("the hnsw index is created");
        let cosine = vector_index_definition(&pool).await;
        assert!(cosine.contains("vector_cosine_ops"), "{cosine}");
        assert!(
            matches!(
                push(&pool, &places()).await.unwrap(),
                push::Outcome::UpToDate { .. }
            ),
            "the same index again is up to date"
        );

        for (distance, opclass) in [("l2", "vector_l2_ops"), ("innerProduct", "vector_ip_ops")] {
            let index = json!({ "fields": ["embedding"], "unique": false, "using": "hnsw",
                                "distance": distance });
            push(&pool, &places_with(index.clone()))
                .await
                .unwrap_or_else(|e| panic!("{distance}: {e}"));
            let definition = vector_index_definition(&pool).await;
            assert!(definition.contains(opclass), "{distance}: {definition}");
            assert!(
                matches!(
                    push(&pool, &places_with(index)).await.unwrap(),
                    push::Outcome::UpToDate { .. }
                ),
                "{distance}: the same index again is up to date"
            );
        }
    })
    .await;
}

/// A schema that asks for a distance on an index that has none, or an `hnsw` index on a column
/// pgvector cannot index, is refused when it is read, naming the field.
#[test]
fn a_vector_index_option_out_of_place_is_refused() {
    let doc = |index: Value| {
        let ast = places_with(json!({ "fields": ["embedding"], "unique": false, "using": "hnsw" }));
        let mut doc = serde_json::to_value(&ast).unwrap();
        doc["models"][0]["annotations"]["db"]["indexes"][1] = index;
        parser::parse(&doc.to_string())
            .map(|_| ())
            .unwrap_err()
            .to_string()
    };
    let on_gist =
        doc(json!({ "fields": ["point"], "unique": false, "using": "gist", "distance": "l2" }));
    assert!(on_gist.contains("only an `hnsw` index"), "{on_gist}");
    let on_text = doc(json!({ "fields": ["name"], "unique": false, "using": "hnsw" }));
    assert!(
        on_text.contains("'name', which is not a Vector field"),
        "{on_text}"
    );
}

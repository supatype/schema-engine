//! A many-to-many is one junction table, whichever side declares it (B6).
//!
//! `Post.tags: ManyToMany<Tag>` and `Tag.posts: ManyToMany<Post>` made `Tag_post` and `Post_tag`,
//! one per side and both mixed case, so a tag added from a post was not visible from the tag. Both
//! sides now share `post_tag`, named by the two tables sorted. A project an older engine pushed
//! keeps its links: one old table is renamed, and two are refused with the SQL that merges them.

mod common;

use serde_json::{json, Value};
use supatype_engine::parser::{self, ast::SchemaAst};

const POST: &str = "11111111-1111-1111-1111-111111111111";
const TAG: &str = "22222222-2222-2222-2222-222222222222";

fn id_field() -> Value {
    json!({ "kind": "uuid", "primaryKey": true, "required": true,
            "default": { "kind": "genRandomUuid" },
            "annotations": { "db": { "pgType": "UUID", "unique": false } } })
}

fn many(target: &str) -> Value {
    json!({ "kind": "relation", "cardinality": "manyToMany", "target": target })
}

fn model(name: &str, table: &str, relation: Option<(&str, &str)>) -> Value {
    let mut fields = json!({ "id": id_field() });
    if let Some((field, target)) = relation {
        fields[field] = many(target);
    }
    json!({ "name": name, "fields": fields,
            "options": { "timestamps": false, "softDelete": false },
            "annotations": { "db": { "tableName": table, "indexes": [] },
                             "platform": { "access": { "read": { "type": "public" } } } } })
}

fn parse(models: Vec<Value>) -> SchemaAst {
    let doc = json!({ "astVersion": 2, "models": models });
    parser::parse(&doc.to_string()).expect("the fixture parses")
}

/// Post and Tag, each declaring the relation, Post first.
fn both_sides() -> SchemaAst {
    parse(vec![
        model("Post", "post", Some(("tags", "Tag"))),
        model("Tag", "tag", Some(("posts", "Post"))),
    ])
}

fn names(ast: &SchemaAst) -> Vec<String> {
    ast.junction_tables.iter().map(|j| j.name.clone()).collect()
}

#[test]
fn both_sides_share_one_lowercase_junction() {
    assert_eq!(names(&both_sides()), vec!["post_tag".to_string()]);
}

#[test]
fn the_junction_does_not_depend_on_declaration_order() {
    let tag_first = parse(vec![
        model("Tag", "tag", Some(("posts", "Post"))),
        model("Post", "post", Some(("tags", "Tag"))),
    ]);
    assert_eq!(names(&tag_first), names(&both_sides()));
    let (a, b) = (
        &tag_first.junction_tables[0],
        &both_sides().junction_tables[0],
    );
    assert_eq!((&a.model_a, &a.fk_a), (&b.model_a, &b.fk_a));
}

#[test]
fn a_one_sided_declaration_uses_the_same_name() {
    let tag_only = parse(vec![
        model("Post", "post", None),
        model("Tag", "tag", Some(("posts", "Post"))),
    ]);
    assert_eq!(names(&tag_only), vec!["post_tag".to_string()]);
}

/// `ast` as an engine before B6 pushed it: one junction per declaring side, under its old name.
fn as_an_older_engine_named_it(mut ast: SchemaAst, old: &[&str]) -> SchemaAst {
    let current = ast.junction_tables[0].clone();
    ast.junction_tables = old
        .iter()
        .map(|name| {
            let mut jt = current.clone();
            jt.name = name.to_string();
            jt
        })
        .collect();
    ast
}

async fn rows(pool: &sqlx::PgPool) {
    let sql = format!(
        "INSERT INTO public.post (id) VALUES ('{POST}'); INSERT INTO public.tag (id) VALUES ('{TAG}');"
    );
    common::exec(pool, &sql).await.expect("the ends");
}

async fn link_count(pool: &sqlx::PgPool, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM public.{table}"))
        .fetch_one(pool)
        .await
        .expect("counts the links")
}

async fn table_exists(pool: &sqlx::PgPool, table: &str) -> bool {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(format!("public.\"{table}\""))
        .fetch_one(pool)
        .await
        .expect("looks the table up")
}

#[tokio::test(flavor = "multi_thread")]
async fn one_old_junction_is_renamed_with_its_links() {
    common::with_integration_pool(|pool| async move {
        let old = as_an_older_engine_named_it(both_sides(), &["Tag_post"]);
        common::push(&pool, &old).await.expect("the old push");
        rows(&pool).await;
        let link =
            format!("INSERT INTO public.\"Tag_post\" (post_id, tag_id) VALUES ('{POST}', '{TAG}')");
        common::exec(&pool, &link).await.expect("a link");
        common::push(&pool, &both_sides())
            .await
            .expect("the push renames the junction");
        assert!(!table_exists(&pool, "Tag_post").await);
        assert_eq!(link_count(&pool, "post_tag").await, 1);
        common::push(&pool, &both_sides())
            .await
            .expect("a second push");
        assert_eq!(link_count(&pool, "post_tag").await, 1);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn two_old_junctions_are_refused_with_the_merge() {
    common::with_integration_pool(|pool| async move {
        let old = as_an_older_engine_named_it(both_sides(), &["Tag_post", "Post_tag"]);
        common::push(&pool, &old).await.expect("the old push");
        let refused = common::push(&pool, &both_sides())
            .await
            .expect_err("two old junctions cannot both be renamed");
        let message = format!("{refused:#}");
        assert!(message.contains("\"Tag_post\""), "{message}");
        assert!(message.contains("\"Post_tag\""), "{message}");
        assert!(message.contains("ON CONFLICT DO NOTHING"), "{message}");
        assert!(table_exists(&pool, "Tag_post").await && table_exists(&pool, "Post_tag").await);
    })
    .await;
}

/// GraphQL reads the one junction from both ends.
#[tokio::test(flavor = "multi_thread")]
async fn graphql_reaches_the_junction_from_both_ends() {
    common::with_integration_pool(|pool| async move {
        let loaded = common::exec(&pool, "CREATE EXTENSION IF NOT EXISTS pg_graphql")
            .await
            .is_ok();
        assert!(
            loaded || !common::force_integration_tests(),
            "pg_graphql is missing"
        );
        if !loaded {
            return;
        }
        common::push(&pool, &both_sides()).await.expect("push");
        for end in ["post", "tag"] {
            let query = format!("{{ __type(name: \"{end}\") {{ fields {{ name }} }} }}");
            let result: Value = sqlx::query_scalar("SELECT graphql.resolve($1)")
                .bind(&query)
                .fetch_one(&pool)
                .await
                .expect("graphql resolves");
            let fields = result["data"]["__type"]["fields"].to_string();
            assert!(fields.contains("post_tagCollection"), "{end}: {fields}");
        }
    })
    .await;
}

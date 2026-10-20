//! GraphQL names a relation as the schema does.
//!
//! pg_graphql names a relation after the tables it joins: the reverse side of `talk.speaker_id` is
//! `talkCollection` on `speaker`, whatever the schema called it. A schema that declares
//! `talks: HasMany<Talk>` promised a `talks` field, and a query for it failed with
//! `Unknown field "talks" on type "speaker"`. The push now names both ends of each key in the
//! `@graphql` directive pg_graphql reads from the key's comment.

mod common;

use serde_json::{json, Value};
use supatype_engine::{parser, parser::ast::SchemaAst};

use common::{exec, push};

fn id_field() -> Value {
    json!({ "kind": "uuid", "primaryKey": true, "required": true,
            "default": { "kind": "genRandomUuid" },
            "annotations": { "db": { "pgType": "UUID", "unique": false } } })
}

fn model(name: &str, table: &str, fields: Value) -> Value {
    let mut all = json!({ "id": id_field() });
    for (key, field) in fields.as_object().expect("fields are an object") {
        all[key] = field.clone();
    }
    json!({ "name": name, "fields": all,
            "options": { "timestamps": false, "softDelete": false },
            "annotations": { "db": { "tableName": table, "indexes": [] },
                             "platform": { "access": { "read": { "type": "public" } } } } })
}

/// A speaker with the talks it gives, and a room that declares no relation back to its talks.
fn schema() -> SchemaAst {
    let speaker = model(
        "Speaker",
        "gr_speaker",
        json!({
            "talks": { "kind": "relation", "cardinality": "hasMany", "target": "Talk" }
        }),
    );
    let room = model("Room", "gr_room", json!({}));
    let talk = model(
        "Talk",
        "gr_talk",
        json!({
            "presenter": { "kind": "relation", "cardinality": "belongsTo", "target": "Speaker" },
            "room": { "kind": "relation", "cardinality": "belongsTo", "target": "Room" }
        }),
    );
    let doc = json!({ "astVersion": 2, "models": [speaker, room, talk] });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// The field names GraphQL's type `name` lists.
async fn fields_of(pool: &sqlx::PgPool, name: &str) -> Vec<String> {
    let query = format!("{{ __type(name: \"{name}\") {{ fields {{ name }} }} }}");
    let result: Value = sqlx::query_scalar("SELECT graphql.resolve($1)")
        .bind(&query)
        .fetch_one(pool)
        .await
        .expect("graphql resolves");
    result["data"]["__type"]["fields"]
        .as_array()
        .unwrap_or_else(|| panic!("no type {name}: {result}"))
        .iter()
        .filter_map(|f| f["name"].as_str().map(str::to_string))
        .collect()
}

/// Whether this database has pg_graphql; outside a forced run a database without it skips.
async fn has_graphql(pool: &sqlx::PgPool) -> bool {
    let loaded = exec(pool, "CREATE EXTENSION IF NOT EXISTS pg_graphql")
        .await
        .is_ok();
    assert!(
        loaded || !common::force_integration_tests(),
        "pg_graphql is missing"
    );
    loaded
}

async fn key_comment(pool: &sqlx::PgPool, key: &str) -> Option<String> {
    sqlx::query_scalar(
        "SELECT obj_description(oid, 'pg_constraint') FROM pg_constraint WHERE conname = $1",
    )
    .bind(key)
    .fetch_one(pool)
    .await
    .expect("the key exists")
}

/// Both ends of a key carry the schema's names: `talks` on the speaker, `presenter` on the talk,
/// where pg_graphql alone says `gr_talkCollection` and `gr_speaker`.
#[tokio::test(flavor = "multi_thread")]
async fn each_end_of_a_relation_has_the_name_the_schema_gave_it() {
    common::with_integration_pool(|pool| async move {
        if !has_graphql(&pool).await {
            return;
        }
        push(&pool, &schema()).await.unwrap();
        let speaker = fields_of(&pool, "gr_speaker").await;
        assert!(speaker.contains(&"talks".to_string()), "{speaker:?}");
        assert!(
            !speaker.contains(&"gr_talkCollection".to_string()),
            "{speaker:?}"
        );
        let talk = fields_of(&pool, "gr_talk").await;
        assert!(talk.contains(&"presenter".to_string()), "{talk:?}");
        assert!(talk.contains(&"room".to_string()), "{talk:?}");
    })
    .await;
}

/// A relation the far side does not declare keeps pg_graphql's own name for it, rather than one
/// made up for it.
#[tokio::test(flavor = "multi_thread")]
async fn an_undeclared_reverse_keeps_the_default_name() {
    common::with_integration_pool(|pool| async move {
        if !has_graphql(&pool).await {
            return;
        }
        push(&pool, &schema()).await.unwrap();
        let room = fields_of(&pool, "gr_room").await;
        assert!(room.contains(&"gr_talkCollection".to_string()), "{room:?}");
    })
    .await;
}

/// What someone wrote on a key stays, and a second push leaves the comment exactly as the first
/// left it.
#[tokio::test(flavor = "multi_thread")]
async fn a_comment_on_the_key_survives_and_a_second_push_changes_nothing() {
    common::with_integration_pool(|pool| async move {
        if !has_graphql(&pool).await {
            return;
        }
        push(&pool, &schema()).await.unwrap();
        let key = "gr_talk_presenter_id_fkey";
        exec(
            &pool,
            &format!(
                "COMMENT ON CONSTRAINT {key} ON public.gr_talk IS 'who gives it (one person)'"
            ),
        )
        .await
        .unwrap();
        push(&pool, &schema()).await.unwrap();
        let first = key_comment(&pool, key).await.expect("a comment");
        assert!(first.starts_with("who gives it (one person)\n"), "{first}");
        assert!(first.contains("@graphql("), "{first}");
        push(&pool, &schema()).await.unwrap();
        assert_eq!(
            key_comment(&pool, key).await.as_deref(),
            Some(first.as_str())
        );
        let speaker = fields_of(&pool, "gr_speaker").await;
        assert!(speaker.contains(&"talks".to_string()), "{speaker:?}");
    })
    .await;
}

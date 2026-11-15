//! Private realtime channels, engine half: the AST, the validation, the SQL a push emits, and the
//! functions run against Postgres as `anon` and as two signed-in users.
//!
//! The fixture is the design note's example: a `LotChannel` (`lot:{id}`, one UUID parameter, rules
//! that read `lot_watchers` and `lots` through `Rows<>`) and a `Lobby` (a literal topic).

mod common;

use serde_json::{json, Value};
use sqlx::{Connection, PgPool, Row};
use supatype_engine::generator::sql::realtime;
use supatype_engine::parser::{self, ast::SchemaAst};

const ALICE: &str = "11111111-1111-1111-1111-111111111111";
const BOB: &str = "22222222-2222-2222-2222-222222222222";
const LOT_1: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const LOT_2: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

fn uuid_field(default: bool) -> Value {
    let mut field = json!({
        "kind": "uuid", "required": true,
        "annotations": { "db": { "pgType": "UUID", "unique": false, "index": false } }
    });
    if default {
        field["primaryKey"] = json!(true);
        field["default"] = json!({ "kind": "genRandomUuid" });
    }
    field
}

fn model(name: &str, table: &str, fields: Value, access: Value) -> Value {
    json!({
        "name": name, "fields": fields, "options": {},
        "annotations": {
            "db": { "tableName": table, "indexes": [] },
            "platform": { "access": access }
        }
    })
}

fn mine(column: &str) -> Value {
    json!({ "type": "compare", "left": { "kind": "column", "name": column },
            "op": "eq", "right": { "kind": "authUid" } })
}

fn watchers() -> Value {
    json!({ "kind": "rows", "table": "lot_watchers", "column": "lot_id", "where": mine("user_id") })
}

fn lot_channel() -> Value {
    json!({
        "name": "LotChannel", "pattern": "lot:{id}",
        "params": [{ "name": "id", "type": "uuid" }],
        "access": {
            "join": { "type": "any", "rules": [
                { "type": "in", "column": "id", "source": watchers() },
                { "type": "role", "roles": ["auctioneer"] } ] },
            "send": { "type": "any", "rules": [
                { "type": "exists", "source": { "kind": "rows", "table": "lots", "column": "id",
                    "where": { "type": "all", "rules": [
                        { "type": "compare", "left": { "kind": "column", "name": "id" }, "op": "eq",
                          "right": { "kind": "param", "name": "id" } },
                        mine("seller_id") ] } } },
                { "type": "role", "roles": ["auctioneer"] } ] },
            "track": { "type": "all", "rules": [
                { "type": "authenticated" },
                { "type": "in", "column": "id", "source": watchers() } ] }
        }
    })
}

fn lobby() -> Value {
    let authenticated = json!({ "type": "authenticated" });
    json!({
        "name": "Lobby", "pattern": "lobby", "params": [],
        "access": { "join": authenticated, "send": authenticated, "track": authenticated }
    })
}

fn document(channels: Vec<Value>, mode: &str) -> Value {
    let models = vec![
        model(
            "Lot",
            "lots",
            json!({
                "id": uuid_field(true), "seller_id": uuid_field(false)
            }),
            json!({ "read": { "type": "public" } }),
        ),
        model(
            "LotWatcher",
            "lot_watchers",
            json!({
                "id": uuid_field(true), "lot_id": uuid_field(false), "user_id": uuid_field(false)
            }),
            json!({ "read": mine("user_id") }),
        ),
    ];
    json!({
        "astVersion": 2, "models": models, "channels": channels,
        "realtime": { "channels": mode }
    })
}

fn parse(doc: &Value) -> anyhow::Result<SchemaAst> {
    parser::parse(&doc.to_string())
}

fn example() -> SchemaAst {
    parse(&document(vec![lot_channel(), lobby()], "declared")).expect("the example parses")
}

// ---------------------------------------------------------------------------------------------
// The SQL a push emits
// ---------------------------------------------------------------------------------------------

fn function_body(ast: &SchemaAst, name: &str) -> String {
    realtime::functions(ast, "public")
        .into_iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no function {name}"))
        .body
}

#[test]
fn the_example_renders_one_branch_per_shape_in_declaration_order() {
    let body = function_body(&example(), "realtime_channel_access");
    let lot = body.find("-- LotChannel: lot:{id}").expect("lot branch");
    let misfit = body
        .find("whose parameters do not fit")
        .expect("misfit branch");
    let lobby = body.find("-- Lobby: lobby").expect("lobby branch");
    assert!(lot < misfit && misfit < lobby, "{body}");
    assert!(body.contains("IF $1 = 'lobby' THEN"), "{body}");
}

#[test]
fn the_cast_is_inside_a_case_guarded_by_the_typed_shape() {
    let body = function_body(&example(), "realtime_channel_access");
    assert!(
        body.contains("CASE WHEN $1 ~ '^lot:([0-9a-fA-F]{8}-"),
        "the cast must be guarded by the shape: {body}"
    );
    assert!(body.contains("))[1]::uuid END AS \"id\""), "{body}");
}

#[test]
fn a_param_inside_a_rows_filter_reads_the_derived_column() {
    let body = function_body(&example(), "realtime_channel_access");
    assert!(
        body.contains("\"lots\".\"id\" = \"_realtime_channel\".\"id\""),
        "Param<\"id\"> must qualify as the derived column, not the source table: {body}"
    );
}

#[test]
fn every_emitted_function_is_invoker_or_pins_its_search_path() {
    for f in realtime::functions(&example(), "public") {
        assert!(f.attributes.contains("SET search_path = ''"), "{}", f.name);
        assert!(
            !f.attributes.contains("SECURITY DEFINER"),
            "{} must not be definer: it would judge the owner, not the caller",
            f.name
        );
    }
}

#[test]
fn an_operation_left_out_renders_false() {
    let mut doc = document(vec![lobby()], "open");
    doc["channels"][0]["access"] = json!({ "join": { "type": "authenticated" } });
    let body = function_body(&parse(&doc).unwrap(), "realtime_channel_access");
    assert!(body.contains("NULL::boolean, NULL::boolean"), "{body}");
}

#[test]
fn a_schema_with_no_channels_still_emits_every_function_with_no_rows() {
    let ast = parse(&json!({ "astVersion": 2, "models": [] })).unwrap();
    let body = function_body(&ast, "realtime_channel_access");
    assert!(!body.contains("RETURN QUERY"), "{body}");
    assert!(function_body(&ast, "realtime_channel_mode").contains("'open'"));
    assert!(function_body(&ast, "realtime_channel_send_checks").contains("WHERE FALSE"));
    assert!(function_body(&ast, "realtime_channel_dependencies").contains("WHERE FALSE"));
}

#[test]
fn the_mode_function_carries_the_projects_setting() {
    assert!(function_body(&example(), "realtime_channel_mode").contains("'declared'"));
}

#[test]
fn dependencies_list_each_table_a_rule_reads_once() {
    let body = function_body(&example(), "realtime_channel_dependencies");
    assert!(
        body.contains("('LotChannel'::text, 'public'::text, 'lot_watchers'::text)"),
        "{body}"
    );
    assert!(
        body.contains("('LotChannel'::text, 'public'::text, 'lots'::text)"),
        "{body}"
    );
    assert_eq!(body.matches("lot_watchers").count(), 1, "{body}");
    assert!(
        !body.contains("Lobby"),
        "a channel that reads no table has no row: {body}"
    );
}

// ---------------------------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------------------------

fn refused(channels: Vec<Value>) -> String {
    match parse(&document(channels, "open")) {
        Ok(_) => panic!("expected the schema to be refused"),
        Err(e) => format!("{e:#}"),
    }
}

fn channel(name: &str, pattern: &str, params: Value, join: Value) -> Value {
    json!({ "name": name, "pattern": pattern, "params": params, "access": { "join": join } })
}

#[test]
fn two_patterns_that_can_match_one_topic_are_refused_naming_both() {
    let id = json!([{ "name": "id", "type": "string" }]);
    let message = refused(vec![
        channel("Lot", "lot:{id}", id, json!({ "type": "authenticated" })),
        channel(
            "Featured",
            "lot:featured",
            json!([]),
            json!({ "type": "authenticated" }),
        ),
    ]);
    assert!(
        message.contains("'Lot'") && message.contains("'Featured'"),
        "{message}"
    );
}

#[test]
fn a_uuid_parameter_and_a_literal_that_is_not_a_uuid_do_not_overlap() {
    let id = json!([{ "name": "id", "type": "uuid" }]);
    parse(&document(
        vec![
            channel("Lot", "lot:{id}", id, json!({ "type": "authenticated" })),
            channel(
                "Featured",
                "lot:featured",
                json!([]),
                json!({ "type": "authenticated" }),
            ),
        ],
        "open",
    ))
    .expect("disjoint");
}

#[test]
fn a_wildcard_overlaps_what_it_covers_and_not_what_it_does_not() {
    let any = json!({ "type": "authenticated" });
    let message = refused(vec![
        channel("Org", "org:*", json!([]), any.clone()),
        channel("Deep", "org:a:b", json!([]), any.clone()),
    ]);
    assert!(
        message.contains("'Org'") && message.contains("'Deep'"),
        "{message}"
    );
    parse(&document(
        vec![
            channel("Org", "org:*", json!([]), any.clone()),
            channel("Org", "org", json!([]), any.clone()),
        ],
        "open",
    ))
    .expect_err("the same name twice is refused");
    parse(&document(
        vec![
            channel("Org", "org:*", json!([]), any.clone()),
            channel("Bare", "org", json!([]), any),
        ],
        "open",
    ))
    .expect("`org:*` needs at least one segment after `org`, so `org` is its own channel");
}

#[test]
fn a_pattern_and_its_parameters_must_agree() {
    let any = json!({ "type": "authenticated" });
    let unbound = refused(vec![channel("A", "a:{x}", json!([]), any.clone())]);
    assert!(unbound.contains("{x}"), "{unbound}");
    let unused = refused(vec![channel(
        "A",
        "a",
        json!([{ "name": "x", "type": "uuid" }]),
        any,
    )]);
    assert!(unused.contains("parameter 'x'"), "{unused}");
}

#[test]
fn reserved_prefixes_and_misplaced_wildcards_are_refused() {
    let any = json!({ "type": "authenticated" });
    for pattern in ["realtime:x", "_supatype_x", "a:*:b", "a::b", "a:b c"] {
        let message = refused(vec![channel("A", pattern, json!([]), any.clone())]);
        assert!(message.contains("'A'"), "{pattern}: {message}");
    }
}

#[test]
fn a_rule_naming_something_that_is_not_a_parameter_is_refused() {
    let id = json!([{ "name": "id", "type": "uuid" }]);
    let bad_column =
        json!({ "type": "in", "column": "nope", "source": { "kind": "literal", "values": ["a"] } });
    assert!(refused(vec![channel("A", "a:{id}", id.clone(), bad_column)]).contains("\"nope\""));
    let bad_param = json!({ "type": "compare", "left": { "kind": "authUid" }, "op": "eq",
                            "right": { "kind": "param", "name": "other" } });
    assert!(
        refused(vec![channel("A", "a:{id}", id.clone(), bad_param)]).contains("Param<\"other\">")
    );
    let owner = json!({ "type": "owner", "field": "id" });
    assert!(refused(vec![channel("A", "a:{id}", id, owner)]).contains("Owner"));
}

#[test]
fn event_and_payload_are_valid_only_in_send() {
    let event = json!({ "type": "event", "name": "bid" });
    let message = refused(vec![channel("A", "a", json!([]), event)]);
    assert!(message.contains("valid only in `send`"), "{message}");
}

#[test]
fn param_event_and_payload_in_a_model_rule_are_refused() {
    let mut doc = document(vec![], "open");
    doc["models"][0]["annotations"]["platform"]["access"]["read"] = json!({ "type": "compare", "left": { "kind": "param", "name": "id" }, "op": "eq",
                "right": { "kind": "authUid" } });
    let message = format!("{:#}", parse(&doc).unwrap_err());
    assert!(
        message.contains("Model 'Lot'") && message.contains("Param"),
        "{message}"
    );
}

fn send_rule(rule: Value) -> Value {
    let mut c = lobby();
    c["access"]["send"] = rule;
    c
}

#[test]
fn content_nodes_split_out_of_a_top_level_all_and_leave_the_rest_for_sql() {
    let rule = json!({ "type": "all", "rules": [
        { "type": "event", "name": "bid" },
        { "type": "payload", "field": "amount", "check": { "kind": "number", "min": 1 } },
        { "type": "authenticated" } ] });
    let ast = parse(&document(vec![send_rule(rule)], "declared")).unwrap();
    let checks = function_body(&ast, "realtime_channel_send_checks");
    assert!(checks.contains(r#"{"type":"all","rules":[{"type":"event","name":"bid"},{"type":"payload","field":"amount","check":{"kind":"number","min":1.0}}]}"#), "{checks}");
    let access = function_body(&ast, "realtime_channel_access");
    assert!(
        !access.contains("bid"),
        "content must not reach the access function: {access}"
    );
}

#[test]
fn content_mixed_with_caller_tests_under_any_or_not_is_refused() {
    let rule = json!({ "type": "any", "rules": [
        { "type": "all", "rules": [ { "type": "event", "name": "a" }, { "type": "role", "roles": ["admin"] } ] },
        { "type": "event", "name": "b" } ] });
    let message = refused(vec![send_rule(rule)]);
    assert!(message.contains("without widening it"), "{message}");
    let not = json!({ "type": "not", "rule": { "type": "all", "rules": [
        { "type": "event", "name": "a" }, { "type": "authenticated" } ] } });
    assert!(refused(vec![send_rule(not)]).contains("without widening it"));
}

#[test]
fn a_content_only_rule_under_any_is_still_the_servers_to_decide() {
    let rule = json!({ "type": "any", "rules": [
        { "type": "event", "name": "a" }, { "type": "event", "name": "b" } ] });
    let ast = parse(&document(vec![send_rule(rule)], "declared")).unwrap();
    assert!(function_body(&ast, "realtime_channel_send_checks").contains(r#""type":"any""#));
}

#[test]
fn only_astversion_two_is_read() {
    parse(&json!({ "astVersion": 2, "models": [], "channels": [lobby()] }))
        .expect("v2 carries channels");
    let message = format!(
        "{:#}",
        parse(&json!({ "astVersion": 3, "models": [] })).unwrap_err()
    );
    assert!(message.contains("astVersion"), "{message}");
}

#[test]
fn an_unknown_mode_is_refused() {
    let message = format!(
        "{:#}",
        parse(&json!({ "astVersion": 2, "models": [], "realtime": { "channels": "sometimes" } }))
            .unwrap_err()
    );
    assert!(message.contains("realtime"), "{message}");
}

#[test]
fn the_ast_round_trips_with_its_channels() {
    let ast = example();
    let again = parse(&serde_json::to_value(&ast).unwrap()).unwrap();
    assert_eq!(ast.channels, again.channels);
    assert_eq!(ast.realtime, again.realtime);
    assert_eq!(again.ast_version, 2);
}

// ---------------------------------------------------------------------------------------------
// Against Postgres
// ---------------------------------------------------------------------------------------------

/// One request as `role`, with `sub` as its user: `SET LOCAL ROLE` and the claims, on a
/// connection of its own so no state survives into the next.
async fn as_caller<T, F>(pool: &PgPool, role: &str, sub: Option<&str>, f: F) -> T
where
    F: for<'c> FnOnce(
        &'c mut sqlx::PgConnection,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'c>>,
{
    let mut conn = pool.acquire().await.expect("connection");
    let mut tx = conn.begin().await.expect("begin");
    let claims = match sub {
        Some(sub) => json!({ "sub": sub, "role": role }),
        None => json!({ "role": role }),
    };
    sqlx::query("SELECT set_config('request.jwt.claims', $1, true)")
        .bind(claims.to_string())
        .execute(&mut *tx)
        .await
        .expect("claims");
    let db_role = if role == "service_role" {
        "service_role"
    } else if sub.is_some() {
        "authenticated"
    } else {
        "anon"
    };
    sqlx::raw_sql(&format!("SET LOCAL ROLE {db_role}"))
        .execute(&mut *tx)
        .await
        .expect("role");
    let out = f(&mut tx).await;
    tx.rollback().await.expect("rollback");
    out
}

#[derive(Debug, PartialEq)]
struct Verdict {
    channel: String,
    pattern: String,
    fits: bool,
    param_error: Option<String>,
    join: Option<bool>,
    send: Option<bool>,
    track: Option<bool>,
}

async fn access(pool: &PgPool, role: &str, sub: Option<&str>, topic: &str) -> Vec<Verdict> {
    let topic = topic.to_string();
    as_caller(pool, role, sub, move |conn| {
        Box::pin(async move {
            sqlx::query(
                "SELECT channel, pattern, fits, param_error, can_join, can_send, can_track \
                 FROM _supatype.realtime_channel_access($1)",
            )
            .bind(topic)
            .fetch_all(&mut *conn)
            .await
            .expect("the access function answers")
            .iter()
            .map(|r| Verdict {
                channel: r.get(0),
                pattern: r.get(1),
                fits: r.get(2),
                param_error: r.get(3),
                join: r.get(4),
                send: r.get(5),
                track: r.get(6),
            })
            .collect()
        })
    })
    .await
}

async fn seed(pool: &PgPool) {
    sqlx::raw_sql(&format!(
        "INSERT INTO lots (id, seller_id) VALUES ('{LOT_1}', '{ALICE}'), ('{LOT_2}', '{BOB}');
         INSERT INTO lot_watchers (lot_id, user_id) VALUES ('{LOT_1}', '{BOB}');"
    ))
    .execute(pool)
    .await
    .expect("seed");
}

fn verdict(channel: &str, join: bool, send: bool, track: bool) -> Vec<Verdict> {
    let pattern = if channel == "Lobby" {
        "lobby"
    } else {
        "lot:{id}"
    };
    vec![Verdict {
        channel: channel.into(),
        pattern: pattern.into(),
        fits: true,
        param_error: None,
        join: Some(join),
        send: Some(send),
        track: Some(track),
    }]
}

#[tokio::test]
async fn the_access_function_judges_each_caller_by_the_rules() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &example()).await.expect("the push applies");
        seed(&pool).await;
        let lot = format!("lot:{LOT_1}");

        // Bob watches lot 1 and does not sell it.
        assert_eq!(access(&pool, "authenticated", Some(BOB), &lot).await, verdict("LotChannel", true, false, true));
        // Alice sells lot 1 and does not watch it.
        assert_eq!(access(&pool, "authenticated", Some(ALICE), &lot).await, verdict("LotChannel", false, true, false));
        // A signed-out caller gets nothing, and gets an answer.
        assert_eq!(access(&pool, "anon", None, &lot).await, verdict("LotChannel", false, false, false));
        // The role claim opens join and send, not track.
        let auctioneer = as_caller(&pool, "authenticated", Some(ALICE), |c| Box::pin(async move {
            sqlx::query("SELECT set_config('request.jwt.claims', '{\"sub\":\"11111111-1111-1111-1111-111111111111\",\"role\":\"auctioneer\"}', true)")
                .execute(&mut *c).await.unwrap();
            sqlx::query("SELECT can_join, can_send, can_track FROM _supatype.realtime_channel_access($1)")
                .bind(format!("lot:{LOT_2}")).fetch_one(&mut *c).await.unwrap().get::<Option<bool>, _>(0)
        })).await;
        assert!(auctioneer == Some(true), "Role<auctioneer> must open join");

        // Literal topic.
        assert_eq!(access(&pool, "authenticated", Some(BOB), "lobby").await, verdict("Lobby", true, true, true));
        assert_eq!(access(&pool, "anon", None, "lobby").await, verdict("Lobby", false, false, false));
    })
    .await;
}

#[tokio::test]
async fn an_undeclared_topic_has_no_row() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &example())
            .await
            .expect("the push applies");
        for topic in ["lobby-2", "lobby:x", "other", "", "lot", "lot:", "lot:a:b"] {
            assert!(
                access(&pool, "authenticated", Some(BOB), topic)
                    .await
                    .is_empty(),
                "{topic:?}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn a_topic_that_does_not_fit_answers_without_raising() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &example())
            .await
            .expect("the push applies");
        for topic in [
            "lot:abc",
            "lot:not-a-uuid",
            &format!("lot:{LOT_1}0"),
            "lot:{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}",
            "lot:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            let rows = access(&pool, "authenticated", Some(BOB), topic).await;
            assert_eq!(
                rows,
                vec![Verdict {
                    channel: "LotChannel".into(),
                    pattern: "lot:{id}".into(),
                    fits: false,
                    param_error: Some("id must be a UUID".into()),
                    join: Some(false),
                    send: Some(false),
                    track: Some(false),
                }],
                "{topic}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn rows_in_a_rule_respect_row_level_security_for_the_caller() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &example())
            .await
            .expect("the push applies");
        seed(&pool).await;
        // Alice has no watcher row. The table's own policy shows each user their own rows, so a
        // function that judged as the owner would see Bob's row and admit her.
        let lot = format!("lot:{LOT_1}");
        let alice = access(&pool, "authenticated", Some(ALICE), &lot).await;
        assert!(
            alice[0].join == Some(false),
            "Alice must not be judged by Bob's watcher row: {alice:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn the_mode_checks_and_dependencies_functions_answer() {
    common::with_integration_pool(|pool| async move {
        let ast = parse(&document(vec![
            lot_channel(),
            send_rule(json!({ "type": "all", "rules": [{ "type": "event", "name": "x" }] })),
        ], "declared")).unwrap();
        common::push(&pool, &ast).await.expect("the push applies");
        let mode: String = sqlx::query_scalar("SELECT _supatype.realtime_channel_mode()").fetch_one(&pool).await.unwrap();
        assert_eq!(mode, "declared");
        let checks: Vec<(String, Value)> = sqlx::query_as("SELECT channel, checks FROM _supatype.realtime_channel_send_checks()").fetch_all(&pool).await.unwrap();
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].0, "Lobby");
        assert_eq!(checks[0].1["rules"][0]["name"], "x");
        let mut deps: Vec<(String, String, String)> = sqlx::query_as("SELECT channel, table_schema, table_name FROM _supatype.realtime_channel_dependencies()").fetch_all(&pool).await.unwrap();
        deps.sort_by(|a, b| a.2.cmp(&b.2));
        assert_eq!(deps, vec![
            ("LotChannel".into(), "public".into(), "lot_watchers".into()),
            ("LotChannel".into(), "public".into(), "lots".into()),
        ]);
    })
    .await;
}

#[tokio::test]
async fn a_repush_removing_a_channel_removes_its_branch() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &example()).await.expect("first");
        common::push(&pool, &parse(&document(vec![lobby()], "open")).unwrap())
            .await
            .expect("second");
        assert!(
            access(&pool, "authenticated", Some(BOB), &format!("lot:{LOT_1}"))
                .await
                .is_empty()
        );
        assert_eq!(
            access(&pool, "authenticated", Some(BOB), "lobby")
                .await
                .len(),
            1
        );
        let mode: String = sqlx::query_scalar("SELECT _supatype.realtime_channel_mode()")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(mode, "open");
    })
    .await;
}

#[tokio::test]
async fn the_access_function_is_invoker_pinned_and_not_open_to_public() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &example())
            .await
            .expect("the push applies");
        let rows = sqlx::query(
            "SELECT p.proname, p.prosecdef, p.proconfig::text, \
                    has_function_privilege('public', p.oid, 'EXECUTE') \
             FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
             WHERE n.nspname = '_supatype' AND p.proname LIKE 'realtime_%'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), realtime::FUNCTION_NAMES.len());
        for row in rows {
            let name: String = row.get(0);
            assert!(!row.get::<bool, _>(1), "{name} is security definer");
            let config: String = row.get(2);
            assert!(config.replace('\\', "").contains("search_path=\"\""), "{name}: {config}");
            assert!(!row.get::<bool, _>(3), "{name} is executable by PUBLIC");
        }
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// realtime_send
// ---------------------------------------------------------------------------------------------

/// Runs `realtime_send` as a caller and returns the error's SQLSTATE and message, if it raised.
async fn send_as(
    pool: &PgPool,
    role: &str,
    sub: Option<&str>,
    topic: &str,
    event: &str,
    payload: Value,
) -> Result<(), (String, String)> {
    let (topic, event) = (topic.to_string(), event.to_string());
    as_caller(pool, role, sub, move |conn| {
        Box::pin(async move {
            sqlx::query("SELECT _supatype.realtime_send($1, $2, $3)")
                .bind(topic)
                .bind(event)
                .bind(payload)
                .execute(&mut *conn)
                .await
                .map(|_| ())
                .map_err(|e| {
                    let db = e.as_database_error().expect("a database error");
                    (
                        db.code().unwrap_or_default().to_string(),
                        db.message().to_string(),
                    )
                })
        })
    })
    .await
}

fn send_document(mode: &str) -> SchemaAst {
    let content = json!({ "type": "all", "rules": [
        { "type": "event", "name": "bid" },
        { "type": "payload", "field": "amount", "check": { "kind": "number", "min": 1, "max": 1000 } },
        { "type": "payload", "field": "note", "check": { "kind": "string", "maxLength": 5 } },
        { "type": "authenticated" } ] });
    let mut bids = lobby();
    bids["name"] = json!("Bids");
    bids["pattern"] = json!("bids");
    bids["access"]["send"] = content;
    parse(&document(vec![lot_channel(), lobby(), bids], mode)).expect("parses")
}

#[tokio::test]
async fn realtime_send_raises_42501_with_the_documented_wording() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &send_document("declared"))
            .await
            .expect("push");
        seed(&pool).await;
        let lot = format!("lot:{LOT_1}");

        // Bob watches lot 1 but does not sell it.
        let (code, message) = send_as(&pool, "authenticated", Some(BOB), &lot, "bid", json!({}))
            .await
            .unwrap_err();
        assert_eq!(code, "42501");
        assert_eq!(
            message,
            format!("not allowed to broadcast on {lot}: the send rule of LotChannel denied it")
        );

        // Does not fit, and undeclared in declared mode.
        let (_, message) = send_as(
            &pool,
            "authenticated",
            Some(BOB),
            "lot:abc",
            "bid",
            json!({}),
        )
        .await
        .unwrap_err();
        assert_eq!(message, "lot:abc does not fit lot:{id}: id must be a UUID");
        let (code, message) = send_as(
            &pool,
            "authenticated",
            Some(BOB),
            "nowhere",
            "bid",
            json!({}),
        )
        .await
        .unwrap_err();
        assert_eq!(code, "42501");
        assert!(
            message.starts_with("nowhere matches no declared channel"),
            "{message}"
        );

        // Alice sells lot 1: allowed.
        send_as(
            &pool,
            "authenticated",
            Some(ALICE),
            &lot,
            "bid",
            json!({ "amount": 5 }),
        )
        .await
        .expect("seller may send");
        // The service role bypasses every rule, and so does a topic nobody declared.
        send_as(&pool, "service_role", None, "nowhere", "x", json!({}))
            .await
            .expect("service role");
    })
    .await;
}

#[tokio::test]
async fn realtime_send_is_refused_to_anon_and_open_mode_admits_an_undeclared_topic() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &send_document("open"))
            .await
            .expect("push");
        let denied = send_as(&pool, "anon", None, "lobby", "x", json!({}))
            .await
            .unwrap_err();
        assert_eq!(denied.0, "42501", "anon holds no EXECUTE: {denied:?}");
        send_as(&pool, "authenticated", Some(BOB), "nowhere", "x", json!({}))
            .await
            .expect("open mode, undeclared");
        // A declared channel is enforced in either mode.
        let (_, message) = send_as(
            &pool,
            "authenticated",
            Some(BOB),
            &format!("lot:{LOT_1}"),
            "x",
            json!({}),
        )
        .await
        .unwrap_err();
        assert!(message.contains("LotChannel denied it"), "{message}");
    })
    .await;
}

#[tokio::test]
async fn realtime_send_checks_the_event_and_payload_and_fails_closed() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &send_document("declared"))
            .await
            .expect("push");
        let ok = json!({ "amount": 10, "note": "hi" });
        send_as(&pool, "authenticated", Some(BOB), "bids", "bid", ok)
            .await
            .expect("a fitting message");
        for payload in [
            json!({ "amount": 0, "note": "hi" }),
            json!({ "amount": 1001, "note": "hi" }),
            json!({ "amount": "10", "note": "hi" }),
            json!({ "note": "hi" }),
            json!({ "amount": 10, "note": "toolong" }),
            json!({ "amount": 10, "note": 5 }),
            json!(null),
            json!([1]),
        ] {
            let (code, message) = send_as(
                &pool,
                "authenticated",
                Some(BOB),
                "bids",
                "bid",
                payload.clone(),
            )
            .await
            .unwrap_err();
            assert_eq!(code, "42501", "{payload}");
            assert_eq!(
                message,
                "not allowed to broadcast bid on bids: the send rule of Bids refused the payload",
                "{payload}"
            );
        }
        let (code, _) = send_as(
            &pool,
            "authenticated",
            Some(BOB),
            "bids",
            "other",
            json!({ "amount": 10, "note": "hi" }),
        )
        .await
        .unwrap_err();
        assert_eq!(code, "42501", "the wrong event");
    })
    .await;
}

#[tokio::test]
async fn the_outbox_is_written_and_emptied_in_one_transaction_and_reaches_the_slot() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &send_document("declared"))
            .await
            .expect("push");
        let wal: String = sqlx::query_scalar("SHOW wal_level")
            .fetch_one(&pool)
            .await
            .unwrap();
        if wal != "logical" {
            assert!(!common::force_integration_tests(), "wal_level is {wal}");
            eprintln!("SKIP slot check: wal_level is {wal}");
            return;
        }
        let mut conn = pool.acquire().await.unwrap();
        if !create_slot(&mut conn).await {
            assert!(!common::force_integration_tests(), "no usable output plugin");
            eprintln!("SKIP slot check: neither wal2json nor test_decoding may be used here");
            return;
        }
        // Committed for real, as a superuser (which `realtime_send` treats as the service role).
        sqlx::query("SELECT _supatype.realtime_send('lobby', 'hello', '{\"a\":1}')")
            .execute(&mut *conn)
            .await
            .unwrap();
        let changes: Vec<String> = sqlx::query_scalar(
            "SELECT data FROM pg_logical_slot_get_changes('rt_outbox_test', NULL, NULL)",
        )
        .fetch_all(&mut *conn)
        .await
        .unwrap();
        sqlx::query("SELECT pg_drop_replication_slot('rt_outbox_test')")
            .execute(&mut *conn)
            .await
            .unwrap();
        let outbox: Vec<&String> = changes
            .iter()
            .filter(|c| c.contains("realtime_outbox"))
            .collect();
        assert!(
            outbox
                .iter()
                .any(|c| c.to_lowercase().contains("insert") && c.contains("hello")),
            "{changes:#?}"
        );
        assert!(outbox.iter().any(|c| c.to_lowercase().contains("delete")), "{changes:#?}");
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM _supatype.realtime_outbox")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(left, 0, "the outbox must not accumulate");
    })
    .await;
}

#[tokio::test]
async fn a_direct_insert_into_the_outbox_is_judged_like_a_call() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &send_document("declared"))
            .await
            .expect("push");
        seed(&pool).await;
        let insert = |role: &'static str,
                      sub: Option<&'static str>,
                      topic: String,
                      sender: Option<&'static str>| {
            let pool = pool.clone();
            async move {
                as_caller(&pool, role, sub, move |conn| {
                    Box::pin(async move {
                        sqlx::query(
                            "INSERT INTO _supatype.realtime_outbox (topic, event, payload, sender) \
                             VALUES ($1, 'e', '{}', $2::uuid)",
                        )
                        .bind(topic)
                        .bind(sender)
                        .execute(&mut *conn)
                        .await
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                    })
                })
                .await
            }
        };
        let lot = format!("lot:{LOT_1}");
        assert!(
            insert("authenticated", Some(BOB), lot.clone(), Some(BOB))
                .await
                .is_err(),
            "Bob may not send on lot 1"
        );
        assert!(
            insert("authenticated", Some(ALICE), lot.clone(), Some(BOB))
                .await
                .is_err(),
            "the sender must be the caller"
        );
        assert!(
            insert("authenticated", Some(ALICE), lot, Some(ALICE))
                .await
                .is_ok(),
            "the seller, as herself"
        );
        assert!(
            insert("anon", None, "lobby".into(), None).await.is_err(),
            "anon holds no grant"
        );
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// Diff and drift
// ---------------------------------------------------------------------------------------------

use supatype_engine::differ::channel_diff::{ChannelChange, ChannelChangeKind};

async fn plan_diff(pool: &PgPool, ast: &SchemaAst) -> supatype_engine::differ::DiffOutput {
    supatype_engine::push::prepare(pool, ast, "public")
        .await
        .expect("the plan reads")
        .diff
}

fn change(
    channel: &str,
    pattern: &str,
    kind: ChannelChangeKind,
    changed: &[&str],
) -> ChannelChange {
    ChannelChange {
        name: channel.into(),
        pattern: pattern.into(),
        change: kind,
        operations: (kind == ChannelChangeKind::Changed)
            .then(|| changed.iter().map(|s| (*s).to_string()).collect()),
    }
}

#[tokio::test]
async fn the_diff_lists_added_changed_and_removed_channels_and_warns_on_a_mode_flip() {
    common::with_integration_pool(|pool| async move {
        // Nothing pushed yet: both channels are added, and a first push warns of nothing.
        let first = parse(&document(vec![lot_channel(), lobby()], "open")).unwrap();
        let diff = plan_diff(&pool, &first).await;
        assert_eq!(
            diff.channels,
            vec![
                change("LotChannel", "lot:{id}", ChannelChangeKind::Added, &[]),
                change("Lobby", "lobby", ChannelChangeKind::Added, &[]),
            ]
        );
        assert!(
            diff.warnings
                .iter()
                .all(|w| !w.contains("realtime.channels")),
            "{:?}",
            diff.warnings
        );
        common::push(&pool, &first).await.expect("first push");

        // Lobby's send rule changes, LotChannel goes, a new channel arrives, the mode tightens.
        let mut lobby_open = lobby();
        lobby_open["access"]["send"] = json!({ "type": "role", "roles": ["admin"] });
        let mut news = lobby();
        news["name"] = json!("News");
        news["pattern"] = json!("news");
        let second = parse(&document(vec![lobby_open, news], "declared")).unwrap();
        let diff = plan_diff(&pool, &second).await;
        assert_eq!(
            diff.channels,
            vec![
                change("Lobby", "lobby", ChannelChangeKind::Changed, &["send"]),
                change("News", "news", ChannelChangeKind::Added, &[]),
                change("LotChannel", "lot:{id}", ChannelChangeKind::Removed, &[]),
            ]
        );
        let warnings = diff.warnings.join("\n");
        assert!(
            warnings.contains("Channel LotChannel (\"lot:{id}\") is removed"),
            "{warnings}"
        );
        assert!(
            warnings.contains("broadcast and presence on them are refused"),
            "{warnings}"
        );
        assert!(
            warnings.contains("changes from \"open\" to \"declared\""),
            "{warnings}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_hand_edit_of_a_channel_function_is_reported_and_then_replaced() {
    common::with_integration_pool(|pool| async move {
        let ast = example();
        common::push(&pool, &ast).await.expect("first push");
        let clean = plan_diff(&pool, &ast).await;
        assert!(
            clean
                .warnings
                .iter()
                .all(|w| !w.contains("changed outside Supatype")),
            "{:?}",
            clean.warnings
        );

        sqlx::raw_sql(
            "CREATE OR REPLACE FUNCTION _supatype.realtime_channel_mode() RETURNS text \
             LANGUAGE sql STABLE SET search_path = '' AS $$ SELECT 'open'::text $$",
        )
        .execute(&pool)
        .await
        .expect("a hand edit");
        let drifted = plan_diff(&pool, &ast).await;
        assert!(
            drifted
                .warnings
                .iter()
                .any(|w| w
                    .starts_with("_supatype.realtime_channel_mode was changed outside Supatype")),
            "{:?}",
            drifted.warnings
        );

        common::push(&pool, &ast).await.expect("the repush");
        let mode: String = sqlx::query_scalar("SELECT _supatype.realtime_channel_mode()")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            mode, "declared",
            "the push must put the schema's function back"
        );
        let after = plan_diff(&pool, &ast).await;
        assert!(
            after
                .warnings
                .iter()
                .all(|w| !w.contains("changed outside Supatype")),
            "{:?}",
            after.warnings
        );
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// Wildcards and parameter types
// ---------------------------------------------------------------------------------------------

fn org_document() -> SchemaAst {
    let any = json!({ "type": "authenticated" });
    let org = json!({
        "name": "Org", "pattern": "org:{org}:*",
        "params": [{ "name": "org", "type": "uuid" }],
        "access": { "join": any, "send": any, "track": any }
    });
    let room = json!({
        "name": "Room", "pattern": "room:{n}",
        "params": [{ "name": "n", "type": "integer" }],
        "access": { "join": any }
    });
    parse(&document(vec![org, room], "declared")).expect("parses")
}

#[tokio::test]
async fn a_trailing_wildcard_matches_one_or_more_segments_and_never_none() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &org_document()).await.expect("push");
        let org = LOT_1;
        let hit = |rows: &[Verdict]| rows.len() == 1 && rows[0].channel == "Org" && rows[0].fits;
        for topic in [format!("org:{org}:a"), format!("org:{org}:a:b:c")] {
            assert!(
                hit(&access(&pool, "authenticated", Some(BOB), &topic).await),
                "{topic}"
            );
        }
        for topic in [
            format!("org:{org}"),
            format!("org:{org}:"),
            format!("org:{org}::a"),
            "org:x:y".to_string(),
        ] {
            let rows = access(&pool, "authenticated", Some(BOB), &topic).await;
            assert!(!rows.iter().any(|r| r.fits), "{topic}: {rows:?}");
        }
    })
    .await;
}

#[tokio::test]
async fn an_integer_parameter_fits_digits_only_and_never_overflows() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &org_document()).await.expect("push");
        for topic in ["room:1", "room:007", "room:999999999999999999"] {
            let rows = access(&pool, "authenticated", Some(BOB), topic).await;
            assert!(
                rows.len() == 1 && rows[0].fits && rows[0].join == Some(true),
                "{topic}: {rows:?}"
            );
        }
        // Nineteen digits would overflow a bigint, a sign and a decimal are not digits: each is a
        // topic of this shape that does not fit, answered without an error.
        for topic in [
            "room:9999999999999999999",
            "room:-1",
            "room:1.5",
            "room:abc",
        ] {
            let rows = access(&pool, "authenticated", Some(BOB), topic).await;
            assert!(
                rows.len() == 1 && !rows[0].fits && rows[0].join == Some(false),
                "{topic}: {rows:?}"
            );
        }
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// The server's amendments: denial not error, NULL for no rule, pattern and param_error, length cap
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_rule_reading_a_table_the_caller_cannot_touch_is_a_denial_not_an_error() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &example()).await.expect("push");
        seed(&pool).await;
        sqlx::raw_sql("REVOKE ALL ON public.lot_watchers FROM authenticated")
            .execute(&pool)
            .await
            .expect("revoke");
        let rows = access(&pool, "authenticated", Some(BOB), &format!("lot:{LOT_1}")).await;
        assert_eq!(
            rows,
            verdict_with("LotChannel", Some(false), Some(false), Some(false)),
            "{rows:?}"
        );
    })
    .await;
}

fn verdict_with(
    channel: &str,
    join: Option<bool>,
    send: Option<bool>,
    track: Option<bool>,
) -> Vec<Verdict> {
    vec![Verdict {
        channel: channel.into(),
        pattern: "lot:{id}".into(),
        fits: true,
        param_error: None,
        join,
        send,
        track,
    }]
}

#[tokio::test]
async fn an_operation_with_no_rule_answers_null_and_a_denying_rule_answers_false() {
    common::with_integration_pool(|pool| async move {
        let mut only_join = lobby();
        only_join["access"] = json!({ "join": { "type": "authenticated" } });
        common::push(
            &pool,
            &parse(&document(vec![only_join], "declared")).unwrap(),
        )
        .await
        .expect("push");
        let signed_in = access(&pool, "authenticated", Some(BOB), "lobby").await;
        assert_eq!(
            (signed_in[0].join, signed_in[0].send, signed_in[0].track),
            (Some(true), None, None)
        );
        let signed_out = access(&pool, "anon", None, "lobby").await;
        assert_eq!(
            signed_out[0].join,
            Some(false),
            "a rule that denies is FALSE, not NULL"
        );
        let (_, message) = send_as(&pool, "authenticated", Some(BOB), "lobby", "x", json!({}))
            .await
            .unwrap_err();
        assert_eq!(
            message,
            "Lobby declares no send rule, so only the service role may broadcast on lobby"
        );
    })
    .await;
}

#[tokio::test]
async fn a_topic_over_255_characters_has_no_row_and_the_param_error_names_the_parameter() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &org_document()).await.expect("push");
        let long = format!("room:{}", "9".repeat(251));
        assert_eq!(long.chars().count(), 256);
        assert!(access(&pool, "authenticated", Some(BOB), &long)
            .await
            .is_empty());
        let rows = access(&pool, "authenticated", Some(BOB), "room:abc").await;
        assert_eq!(rows[0].param_error.as_deref(), Some("n must be an integer"));
        assert_eq!(rows[0].pattern, "room:{n}");
        let rows = access(&pool, "authenticated", Some(BOB), "org:xyz:a").await;
        assert_eq!(rows[0].param_error.as_deref(), Some("org must be a UUID"));
    })
    .await;
}

#[tokio::test]
async fn a_push_with_nothing_else_to_apply_still_puts_a_hand_edited_function_back() {
    // The up-to-date path: no model changed, so no migration runs. The realtime functions are
    // re-asserted there too, or a hand edit would survive every push that changed nothing.
    common::with_integration_pool(|pool| async move {
        let ast = example();
        common::push(&pool, &ast).await.expect("first push");
        sqlx::raw_sql("DROP FUNCTION _supatype.realtime_channel_dependencies()")
            .execute(&pool)
            .await
            .expect("drop");
        common::push(&pool, &ast).await.expect("an up-to-date push");
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM _supatype.realtime_channel_dependencies()")
                .fetch_one(&pool)
                .await
                .expect("the function is back");
        assert_eq!(rows, 2);
    })
    .await;
}

/// Prints what a push emits for the example: `cargo test --test realtime_channels_tests
/// print_the_example_sql -- --ignored --nocapture`.
#[test]
#[ignore]
fn print_the_example_sql() {
    println!("{}", realtime::generate(&example(), "public"));
}

/// A logical slot on the first output plugin this server lets us use, or false when none.
async fn create_slot(conn: &mut sqlx::PgConnection) -> bool {
    for plugin in ["wal2json", "test_decoding"] {
        let made = sqlx::query("SELECT pg_create_logical_replication_slot('rt_outbox_test', $1)")
            .bind(plugin)
            .execute(&mut *conn)
            .await;
        if made.is_ok() {
            return true;
        }
    }
    false
}

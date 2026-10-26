//! Executing a seed, against a real Postgres.
//!
//! Two things can only be proven here. The statement shapes have to be ones Postgres
//! actually accepts, and the SQLSTATE mapping is a claim about what Postgres *returns*, so
//! mocking an error object would test the mock. Every failure below is provoked by a real
//! failing statement.

mod common;

use std::collections::HashMap;
use supatype_engine::parser;
use supatype_engine::seed::errors::{constraint_index_for, SeedFailure};
use supatype_engine::seed::execute::execute;
use supatype_engine::seed::plan::plan;
use supatype_engine::seed::SeedIr;

/// Two models with the shapes the failures need: a unique natural key, a required column,
/// a foreign key, and a check constraint.
const SCHEMA: &str = r#"{
    "astVersion": 2,
    "models": [
        {
            "name": "Organiser",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {"kind": "genRandomUuid"},
                       "annotations": {"db": {"unique": true}}},
                "slug": {"kind": "text", "required": true, "annotations": {"db": {"unique": true}}},
                "name": {"kind": "text", "required": true},
                "seats": {"kind": "integer", "required": false, "check": "seats > 0"},
                "events": {"kind": "relation", "cardinality": "hasMany", "target": "Event"}
            },
            "annotations": {"db": {"tableName": "organiser"}}
        },
        {
            "name": "Event",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {"kind": "genRandomUuid"},
                       "annotations": {"db": {"unique": true}}},
                "title": {"kind": "text", "required": true},
                "starts_at": {"kind": "datetime", "required": false},
                "organiser": {"kind": "relation", "cardinality": "belongsTo", "target": "Organiser",
                              "required": false,
                              "annotations": {"db": {"foreignKey": "organiser_id"}}},
                "ticket_types": {"kind": "relation", "cardinality": "hasMany", "target": "TicketType"}
            },
            "annotations": {"db": {"tableName": "event"}}
        },
        {
            "name": "TicketType",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {"kind": "genRandomUuid"},
                       "annotations": {"db": {"unique": true}}},
                "name": {"kind": "text", "required": true},
                "event": {"kind": "relation", "cardinality": "belongsTo", "target": "Event",
                          "required": false,
                          "annotations": {"db": {"foreignKey": "event_id"}}}
            },
            "annotations": {"db": {"tableName": "ticket_type"}}
        }
    ]
}"#;

fn ir(operations: &str) -> SeedIr {
    let document =
        format!(r#"{{"irVersion":1,"schemaFingerprint":"sha256:x","operations":{operations}}}"#);
    serde_json::from_str(&document).expect("the IR fixture parses")
}

/// Apply the schema, then run a seed against it.
macro_rules! with_seeded_schema {
    (|$pool:ident, $ast:ident| $body:block) => {
        common::with_integration_pool(|$pool| async move {
            let $ast = parser::parse(SCHEMA).expect("the schema fixture parses");
            // The migration a push applies, foreign keys included: a seed that breaks one has
            // to have one to break.
            let sql = supatype_engine::push::fresh_migration(&$ast, "public", false)
                .expect("renders")
                .up_script();
            sqlx::raw_sql(&sql)
                .execute(&$pool)
                .await
                .expect("the schema applies");
            $body
        })
        .await;
    };
}

async fn run(
    pool: &sqlx::PgPool,
    ast: &parser::ast::SchemaAst,
    operations: &str,
) -> Result<supatype_engine::seed::execute::Report, supatype_engine::seed::errors::SeedError> {
    let planned = plan(&ir(operations), ast).expect("plans");
    execute(
        pool,
        &planned,
        supatype_engine::seed::execute::Context {
            ast,
            constraints: &constraint_index_for(ast),
            schema: "public",
            environment: None,
        },
    )
    .await
}

async fn count(pool: &sqlx::PgPool, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(pool)
        .await
        .expect("counts")
}

#[tokio::test]
async fn it_writes_rows_and_reports_what_it_wrote() {
    with_seeded_schema!(|pool, ast| {
        let report = run(
            &pool,
            &ast,
            r#"[{"op":"createMany","model":"Organiser","rows":[
                {"slug":"a","name":"A"},
                {"slug":"b","name":"B"}
            ]}]"#,
        )
        .await
        .expect("the seed applies");

        assert_eq!(report.written.get("Organiser"), Some(&2));
        assert_eq!(count(&pool, "organiser").await, 2);
    });
}

/// The shape that keeps a large seed to one statement.
#[tokio::test]
async fn a_thousand_rows_are_one_statement_postgres_accepts() {
    with_seeded_schema!(|pool, ast| {
        let rows: Vec<String> = (0..1000)
            .map(|n| format!(r#"{{"slug":"s{n}","name":"Organiser {n}"}}"#))
            .collect();
        let report = run(
            &pool,
            &ast,
            &format!(
                r#"[{{"op":"createMany","model":"Organiser","rows":[{}]}}]"#,
                rows.join(",")
            ),
        )
        .await
        .expect("a thousand rows apply");

        assert_eq!(report.written.get("Organiser"), Some(&1000));
        assert_eq!(count(&pool, "organiser").await, 1000);
    });
}

/// Re-running must converge rather than duplicate or fail. This is the whole reason
/// `upsert` is the operation seeds are built around.
#[tokio::test]
async fn an_upsert_is_idempotent_across_runs() {
    with_seeded_schema!(|pool, ast| {
        let operations = r#"[{"op":"upsert","model":"Organiser","where":{"slug":"n"},
                              "data":{"name":"Northern"}}]"#;

        run(&pool, &ast, operations).await.expect("first run");
        run(&pool, &ast, operations).await.expect("second run");

        assert_eq!(count(&pool, "organiser").await, 1, "one row, not two");

        let name: String = sqlx::query_scalar("SELECT name FROM organiser WHERE slug = 'n'")
            .fetch_one(&pool)
            .await
            .expect("reads back");
        assert_eq!(name, "Northern");
    });
}

#[tokio::test]
async fn an_upsert_updates_the_row_it_conflicts_with() {
    with_seeded_schema!(|pool, ast| {
        run(
            &pool,
            &ast,
            r#"[{"op":"upsert","model":"Organiser","where":{"slug":"n"},"data":{"name":"First"}}]"#,
        )
        .await
        .expect("first");
        run(
            &pool,
            &ast,
            r#"[{"op":"upsert","model":"Organiser","where":{"slug":"n"},"data":{"name":"Second"}}]"#,
        )
        .await
        .expect("second");

        let name: String = sqlx::query_scalar("SELECT name FROM organiser WHERE slug = 'n'")
            .fetch_one(&pool)
            .await
            .expect("reads back");
        assert_eq!(name, "Second", "the second run updated the row");
    });
}

/// A time operand has to be a thing Postgres evaluates, not text.
#[tokio::test]
async fn a_time_operand_is_evaluated_by_the_database() {
    with_seeded_schema!(|pool, ast| {
        run(
            &pool,
            &ast,
            r#"[{"op":"create","model":"Event","data":{"title":"Conf","starts_at":
                {"kind":"after","base":{"kind":"startOf","unit":"day"},
                 "interval":{"days":30,"hours":9}}}}]"#,
        )
        .await
        .expect("applies");

        let within: bool = sqlx::query_scalar(
            "SELECT starts_at > now() + INTERVAL '29 days'
                AND starts_at < now() + INTERVAL '31 days' FROM event",
        )
        .fetch_one(&pool)
        .await
        .expect("reads back");
        assert!(within, "the operand was evaluated, not stored as text");
    });
}

/// A reference is resolved from what the earlier statement returned.
#[tokio::test]
async fn a_reference_resolves_to_a_generated_id() {
    with_seeded_schema!(|pool, ast| {
        run(
            &pool,
            &ast,
            r#"[
            {"op":"create","model":"Organiser","id":"northern","data":{"slug":"n","name":"N"}},
            {"op":"create","model":"Event","data":{"title":"Conf",
                "organiser_id":{"$ref":"northern.id"}}}
        ]"#,
        )
        .await
        .expect("applies");

        let linked: bool = sqlx::query_scalar(
            "SELECT e.organiser_id = o.id FROM event e, organiser o WHERE o.slug = 'n'",
        )
        .fetch_one(&pool)
        .await
        .expect("reads back");
        assert!(linked, "the event points at the organiser that was created");
    });
}

/// A failure leaves nothing behind. Seeds are re-run, and partial state is what the next
/// run collides with.
#[tokio::test]
async fn a_failure_halfway_leaves_no_rows() {
    with_seeded_schema!(|pool, ast| {
        let error = run(
            &pool,
            &ast,
            r#"[
            {"op":"createMany","model":"Organiser","rows":[{"slug":"a","name":"A"}]},
            {"op":"createMany","model":"Organiser","rows":[{"slug":"a","name":"duplicate"}]}
        ]"#,
        )
        .await
        .expect_err("the duplicate slug fails");

        assert!(
            matches!(*error.failure, SeedFailure::Constraint { .. }),
            "{error}"
        );
        assert_eq!(
            count(&pool, "organiser").await,
            0,
            "the first insert must have rolled back with the second"
        );
    });
}

// --- Conditions ---

#[tokio::test]
async fn a_false_condition_skips_its_group_and_says_so() {
    with_seeded_schema!(|pool, ast| {
        run(
            &pool,
            &ast,
            r#"[{"op":"create","model":"Organiser","data":{"slug":"x","name":"X"}}]"#,
        )
        .await
        .expect("seeds one row");

        let report = run(
            &pool,
            &ast,
            r#"[{"op":"group","if":{"kind":"notExists","model":"Organiser"},"operations":[
                {"op":"create","model":"Organiser","data":{"slug":"y","name":"Y"}}
            ]}]"#,
        )
        .await
        .expect("applies");

        assert_eq!(count(&pool, "organiser").await, 1, "the group did not run");
        assert_eq!(report.skipped.len(), 1, "and it is reported as skipped");
    });
}

#[tokio::test]
async fn a_true_condition_runs_its_group() {
    with_seeded_schema!(|pool, ast| {
        let report = run(
            &pool,
            &ast,
            r#"[{"op":"group","if":{"kind":"notExists","model":"Organiser"},"operations":[
                {"op":"create","model":"Organiser","data":{"slug":"y","name":"Y"}}
            ]}]"#,
        )
        .await
        .expect("applies");

        assert_eq!(count(&pool, "organiser").await, 1);
        assert!(report.skipped.is_empty(), "nothing was skipped");
    });
}

/// A filtered condition compiles through the same code path as a policy predicate.
#[tokio::test]
async fn a_filtered_condition_is_evaluated_by_the_database() {
    with_seeded_schema!(|pool, ast| {
        run(
            &pool,
            &ast,
            r#"[{"op":"create","model":"Organiser","data":{"slug":"published","name":"P"}}]"#,
        )
        .await
        .expect("seeds");

        let report = run(
            &pool,
            &ast,
            r#"[{"op":"group","if":{"kind":"exists","model":"Organiser","where":
                {"type":"compare","op":"eq","left":{"kind":"column","name":"slug"},
                 "right":{"kind":"literal","value":"published"}}},
                "operations":[
                  {"op":"create","model":"Event","data":{"title":"Conf"}}
                ]}]"#,
        )
        .await
        .expect("applies");

        assert_eq!(count(&pool, "event").await, 1, "the filter matched");
        assert!(report.skipped.is_empty());
    });
}

// --- SQLSTATE mapping, from real failing statements ---

/// Every code below is provoked by a statement Postgres actually refuses. The mapping is a
/// claim about what Postgres returns, so a mocked error object would test the mock.
#[tokio::test]
async fn a_unique_violation_names_the_model_and_field() {
    with_seeded_schema!(|pool, ast| {
        run(
            &pool,
            &ast,
            r#"[{"op":"create","model":"Organiser","data":{"slug":"dup","name":"A"}}]"#,
        )
        .await
        .expect("first");

        let error = run(
            &pool,
            &ast,
            r#"[{"op":"create","model":"Organiser","data":{"slug":"dup","name":"B"}}]"#,
        )
        .await
        .expect_err("the duplicate fails");

        match &*error.failure {
            SeedFailure::Constraint { sqlstate, .. } => assert_eq!(sqlstate, "23505"),
            other => panic!("expected a constraint failure, got {other:?}"),
        }
        assert!(
            error.to_string().contains("Organiser"),
            "the error names the model: {error}"
        );
    });
}

#[tokio::test]
async fn a_foreign_key_violation_is_reported_as_one() {
    with_seeded_schema!(|pool, ast| {
        let error = run(
            &pool,
            &ast,
            r#"[{"op":"create","model":"Event","data":{"title":"Orphan",
                "organiser_id":"11111111-1111-4111-8111-111111111111"}}]"#,
        )
        .await
        .expect_err("the missing parent fails");

        match &*error.failure {
            SeedFailure::Constraint { sqlstate, .. } => assert_eq!(sqlstate, "23503"),
            other => panic!("expected a foreign key failure, got {other:?}"),
        }
    });
}

#[tokio::test]
async fn a_not_null_violation_is_reported_as_one() {
    with_seeded_schema!(|pool, ast| {
        let error = run(
            &pool,
            &ast,
            r#"[{"op":"create","model":"Organiser","data":{"slug":"x","name":null}}]"#,
        )
        .await
        .expect_err("a null in a required column fails");

        match &*error.failure {
            SeedFailure::Constraint { sqlstate, .. } => assert_eq!(sqlstate, "23502"),
            other => panic!("expected a not-null failure, got {other:?}"),
        }
    });
}

#[tokio::test]
async fn a_check_violation_is_reported_as_one() {
    with_seeded_schema!(|pool, ast| {
        let error = run(
            &pool,
            &ast,
            r#"[{"op":"create","model":"Organiser","data":{"slug":"x","name":"X","seats":-5}}]"#,
        )
        .await
        .expect_err("a negative seat count fails the check");

        match &*error.failure {
            SeedFailure::Constraint { sqlstate, .. } => assert_eq!(sqlstate, "23514"),
            other => panic!("expected a check failure, got {other:?}"),
        }
    });
}

/// The most common seed failure there is, and the one Postgres words worst: it says
/// `relation "..." does not exist`, which reads like a bug in the seed.
#[tokio::test]
async fn a_missing_table_is_reported_as_schema_drift_with_a_remedy() {
    with_seeded_schema!(|pool, ast| {
        let mut tables: HashMap<String, String> = HashMap::new();
        tables.insert("Organiser".to_string(), "organiser".to_string());
        let _ = tables;

        // A model the database does not have, reached through a raw statement so the
        // failure comes from Postgres rather than from validation.
        let error = run(
            &pool,
            &ast,
            r#"[{"op":"sql","text":"INSERT INTO speaker (name) VALUES ('x')","params":[]}]"#,
        )
        .await
        .expect_err("a missing table fails");

        match &*error.failure {
            SeedFailure::SchemaDrift { remedy, .. } => {
                assert!(remedy.contains("supatype push"), "{remedy}")
            }
            other => panic!("expected schema drift, got {other:?}"),
        }
    });
}

#[tokio::test]
async fn a_missing_column_is_reported_as_schema_drift() {
    with_seeded_schema!(|pool, ast| {
        let error = run(
            &pool,
            &ast,
            r#"[{"op":"sql","text":"INSERT INTO organiser (slug, name, nmae) VALUES ('a','b','c')","params":[]}]"#,
        )
        .await
        .expect_err("a missing column fails");

        match &*error.failure {
            SeedFailure::SchemaDrift { remedy, .. } => {
                assert!(remedy.contains("supatype generate"), "{remedy}")
            }
            other => panic!("expected schema drift, got {other:?}"),
        }
    });
}

/// A raw statement runs in the same transaction, in position.
#[tokio::test]
async fn a_raw_statement_shares_the_transaction() {
    with_seeded_schema!(|pool, ast| {
        let error = run(
            &pool,
            &ast,
            r#"[
            {"op":"createMany","model":"Organiser","rows":[{"slug":"a","name":"A"}]},
            {"op":"sql","text":"INSERT INTO organiser (slug, name) VALUES ('a', 'duplicate')","params":[]}
        ]"#,
        )
        .await
        .expect_err("the raw statement violates the unique index");

        assert!(
            matches!(*error.failure, SeedFailure::Constraint { .. }),
            "{error}"
        );
        assert_eq!(
            count(&pool, "organiser").await,
            0,
            "the typed write rolled back with the raw one"
        );
    });
}

// --- Relations ---

/// A nested write has to reach the target's table, and the child has to point at the
/// parent. Both were broken: the planner carried the relation's name as the model, so the
/// executor used `events` as a table name and the insert failed with
/// `relation "events" does not exist`.
#[tokio::test]
async fn a_nested_create_writes_the_target_table_and_links_it() {
    with_seeded_schema!(|pool, ast| {
        let report = run(
            &pool,
            &ast,
            r#"[{"op":"create","model":"Organiser","id":"northern","data":{
                "slug":"n","name":"Northern",
                "events":{"create":[{"title":"Conf"}]}
            }}]"#,
        )
        .await
        .expect("the nested seed runs");

        assert_eq!(report.written.get("Event"), Some(&1));
        assert_eq!(count(&pool, "event").await, 1);

        let linked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM event e JOIN organiser o ON o.id = e.organiser_id \
             WHERE o.slug = 'n'",
        )
        .fetch_one(&pool)
        .await
        .expect("counts");
        assert_eq!(linked, 1, "the nested event points at its parent");
    });
}

/// Three levels, because the middle one is both a child and a parent: it needs a label of
/// its own for its children to reference, and nothing in the document gave it one.
#[tokio::test]
async fn a_three_level_nested_create_links_every_level() {
    with_seeded_schema!(|pool, ast| {
        run(
            &pool,
            &ast,
            r#"[{"op":"create","model":"Organiser","id":"northern","data":{
                "slug":"n","name":"Northern",
                "events":{"create":[
                    {"title":"Conf","ticket_types":{"createMany":[{"name":"Early"},{"name":"Std"}]}}
                ]}
            }}]"#,
        )
        .await
        .expect("the nested seed runs");

        let linked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM ticket_type t \
             JOIN event e ON e.id = t.event_id \
             JOIN organiser o ON o.id = e.organiser_id WHERE o.slug = 'n'",
        )
        .fetch_one(&pool)
        .await
        .expect("counts");
        assert_eq!(linked, 2, "both ticket types reach the organiser");
    });
}

/// `connect` by the referenced column: the value is one the plan already holds.
#[tokio::test]
async fn a_connect_by_reference_fills_the_foreign_key() {
    with_seeded_schema!(|pool, ast| {
        run(
            &pool,
            &ast,
            r#"[
                {"op":"create","model":"Organiser","id":"northern","data":{"slug":"n","name":"N"}},
                {"op":"create","model":"Event","data":{
                    "title":"Conf",
                    "organiser":{"connect":{"id":{"$ref":"northern.id"}}}
                }}
            ]"#,
        )
        .await
        .expect("the seed runs");

        let linked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM event e JOIN organiser o ON o.id = e.organiser_id \
             WHERE o.slug = 'n'",
        )
        .fetch_one(&pool)
        .await
        .expect("counts");
        assert_eq!(linked, 1);
    });
}

/// `connect` by a natural key: only the database knows which id that slug has, and it
/// resolves it inside the one statement rather than in a round trip per row.
#[tokio::test]
async fn a_connect_by_natural_key_resolves_against_the_database() {
    with_seeded_schema!(|pool, ast| {
        run(
            &pool,
            &ast,
            r#"[{"op":"createMany","model":"Organiser","rows":[
                {"slug":"north","name":"North"},
                {"slug":"south","name":"South"}
            ]}]"#,
        )
        .await
        .expect("the organisers are written");

        run(
            &pool,
            &ast,
            r#"[{"op":"createMany","model":"Event","rows":[
                {"title":"A","organiser":{"connect":{"slug":"north"}}},
                {"title":"B","organiser":{"connect":{"slug":"south"}}}
            ]}]"#,
        )
        .await
        .expect("the events are written");

        let pairs: Vec<(String, String)> = sqlx::query_as(
            "SELECT e.title, o.slug FROM event e JOIN organiser o ON o.id = e.organiser_id \
             ORDER BY e.title",
        )
        .fetch_all(&pool)
        .await
        .expect("reads back");
        assert_eq!(
            pairs,
            vec![
                ("A".to_string(), "north".to_string()),
                ("B".to_string(), "south".to_string())
            ],
            "each row connected to the organiser its own key named"
        );
    });
}

/// A key that matches nothing is not silently a null foreign key on a nullable column.
#[tokio::test]
async fn a_connect_that_matches_nothing_leaves_the_key_null() {
    with_seeded_schema!(|pool, ast| {
        run(
            &pool,
            &ast,
            r#"[{"op":"create","model":"Event","data":{
                "title":"Orphan","organiser":{"connect":{"slug":"nobody"}}
            }}]"#,
        )
        .await
        .expect("a nullable foreign key accepts no match");

        let orphans: i64 =
            sqlx::query_scalar("SELECT count(*) FROM event WHERE organiser_id IS NULL")
                .fetch_one(&pool)
                .await
                .expect("counts");
        assert_eq!(orphans, 1);
    });
}

//! Identity and generated columns against a database (identity-contract): created, changed and
//! read back, recorded in the ledger with an identity column's sequence, and each change converging
//! (a second push is up to date and doctor reports nothing).

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{differ::doctor::DoctorReport, parser, parser::ast::SchemaAst, push};

use common::{exec, push};

fn int(extra: Value) -> Value {
    let mut f = json!({ "kind": "integer", "required": true,
                        "annotations": { "db": { "pgType": "INTEGER" } } });
    f.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    f
}

fn text(extra: Value) -> Value {
    let mut f = json!({ "kind": "text", "required": false,
                        "annotations": { "db": { "pgType": "TEXT" } } });
    f.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    f
}

fn posts_with(fields: Value, access: Value) -> SchemaAst {
    let doc = json!({
        "astVersion": 2,
        "models": [{
            "name": "Post",
            "fields": fields,
            "options": { "timestamps": false, "softDelete": false, "singleton": false },
            "annotations": { "db": { "tableName": "posts", "indexes": [] },
                             "platform": { "access": access } }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

fn posts(fields: Value) -> SchemaAst {
    posts_with(fields, json!({ "read": { "type": "public" } }))
}

fn with_id(id: Value, title_lower: Option<&str>) -> SchemaAst {
    let mut fields = json!({ "id": id, "title": text(json!({})) });
    if let Some(expression) = title_lower {
        fields["title_lower"] =
            text(json!({ "generated": { "expression": expression, "stored": true } }));
    }
    posts(fields)
}

fn identity(how: &str) -> Value {
    int(json!({ "primaryKey": true, "identity": how }))
}

fn up_to_date(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::UpToDate { .. })
}

fn is_clean(report: &DoctorReport) -> bool {
    report.missing.is_empty()
        && report.stale_managed.is_empty()
        && report.unmanaged_drift.is_empty()
        && report.drifted.is_empty()
        && report.conflicting.is_empty()
        && report.released.is_empty()
        && report.claimed.is_empty()
}

/// Pushed, then a second push is up to date and doctor reports nothing.
async fn converges(pool: &PgPool, ast: &SchemaAst) -> push::Outcome {
    let outcome = push(pool, ast).await.expect("push");
    let again = push(pool, ast).await.expect("second push");
    assert!(up_to_date(&again), "{again:?}");
    let report = common::doctor(pool, ast).await;
    assert!(is_clean(&report), "{report:#?}");
    outcome
}

async fn one<
    T: for<'r> sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Send + Unpin,
>(
    pool: &PgPool,
    sql: &str,
) -> T {
    sqlx::query_scalar(sql)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
}

/// `information_schema`'s `(is_identity, identity_generation, is_generated)` for a column.
async fn how_filled(pool: &PgPool, column: &str) -> (String, Option<String>, String) {
    sqlx::query_as(
        "SELECT is_identity::text, identity_generation::text, is_generated::text
           FROM information_schema.columns
          WHERE table_schema = 'public' AND table_name = 'posts' AND column_name = $1",
    )
    .bind(column)
    .fetch_one(pool)
    .await
    .expect("column")
}

async fn recorded_sequences(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT name FROM _supatype.managed_objects WHERE kind = 'sequence' ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_new_table_numbers_and_computes_its_columns() {
    common::with_integration_pool(|pool| async move {
        let ast = with_id(identity("always"), Some("lower(title)"));
        converges(&pool, &ast).await;
        exec(
            &pool,
            "INSERT INTO public.posts (title) VALUES ('Hello'), ('World')",
        )
        .await
        .unwrap();
        assert_eq!(
            one::<i32>(&pool, "SELECT max(id) FROM public.posts").await,
            2
        );
        assert_eq!(
            one::<String>(&pool, "SELECT title_lower FROM public.posts WHERE id = 1").await,
            "hello"
        );
        // Postgres refuses to write either.
        assert!(exec(
            &pool,
            "INSERT INTO public.posts (id, title) VALUES (9, 'x')"
        )
        .await
        .is_err());
        assert!(exec(
            &pool,
            "UPDATE public.posts SET title_lower = 'x' WHERE id = 1"
        )
        .await
        .is_err());
        // The identity column's sequence is recorded like a serial's.
        assert_eq!(recorded_sequences(&pool).await, ["posts_id_seq"]);

        // What the introspection hands the CLI.
        let mut conn = pool.acquire().await.unwrap();
        let state = supatype_engine::introspector::introspect_connection(&mut conn, "public")
            .await
            .unwrap();
        let table = state.tables.iter().find(|t| t.name == "posts").unwrap();
        let id = table.columns.iter().find(|c| c.name == "id").unwrap();
        assert!(id.is_identity);
        assert_eq!(id.identity_generation.as_deref(), Some("ALWAYS"));
        let lower = table
            .columns
            .iter()
            .find(|c| c.name == "title_lower")
            .unwrap();
        assert!(lower.is_generated);
        assert!(
            lower
                .generation_expression
                .as_deref()
                .unwrap_or_default()
                .contains("lower"),
            "{lower:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_plain_key_becomes_an_identity_numbered_past_its_rows_and_back() {
    common::with_integration_pool(|pool| async move {
        converges(&pool, &with_id(int(json!({ "primaryKey": true })), None)).await;
        exec(
            &pool,
            "INSERT INTO public.posts (id, title) VALUES (1, 'a'), (7, 'b')",
        )
        .await
        .unwrap();

        converges(&pool, &with_id(identity("byDefault"), None)).await;
        assert_eq!(
            how_filled(&pool, "id").await,
            ("YES".into(), Some("BY DEFAULT".into()), "NEVER".into())
        );
        exec(&pool, "INSERT INTO public.posts (title) VALUES ('c')")
            .await
            .unwrap();
        assert_eq!(
            one::<i32>(&pool, "SELECT max(id) FROM public.posts").await,
            8
        );
        assert_eq!(recorded_sequences(&pool).await, ["posts_id_seq"]);

        converges(&pool, &with_id(identity("always"), None)).await;
        assert_eq!(how_filled(&pool, "id").await.1.as_deref(), Some("ALWAYS"));

        converges(&pool, &with_id(int(json!({ "primaryKey": true })), None)).await;
        assert_eq!(how_filled(&pool, "id").await.0, "NO");
        exec(
            &pool,
            "INSERT INTO public.posts (id, title) VALUES (20, 'd')",
        )
        .await
        .unwrap();
    })
    .await;
}

#[tokio::test]
async fn a_changed_expression_computes_every_row_again() {
    common::with_integration_pool(|pool| async move {
        converges(&pool, &with_id(identity("always"), Some("lower(title)"))).await;
        exec(
            &pool,
            "CREATE INDEX posts_title_lower_by_hand ON public.posts (title_lower);
                     INSERT INTO public.posts (title) VALUES ('Hello')",
        )
        .await
        .unwrap();

        let upper = with_id(identity("always"), Some("upper(title)"));
        push(&pool, &upper).await.expect("push");
        assert!(up_to_date(&push(&pool, &upper).await.unwrap()));
        let report = common::doctor(&pool, &upper).await;
        let unmanaged: Vec<&str> = report
            .unmanaged_drift
            .iter()
            .map(|i| i.name.as_str())
            .collect();
        assert_eq!(unmanaged, ["posts_title_lower_by_hand"], "{report:#?}");
        assert!(
            report.drifted.is_empty() && report.missing.is_empty(),
            "{report:#?}"
        );
        assert_eq!(
            one::<String>(&pool, "SELECT title_lower FROM public.posts").await,
            "HELLO"
        );
        // Changed in place (17) or made again with what depended on it (16).
        assert_eq!(
            one::<i64>(
                &pool,
                "SELECT count(*) FROM pg_indexes WHERE indexname = 'posts_title_lower_by_hand'"
            )
            .await,
            1
        );
    })
    .await;
}

#[tokio::test]
async fn a_column_stops_and_starts_being_generated() {
    common::with_integration_pool(|pool| async move {
        converges(&pool, &with_id(identity("always"), Some("lower(title)"))).await;
        exec(&pool, "INSERT INTO public.posts (title) VALUES ('Hello')")
            .await
            .unwrap();

        // Plain: it keeps its values and can be written.
        let plain = posts(json!({
            "id": identity("always"),
            "title": text(json!({})),
            "title_lower": text(json!({})),
        }));
        converges(&pool, &plain).await;
        assert_eq!(how_filled(&pool, "title_lower").await.2, "NEVER");
        assert_eq!(
            one::<String>(&pool, "SELECT title_lower FROM public.posts").await,
            "hello"
        );
        exec(
            &pool,
            "UPDATE public.posts SET title_lower = 'mine' WHERE true",
        )
        .await
        .unwrap();

        // Generated again: its values are replaced by the expression's, which is destructive.
        let generated = with_id(identity("always"), Some("upper(title)"));
        let refused = push(&pool, &generated).await;
        assert!(
            refused.is_err(),
            "replacing a column's values needs --force: {refused:?}"
        );
        common::push_with(
            &pool,
            &generated,
            push::ApplyOptions {
                force: true,
                ..Default::default()
            },
        )
        .await
        .expect("forced");
        assert_eq!(
            one::<String>(&pool, "SELECT title_lower FROM public.posts").await,
            "HELLO"
        );
        assert!(up_to_date(&push(&pool, &generated).await.unwrap()));
        assert!(is_clean(&common::doctor(&pool, &generated).await));
    })
    .await;
}

/// Renumbering a key is a change to ask for: a serial the schema now declares as an identity column
/// is left, the push says how to convert it, and once converted by hand the schema agrees.
#[tokio::test]
async fn a_serial_is_not_converted_without_asking() {
    common::with_integration_pool(|pool| async move {
        let serial = posts(json!({
            "id": { "kind": "serial", "primaryKey": true, "required": true,
                    "annotations": { "db": { "pgType": "SERIAL" } } },
            "title": text(json!({})),
        }));
        converges(&pool, &serial).await;
        exec(
            &pool,
            "INSERT INTO public.posts (title) VALUES ('a'), ('b')",
        )
        .await
        .unwrap();

        let declared = with_id(identity("always"), None);
        let outcome = push(&pool, &declared).await.unwrap();
        let warnings = match &outcome {
            push::Outcome::Applied { warnings, .. } | push::Outcome::UpToDate { warnings } => {
                warnings
            }
        };
        let warning = warnings
            .iter()
            .find(|w| w.contains("is a serial column"))
            .unwrap_or_else(|| panic!("{outcome:?}"));
        assert_eq!(how_filled(&pool, "id").await.0, "NO", "left a serial");
        assert!(up_to_date(&push(&pool, &declared).await.unwrap()));

        // The conversion the warning gives, run deliberately.
        let statements = warning.split_once("To convert it, run: ").unwrap().1;
        exec(&pool, statements).await.expect("the conversion runs");
        assert_eq!(how_filled(&pool, "id").await.1.as_deref(), Some("ALWAYS"));
        exec(&pool, "INSERT INTO public.posts (title) VALUES ('c')")
            .await
            .unwrap();
        assert_eq!(
            one::<i32>(&pool, "SELECT max(id) FROM public.posts").await,
            3
        );
        let after = push(&pool, &declared).await.unwrap();
        let warnings = match &after {
            push::Outcome::Applied { warnings, .. } | push::Outcome::UpToDate { warnings } => {
                warnings
            }
        };
        assert!(
            !warnings.iter().any(|w| w.contains("is a serial column")),
            "{after:?}"
        );
        assert!(up_to_date(&push(&pool, &declared).await.unwrap()));
        assert_eq!(recorded_sequences(&pool).await, ["posts_id_seq"]);
    })
    .await;
}

/// A write privilege narrowed to columns never names one Postgres refuses to write.
#[tokio::test]
async fn a_narrowed_write_privilege_leaves_out_generated_columns() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            return;
        }
        let ast = posts_with(
            json!({
                "id": identity("always"),
                "title": text(json!({})),
                "locked": text(json!({})),
                "title_lower": text(json!({ "generated": { "expression": "lower(title)", "stored": true } })),
            }),
            json!({
                "read": { "type": "public" },
                "create": { "type": "authenticated" },
                "update": { "type": "authenticated" },
                "fields": { "locked": { "write": { "type": "private" } } }
            }),
        );
        converges(&pool, &ast).await;
        let columns: Vec<String> = sqlx::query_scalar(
            "SELECT column_name::text FROM information_schema.column_privileges
              WHERE table_schema = 'public' AND table_name = 'posts'
                AND grantee = 'authenticated' AND privilege_type = 'UPDATE'
              ORDER BY 1",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(columns, ["title"]);
    })
    .await;
}

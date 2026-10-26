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

/// Refused without consent, as a drop is, then pushed with `--force` and converging.
async fn converges_only_forced(pool: &PgPool, ast: &SchemaAst) {
    let refused = push(pool, ast).await;
    assert!(
        refused
            .as_ref()
            .is_err_and(|e| e.to_string().contains("Use --force")),
        "needs --force: {refused:?}"
    );
    common::push_with(
        pool,
        ast,
        push::ApplyOptions {
            force: true,
            ..Default::default()
        },
    )
    .await
    .expect("forced");
    assert!(up_to_date(&push(pool, ast).await.expect("second push")));
    let report = common::doctor(pool, ast).await;
    assert!(is_clean(&report), "{report:#?}");
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

        // Taking the identity away is asked for, as a drop is.
        let plain = with_id(int(json!({ "primaryKey": true })), None);
        converges_only_forced(&pool, &plain).await;
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

        // Plain: asked for, as a drop is; it keeps its values and can be written.
        let plain = posts(json!({
            "id": identity("always"),
            "title": text(json!({})),
            "title_lower": text(json!({})),
        }));
        converges_only_forced(&pool, &plain).await;
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

/// `posts` with three rows, then `column` added to it: the push applies (no backfill `DEFAULT`
/// beside the identity or expression, which Postgres refuses), the next is up to date, and doctor
/// reports nothing.
async fn added_to_rows(pool: &PgPool, column: Value) {
    converges(pool, &with_id(identity("always"), None)).await;
    exec(
        pool,
        "INSERT INTO public.posts (title) VALUES ('A'), ('B'), ('C')",
    )
    .await
    .unwrap();
    let added = posts(json!({
        "id": identity("always"),
        "title": text(json!({})),
        "added": column,
    }));
    let outcome = converges(pool, &added).await;
    assert!(
        matches!(outcome, push::Outcome::Applied { .. }),
        "{outcome:?}"
    );
}

/// The identity numbers the rows already there, and new ones carry on past them.
async fn numbered(pool: &PgPool) {
    assert_eq!(
        one::<Vec<i32>>(
            pool,
            "SELECT array_agg(added ORDER BY id) FROM public.posts"
        )
        .await,
        [1, 2, 3]
    );
    exec(pool, "INSERT INTO public.posts (title) VALUES ('D')")
        .await
        .unwrap();
    assert_eq!(
        one::<i32>(pool, "SELECT added FROM public.posts WHERE title = 'D'").await,
        4
    );
}

#[tokio::test]
async fn a_required_auto_increment_column_added_to_rows_numbers_them() {
    common::with_integration_pool(|pool| async move {
        added_to_rows(
            &pool,
            int(json!({ "identity": "byDefault", "autoIncrement": true })),
        )
        .await;
        assert_eq!(
            how_filled(&pool, "added").await,
            ("YES".into(), Some("BY DEFAULT".into()), "NEVER".into())
        );
        numbered(&pool).await;
    })
    .await;
}

#[tokio::test]
async fn a_required_identity_always_column_added_to_rows_numbers_them() {
    common::with_integration_pool(|pool| async move {
        added_to_rows(&pool, int(json!({ "identity": "always" }))).await;
        assert_eq!(
            how_filled(&pool, "added").await,
            ("YES".into(), Some("ALWAYS".into()), "NEVER".into())
        );
        numbered(&pool).await;
    })
    .await;
}

#[tokio::test]
async fn a_required_generated_column_added_to_rows_computes_them() {
    common::with_integration_pool(|pool| async move {
        added_to_rows(
            &pool,
            text(json!({ "required": true,
                         "generated": { "expression": "lower(coalesce(title, ''))", "stored": true } })),
        )
        .await;
        assert_eq!(how_filled(&pool, "added").await.2, "ALWAYS");
        assert_eq!(
            one::<Vec<String>>(&pool, "SELECT array_agg(added ORDER BY id) FROM public.posts")
                .await,
            ["a", "b", "c"]
        );
    })
    .await;
}

fn serial_posts() -> SchemaAst {
    posts(json!({
        "id": { "kind": "serial", "primaryKey": true, "required": true,
                "annotations": { "db": { "pgType": "SERIAL" } } },
        "title": text(json!({})),
    }))
}

fn auto_increment_posts() -> SchemaAst {
    with_id(
        int(json!({ "primaryKey": true, "identity": "byDefault", "autoIncrement": true })),
        None,
    )
}

fn warnings_of(outcome: &push::Outcome) -> &[String] {
    match outcome {
        push::Outcome::Applied { warnings, .. } | push::Outcome::UpToDate { warnings } => warnings,
    }
}

/// `posts.id`'s default, a serial's `nextval(...)` or nothing.
async fn id_default(pool: &PgPool) -> Option<String> {
    one(
        pool,
        "SELECT column_default::text FROM information_schema.columns
          WHERE table_schema = 'public' AND table_name = 'posts' AND column_name = 'id'",
    )
    .await
}

/// A new `AutoIncrement` column is an identity column generated by default.
#[tokio::test]
async fn a_new_auto_increment_column_is_an_identity_by_default() {
    common::with_integration_pool(|pool| async move {
        converges(&pool, &auto_increment_posts()).await;
        assert_eq!(
            how_filled(&pool, "id").await,
            ("YES".into(), Some("BY DEFAULT".into()), "NEVER".into())
        );
        assert_eq!(recorded_sequences(&pool).await, ["posts_id_seq"]);
    })
    .await;
}

/// `AutoIncrement` made a serial before it meant identity. A column made then satisfies it: every
/// push leaves it as it is and says nothing, and it numbers on as before.
#[tokio::test]
async fn a_serial_satisfies_auto_increment_on_every_push() {
    common::with_integration_pool(|pool| async move {
        converges(&pool, &serial_posts()).await;
        exec(
            &pool,
            "INSERT INTO public.posts (title) VALUES ('a'), ('b')",
        )
        .await
        .unwrap();
        let default = id_default(&pool).await;

        let declared = auto_increment_posts();
        for _ in 0..2 {
            let outcome = push(&pool, &declared).await.expect("push");
            assert!(up_to_date(&outcome), "{outcome:?}");
            assert!(warnings_of(&outcome).is_empty(), "{outcome:?}");
        }
        assert!(is_clean(&common::doctor(&pool, &declared).await));
        assert_eq!(how_filled(&pool, "id").await.0, "NO", "still a serial");
        assert_eq!(id_default(&pool).await, default);
        exec(&pool, "INSERT INTO public.posts (title) VALUES ('c')")
            .await
            .unwrap();
        assert_eq!(
            one::<i32>(&pool, "SELECT max(id) FROM public.posts").await,
            3
        );
        assert_eq!(recorded_sequences(&pool).await, ["posts_id_seq"]);
    })
    .await;
}

/// An explicit `Identity` on a serial asks for the conversion: the serial's default and sequence go
/// and the identity numbers on past the rows there.
#[tokio::test]
async fn an_explicit_identity_converts_a_serial() {
    common::with_integration_pool(|pool| async move {
        converges(&pool, &serial_posts()).await;
        exec(&pool, "INSERT INTO public.posts (title) VALUES ('a'), ('b')")
            .await
            .unwrap();

        let declared = with_id(identity("always"), None);
        let outcome = converges(&pool, &declared).await;
        assert!(
            warnings_of(&outcome)
                .iter()
                .any(|w| w.contains("a serial column becomes an identity column")),
            "{outcome:?}"
        );
        assert_eq!(how_filled(&pool, "id").await.1.as_deref(), Some("ALWAYS"));
        assert_eq!(id_default(&pool).await, None);
        exec(&pool, "INSERT INTO public.posts (title) VALUES ('c')")
            .await
            .unwrap();
        assert_eq!(
            one::<i32>(&pool, "SELECT max(id) FROM public.posts").await,
            3
        );
        assert_eq!(recorded_sequences(&pool).await, ["posts_id_seq"]);
        assert_eq!(
            one::<i64>(
                &pool,
                "SELECT count(*) FROM pg_class WHERE relkind = 'S' AND relnamespace = 'public'::regnamespace"
            )
            .await,
            1,
            "the serial's own sequence is gone"
        );
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

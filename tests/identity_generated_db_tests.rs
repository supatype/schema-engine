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

/// Decision D8: a new `AutoIncrement` column takes its table's style. On a table numbered by a
/// serial it is a serial too, numbering the rows already there, so the table does not mix the two
/// (E37); on a new table, or one numbered by an identity, it is an identity column.
#[tokio::test]
async fn a_new_auto_increment_column_on_a_serial_table_is_a_serial() {
    common::with_integration_pool(|pool| async move {
        converges(&pool, &serial_posts()).await;
        exec(
            &pool,
            "INSERT INTO public.posts (title) VALUES ('a'), ('b'), ('c')",
        )
        .await
        .unwrap();

        let declared = posts(json!({
            "id": { "kind": "serial", "primaryKey": true, "required": true,
                    "annotations": { "db": { "pgType": "SERIAL" } } },
            "title": text(json!({})),
            "added": int(json!({ "identity": "byDefault", "autoIncrement": true })),
        }));
        converges(&pool, &declared).await;
        let (identity, _, _) = how_filled(&pool, "added").await;
        assert_eq!(identity, "NO", "a serial table gained an identity column");
        let default: Option<String> = one(
            &pool,
            "SELECT column_default::text FROM information_schema.columns
              WHERE table_name = 'posts' AND column_name = 'added'",
        )
        .await;
        assert!(
            default
                .as_deref()
                .is_some_and(|d| d.starts_with("nextval(")),
            "{default:?}"
        );
        numbered(&pool).await;
        assert!(is_clean(&common::doctor(&pool, &declared).await));
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

/// What depends on `posts.title_lower` by the user's hand, as Postgres prints it: the foreign key's
/// `pg_get_constraintdef` and the partial index's `pg_get_indexdef`, each None when it is gone.
async fn hand_made_on_title_lower(pool: &PgPool) -> (Option<String>, Option<String>) {
    sqlx::query_as(
        "SELECT (SELECT pg_get_constraintdef(oid) FROM pg_constraint
                  WHERE conname = 'posts_title_lower_tag_fkey'),
                (SELECT pg_get_indexdef(indexrelid) FROM pg_index
                  WHERE indexrelid = to_regclass('public.posts_title_lower_partial'))",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

/// A column made again (here: a plain column becoming generated) gets back what the user made on
/// it exactly as it was: the foreign key's `MATCH FULL` and `DEFERRABLE INITIALLY DEFERRED`, and
/// the index's `DESC` and `WHERE`, not objects rebuilt from the parts the engine happens to model.
#[tokio::test]
async fn a_recreated_column_keeps_a_users_own_key_and_index_exactly() {
    common::with_integration_pool(|pool| async move {
        let plain = posts(json!({
            "id": identity("always"),
            "title": text(json!({})),
            "title_lower": text(json!({})),
        }));
        converges(&pool, &plain).await;
        exec(
            &pool,
            "CREATE TABLE public.tags (name TEXT PRIMARY KEY);
             INSERT INTO public.tags (name) VALUES ('hello');
             INSERT INTO public.posts (title, title_lower) VALUES ('Hello', 'hello');
             ALTER TABLE public.posts ADD CONSTRAINT posts_title_lower_tag_fkey
               FOREIGN KEY (title_lower) REFERENCES public.tags (name)
               MATCH FULL ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
             CREATE INDEX posts_title_lower_partial ON public.posts (title_lower DESC)
               WHERE title_lower <> '';",
        )
        .await
        .unwrap();
        let before = hand_made_on_title_lower(&pool).await;
        assert!(before.0.is_some() && before.1.is_some(), "{before:?}");

        let generated = with_id(identity("always"), Some("lower(title)"));
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
        assert_eq!(how_filled(&pool, "title_lower").await.2, "ALWAYS");
        assert_eq!(
            hand_made_on_title_lower(&pool).await,
            before,
            "the key and the index come back as they were"
        );
    })
    .await;
}

/// `posts` with a plain `title_lower`, pushed, a row in it, and `setup` run by hand; then
/// `title_lower` becomes generated (forced), which drops and adds the column again.
async fn recreate_title_lower_around(pool: &PgPool, setup: &str) {
    let plain = posts(json!({
        "id": identity("always"),
        "title": text(json!({})),
        "title_lower": text(json!({})),
    }));
    converges(pool, &plain).await;
    exec(
        pool,
        "INSERT INTO public.posts (title, title_lower) VALUES ('Hello', 'hello')",
    )
    .await
    .unwrap();
    exec(pool, setup).await.unwrap();
    let generated = with_id(identity("always"), Some("lower(title)"));
    common::push_with(
        pool,
        &generated,
        push::ApplyOptions {
            force: true,
            ..Default::default()
        },
    )
    .await
    .expect("forced");
    assert_eq!(how_filled(pool, "title_lower").await.2, "ALWAYS");
}

/// Every index and constraint in `public` other than the engine's own, by name, with its
/// definition as Postgres prints it.
async fn hand_made_objects(pool: &PgPool) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT c.relname::text, pg_get_indexdef(c.oid) FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'public' AND c.relkind = 'i' AND c.relname LIKE 'mine_%'
         UNION ALL
         SELECT k.conname::text, pg_get_constraintdef(k.oid) FROM pg_constraint k
           JOIN pg_namespace n ON n.oid = k.connamespace
          WHERE n.nspname = 'public' AND k.conname LIKE 'mine_%'
         ORDER BY 1, 2",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// An index that uses the recreated column only in an expression, in `INCLUDE` or in its `WHERE`
/// depends on it as much as one keyed on it does: Postgres drops it with the column, and the push
/// makes it again.
#[tokio::test]
async fn a_recreated_column_keeps_indexes_that_use_it_outside_their_keys() {
    common::with_integration_pool(|pool| async move {
        let setup = "CREATE INDEX mine_expression ON public.posts (upper(title_lower));
                     CREATE INDEX mine_include ON public.posts (id) INCLUDE (title_lower);
                     CREATE INDEX mine_partial ON public.posts (id) WHERE title_lower IS NOT NULL;";
        recreate_title_lower_around(&pool, setup).await;
        let index = |name: &str, definition: &str| (name.to_string(), definition.to_string());
        assert_eq!(
            hand_made_objects(&pool).await,
            [
                index(
                    "mine_expression",
                    "CREATE INDEX mine_expression ON public.posts USING btree (upper(title_lower))"
                ),
                index(
                    "mine_include",
                    "CREATE INDEX mine_include ON public.posts USING btree (id) INCLUDE (title_lower)"
                ),
                index(
                    "mine_partial",
                    "CREATE INDEX mine_partial ON public.posts USING btree (id) WHERE (title_lower IS NOT NULL)"
                ),
            ]
        );
    })
    .await;
}

/// A unique constraint and a check on the recreated column, and another table's foreign key to it:
/// the unique constraint's index cannot be dropped on its own, and the key cannot come back before
/// the unique constraint it needs does.
#[tokio::test]
async fn a_recreated_column_keeps_its_constraints_and_the_keys_that_reference_it() {
    common::with_integration_pool(|pool| async move {
        let setup = "ALTER TABLE public.posts ADD CONSTRAINT mine_title_lower_key UNIQUE (title_lower);
                     ALTER TABLE public.posts ADD CONSTRAINT mine_title_lower_check
                       CHECK (title_lower <> '');
                     CREATE TABLE public.notes (id INT PRIMARY KEY, post_title TEXT,
                       CONSTRAINT mine_note_post_fkey FOREIGN KEY (post_title)
                         REFERENCES public.posts (title_lower) DEFERRABLE INITIALLY DEFERRED);
                     INSERT INTO public.notes VALUES (1, 'hello');";
        recreate_title_lower_around(&pool, setup).await;
        let object = |name: &str, definition: &str| (name.to_string(), definition.to_string());
        assert_eq!(
            hand_made_objects(&pool).await,
            [
                object(
                    "mine_note_post_fkey",
                    "FOREIGN KEY (post_title) REFERENCES posts(title_lower) DEFERRABLE INITIALLY DEFERRED"
                ),
                object("mine_title_lower_check", "CHECK ((title_lower <> ''::text))"),
                object(
                    "mine_title_lower_key",
                    "CREATE UNIQUE INDEX mine_title_lower_key ON public.posts USING btree (title_lower)"
                ),
                object("mine_title_lower_key", "UNIQUE (title_lower)"),
            ]
        );
    })
    .await;
}

/// What a user made by hand on `posts.title_lower`, besides keys and indexes: each trigger's
/// `pg_get_triggerdef` and `tgenabled` (`O` origin, `D` disabled, `R` replica, `A` always), and
/// each policy as `pg_policies` describes it, by name.
async fn hand_made_triggers_and_policies(pool: &PgPool) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT tgname::text, pg_get_triggerdef(oid) || ' | ' || tgenabled::text FROM pg_trigger
          WHERE tgrelid = 'public.posts'::regclass AND tgname LIKE 'mine_%'
         UNION ALL
         SELECT policyname::text,
                concat_ws(' | ', permissive, cmd, roles::text, qual, with_check)
           FROM pg_policies
          WHERE schemaname = 'public' AND tablename = 'posts' AND policyname LIKE 'mine_%'
         ORDER BY 1, 2",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// A trigger that fires on the recreated column and a policy that reads it come back exactly as
/// they were, a trigger's enabled state (here: always, and disabled) included. A restrictive
/// policy that went missing would widen who sees what, so losing one is a security fault, not an
/// inconvenience.
#[tokio::test]
async fn a_recreated_column_keeps_a_users_triggers_and_policies() {
    common::with_integration_pool(|pool| async move {
        let setup = "CREATE FUNCTION public.mine_touch() RETURNS trigger LANGUAGE plpgsql
                       AS $$ BEGIN RETURN NEW; END $$;
                     CREATE TRIGGER mine_on_title_lower BEFORE UPDATE OF title_lower
                       ON public.posts FOR EACH ROW EXECUTE FUNCTION public.mine_touch();
                     CREATE TRIGGER mine_when_title_lower AFTER INSERT ON public.posts
                       FOR EACH ROW WHEN (NEW.title_lower IS NOT NULL)
                       EXECUTE FUNCTION public.mine_touch();
                     ALTER TABLE public.posts ENABLE ALWAYS TRIGGER mine_on_title_lower;
                     ALTER TABLE public.posts DISABLE TRIGGER mine_when_title_lower;
                     CREATE POLICY mine_hide_secret ON public.posts AS RESTRICTIVE
                       FOR SELECT TO authenticated USING (title_lower <> 'secret');
                     CREATE POLICY mine_write_lower ON public.posts FOR UPDATE TO PUBLIC
                       USING (true) WITH CHECK (title_lower = lower(title_lower));";
        recreate_title_lower_around(&pool, setup).await;
        let object = |name: &str, definition: &str| (name.to_string(), definition.to_string());
        assert_eq!(
            hand_made_triggers_and_policies(&pool).await,
            [
                object(
                    "mine_hide_secret",
                    "RESTRICTIVE | SELECT | {authenticated} | (title_lower <> 'secret'::text)"
                ),
                object(
                    "mine_on_title_lower",
                    "CREATE TRIGGER mine_on_title_lower BEFORE UPDATE OF title_lower ON public.posts FOR EACH ROW EXECUTE FUNCTION mine_touch() | A"
                ),
                object(
                    "mine_when_title_lower",
                    "CREATE TRIGGER mine_when_title_lower AFTER INSERT ON public.posts FOR EACH ROW WHEN ((new.title_lower IS NOT NULL)) EXECUTE FUNCTION mine_touch() | D"
                ),
                object(
                    "mine_write_lower",
                    "PERMISSIVE | UPDATE | {public} | true | (title_lower = lower(title_lower))"
                ),
            ]
        );
    })
    .await;
}

/// `posts.title_lower` plain and pushed with a row, `setup` run by hand, then the push that would
/// make the column generated: refused, with a message naming what is in the way, and nothing
/// changed.
async fn recreate_is_refused_around(pool: &PgPool, setup: &str, names: &[&str]) {
    let plain = posts(json!({
        "id": identity("always"),
        "title": text(json!({})),
        "title_lower": text(json!({})),
    }));
    converges(pool, &plain).await;
    exec(
        pool,
        "INSERT INTO public.posts (title, title_lower) VALUES ('Hello', 'hello')",
    )
    .await
    .unwrap();
    exec(pool, setup).await.unwrap();
    let generated = with_id(identity("always"), Some("lower(title)"));
    let refused = common::push_with(
        pool,
        &generated,
        push::ApplyOptions {
            force: true,
            ..Default::default()
        },
    )
    .await
    .expect_err("the push is refused");
    let message = format!("{refused:#}");
    for name in names {
        assert!(message.contains(name), "names {name}: {message}");
    }
    assert!(
        !message.contains("Failed to apply migration"),
        "refused before anything ran: {message}"
    );
    assert_eq!(
        how_filled(pool, "title_lower").await.2,
        "NEVER",
        "nothing changed"
    );
}

/// A view on the recreated column cannot be put back by the push (it may be anything), so the push
/// is refused before it changes anything, naming the view.
#[tokio::test]
async fn a_view_on_a_recreated_column_refuses_the_push_before_any_change() {
    common::with_integration_pool(|pool| async move {
        recreate_is_refused_around(
            &pool,
            "CREATE VIEW public.mine_titles AS SELECT id, title_lower FROM public.posts;",
            &["public.mine_titles", "title_lower"],
        )
        .await;
        let still: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_views WHERE schemaname = 'public' AND viewname = 'mine_titles'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(still, 1, "the view is untouched");
    })
    .await;
}

/// A key from a table in another schema to the recreated column is refused the same way: the push
/// works in its own schema only.
#[tokio::test]
async fn a_dependent_in_another_schema_refuses_the_push_before_any_change() {
    common::with_integration_pool(|pool| async move {
        recreate_is_refused_around(
            &pool,
            "ALTER TABLE public.posts ADD CONSTRAINT mine_title_lower_key UNIQUE (title_lower);
             CREATE SCHEMA mine_elsewhere;
             CREATE TABLE mine_elsewhere.notes (id INT PRIMARY KEY, post_title TEXT,
               CONSTRAINT mine_note_post_fkey FOREIGN KEY (post_title)
                 REFERENCES public.posts (title_lower));",
            &["mine_elsewhere", "mine_note_post_fkey"],
        )
        .await;
    })
    .await;
}

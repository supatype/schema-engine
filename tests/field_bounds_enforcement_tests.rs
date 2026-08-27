//! Declared bounds, applied to a real Postgres and breached one at a time.
//!
//! Everything else about bounds is asserted against generated text: that the CLI compiles the right
//! expression, that the engine keeps it, that the differ notices a change. Text is not enforcement.
//! `char_length(text[])` looks perfectly reasonable in a string and does not exist in Postgres;
//! `jsonb_array_length` on an object parses and then raises at insert time. Both of those shipped.
//!
//! So this suite applies the DDL the engine actually generates and then tries to break each bound,
//! one at a time, with a row that is otherwise valid. A bound that is silently absent shows up as an
//! insert that should have failed and did not, which no amount of string matching can catch.
//!
//! It covers the localized case too, because a translated field was the one field nothing enforced:
//! the scalar expression cannot run against a locale map, so the generator used to drop it.

mod common;

use supatype_engine::{
    differ, generator::sql::migration, introspector, parser,
    state::database_state::DatabaseState,
};

/// One model carrying every bound shape that reaches the database, scalar and localized.
const SCHEMA: &str = r#"{
  "astVersion": 2,
  "locales": ["en", "fr"],
  "defaultLocale": "en",
  "models": [
    {
      "name": "Page",
      "fields": {
        "id": { "kind": "uuid", "primaryKey": true, "required": true,
                "default": { "kind": "genRandomUuid" },
                "annotations": { "db": { "pgType": "UUID", "unique": false } } },

        "headline": { "kind": "text", "required": false,
                      "check": "char_length(\"{name}\") <= 10",
                      "validation": { "maxLength": 10 },
                      "annotations": { "db": { "pgType": "TEXT" } } },
        "tagline": { "kind": "text", "required": false,
                      "check": "char_length(\"{name}\") >= 5",
                      "validation": { "minLength": 5 },
                      "annotations": { "db": { "pgType": "TEXT" } } },
        "tags": { "kind": "array", "required": false,
                  "check": "cardinality(\"{name}\") <= 3",
                  "validation": { "maxItems": 3 },
                  "annotations": { "db": { "pgType": "ARRAY", "elementType": "TEXT" } } },
        "keywords": { "kind": "json", "required": false,
                  "check": "jsonb_typeof(\"{name}\") = 'array' AND jsonb_array_length(\"{name}\") >= 1",
                  "validation": { "minItems": 1 },
                  "annotations": { "db": { "pgType": "JSONB" } } },
        "body": { "kind": "richText", "required": false,
                  "check": "char_length(_supatype.richtext_text(\"{name}\")) <= 12",
                  "validation": { "maxLength": 12 },
                  "annotations": { "db": { "pgType": "JSONB" } } },
        "score": { "kind": "integer", "required": false,
                   "check": "(\"{name}\" >= 1) AND (\"{name}\" <= 5)",
                   "validation": { "min": 1, "max": 5 },
                   "annotations": { "db": { "pgType": "INTEGER" } } },
        "event_day": { "kind": "date", "required": false,
                   "check": "(\"{name}\" <= '2026-12-31'::date)",
                   "validation": { "max": "2026-12-31" },
                   "annotations": { "db": { "pgType": "DATE" } } },

        "title_i18n": { "kind": "text", "required": false, "localized": true,
                      "check": "char_length(\"{name}\") <= 10",
                      "validation": { "maxLength": 10 },
                      "annotations": { "db": { "pgType": "TEXT" } } },
        "blurb_i18n": { "kind": "richText", "required": false, "localized": true,
                      "check": "char_length(_supatype.richtext_text(\"{name}\")) <= 12",
                      "validation": { "maxLength": 12 },
                      "annotations": { "db": { "pgType": "JSONB" } } },
        "terms_i18n": { "kind": "json", "required": false, "localized": true,
                      "check": "jsonb_typeof(\"{name}\") = 'array' AND jsonb_array_length(\"{name}\") >= 1",
                      "validation": { "minItems": 1 },
                      "annotations": { "db": { "pgType": "JSONB" } } },
        "reading_i18n": { "kind": "integer", "required": false, "localized": true,
                      "check": "(\"{name}\" <= 60)",
                      "validation": { "max": 60 },
                      "annotations": { "db": { "pgType": "INTEGER" } } }
      },
      "options": { "timestamps": false, "softDelete": false },
      "annotations": { "db": { "tableName": "pages", "indexes": [] }, "platform": { "access": {} } }
    }
  ]
}"#;

fn forward_sql_for(schema_json: &str, db: &DatabaseState) -> String {
    let ast = parser::parse(schema_json).unwrap();
    let diff = differ::diff(&ast, db).unwrap();
    migration::forward_sql(&diff, true, "public", &ast).unwrap()
}

/// A row that satisfies every bound. Each case below overrides exactly one column of it.
const COMPLIANT: &str = r#"
  headline => 'short',
  tagline => 'plenty',
  tags => ARRAY['a','b'],
  keywords => '["k"]'::jsonb,
  body => '{"root":{"children":[{"type":"text","text":"hi"}]}}'::jsonb,
  score => 3,
  event_day => DATE '2026-06-01',
  title_i18n => '{"en":"short","fr":"court"}'::jsonb,
  blurb_i18n => '{"en":{"root":{"children":[{"type":"text","text":"hi"}]}},"fr":{"root":{"children":[]}}}'::jsonb,
  terms_i18n => '{"en":["a"],"fr":["b"]}'::jsonb,
  reading_i18n => '{"en":5,"fr":7}'::jsonb
"#;

/// `INSERT` for the compliant row, with `column` replaced by `value`.
fn insert_with(column: &str, value: &str) -> String {
    let mut cols = Vec::new();
    let mut vals = Vec::new();
    // Split per line, not on commas: `ARRAY['a','b']` contains commas of its own, and a splitter
    // that does not know that produces SQL which fails to parse rather than a bound that fails.
    for pair in COMPLIANT.lines() {
        let Some((name, default)) = pair.trim().trim_end_matches(',').split_once("=>") else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        cols.push(format!("\"{name}\""));
        vals.push(if name == column {
            value.to_string()
        } else {
            default.trim().to_string()
        });
    }
    format!(
        "INSERT INTO public.pages ({}) VALUES ({});",
        cols.join(", "),
        vals.join(", ")
    )
}

/// (column, breaching value, what the bound was)
const BREACHES: &[(&str, &str, &str)] = &[
    ("headline", "'far too long to fit'", "MaxLength 10 on text"),
    ("tags", "ARRAY['a','b','c','d']", "MaxItems 3 on an array"),
    ("keywords", "'[]'::jsonb", "MinItems 1 on a JSON array"),
    ("keywords", "'{\"a\":1}'::jsonb", "MinItems 1 given a JSON object, not an array"),
    (
        "body",
        "'{\"root\":{\"children\":[{\"type\":\"text\",\"text\":\"far too long to fit\"}]}}'::jsonb",
        "MaxLength 12 on rich text, measured as plain text",
    ),
    ("score", "9", "Between 1..5 on an integer"),
    ("event_day", "DATE '2027-06-01'", "Between max on a date"),
    (
        "title_i18n",
        "'{\"en\":\"short\",\"fr\":\"beaucoup trop long\"}'::jsonb",
        "MaxLength 10 on a localized text field, breached in fr only",
    ),
    (
        "blurb_i18n",
        "'{\"en\":{\"root\":{\"children\":[]}},\"fr\":{\"root\":{\"children\":[{\"type\":\"text\",\"text\":\"far too long to fit\"}]}}}'::jsonb",
        "MaxLength 12 on localized rich text, breached in fr only",
    ),
    (
        "terms_i18n",
        "'{\"en\":[\"a\"],\"fr\":[]}'::jsonb",
        "MinItems 1 on a localized JSON array, breached in fr only",
    ),
    (
        "reading_i18n",
        "'{\"en\":5,\"fr\":99}'::jsonb",
        "Between max on a localized number, breached in fr only",
    ),
];

#[tokio::test]
async fn every_declared_bound_is_enforced_by_the_database() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql(&forward_sql_for(SCHEMA, &DatabaseState::default()))
            .execute(&pool)
            .await
            .expect("generated DDL must apply");

        // The compliant row establishes that the failures below are caused by the breach and not by
        // something wrong with the row as a whole.
        sqlx::raw_sql(&insert_with("", ""))
            .execute(&pool)
            .await
            .expect("a row satisfying every bound must insert");

        for (column, value, what) in BREACHES {
            let result = sqlx::raw_sql(&insert_with(column, value)).execute(&pool).await;
            let err = result.err().unwrap_or_else(|| {
                panic!("{what}: the row was accepted, so the bound on \"{column}\" is not enforced")
            });
            let message = err.to_string();
            assert!(
                message.contains("violates check constraint") || message.contains("check constraint"),
                "{what}: expected a check-constraint rejection on \"{column}\", got: {message}"
            );
        }

        let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM public.pages")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, 1, "only the compliant row should have survived");
    })
    .await;
}

#[tokio::test]
async fn tightening_a_bound_migrates_and_takes_effect() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql(&forward_sql_for(SCHEMA, &DatabaseState::default()))
            .execute(&pool)
            .await
            .expect("generated DDL must apply");

        // A value that is legal under the current bound and illegal under the tightened one.
        sqlx::raw_sql(&insert_with("headline", "'exactly10'"))
            .execute(&pool)
            .await
            .expect("nine characters is within MaxLength 10");

        // Re-diff against the live database, which is the path a real push takes.
        let tightened = SCHEMA.replace(r#""maxLength": 10"#, r#""maxLength": 5"#).replace(
            r#""check": "char_length(\"{name}\") <= 10""#,
            r#""check": "char_length(\"{name}\") <= 5""#,
        );
        let live = introspector::introspect(&pool, "public").await.unwrap();
        let migration_sql = forward_sql_for(&tightened, &live);

        // Rows breach the new bound, so the migration must refuse rather than silently skip it.
        // Run it on a connection of its own. The script is a single BEGIN..COMMIT, so a failure part
        // way through leaves that session inside an aborted transaction, and a pooled connection
        // carrying that state poisons whatever query picks it up next. A real client rolls back, so
        // this does too, rather than papering over it by reconnecting.
        let mut conn = pool.acquire().await.unwrap();
        let refused = sqlx::raw_sql(&migration_sql).execute(&mut *conn).await;
        assert!(
            refused.is_err(),
            "tightening a bound past existing data must fail, not pass silently:\n{migration_sql}"
        );
        sqlx::raw_sql("ROLLBACK").execute(&mut *conn).await.unwrap();
        drop(conn);

        // And the old bound is still in force, because the migration is one transaction.
        sqlx::raw_sql("DELETE FROM public.pages WHERE true")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(&migration_sql)
            .execute(&pool)
            .await
            .expect("with the offending rows gone, the same migration must apply");

        let now_rejected = sqlx::raw_sql(&insert_with("headline", "'exactly10'"))
            .execute(&pool)
            .await;
        assert!(
            now_rejected.is_err(),
            "after tightening, a value that was legal before must now be rejected"
        );
    })
    .await;
}

/// (column, value exactly at the bound, which bound it sits on)
///
/// The mirror of the breaches above. A bound compiled as `<` where `<=` was meant rejects a legal
/// value, and nothing that only tests breaches would notice: every breach still fails, correctly,
/// for the wrong reason. Studio asserts the same boundaries in `bounds-parity.test.ts`, which is
/// what makes "Studio refuses exactly what Postgres refuses" a checked claim rather than a hope.
const AT_THE_BOUNDARY: &[(&str, &str, &str)] = &[
    ("headline", "'exactly10!'", "char_length = 10, the MaxLength"),
    ("tags", "ARRAY['a','b','c']", "cardinality = 3, the MaxItems"),
    ("keywords", "'[\"one\"]'::jsonb", "jsonb_array_length = 1, the MinItems"),
    (
        "body",
        "'{\"root\":{\"children\":[{\"type\":\"text\",\"text\":\"123456789012\"}]}}'::jsonb",
        "plain-text length = 12, the MaxLength",
    ),
    ("score", "5", "the top of Between 1..5"),
    ("score", "1", "the bottom of Between 1..5"),
    ("event_day", "DATE '2026-12-31'", "the last day the range admits"),
    (
        "title_i18n",
        "'{\"en\":\"exactly10!\",\"fr\":\"court\"}'::jsonb",
        "char_length = 10 in one locale, the localized MaxLength",
    ),
    (
        "terms_i18n",
        "'{\"en\":[\"a\"],\"fr\":[\"b\"]}'::jsonb",
        "one item per locale, the localized MinItems",
    ),
    ("reading_i18n", "'{\"en\":60,\"fr\":1}'::jsonb", "60, the localized maximum"),
];

/// Absence is legal however tight the bound: a CHECK that evaluates to NULL passes.
const ABSENT: &[(&str, &str)] = &[
    ("headline", "NULL"),
    ("tags", "NULL"),
    ("keywords", "NULL"),
    ("body", "NULL"),
    ("score", "NULL"),
    ("event_day", "NULL"),
    ("title_i18n", "NULL"),
];

#[tokio::test]
async fn bounds_are_inclusive_and_absence_is_legal() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql(&forward_sql_for(SCHEMA, &DatabaseState::default()))
            .execute(&pool)
            .await
            .expect("generated DDL must apply");

        for (column, value, which) in AT_THE_BOUNDARY {
            sqlx::raw_sql(&insert_with(column, value))
                .execute(&pool)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "{which}: a value exactly at the bound must be accepted, but \"{column}\" \
                         was rejected. The bound is compiled exclusive where it should be \
                         inclusive: {e}"
                    )
                });
        }

        for (column, value) in ABSENT {
            sqlx::raw_sql(&insert_with(column, value))
                .execute(&pool)
                .await
                .unwrap_or_else(|e| {
                    panic!("an absent \"{column}\" must be accepted, a CHECK against NULL passes: {e}")
                });
        }

        // The fact Studio's serializer exists to bridge: Postgres does **not** treat an empty
        // string as absent, so a blank optional field would be rejected by a minimum unless it is
        // sent as NULL. Studio's side of this is asserted in `bounds-parity.test.ts`.
        let blank = sqlx::raw_sql(&insert_with("tagline", "''")).execute(&pool).await;
        assert!(
            blank.is_err(),
            "'' must fail char_length >= 5: if Postgres ever treated blank as absent, Studio's              blank-to-null conversion would be unnecessary rather than load-bearing"
        );
        sqlx::raw_sql(&insert_with("tagline", "NULL"))
            .execute(&pool)
            .await
            .expect("NULL must pass the same bound, which is what makes the conversion correct");
    })
    .await;
}

/// Model-level constraints, applied and then broken one at a time.
///
/// Rendering the right text is not enforcement. `jsonb_array_length` on an object parses and raises
/// at insert; a regex that Postgres reads differently from JavaScript matches different rows. Only
/// running it settles either.
const CONSTRAINED: &str = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Event",
      "fields": {
        "id": { "kind": "uuid", "primaryKey": true, "required": true,
                "default": { "kind": "genRandomUuid" },
                "annotations": { "db": { "pgType": "UUID", "unique": false } } },
        "starts_at": { "kind": "datetime", "required": false,
                "annotations": { "db": { "pgType": "TIMESTAMPTZ" } } },
        "ends_at": { "kind": "datetime", "required": false,
                "annotations": { "db": { "pgType": "TIMESTAMPTZ" } } },
        "sku": { "kind": "text", "required": false,
                "annotations": { "db": { "pgType": "TEXT" } } },
        "tags": { "kind": "array", "required": false,
                "annotations": { "db": { "pgType": "ARRAY", "elementType": "TEXT" } } },
        "refs": { "kind": "json", "required": false, "jsonArray": true,
                "annotations": { "db": { "pgType": "JSONB" } } },
        "body": { "kind": "richText", "required": false,
                "annotations": { "db": { "pgType": "JSONB" } } }
      },
      "options": { "timestamps": false, "softDelete": false },
      "annotations": {
        "db": {
          "tableName": "events",
          "indexes": [],
          "constraints": [
            { "type": "compare", "op": "lte",
              "left": { "kind": "column", "name": "starts_at" },
              "right": { "kind": "column", "name": "ends_at" } },
            { "type": "matches", "column": "sku", "pattern": "^[A-Z]{3}$" },
            { "type": "compare", "op": "lte",
              "left": { "kind": "itemCount", "column": "tags", "form": "array" },
              "right": { "kind": "literal", "value": 3 } },
            { "type": "compare", "op": "gte",
              "left": { "kind": "itemCount", "column": "refs", "form": "jsonbArray" },
              "right": { "kind": "literal", "value": 1 } },
            { "type": "compare", "op": "lte",
              "left": { "kind": "length", "column": "body", "form": "richText" },
              "right": { "kind": "literal", "value": 12 } },
            { "type": "any", "rules": [
              { "type": "compare", "op": "eq",
                "left": { "kind": "column", "name": "sku" },
                "right": { "kind": "literal", "value": "ABC" } },
              { "type": "nullCheck", "operand": { "kind": "column", "name": "body" },
                "isNull": false } ] }
          ]
        },
        "platform": { "access": {} }
      }
    }
  ]
}"#;

const EVENT_COMPLIANT: &str = r#"
  starts_at => TIMESTAMPTZ '2026-01-01'
  ends_at => TIMESTAMPTZ '2026-02-01'
  sku => 'ABC'
  tags => ARRAY['a','b']
  refs => '["r"]'::jsonb
  body => '{"root":{"children":[{"type":"text","text":"hi"}]}}'::jsonb
"#;

fn insert_event(column: &str, value: &str) -> String {
    let mut cols = Vec::new();
    let mut vals = Vec::new();
    for pair in EVENT_COMPLIANT.lines() {
        let Some((name, default)) = pair.trim().trim_end_matches(',').split_once("=>") else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        cols.push(format!("\"{name}\""));
        vals.push(if name == column {
            value.to_string()
        } else {
            default.trim().to_string()
        });
    }
    format!(
        "INSERT INTO public.events ({}) VALUES ({});",
        cols.join(", "),
        vals.join(", ")
    )
}

#[tokio::test]
async fn model_constraints_are_enforced_by_the_database() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql(&forward_sql_for(CONSTRAINED, &DatabaseState::default()))
            .execute(&pool)
            .await
            .expect("constraint DDL must apply");

        sqlx::raw_sql(&insert_event("", ""))
            .execute(&pool)
            .await
            .expect("a row satisfying every constraint must insert");

        let breaches: &[(&str, &str, &str)] = &[
            ("ends_at", "TIMESTAMPTZ '2025-01-01'", "ends before it starts, a cross-column rule"),
            ("sku", "'abc'", "lowercase against the ^[A-Z]{3}$ pattern"),
            ("sku", "'ABCD'", "four characters against a three-character pattern"),
            ("tags", "ARRAY['a','b','c','d']", "four elements over ItemCount 3"),
            ("refs", "'[]'::jsonb", "no items under ItemCount 1"),
            ("refs", "'{\"a\":1}'::jsonb", "an object where an array was declared"),
            (
                "body",
                "'{\"root\":{\"children\":[{\"type\":\"text\",\"text\":\"far too long to fit\"}]}}'::jsonb",
                "rich text over Length 12, measured as plain text",
            ),
        ];

        for (column, value, what) in breaches {
            let result = sqlx::raw_sql(&insert_event(column, value)).execute(&pool).await;
            assert!(
                result.is_err(),
                "{what}: the row was accepted, so the constraint on \"{column}\" is not enforced"
            );
        }

        let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM public.events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, 1, "only the compliant row should have survived");
    })
    .await;
}

/// Editing a model constraint migrates, against a real database.
///
/// The differ tests assert the DDL; this asserts the outcome. A constraint that is created once and
/// never reconciled leaves the database enforcing yesterday's rule while the schema claims today's,
/// and no amount of string matching on generated SQL shows that.
#[tokio::test]
async fn changing_a_model_constraint_takes_effect() {
    common::with_integration_pool(|pool| async move {
        let lte = CONSTRAINED;
        sqlx::raw_sql(&forward_sql_for(lte, &DatabaseState::default()))
            .execute(&pool)
            .await
            .expect("constraint DDL must apply");

        // Legal under `starts_at <= ends_at`, and illegal once that becomes `<`.
        let equal_dates = insert_event("ends_at", "TIMESTAMPTZ '2026-01-01'");
        sqlx::raw_sql(&equal_dates)
            .execute(&pool)
            .await
            .expect("equal timestamps satisfy <=");

        let tightened = lte.replace(r#""op": "lte""#, r#""op": "lt""#);
        let live = introspector::introspect(&pool, "public").await.unwrap();
        let migration_sql = forward_sql_for(&tightened, &live);

        // The row breaches the new rule, so the migration must refuse rather than skip it.
        let mut conn = pool.acquire().await.unwrap();
        let refused = sqlx::raw_sql(&migration_sql).execute(&mut *conn).await;
        assert!(
            refused.is_err(),
            "tightening a constraint past existing data must fail:\n{migration_sql}"
        );
        sqlx::raw_sql("ROLLBACK").execute(&mut *conn).await.unwrap();
        drop(conn);

        sqlx::raw_sql("DELETE FROM public.events WHERE true")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(&migration_sql)
            .execute(&pool)
            .await
            .expect("with the offending row gone, the same migration must apply");

        // The old rule is gone and the new one is live.
        assert!(
            sqlx::raw_sql(&equal_dates).execute(&pool).await.is_err(),
            "after tightening, equal timestamps must be rejected"
        );
        sqlx::raw_sql(&insert_event("", ""))
            .execute(&pool)
            .await
            .expect("a row satisfying the tightened rule must still insert");

        // And a second push with no schema change must be a no-op, or every deploy churns.
        let live_again = introspector::introspect(&pool, "public").await.unwrap();
        let ast = parser::parse(&tightened).unwrap();
        let diff = differ::diff(&ast, &live_again).unwrap();
        assert!(
            !diff
                .operations
                .iter()
                .any(|op| matches!(op, differ::Operation::AddCheckConstraint { .. }
                    | differ::Operation::DropCheckConstraint { .. })),
            "an unchanged constraint must produce no operations on the next push: {:?}",
            diff.operations
        );
    })
    .await;
}

/// A constraint that mentions `IS NOT NULL` must still be visible to the differ.
///
/// Introspection used to drop every check whose definition contained that string, meaning to skip
/// the not-null pseudo-constraint. No supported Postgres produces one here: PG17 keeps a column's
/// `NOT NULL` off `pg_constraint` entirely, and PG18 catalogues it as `contype = 'n'`. What the
/// filter actually caught was real constraints, because `NotNull<"col">` inside a larger rule
/// renders as `IS NOT NULL` too. The differ then saw no such constraint, tried to add one that was
/// already there, and every subsequent push died on the duplicate name.
#[tokio::test]
async fn a_constraint_mentioning_is_not_null_is_not_lost_to_introspection() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql(&forward_sql_for(CONSTRAINED, &DatabaseState::default()))
            .execute(&pool)
            .await
            .expect("constraint DDL must apply");

        let live = introspector::introspect(&pool, "public").await.unwrap();
        let seen = live
            .constraints
            .iter()
            .filter(|c| c.table == "events")
            .filter_map(|c| c.check_expression.as_deref())
            .any(|def| def.contains("IS NOT NULL"));
        assert!(
            seen,
            "the null-check constraint the DDL just applied must come back from introspection"
        );

        // And the push that follows must be a no-op. This is the failure as it was actually met: a
        // second push refused with `constraint "events_check_6" for relation "events" already
        // exists`, which locks the project out of every later schema change.
        let ast = parser::parse(CONSTRAINED).unwrap();
        let diff = differ::diff(&ast, &live).unwrap();
        assert!(
            !diff.operations.iter().any(|op| matches!(
                op,
                differ::Operation::AddCheckConstraint { .. }
            )),
            "an unchanged constraint must not be added twice: {:?}",
            diff.operations
        );

        // Both legs of the OR have to be false for the rule to bite, so the sku moves off the
        // literal the rule names while staying inside the pattern constraint on that column.
        let breach = insert_event("body", "NULL").replace("'ABC'", "'XYZ'");
        sqlx::raw_sql(&breach)
            .execute(&pool)
            .await
            .expect_err("a null body with a non-matching sku must breach the rule");
    })
    .await;
}

/// A push must survive a cached snapshot that under-reports what the database holds.
///
/// `push` diffs against `_supatype.schema_state`, not against a fresh introspection, so its input
/// is whatever some earlier engine build recorded. An engine that recorded less than this one does
/// leaves a snapshot with constraints missing from it, and the differ then plans to add one that
/// is already there. That has to be recoverable from inside the tool: the alternative is a project
/// that cannot apply any schema change again without someone editing a catalog table by hand.
#[tokio::test]
async fn a_stale_snapshot_missing_a_constraint_still_pushes() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql(&forward_sql_for(CONSTRAINED, &DatabaseState::default()))
            .execute(&pool)
            .await
            .expect("constraint DDL must apply");

        // The snapshot an older engine would have left: everything it saw, minus the constraint it
        // could not see.
        let mut stale = introspector::introspect(&pool, "public").await.unwrap();
        let before = stale.constraints.len();
        stale.constraints.retain(|c| {
            !c.check_expression
                .as_deref()
                .is_some_and(|def| def.contains("IS NOT NULL"))
        });
        assert!(
            stale.constraints.len() < before,
            "the fixture must contain a constraint an older engine would have dropped"
        );

        sqlx::raw_sql(&forward_sql_for(CONSTRAINED, &stale))
            .execute(&pool)
            .await
            .expect("a push against an under-reporting snapshot must still apply");

        // And the rule is still enforced afterwards, not quietly dropped on the way through.
        let breach = insert_event("body", "NULL").replace("'ABC'", "'XYZ'");
        sqlx::raw_sql(&breach)
            .execute(&pool)
            .await
            .expect_err("the constraint must still hold after the recovering push");
    })
    .await;
}

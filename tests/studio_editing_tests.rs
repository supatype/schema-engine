//! A Studio user edits as Studio: the app's row rules do not limit them, its field rules still do.
//!
//! Studio's gateway forwards a Studio editor's or viewer's request with their own identity and one
//! claim more, `supatype_studio` (`read` or `write`), which only the gateway signs. The engine puts
//! two permissive policies on every table it manages that admit that claim, so the app's row rules
//! stop deciding what a Studio user may do, while the request still runs as `authenticated` with
//! the caller's `sub` and app role: neither `supatype_mask` (tier 1) nor the `api` views (tier 2)
//! exempt it, so a masked field stays masked by the caller's own identity.
//!
//! Before this, a Studio editor whose app role was `authenticated` saving a draft of a model whose
//! rules say `Role<"editor">` was refused with `new row violates row-level security policy for
//! table "posts_versions"`, and the only other route, the service role, unmasks every field.

mod common;

use serde_json::{json, Value};
use supatype_engine::parser::{self, ast::SchemaAst};

const A: &str = "8517c5e3-067d-4327-9dfc-ba8f8b4bc4f7";
const B: &str = "e6779ad7-38f7-4f58-a926-a652bb90b8db";
/// A Studio editor with no row of their own and no app role beyond `authenticated`.
const EDITOR: &str = "11111111-1111-1111-1111-111111111111";

/// Where a tier serves its rows from.
#[derive(Clone, Copy, Debug)]
enum Tier {
    Extension,
    Views,
}

impl Tier {
    fn relation(self) -> &'static str {
        match self {
            Tier::Extension => "public.st_employee",
            Tier::Views => "api.st_employee",
        }
    }
}

fn column(kind: &str, pg_type: &str, required: bool) -> Value {
    json!({ "kind": kind, "required": required,
            "annotations": { "db": { "pgType": pg_type, "unique": false } } })
}

/// Rows readable and writable by their owner only, `salary` the app admin's, `ssn` the owner's.
fn fixture() -> SchemaAst {
    let owner = json!({ "type": "owner", "field": "id" });
    let admin = json!({ "type": "role", "roles": ["admin"] });
    let employee = json!({
        "name": "StEmployee",
        "fields": {
            "id": { "kind": "uuid", "primaryKey": true, "required": true,
                    "annotations": { "db": { "pgType": "UUID", "unique": false } } },
            "name": column("text", "TEXT", true),
            "salary": column("integer", "INTEGER", false),
            "ssn": column("text", "TEXT", false),
        },
        "options": { "timestamps": false, "softDelete": false },
        "annotations": {
            "db": { "tableName": "st_employee", "indexes": [] },
            "platform": { "access": {
                "read": owner, "create": admin, "update": owner, "delete": admin,
                "fields": {
                    "salary": { "read": admin, "write": admin },
                    "ssn": { "read": owner }
                }
            } }
        }
    });
    let doc = json!({ "astVersion": 2, "models": [employee] }).to_string();
    parser::parse(&doc).expect("the fixture parses")
}

/// Push the fixture in `tier` and seed Alice and Bob as the superuser.
async fn pushed(pool: &sqlx::PgPool, tier: Tier) {
    if matches!(tier, Tier::Extension) {
        assert!(
            common::mask_extension_available(pool).await,
            "tier 1 needs supatype_mask"
        );
    }
    common::push(pool, &fixture()).await.expect("push");
    sqlx::raw_sql(&format!(
        "INSERT INTO public.st_employee (id, name, salary, ssn) VALUES
           ('{A}', 'Alice', 50000, 'A-SSN'), ('{B}', 'Bob', 90000, 'B-SSN');"
    ))
    .execute(pool)
    .await
    .expect("seed");
}

/// The claims of `sub` as their app issues them, plus Studio's claim when `studio` is set.
fn claims(sub: &str, studio: Option<&str>) -> Value {
    let mut claims = json!({ "role": "authenticated", "sub": sub });
    if let Some(level) = studio {
        claims["supatype_studio"] = json!(level);
    }
    claims
}

/// Runs `sql` (a query, or DML with `RETURNING`) as `authenticated` with `claims`, as PostgREST
/// does, and returns its rows as JSON, then `stored`, read as the superuser, all rolled back.
async fn as_caller(
    pool: &sqlx::PgPool,
    claims: &Value,
    sql: &str,
) -> (Result<Vec<Value>, String>, Vec<String>) {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('request.jwt.claims', $1, true)")
        .bind(claims.to_string())
        .execute(&mut *tx)
        .await
        .expect("set the claims");
    sqlx::raw_sql("SET LOCAL ROLE authenticated; SAVEPOINT caller")
        .execute(&mut *tx)
        .await
        .expect("assume authenticated");
    let wrapped = format!("WITH q AS ({sql}) SELECT coalesce(json_agg(q), '[]')::text FROM q");
    let rows = match sqlx::query_scalar::<_, String>(&wrapped)
        .fetch_one(&mut *tx)
        .await
    {
        Ok(text) => Ok(serde_json::from_str(&text).expect("json rows")),
        Err(e) => {
            sqlx::raw_sql("ROLLBACK TO SAVEPOINT caller")
                .execute(&mut *tx)
                .await
                .expect("rollback");
            Err(e.to_string())
        }
    };
    sqlx::raw_sql("RESET ROLE")
        .execute(&mut *tx)
        .await
        .expect("reset role");
    let stored = stored_rows(&mut tx).await;
    let _ = tx.rollback().await;
    (rows, stored)
}

/// What [`stored_rows`] reads per fixture: the table, and its rows as text, by name.
const STORED: [(&str, &str); 2] = [
    (
        "public.st_employee",
        "SELECT name || '|' || coalesce(salary::text, '-') || '|' || coalesce(ssn, '-')
           FROM public.st_employee ORDER BY name",
    ),
    (
        "public.st_staff",
        "SELECT name || '|' || coalesce(salary::text, '-') FROM public.st_staff ORDER BY name",
    ),
];

/// The stored rows of whichever fixture was pushed ([`STORED`]), read with no tier in the way;
/// none where neither was.
async fn stored_rows(tx: &mut sqlx::PgConnection) -> Vec<String> {
    for (table, read) in STORED {
        let pushed: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(table)
            .fetch_one(&mut *tx)
            .await
            .expect("look for the table");
        if pushed {
            return sqlx::query_scalar(read)
                .fetch_all(&mut *tx)
                .await
                .expect("read the stored rows");
        }
    }
    Vec::new()
}

/// `(name, salary, ssn)` per row, as returned.
fn shown(rows: Result<Vec<Value>, String>) -> Vec<(Value, Value, Value)> {
    rows.unwrap_or_else(|e| panic!("refused: {e}"))
        .iter()
        .map(|r| (r["name"].clone(), r["salary"].clone(), r["ssn"].clone()))
        .collect()
}

fn read_all(tier: Tier) -> String {
    format!(
        "SELECT name, salary, ssn FROM {} ORDER BY name",
        tier.relation()
    )
}

async fn reads_every_row_masked(tier: Tier) {
    common::with_integration_pool(|pool| async move {
        pushed(&pool, tier).await;
        let read = read_all(tier);
        let (app, _) = as_caller(&pool, &claims(EDITOR, None), &read).await;
        assert_eq!(
            shown(app),
            Vec::new(),
            "{tier:?}: the app's rules show the editor no row"
        );

        let null = Value::Null;
        for level in ["read", "write"] {
            let (studio, _) = as_caller(&pool, &claims(EDITOR, Some(level)), &read).await;
            assert_eq!(
                shown(studio),
                vec![
                    (json!("Alice"), null.clone(), null.clone()),
                    (json!("Bob"), null.clone(), null.clone()),
                ],
                "{tier:?} {level}: every row, salary and ssn still masked for the editor"
            );
        }
        let (alice, _) = as_caller(&pool, &claims(A, Some("read")), &read).await;
        assert_eq!(
            shown(alice),
            vec![
                (json!("Alice"), null.clone(), json!("A-SSN")),
                (json!("Bob"), null.clone(), null.clone()),
            ],
            "{tier:?}: masking keys off the caller's own identity: Alice reads her own ssn only"
        );
    })
    .await;
}

#[tokio::test]
async fn a_studio_user_reads_every_row_with_field_masking_applied_tier_one() {
    reads_every_row_masked(Tier::Extension).await;
}

#[tokio::test]
async fn a_studio_user_reads_every_row_with_field_masking_applied_tier_two() {
    reads_every_row_masked(Tier::Views).await;
}

const SEEDED: [&str; 2] = ["Alice|50000|A-SSN", "Bob|90000|B-SSN"];

/// An editor writes rows the app's rules would refuse them, and their writes are attributed to
/// the rows they meant: a rename keeps the masked salary they never saw.
async fn editor_writes_past_row_rules(tier: Tier) {
    common::with_integration_pool(|pool| async move {
        pushed(&pool, tier).await;
        let rel = tier.relation();
        let rename = format!("UPDATE {rel} SET name = 'Alicia' WHERE id = '{A}' RETURNING name");
        let (app, stored) = as_caller(&pool, &claims(EDITOR, None), &rename).await;
        assert_eq!(
            app.expect("an update no rule admits changes nothing"),
            Vec::<Value>::new()
        );
        assert_eq!(
            stored, SEEDED,
            "{tier:?}: the app's rules refuse the editor"
        );

        let editor = claims(EDITOR, Some("write"));
        let (renamed, stored) = as_caller(&pool, &editor, &rename).await;
        assert_eq!(renamed.expect("renamed"), vec![json!({ "name": "Alicia" })]);
        assert_eq!(
            stored,
            ["Alicia|50000|A-SSN", "Bob|90000|B-SSN"],
            "{tier:?}: salary kept"
        );

        let insert =
            format!("INSERT INTO {rel} (id, name) VALUES ('{EDITOR}', 'Eve') RETURNING name");
        let (inserted, _) = as_caller(&pool, &editor, &insert).await;
        assert_eq!(
            inserted.expect("inserted"),
            vec![json!({ "name": "Eve" })],
            "{tier:?}"
        );

        let delete = format!("DELETE FROM {rel} WHERE id = '{B}' RETURNING id");
        let (_, stored) = as_caller(&pool, &editor, &delete).await;
        assert_eq!(
            stored,
            ["Alice|50000|A-SSN"],
            "{tier:?}: the editor deletes past the rules"
        );
    })
    .await;
}

#[tokio::test]
async fn a_studio_editor_writes_past_the_apps_row_rules_tier_one() {
    editor_writes_past_row_rules(Tier::Extension).await;
}

#[tokio::test]
async fn a_studio_editor_writes_past_the_apps_row_rules_tier_two() {
    editor_writes_past_row_rules(Tier::Views).await;
}

/// The record a caller creates in the tests below, for someone other than the editor.
const NEW: &str = "22222222-2222-2222-2222-222222222222";

/// The claims of `sub` as an app admin, who passes the fixture's create rule and its salary rule.
fn app_admin(sub: &str) -> Value {
    json!({ "role": "authenticated", "sub": sub, "app_metadata": { "role": "admin" } })
}

/// Nia's record, `NEW`'s, created in `tier` with both masked fields given.
fn insert_nia(tier: Tier) -> String {
    format!(
        "INSERT INTO {} (id, name, salary, ssn) VALUES ('{NEW}', 'Nia', 7, 'N-SSN') RETURNING id",
        tier.relation()
    )
}

const NIA: &str = "Nia|7|N-SSN";

/// A Studio editor creating a record may give the fields masked from them: on a new record they see
/// only what they typed. Once the record exists those fields are protected as before, and a Studio
/// reader creates nothing.
async fn studio_create_sets_masked_fields(tier: Tier) {
    common::with_integration_pool(|pool| async move {
        pushed(&pool, tier).await;
        let editor = claims(EDITOR, Some("write"));
        let (created, stored) = as_caller(&pool, &editor, &insert_nia(tier)).await;
        created.unwrap_or_else(|e| panic!("{tier:?}: the editor's create was refused: {e}"));
        assert!(stored.contains(&NIA.to_string()), "{tier:?}: {stored:?}");

        let rel = tier.relation();
        let overwrite =
            format!("UPDATE {rel} SET salary = 1, ssn = 'X' WHERE id = '{A}' RETURNING id");
        let (_, stored) = as_caller(&pool, &editor, &overwrite).await;
        assert_eq!(
            stored, SEEDED,
            "{tier:?}: an existing record's masked fields are kept"
        );

        let reader = claims(EDITOR, Some("read"));
        let (refused, stored) = as_caller(&pool, &reader, &insert_nia(tier)).await;
        assert!(
            refused.is_err(),
            "{tier:?}: a Studio reader created a record"
        );
        assert_eq!(stored, SEEDED, "{tier:?}");
    })
    .await;
}

#[tokio::test]
async fn a_studio_editor_creates_a_record_with_its_masked_fields_tier_one() {
    studio_create_sets_masked_fields(Tier::Extension).await;
}

#[tokio::test]
async fn a_studio_editor_creates_a_record_with_its_masked_fields_tier_two() {
    studio_create_sets_masked_fields(Tier::Views).await;
}

/// An app caller's create is judged by the field rules as before: an admin may not give the ssn of
/// a record they do not own, and may give their own.
async fn app_create_is_judged_as_before(tier: Tier) {
    common::with_integration_pool(|pool| async move {
        pushed(&pool, tier).await;
        let (refused, stored) = as_caller(&pool, &app_admin(EDITOR), &insert_nia(tier)).await;
        assert!(
            refused.as_ref().is_err_and(|e| e.contains("ssn")),
            "{tier:?}: an app admin gave another's ssn: {refused:?}"
        );
        assert_eq!(stored, SEEDED, "{tier:?}");

        let (own, stored) = as_caller(&pool, &app_admin(NEW), &insert_nia(tier)).await;
        own.unwrap_or_else(|e| panic!("{tier:?}: an admin's own record was refused: {e}"));
        assert!(stored.contains(&NIA.to_string()), "{tier:?}: {stored:?}");
    })
    .await;
}

#[tokio::test]
async fn an_app_callers_create_is_judged_by_the_field_rules_tier_one() {
    app_create_is_judged_as_before(Tier::Extension).await;
}

#[tokio::test]
async fn an_app_callers_create_is_judged_by_the_field_rules_tier_two() {
    app_create_is_judged_as_before(Tier::Views).await;
}

/// An upsert that meets an existing record is not a create. Tier 1 judges its insert half against
/// the record already stored, so a Studio editor overwrites no masked field through it. (Tier 2's
/// views take no `ON CONFLICT`.)
#[tokio::test]
async fn a_studio_upsert_onto_an_existing_record_keeps_its_masked_fields_tier_one() {
    common::with_integration_pool(|pool| async move {
        pushed(&pool, Tier::Extension).await;
        let upsert = format!(
            "INSERT INTO public.st_employee (id, name, salary, ssn) VALUES ('{A}', 'Alice', 1, 'X')
             ON CONFLICT (id) DO UPDATE SET salary = excluded.salary, ssn = excluded.ssn
             RETURNING id"
        );
        let (_, stored) = as_caller(&pool, &claims(EDITOR, Some("write")), &upsert).await;
        assert_eq!(stored, SEEDED, "the upsert kept Alice's masked fields");
    })
    .await;
}

/// A field rule still binds a Studio editor, and a Studio reader writes nothing at all.
async fn field_rules_and_readers_still_bind(tier: Tier) {
    common::with_integration_pool(|pool| async move {
        pushed(&pool, tier).await;
        let rel = tier.relation();
        let raise = format!("UPDATE {rel} SET salary = 1 WHERE id = '{A}' RETURNING id");
        // A column the caller cannot read keeps its stored value, as it does for them in the app:
        // the contract both tiers share (`field_access_contract_tests`).
        let (_, stored) = as_caller(&pool, &claims(EDITOR, Some("write")), &raise).await;
        assert_eq!(
            stored, SEEDED,
            "{tier:?}: salary is the app admin's to write"
        );

        let reader = claims(EDITOR, Some("read"));
        let rename = format!("UPDATE {rel} SET name = 'Alicia' WHERE id = '{A}' RETURNING id");
        let delete = format!("DELETE FROM {rel} WHERE id = '{A}' RETURNING id");
        for sql in [rename, delete] {
            let (_, stored) = as_caller(&pool, &reader, &sql).await;
            assert_eq!(
                stored, SEEDED,
                "{tier:?}: a Studio reader changed a row: {sql}"
            );
        }
        let insert =
            format!("INSERT INTO {rel} (id, name) VALUES ('{EDITOR}', 'Eve') RETURNING id");
        let (refused, _) = as_caller(&pool, &reader, &insert).await;
        assert!(refused.is_err(), "{tier:?}: a Studio reader inserted a row");
    })
    .await;
}

#[tokio::test]
async fn field_rules_and_the_read_level_still_bind_a_studio_user_tier_one() {
    field_rules_and_readers_still_bind(Tier::Extension).await;
}

#[tokio::test]
async fn field_rules_and_the_read_level_still_bind_a_studio_user_tier_two() {
    field_rules_and_readers_still_bind(Tier::Views).await;
}

/// kitchen-sink's case: a model whose rules say `Role<"editor">`, and a Studio editor whose app role
/// is `authenticated`, saving a draft through `create_draft`.
fn versioned_blog() -> SchemaAst {
    let mut doc: Value =
        serde_json::from_str(include_str!("fixtures/versioned_blog.json")).expect("fixture");
    doc["models"][0]["annotations"]["platform"]["access"] = json!({
        "read": { "type": "public" },
        "create": { "type": "role", "roles": ["editor"] },
        "update": { "type": "role", "roles": ["editor"] }
    });
    parser::parse(&doc.to_string()).expect("the blog parses")
}

#[tokio::test]
async fn a_studio_editor_saves_a_draft_the_apps_rules_would_refuse() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &versioned_blog()).await.expect("push");
        sqlx::raw_sql(&format!(
            "INSERT INTO public.posts (id, title, body) VALUES ('{A}', 'Draft', '{{\"en\": \"x\"}}')"
        ))
        .execute(&pool)
        .await
        .expect("seed a post");
        let save = format!(
            "SELECT * FROM supatype.create_draft('posts', '{A}', '{{\"title\": \"Edited\"}}')"
        );
        let (app, _) = as_caller(&pool, &claims(EDITOR, None), &save).await;
        assert!(
            app.as_ref().is_err_and(|e| e.contains(
                "new row violates row-level security policy for table \"posts_versions\""
            )),
            "the app's rules refuse an authenticated caller, as kitchen-sink reported: {app:?}"
        );
        let (studio, _) = as_caller(&pool, &claims(EDITOR, Some("write")), &save).await;
        let saved = studio.unwrap_or_else(|e| panic!("a Studio editor's draft was refused: {e}"));
        assert_eq!(saved.len(), 1, "one draft saved: {saved:?}");
    })
    .await;
}

/// [`team_fixture_with`] with its `bonus` rule.
fn team_fixture() -> SchemaAst {
    team_fixture_with(true)
}

/// A team readable by its owner only, and staff whose `salary` is readable and writable where the
/// staff member's team is one the caller may read: `In<team_id, Rows<st_team, id>>`. With `bonus`,
/// the staff's `bonus` is readable by a caller who may read any team: `Exists<Rows<st_team>>`.
fn team_fixture_with(bonus: bool) -> SchemaAst {
    let owner = json!({ "type": "owner", "field": "owner_id" });
    let in_my_teams = json!({ "type": "in", "column": "team_id",
                              "source": { "kind": "rows", "table": "st_team", "column": "id" } });
    let id = json!({ "kind": "uuid", "primaryKey": true, "required": true,
                     "annotations": { "db": { "pgType": "UUID", "unique": false } } });
    let model = |name: &str, table: &str, fields: Value, access: Value| {
        json!({ "name": name, "fields": fields,
                "options": { "timestamps": false, "softDelete": false },
                "annotations": { "db": { "tableName": table, "indexes": [] },
                                 "platform": { "access": access } } })
    };
    let team = model(
        "StTeam",
        "st_team",
        json!({ "id": id, "name": column("text", "TEXT", true),
                "owner_id": column("uuid", "UUID", true) }),
        json!({ "read": owner }),
    );
    let mut fields = json!({ "salary": { "read": in_my_teams, "write": in_my_teams } });
    if bonus {
        fields["bonus"] = json!({ "read": { "type": "exists", "source": {
            "kind": "rows", "table": "st_team", "column": "id" } } });
    }
    let staff = model(
        "StStaff",
        "st_staff",
        json!({ "id": id, "name": column("text", "TEXT", true),
                "team_id": column("uuid", "UUID", true),
                "salary": column("integer", "INTEGER", false),
                "bonus": column("integer", "INTEGER", false) }),
        json!({ "read": { "type": "public" }, "update": { "type": "role", "roles": ["admin"] },
                "fields": fields }),
    );
    let doc = json!({ "astVersion": 2, "models": [team, staff] }).to_string();
    parser::parse(&doc).expect("the team fixture parses")
}

const TEAM_A: &str = "aaaaaaaa-0000-0000-0000-00000000000a";
const TEAM_B: &str = "bbbbbbbb-0000-0000-0000-00000000000b";

/// Alice's team and Bob's, one staff member in each.
async fn teams_pushed(pool: &sqlx::PgPool) {
    common::push(pool, &team_fixture()).await.expect("push");
    sqlx::raw_sql(&format!(
        "INSERT INTO public.st_team (id, name, owner_id) VALUES
           ('{TEAM_A}', 'Red', '{A}'), ('{TEAM_B}', 'Blue', '{B}');
         INSERT INTO public.st_staff (id, name, team_id, salary, bonus) VALUES
           (gen_random_uuid(), 'Ann', '{TEAM_A}', 100, 10),
           (gen_random_uuid(), 'Ben', '{TEAM_B}', 200, 20);"
    ))
    .execute(pool)
    .await
    .expect("seed the teams");
}

/// A field rule that asks which rows of another table the caller may read answers by the app's
/// rules, never by Studio's: Studio's read-everything policy on `st_team` must not make every team
/// the caller's, or Alice would read Ben's salary in Blue, a team she is not in.
async fn rows_rule_ignores_studio(tier: Tier) {
    common::with_integration_pool(|pool| async move {
        if matches!(tier, Tier::Extension) {
            assert!(
                common::mask_extension_available(&pool).await,
                "tier 1 needs supatype_mask"
            );
        }
        teams_pushed(&pool).await;
        let read = format!("SELECT name, salary FROM {} ORDER BY name", staff(tier));
        let expected = vec![
            json!({ "name": "Ann", "salary": 100 }),
            json!({ "name": "Ben", "salary": null }),
        ];
        for studio in [None, Some("read"), Some("write")] {
            let (rows, _) = as_caller(&pool, &claims(A, studio), &read).await;
            assert_eq!(
                rows.unwrap_or_else(|e| panic!("refused: {e}")),
                expected,
                "{tier:?} studio={studio:?}: Alice reads the salary of her own team's staff only"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn a_rows_field_rule_is_not_widened_by_studio_tier_one() {
    rows_rule_ignores_studio(Tier::Extension).await;
}

#[tokio::test]
async fn a_rows_field_rule_is_not_widened_by_studio_tier_two() {
    rows_rule_ignores_studio(Tier::Views).await;
}

/// Where a tier serves the staff from.
fn staff(tier: Tier) -> &'static str {
    match tier {
        Tier::Extension => "public.st_staff",
        Tier::Views => "api.st_staff",
    }
}

/// The write half: a Studio editor may change any row, but a salary only where the app's rules
/// put its staff member in one of their teams, never every team because Studio reads them all.
async fn rows_write_rule_ignores_studio(tier: Tier) {
    common::with_integration_pool(|pool| async move {
        if matches!(tier, Tier::Extension) {
            assert!(
                common::mask_extension_available(&pool).await,
                "tier 1 needs supatype_mask"
            );
        }
        teams_pushed(&pool).await;
        let raise = |name: &str| {
            format!(
                "UPDATE {} SET salary = 1 WHERE name = '{name}' RETURNING id",
                staff(tier)
            )
        };
        let editor = claims(A, Some("write"));
        let (_, stored) = as_caller(&pool, &editor, &raise("Ben")).await;
        assert_eq!(
            stored,
            ["Ann|100", "Ben|200"],
            "{tier:?}: Alice wrote the salary of Ben, in a team she is not in"
        );
        let (_, stored) = as_caller(&pool, &editor, &raise("Ann")).await;
        assert_eq!(
            stored,
            ["Ann|1", "Ben|200"],
            "{tier:?}: Alice writes her own team's salary"
        );
    })
    .await;
}

#[tokio::test]
async fn a_rows_write_rule_is_not_widened_by_studio_tier_one() {
    rows_write_rule_ignores_studio(Tier::Extension).await;
}

#[tokio::test]
async fn a_rows_write_rule_is_not_widened_by_studio_tier_two() {
    rows_write_rule_ignores_studio(Tier::Views).await;
}

/// An `Exists` rule over another table is not widened either: the editor owns no team, so they
/// read no bonus however many teams Studio shows them, while Alice, who owns one, reads every bonus.
async fn exists_rule_ignores_studio(tier: Tier) {
    common::with_integration_pool(|pool| async move {
        if matches!(tier, Tier::Extension) {
            assert!(
                common::mask_extension_available(&pool).await,
                "tier 1 needs supatype_mask"
            );
        }
        teams_pushed(&pool).await;
        let read = format!("SELECT name, bonus FROM {} ORDER BY name", staff(tier));
        let bonuses = |pairs: [(&str, Value); 2]| -> Vec<Value> {
            pairs
                .map(|(name, bonus)| json!({ "name": name, "bonus": bonus }))
                .to_vec()
        };
        let none = bonuses([("Ann", Value::Null), ("Ben", Value::Null)]);
        let all = bonuses([("Ann", json!(10)), ("Ben", json!(20))]);
        for (caller, expected, who) in [
            (
                claims(EDITOR, Some("read")),
                &none,
                "a Studio reader who owns no team",
            ),
            (claims(EDITOR, None), &none, "an app user who owns no team"),
            (claims(A, None), &all, "Alice in the app, who owns a team"),
            (claims(A, Some("read")), &all, "Alice in Studio"),
        ] {
            let (rows, _) = as_caller(&pool, &caller, &read).await;
            let rows = rows.unwrap_or_else(|e| panic!("refused: {e}"));
            assert_eq!(&rows, expected, "{tier:?}: {who}");
        }
    })
    .await;
}

#[tokio::test]
async fn an_exists_field_rule_is_not_widened_by_studio_tier_one() {
    exists_rule_ignores_studio(Tier::Extension).await;
}

#[tokio::test]
async fn an_exists_field_rule_is_not_widened_by_studio_tier_two() {
    exists_rule_ignores_studio(Tier::Views).await;
}

/// The tier 2 set helpers, by name, and whether `PUBLIC` may call any of them.
async fn staff_helpers(pool: &sqlx::PgPool) -> (Vec<String>, bool) {
    sqlx::query_as(
        r"SELECT coalesce(array_agg(p.proname::text ORDER BY p.proname), '{}'),
                 coalesce(bool_or(EXISTS (
                   SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                    WHERE a.grantee = 0)), false)
            FROM pg_proc p
           WHERE p.pronamespace = '_supatype'::regnamespace
             AND p.proname LIKE 'rule\_set\_%'",
    )
    .fetch_one(pool)
    .await
    .expect("read the helpers")
}

/// The functions and views a second push of `ast` would touch: none, once it has converged.
async fn churn(pool: &sqlx::PgPool, ast: &SchemaAst) -> Vec<String> {
    use supatype_engine::introspector::fingerprint::ObjectKind;
    let plan = supatype_engine::push::prepare(pool, ast, "public")
        .await
        .expect("plan");
    plan.reconcile
        .actions
        .iter()
        .filter(|a| matches!(a.key().kind, ObjectKind::Function | ObjectKind::View))
        .filter(|a| a.is_change())
        .map(|a| format!("{a:?}"))
        .collect()
}

/// Tier 2 reads another table for a rule through a set helper the views call: one per question
/// (salary's read and write rules ask the same one), callable only by the roles that read through
/// the views, left alone by a push that changes nothing, and dropped with the last rule asking it
/// while the view that called it is remade.
#[tokio::test]
async fn tier_two_rule_helpers_follow_their_rules() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &team_fixture()).await.expect("push");
        let (with_bonus, public) = staff_helpers(&pool).await;
        assert_eq!(
            with_bonus.len(),
            2,
            "salary's question and bonus's: {with_bonus:?}"
        );
        assert!(!public, "PUBLIC may not call a rule helper");
        assert_eq!(churn(&pool, &team_fixture()).await, Vec::<String>::new());

        let without = team_fixture_with(false);
        common::push(&pool, &without)
            .await
            .expect("the push dropping bonus's rule applies");
        let (names, _) = staff_helpers(&pool).await;
        assert_eq!(
            names.len(),
            1,
            "bonus's helper went with its rule: {names:?}"
        );
        assert!(with_bonus.contains(&names[0]), "salary's helper was kept");
        assert_eq!(churn(&pool, &without).await, Vec::<String>::new());
    })
    .await;
}

/// A hand edit to a set helper changes who may read a column as surely as an edit to the view that
/// calls it, so it is access drift: a non-interactive push refuses to put it back without consent,
/// and doctor leaves it drifted unless it is told `--accept-access-drift`.
#[tokio::test]
async fn a_hand_edited_rule_set_helper_is_access_drift() {
    common::with_integration_pool(|pool| async move {
        use supatype_engine::{inspect, ledger::reconcile::Action};
        let ast = team_fixture();
        common::push(&pool, &ast).await.expect("push");
        let (helpers, _) = staff_helpers(&pool).await;
        sqlx::raw_sql(&format!(
            "ALTER FUNCTION _supatype.{}() SECURITY INVOKER",
            helpers[0]
        ))
        .execute(&pool)
        .await
        .expect("the hand edit");
        let plan = supatype_engine::push::prepare(&pool, &ast, "public")
            .await
            .expect("plan");
        let access_drift = plan.reconcile.actions.iter().any(|a| {
            matches!(a, Action::Drift { key, security_relevant: true, .. }
                if key.name.starts_with("rule_set_"))
        });
        assert!(access_drift, "{:?}", plan.reconcile.actions);
        let refused = common::push(&pool, &ast).await;
        assert!(
            refused.is_err_and(|e| e.to_string().contains("changed outside Supatype")),
            "a push put the helper back without consent"
        );
        let names = |items: &[supatype_engine::differ::doctor::DoctorItem]| -> Vec<String> {
            items.iter().map(|i| i.name.clone()).collect()
        };
        let without = inspect::rebaseline(&pool, &ast, "public", false)
            .await
            .expect("rebaseline");
        assert!(names(&without.rebaselined).is_empty(), "{without:#?}");
        assert!(
            names(&without.rebaseline_refused)
                .iter()
                .any(|n| n.starts_with(&helpers[0])),
            "{without:#?}"
        );
        let with = inspect::rebaseline(&pool, &ast, "public", true)
            .await
            .expect("rebaseline with consent");
        assert!(
            names(&with.rebaselined)
                .iter()
                .any(|n| n.starts_with(&helpers[0])),
            "{with:#?}"
        );
    })
    .await;
}

/// The versioned blog with `title` the app admin's to read.
fn masked_blog() -> SchemaAst {
    let mut doc: Value =
        serde_json::from_str(include_str!("fixtures/versioned_blog.json")).expect("fixture");
    doc["models"][0]["annotations"]["platform"]["access"] = json!({
        "read": { "type": "public" },
        "update": { "type": "public" },
        "fields": { "title": { "read": { "type": "role", "roles": ["admin"] } } }
    });
    parser::parse(&doc.to_string()).expect("the blog parses")
}

/// Studio shows every draft to a Studio user, so a draft must never hold a value a field rule
/// masks. A snapshot is the whole record as `jsonb`, which neither tier can mask inside, so the
/// engine refuses a versioned model with a field rule before either tier is chosen, and nothing
/// reaches the database: there is no snapshot of a masked field for Studio or the API to serve.
#[tokio::test]
async fn a_versioned_model_cannot_mask_a_field_so_no_draft_holds_one() {
    common::with_integration_pool(|pool| async move {
        let refused = common::push(&pool, &masked_blog())
            .await
            .expect_err("the push is refused");
        assert!(
            format!("{refused:#}")
                .contains("declare both `versions` and per-column `access.fields`"),
            "refused for the masked field in a versioned model: {refused:#}"
        );
        let applied: bool = sqlx::query_scalar(
            "SELECT to_regclass('public.posts_versions') IS NOT NULL
                 OR to_regclass('public.posts') IS NOT NULL",
        )
        .fetch_one(&pool)
        .await
        .expect("look for the tables");
        assert!(!applied, "nothing of the refused schema was applied");
    })
    .await;
}

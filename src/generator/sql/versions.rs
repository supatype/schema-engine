//! Drafts, version history and publishing, for the models that declare `versions`.
//!
//! **The model's table stays the published state.** Snapshots live in a companion
//! `<table>_versions` table, one of which may be a newer draft, so constraints, foreign keys,
//! indexes, access rules and realtime on the model's own table are untouched: it is still an
//! ordinary table holding one row per document. That is what lets a published version stay live
//! while a newer unpublished one exists, which a `status` column cannot do, because a single row
//! holds one copy of the content.
//!
//! Four pieces, in the order a migration needs them:
//!
//! 1. **The versions table**, created like a junction table: engine-owned, stamped with the managed
//!    marker, `IF NOT EXISTS`. Its shape is fixed and does not vary with the model, so it is emitted
//!    by an operation of its own rather than diffed column by column.
//! 2. **Helpers** in `_supatype`, reading the caller's membership and any preview claim.
//! 3. **`draft.<table>` views** with `security_invoker`, reconstructing the model's column shape out
//!    of the snapshot so a client stays typed even though storage is JSONB.
//! 4. **`supatype.publish` and friends**, `SECURITY INVOKER`, so the policy that already governs
//!    editing governs publishing.
//!
//! **Who sees a draft is not the model's `read` rule and not its `update` rule.** It is the record's
//! creator, plus the Studio roles the project nominates, plus the bearer of a signed preview link.
//! Tracking `read` would make every unpublished edit world-readable on a `Public` model; tracking
//! `update` breaks in both directions, hiding a draft from the developer debugging it on an
//! `Owner<>` model and exposing every draft to every signed-in user on a `LoggedIn` one.

use crate::parser::accessors::db_table_name;
use crate::parser::ast::{ModelAst, PublishingAst, SchemaAst, VersionsAst};
use anyhow::{bail, Result};

/// Schema holding one draft view per versioned model, selected with `Accept-Profile: draft`.
///
/// Its own schema rather than a suffix on the table name, so a draft carries the same table name and
/// the same row type as what it is a draft of. Also stated in the CLI (which puts it on
/// `PGRST_DB_SCHEMA`) and in `@supatype/client` (which sends the header).
pub const DRAFT_SCHEMA: &str = "draft";

/// Schema holding the publish functions. On the exposed list, so they are reachable over RPC.
pub const RPC_SCHEMA: &str = "supatype";

/// Schema holding the helpers the policies call. Never exposed to the API.
pub const HELPER_SCHEMA: &str = "_supatype";

/// Suffix on a versioned model's snapshot table.
pub const VERSIONS_SUFFIX: &str = "_versions";

/// The snapshot table for a model's table.
pub fn versions_table_name(table: &str) -> String {
    format!("{table}{VERSIONS_SUFFIX}")
}

/// A model's `versions` declaration, when it has one.
pub fn versions_of(model: &ModelAst) -> Option<&VersionsAst> {
    model.options.versions.as_ref()
}

/// Every model that declares `versions`, in declaration order.
pub fn versioned_models(ast: &SchemaAst) -> Vec<&ModelAst> {
    ast.models
        .iter()
        .filter(|m| versions_of(m).is_some())
        .collect()
}

/// True when this schema needs the versions layer at all.
pub fn has_versions(ast: &SchemaAst) -> bool {
    ast.models.iter().any(|m| versions_of(m).is_some())
}

/// Every snapshot table this schema owns, for the differ's "tables we know about" set.
///
/// Without this the removed-table pass drops them on the next push: they carry the managed marker,
/// so the ownership gate is no protection, and the drop takes every version with it.
pub fn versions_tables(ast: &SchemaAst) -> Vec<String> {
    versioned_models(ast)
        .iter()
        .map(|m| versions_table_name(db_table_name(m)))
        .collect()
}

fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Single-quote a string for SQL.
///
/// Every value passed here comes from a schema the author wrote, but a stray apostrophe in a role
/// name would otherwise end the literal and change the meaning of a policy.
fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Refuse a versioned model that also masks a column.
///
/// The CLI refuses this too, where the message can name the file. Repeated here because the engine
/// is reachable directly: a snapshot is opaque `jsonb`, so neither masking tier can see inside it,
/// and a schema whose restrictions have a hole in them must not be applied.
pub fn assert_no_versions_with_field_rules(ast: &SchemaAst) -> Result<()> {
    let offenders: Vec<String> = ast
        .models
        .iter()
        .filter(|m| versions_of(m).is_some())
        .filter(|m| !crate::parser::accessors::platform_access(m).fields.is_empty())
        .map(|m| m.name.clone())
        .collect();

    if offenders.is_empty() {
        return Ok(());
    }
    bail!(
        "Model(s) {} declare both `versions` and per-column `access.fields`, which cannot both be \
         enforced.\n\nNothing was applied. A version snapshot is opaque JSONB: the masking that \
         rewrites references to a real column cannot see inside it, so a masked value would be \
         readable in the versions table by anyone who can read a draft.\n\nDrop one: keep the field \
         rules, or version a model that does not mask a column.",
        offenders.join(", ")
    );
}

/// The publishing config, or an error naming what the caller failed to send.
///
/// Deliberately not defaulted. The visibility list is a security boundary, and a default applied
/// silently is how a project that widened its setting gets the narrow policy anyway: the exact
/// failure shape this repo has hit before, where a setting reads as applied and is not.
fn require_publishing(ast: &SchemaAst) -> Result<&PublishingAst> {
    match ast.publishing.as_ref() {
        Some(publishing) => Ok(publishing),
        None => bail!(
            "This schema has versioned model(s) but the push carried no `publishing` config, so \
             there is no draft-visibility setting to compile into their policies.\n\nNothing was \
             applied. Rather than fall back on a default, which would quietly narrow or widen who \
             can read unpublished content, this is an error: the caller has to state it. A CLI new \
             enough to send `versions` sends this beside it."
        ),
    }
}

// ─── The snapshot table ───────────────────────────────────────────────────────

/// `CREATE TABLE` for one model's snapshot table.
///
/// Fixed shape: it does not vary with the model, only the `record_id` type does, which follows the
/// model's own primary key. `ON DELETE CASCADE` because a version of a deleted record is not history
/// worth keeping, it is a snapshot of something that no longer exists and whose foreign key would
/// dangle.
pub fn create_versions_table_sql(
    schema: &str,
    table: &str,
    versions_table: &str,
    record_id_type: &str,
    primary_key: &str,
) -> String {
    let marker = crate::managed::managed_comment("table", versions_table, &[]);
    let index = versions_record_index_name(versions_table);
    format!(
        "CREATE TABLE IF NOT EXISTS {schema_q}.{versions_q} (\n    \
         \"id\" UUID PRIMARY KEY DEFAULT gen_random_uuid(),\n    \
         \"record_id\" {record_id_type} NOT NULL REFERENCES {schema_q}.{table_q} ({pk_q}) ON DELETE CASCADE,\n    \
         \"version\" INTEGER NOT NULL,\n    \
         \"status\" TEXT NOT NULL CHECK (\"status\" IN ('draft', 'published')),\n    \
         \"data\" JSONB NOT NULL,\n    \
         -- When each locale is due to go live, if it has been scheduled.\n    \
         -- Per locale rather than one `publish_at` for the row, because publishing is per locale:\n    \
         -- a single column could not say: English at nine, the translation when it lands.\n    \
         \"scheduled_locales\" JSONB NOT NULL DEFAULT '{{}}',\n    \
         \"created_at\" TIMESTAMPTZ NOT NULL DEFAULT now(),\n    \
         \"created_by\" UUID,\n    \
         -- Which locales this version is live for, and when each went live.\n    \
         -- One key per published locale, or the single key `*` for a model with no localized\n    \
         -- column. Publication state lives here rather than on the model's row because the\n    \
         -- column differ drops columns the schema does not declare, and rather than in a table of\n    \
         -- its own because this row already carries the policies and the guard that protect it.\n    \
         \"published_locales\" JSONB NOT NULL DEFAULT '{{}}',\n    \
         UNIQUE (\"record_id\", \"version\")\n\
         );\n\n\
         COMMENT ON TABLE {schema_q}.{versions_q} IS '{marker}';\n\n\
         CREATE INDEX IF NOT EXISTS {index_q} ON {schema_q}.{versions_q} (\"record_id\", \"version\" DESC);",
        schema_q = quoted(schema),
        versions_q = quoted(versions_table),
        table_q = quoted(table),
        pk_q = quoted(primary_key),
        index_q = quoted(&index),
    )
}

/// Name of the index that makes "the newest version of this record" a lookup rather than a scan.
///
/// Every read of a draft goes through it, so it is not optional decoration: the draft view's lateral
/// join orders by `version DESC` and takes one row.
pub fn versions_record_index_name(versions_table: &str) -> String {
    format!("{versions_table}_record_idx")
}

// ─── Settings and helpers ─────────────────────────────────────────────────────

/// The one-row settings table, and the helpers every draft policy calls.
///
/// **Two visibility columns, not one.** `configured_visibility` is written by the push from
/// `supatype.config.ts`; `override_visibility` is written by Studio and wins when it is set. A single
/// column would mean each writer clobbering the other: a push would silently undo an operator's
/// override, or an override would make the file in git a lie. `COALESCE` states the precedence in
/// one place instead.
///
/// `preview_epoch` is how a signed link is withdrawn. A signed token cannot be recalled, only
/// outwaited, so every link carries the epoch it was minted under and bumping the counter
/// invalidates every outstanding link at once.
fn settings_sql(publishing: &PublishingAst) -> String {
    let roles = if publishing.draft_visibility.is_empty() {
        "ARRAY[]::text[]".to_string()
    } else {
        format!(
            "ARRAY[{}]::text[]",
            publishing
                .draft_visibility
                .iter()
                .map(|r| quote_literal(r))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };

    format!(
        "CREATE SCHEMA IF NOT EXISTS {helper};\n\n\
         -- The API roles need to *resolve* names here, because the draft policies on the model\n\
         -- tables call helpers in this schema and a policy expression runs as the caller. Without\n\
         -- it an anonymous read of a versioned model fails `42501 permission denied for schema\n\
         -- _supatype` — on published content, which is most of what a reader asks for.\n\
         --\n\
         -- USAGE alone discloses nothing: every table here still requires its own grant and none\n\
         -- is given. Functions are the exception, and the reason for the revokes below.\n\
         GRANT USAGE ON SCHEMA {helper} TO anon, authenticated, service_role;\n\n\
         CREATE TABLE IF NOT EXISTS {helper}.publishing_settings (\n    \
         \"singleton\" BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (\"singleton\"),\n    \
         \"configured_visibility\" TEXT[] NOT NULL DEFAULT '{{}}',\n    \
         \"override_visibility\" TEXT[],\n    \
         \"preview_epoch\" INTEGER NOT NULL DEFAULT 1,\n    \
         \"updated_at\" TIMESTAMPTZ NOT NULL DEFAULT now()\n\
         );\n\n\
         INSERT INTO {helper}.publishing_settings (\"singleton\") VALUES (TRUE)\n  \
         ON CONFLICT (\"singleton\") DO NOTHING;\n\n\
         -- Only when it actually differs, so a steady-state push does not touch `updated_at` and\n\
         -- make every push look like a settings change.\n\
         UPDATE {helper}.publishing_settings\n   \
         SET \"configured_visibility\" = {roles}, \"updated_at\" = now()\n \
         WHERE \"singleton\" AND \"configured_visibility\" IS DISTINCT FROM {roles};\n\n\
         {helpers}",
        helper = HELPER_SCHEMA,
        helpers = visibility_helpers_sql(),
    )
}

/// The four functions a draft policy calls, all `STABLE` so one statement evaluates them once.
fn visibility_helpers_sql() -> String {
    let helper = HELPER_SCHEMA;
    format!(
        r#"
-- The caller's user id, or NULL when the request has no subject.
--
-- A thin alias for `auth.uid()`, which is what it now means. It was its own implementation while
-- `auth.uid()` fell back to the nil UUID for a subject-less request, and that gap was a hole rather
-- than a nicety: two kinds of request legitimately have no subject, a `service_role` call and a
-- preview link, so a draft saved through Studio was stamped with the nil UUID and every other
-- subject-less caller then satisfied `created_by = auth.uid()`.
--
-- `auth.uid()` answers NULL now, so this exists only to keep the policies below reading as one
-- thought. It is not a second definition to keep in step.
CREATE OR REPLACE FUNCTION {helper}.caller_id() RETURNS uuid
  LANGUAGE sql STABLE SET search_path = '' AS $fn$
    SELECT auth.uid();
  $fn$;

CREATE OR REPLACE FUNCTION {helper}.draft_visibility_roles() RETURNS text[]
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $fn$
    SELECT COALESCE(s."override_visibility", s."configured_visibility")
      FROM {helper}.publishing_settings s WHERE s."singleton";
  $fn$;

-- SECURITY DEFINER because `{helper}` is deliberately unreachable through the data plane: the
-- membership table is not something an API caller may read. This returns one boolean about the
-- caller themselves, so it discloses nothing they could not already infer.
--
-- An absent membership table means no elevated readers rather than an error, so a deployment that
-- has never bootstrapped Studio still has working drafts, visible to their creators.
CREATE OR REPLACE FUNCTION {helper}.sees_all_drafts() RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = '' AS $fn$
  DECLARE
    caller uuid := {helper}.caller_id();
    caller_role text;
  BEGIN
    IF caller IS NULL THEN
      RETURN false;
    END IF;
    SELECT m.role INTO caller_role FROM {helper}.studio_members m WHERE m.user_id = caller;
    IF caller_role IS NULL THEN
      RETURN false;
    END IF;
    RETURN caller_role = ANY (COALESCE({helper}.draft_visibility_roles(), ARRAY[]::text[]));
  EXCEPTION WHEN undefined_table THEN
    RETURN false;
  END;
  $fn$;

CREATE OR REPLACE FUNCTION {helper}.preview_epoch() RETURNS integer
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $fn$
    SELECT s."preview_epoch" FROM {helper}.publishing_settings s WHERE s."singleton";
  $fn$;

-- Whether the caller holds a live preview link covering this record.
--
-- **Expiry is not checked here, and does not need to be.** A link is a JWT signed with the project's
-- own secret, so PostgREST verifies the signature and the expiry and rejects the request before any
-- of this runs: an expired link never reaches a policy. What this adds is scope and revocation.
--
-- The claims setting is written by PostgREST from a verified token, so it is valid JSON or absent.
CREATE OR REPLACE FUNCTION {helper}.preview_allows(target_model text, target_record text)
  RETURNS boolean LANGUAGE sql STABLE SET search_path = '' AS $fn$
    SELECT CASE
      WHEN c.claim IS NULL THEN false
      -- A bumped epoch withdraws every link minted before it.
      WHEN (c.claim->>'epoch') IS DISTINCT FROM {helper}.preview_epoch()::text THEN false
      WHEN c.claim->>'scope' = 'project' THEN true
      WHEN c.claim->>'scope' = 'record'
        THEN c.claim->>'model' = target_model AND c.claim->>'record_id' = target_record
      ELSE false
    END
    FROM (
      SELECT (nullif(current_setting('request.jwt.claims', true), '')::jsonb -> 'preview') AS claim
    ) c;
  $fn$;
"#
    )
}

// ─── The versions table's own access ──────────────────────────────────────────

/// RLS and grants on one model's snapshot table.
///
/// **One SELECT policy and no write policies.** Drafts are written through the generated functions,
/// never by a direct `POST /posts_versions`, so `anon` and `authenticated` are granted `SELECT` and
/// nothing else: a privilege that is not held cannot be reasoned around.
///
/// The policy references no other table, deliberately. The obvious phrasing, "whoever can see the
/// record", would join the model's table, whose own draft-aware policy would want to join back here,
/// and Postgres answers a cycle like that with `infinite recursion detected in policy for relation`.
/// Everything this needs is on the version row itself.
///
/// **Not `FORCE ROW LEVEL SECURITY`**, unlike the model tables. The publish functions write this
/// table as its owner, and the API roles are never its owner, so forcing would break the owner path
/// without narrowing anything a caller can reach.
fn versions_table_access_sql(schema: &str, model_table: &str, versions_table: &str) -> String {
    let policy = format!("{versions_table}_select");
    let comment = crate::managed::managed_comment("rls_policy", versions_table, &["select"]);
    format!(
        "ALTER TABLE {schema_q}.{versions_q} ENABLE ROW LEVEL SECURITY;\n\n\
         DROP POLICY IF EXISTS {policy_q} ON {schema_q}.{versions_q};\n\
         CREATE POLICY {policy_q} ON {schema_q}.{versions_q}\n  \
         FOR SELECT USING (\n    \
         (\"created_by\" IS NOT NULL AND \"created_by\" = {helper}.caller_id())\n    \
         -- Wrapped in a SELECT so it is evaluated once per statement, not once per row.\n    \
         OR (SELECT {helper}.sees_all_drafts())\n    \
         OR {helper}.preview_allows({model_lit}, \"record_id\"::text)\n  \
         );\n\
         COMMENT ON POLICY {policy_q} ON {schema_q}.{versions_q} IS '{comment}';\n\n\
         REVOKE ALL PRIVILEGES ON {schema_q}.{versions_q} FROM anon;\n\
         REVOKE ALL PRIVILEGES ON {schema_q}.{versions_q} FROM authenticated;\n\
         GRANT SELECT ON {schema_q}.{versions_q} TO authenticated;\n\
         GRANT ALL ON {schema_q}.{versions_q} TO service_role;\n\n",
        schema_q = quoted(schema),
        versions_q = quoted(versions_table),
        policy_q = quoted(&policy),
        model_lit = quote_literal(model_table),
        helper = HELPER_SCHEMA,
    )
}

// ─── The draft schema ─────────────────────────────────────────────────────────

/// `CREATE SCHEMA` and grants for the draft schema.
///
/// **Never `anon`.** A draft schema readable without credentials would make every unpublished edit
/// world-readable on a model whose `read` rule is `Public`, and publishing would stop meaning
/// anything. A caller with no account reads a draft by holding a signed preview link, which carries
/// `role: authenticated` and no subject.
fn draft_schema_preamble() -> String {
    format!(
        "REVOKE ALL ON SCHEMA {draft} FROM anon;\n\
         GRANT USAGE ON SCHEMA {draft} TO authenticated, service_role;\n\n",
        draft = quoted(DRAFT_SCHEMA),
    )
}

/// One model's draft view.
///
/// **Reads the snapshot table alone, not a join back to the model's table.** The design note had it
/// joining the table so that "a draft cannot be read by someone who could not read the record", and
/// that is wrong in exactly the case the feature exists for: on a blog whose `read` rule is
/// `published_at <= now()`, an unpublished record is not readable, so the join would return nothing
/// for every draft anyone wanted to preview. Visibility lives in one place instead, on the snapshot
/// table's policy.
///
/// `jsonb_populate_record` restores the model's column shape, so a draft has the same row type as
/// the table and the client stays typed even though storage is JSONB. Referencing a table's
/// composite type needs no privilege on the table, which is what keeps this working under tier-2
/// masking, where the API roles hold nothing on the base tables.
///
/// `DISTINCT ON` takes the newest version per record, which is what the `(record_id, version DESC)`
/// index exists for.
///
/// Dropped and recreated rather than `CREATE OR REPLACE`, which refuses anything but appending
/// columns: a renamed or removed field would break every later push.
fn draft_view_sql(schema: &str, table: &str, versions_table: &str) -> String {
    format!(
        "DROP VIEW IF EXISTS {draft}.{table_q};\n\
         CREATE VIEW {draft}.{table_q} WITH (security_invoker = true) AS\n\
         SELECT (jsonb_populate_record(NULL::{schema_q}.{table_q}, v.\"data\")).*\n  \
         FROM (\n    \
         SELECT DISTINCT ON (pv.\"record_id\") pv.\"record_id\", pv.\"data\"\n      \
         FROM {schema_q}.{versions_q} pv\n     \
         ORDER BY pv.\"record_id\", pv.\"version\" DESC\n  \
         ) v;\n\
         GRANT SELECT ON {draft}.{table_q} TO authenticated, service_role;\n\n",
        draft = quoted(DRAFT_SCHEMA),
        schema_q = quoted(schema),
        table_q = quoted(table),
        versions_q = quoted(versions_table),
    )
}

/// The whole versions layer, re-asserted on every push.
///
/// Every statement is `IF NOT EXISTS`, `CREATE OR REPLACE`, or a drop and recreate, so re-emission
/// costs a parse and settles the question for every push rather than some of them. That is the
/// lesson from the auth-helper gate: a definition emitted only when the diff happens to carry a
/// related operation drifts from the policies that call it, and nothing notices.
pub fn render_versions_layer(ast: &SchemaAst, schema: &str) -> Result<String> {
    let models = versioned_models(ast);
    if models.is_empty() {
        return Ok(String::new());
    }
    assert_no_versions_with_field_rules(ast)?;
    let publishing = require_publishing(ast)?;

    let mut out = String::from("CREATE SCHEMA IF NOT EXISTS ");
    out.push_str(&quoted(DRAFT_SCHEMA));
    out.push_str(";\n\n");
    out.push_str(&settings_sql(publishing));
    out.push('\n');
    out.push_str(&registry_sql(ast, schema));
    out.push_str(&rpc_functions_sql(schema));
    out.push_str(&draft_schema_preamble());

    for model in &models {
        let table = db_table_name(model);
        let versions_table = versions_table_name(table);
        let (primary_key, _) = model_primary_key(model);
        let drafts = versions_of(model).is_some_and(|v| v.drafts);

        // Reading history is the same question for both kinds of versioned model.
        out.push_str(&versions_table_access_sql(schema, table, &versions_table));

        if drafts {
            // The `can_edit` function comes before the policies that call it: a policy naming a
            // function that does not exist is refused at `CREATE POLICY`, not at evaluation time.
            out.push_str(&can_edit_function_sql(ast, model, schema));
            out.push_str(&draft_aware_select_policy_sql(
                schema,
                table,
                &versions_table,
                &primary_key,
            ));
            out.push_str(&versions_write_access_sql(schema, table, &versions_table));
            out.push_str(&draft_view_sql(schema, table, &versions_table));
        } else {
            // History without withholding writes. The table is written directly and each write
            // leaves a snapshot, so there is no pending version to read, no draft view, and nothing
            // for a caller to compose by hand: the snapshot table stays read-only to the API.
            out.push_str(&audit_trigger_sql(
                schema,
                table,
                &versions_table,
                &primary_key,
            ));
        }
    }

    // Last, because both jobs call functions defined above them.
    out.push_str(&cron_jobs_sql());

    Ok(out)
}

// ─── The registry ─────────────────────────────────────────────────────────────

/// The versioned models, as a table the generated functions and the pruning job can read.
///
/// The functions take a table name as a parameter (`supatype.publish('posts', $1)`) rather than
/// being generated one per model, so PostgREST exposes four RPC endpoints instead of four per model.
/// That means dynamic SQL, and dynamic SQL means the table name has to be checked against something
/// rather than interpolated: this is that something. A name not in here is refused before any
/// `format()` runs.
///
/// Replaced wholesale on every push, so a model that stops declaring `versions` stops being
/// publishable. Deleting the row does not drop the snapshot table, which the differ handles as a
/// destructive operation needing `--force`: losing history should take a deliberate act.
fn registry_sql(ast: &SchemaAst, schema: &str) -> String {
    let mut out = format!(
        "CREATE TABLE IF NOT EXISTS {helper}.versioned_models (\n    \
         \"table_name\" TEXT PRIMARY KEY,\n    \
         \"schema_name\" TEXT NOT NULL,\n    \
         \"model_name\" TEXT NOT NULL,\n    \
         \"versions_table\" TEXT NOT NULL,\n    \
         \"primary_key\" TEXT NOT NULL,\n    \
         \"primary_key_type\" TEXT NOT NULL,\n    \
         \"published_at_column\" TEXT,\n    \
         -- The columns holding one value per locale, and the project's locale list. Publishing one\n    \
         -- locale merges its keys into these columns and leaves the others as they were.\n    \
         \"localized_columns\" TEXT[] NOT NULL DEFAULT '{{}}',\n    \
         \"locales\" TEXT[] NOT NULL DEFAULT '{{}}',\n    \
         \"drafts\" BOOLEAN NOT NULL,\n    \
         \"keep\" INTEGER NOT NULL\n\
         );\n\n\
         -- `WHERE TRUE` is not decoration: `supatype/postgres` preloads the safe-update guard,\n\
         -- which refuses an unqualified DELETE outright. Found by running this, not by reading it.\n\
         DELETE FROM {helper}.versioned_models WHERE TRUE;\n",
        helper = HELPER_SCHEMA,
    );

    let locales = text_array(&ast.locales);

    for model in versioned_models(ast) {
        let table = db_table_name(model);
        let versions = versions_table_name(table);
        let options = versions_of(model).expect("filtered to versioned models");
        let (primary_key, primary_key_type) = model_primary_key(model);
        // Publishing stamps this column. A model without one is still publishable, in the sense that
        // a draft is promoted into the live row, just with nothing recording the moment.
        let published_at = if model.fields.contains_key(PUBLISHED_AT_COLUMN) {
            quote_literal(PUBLISHED_AT_COLUMN)
        } else {
            "NULL".to_string()
        };

        out.push_str(&format!(
            "INSERT INTO {helper}.versioned_models\n  \
             (\"table_name\", \"schema_name\", \"model_name\", \"versions_table\", \
             \"primary_key\", \"primary_key_type\", \"published_at_column\", \
             \"localized_columns\", \"locales\", \"drafts\", \"keep\")\n\
             VALUES ({table_lit}, {schema_lit}, {model_lit}, {versions_lit}, {pk_lit}, \
             {pk_type_lit}, {published_at}, {localized}, {locales}, {drafts}, {keep});\n",
            helper = HELPER_SCHEMA,
            table_lit = quote_literal(table),
            schema_lit = quote_literal(schema),
            model_lit = quote_literal(&model.name),
            versions_lit = quote_literal(&versions),
            pk_lit = quote_literal(&primary_key),
            pk_type_lit = quote_literal(&primary_key_type),
            localized = text_array(&localized_columns(model)),
            drafts = options.drafts,
            keep = options.keep,
        ));
    }
    out.push('\n');
    out
}

/// A `text[]` literal, or an empty one.
fn text_array(values: &[String]) -> String {
    if values.is_empty() {
        return "ARRAY[]::text[]".to_string();
    }
    format!(
        "ARRAY[{}]::text[]",
        values
            .iter()
            .map(|v| quote_literal(v))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// The model's columns that hold one value per locale.
///
/// A localized field is a single `jsonb` column keyed by locale, which is what makes per-locale
/// publishing possible at all: publishing one locale merges that key and leaves the rest of the
/// column alone, so an unpublished translation is simply absent from the live row and needs no
/// policy to hide it.
fn localized_columns(model: &ModelAst) -> Vec<String> {
    model
        .fields
        .iter()
        .filter(|(_, field)| crate::differ::column_diff::is_localized(field))
        .flat_map(|(name, field)| crate::differ::column_diff::column_names_for(name, field))
        .filter(|name| !name.is_empty())
        .collect()
}

/// The column publishing stamps, when the model has it.
const PUBLISHED_AT_COLUMN: &str = "published_at";

/// The model's primary key column and its Postgres type.
///
/// Falls back to `id UUID`, which is what every scaffolded model has. A model with no primary key
/// cannot be versioned meaningfully and will have failed earlier for reasons that name the real
/// problem.
fn model_primary_key(model: &ModelAst) -> (String, String) {
    model
        .fields
        .iter()
        .find(|(_, field)| crate::differ::column_diff::field_is_primary_key(field))
        .map(|(name, field)| {
            (
                name.clone(),
                crate::differ::column_diff::field_pg_type(field),
            )
        })
        .unwrap_or_else(|| ("id".to_string(), "UUID".to_string()))
}

// ─── Per-model edit authority ─────────────────────────────────────────────────

fn can_edit_function_name(table: &str) -> String {
    format!("can_edit_{table}")
}

/// `_supatype.can_edit_<table>(record)`: does the model's own `update` rule admit this caller?
///
/// **`SECURITY INVOKER`**, so row level security on the model's table applies and nothing here sees
/// past it. That is what makes it safe to expose the four RPC functions to `authenticated`: they are
/// invoker too, so a caller's own rules govern from end to end and no part of this feature runs with
/// borrowed privilege.
///
/// It works on an unpublished record because the model's table also carries the draft-aware SELECT
/// policy below. Without that, a creator could not see their own unpublished row and so could not
/// edit it, which is the one case the feature exists for.
///
/// A model with **no** `update` rule renders `FALSE`. No rule means no writers through the API, and
/// drafting is a write: granting it here would invent an entitlement the schema withholds.
fn can_edit_function_sql(ast: &SchemaAst, model: &ModelAst, schema: &str) -> String {
    let table = db_table_name(model);
    let (primary_key, primary_key_type) = model_primary_key(model);
    let expr = match crate::parser::accessors::platform_access(model).update.as_ref() {
        Some(rule) => crate::generator::sql::rls::access_rule_to_expr(ast, model, rule, schema),
        None => "FALSE".to_string(),
    };
    let name = can_edit_function_name(table);
    format!(
        "CREATE OR REPLACE FUNCTION {helper}.{fn_q}(p_record {pk_type})\n  \
         RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER AS $fn$\n    \
         SELECT EXISTS (\n      \
         SELECT 1 FROM {schema_q}.{table_q}\n       \
         WHERE {pk_q} = p_record AND ({expr})\n    \
         );\n  \
         $fn$;\n\
         GRANT EXECUTE ON FUNCTION {helper}.{fn_q}({pk_type}) TO authenticated, service_role;\n\n",
        helper = HELPER_SCHEMA,
        fn_q = quoted(&name),
        pk_type = primary_key_type,
        schema_q = quoted(schema),
        table_q = quoted(table),
        pk_q = quoted(&primary_key),
    )
}

fn sees_draft_function_name(table: &str) -> String {
    format!("sees_draft_{table}")
}

/// The extra SELECT policy that lets the right people read an unpublished row, and the helper it
/// asks.
///
/// **The helper is `SECURITY DEFINER`, and that is the whole point of it.** The policy asks a
/// question about drafts, and answering it means reading the snapshot table — which `anon`
/// deliberately holds no privilege on. Written inline, as an `EXISTS` over that table, the policy
/// therefore failed for every anonymous caller with `42501 permission denied for table
/// <table>_versions`, on ordinary reads of *published* content. A blog served nothing to the public.
///
/// Row level security is not what withholds drafts here; the predicate inside is. So the helper may
/// read the table on the caller's behalf and return one boolean, which discloses nothing beyond what
/// the policy would have.
///
/// Found by serving a real page: every test until then ran as the table's owner, which holds the
/// privilege the policy needs, so the whole suite passed against a database no anonymous reader
/// could use.
///
/// The policy itself is permissive, so it ORs with the model's own read rule rather than narrowing
/// it. Without it, a blog whose `read` rule is `published_at <= now()` hides every unpublished
/// record from its own author, and reading, editing and publishing all operate on a row nobody can
/// see.
fn draft_aware_select_policy_sql(
    schema: &str,
    table: &str,
    versions_table: &str,
    primary_key: &str,
) -> String {
    let policy = format!("{table}_draft_select");
    let comment = crate::managed::managed_comment("rls_policy", table, &["draft_select"]);
    let helper_fn = sees_draft_function_name(table);
    format!(
        "CREATE OR REPLACE FUNCTION {helper}.{fn_q}(p_record text)\n  \
         RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $fn$\n    \
         SELECT EXISTS (\n      \
         SELECT 1 FROM {schema_q}.{versions_q} v\n       \
         WHERE v.\"record_id\"::text = p_record\n         \
         AND (\n           \
         (v.\"created_by\" IS NOT NULL AND v.\"created_by\" = {helper}.caller_id())\n           \
         OR (SELECT {helper}.sees_all_drafts())\n           \
         OR {helper}.preview_allows({table_lit}, v.\"record_id\"::text)\n         \
         )\n    \
         );\n  \
         $fn$;\n\
         GRANT EXECUTE ON FUNCTION {helper}.{fn_q}(text) TO anon, authenticated, service_role;\n\n\
         DROP POLICY IF EXISTS {policy_q} ON {schema_q}.{table_q};\n\
         CREATE POLICY {policy_q} ON {schema_q}.{table_q}\n  \
         FOR SELECT USING ({helper}.{fn_q}({pk_q}::text));\n\
         COMMENT ON POLICY {policy_q} ON {schema_q}.{table_q} IS '{comment}';\n\n",
        helper = HELPER_SCHEMA,
        fn_q = quoted(&helper_fn),
        policy_q = quoted(&policy),
        schema_q = quoted(schema),
        table_q = quoted(table),
        versions_q = quoted(versions_table),
        pk_q = quoted(primary_key),
        table_lit = quote_literal(table),
    )
}

// ─── Writing the snapshot table ───────────────────────────────────────────────

/// Write access to one snapshot table: policies, grants and the two triggers that hold its shape.
///
/// `authenticated` is granted `INSERT` and `UPDATE`, gated on `can_edit_<table>`, and **not**
/// `DELETE`: history is append-only, and pruning is the retention job's work, which runs as the
/// owner.
///
/// The grants matter less than the triggers, because PostgREST exposes the snapshot table like any
/// other in the managed schema, so a caller can `POST /posts_versions` directly. Rather than try to
/// prevent that, the triggers make it harmless:
///
/// * **On insert**, `version`, `created_by` and `status` are assigned here and whatever the caller
///   submitted for them is discarded. So a direct insert is a draft save and cannot be a forged
///   published version, a version renumbered over someone else's, or a snapshot attributed to
///   another author.
/// * **On update**, only the publishing state may change: `status`, `published_locales` and
///   `scheduled_locales`. `data` and `created_by` are restored
///   from the stored row, so history cannot be rewritten by whoever can still edit the record.
fn versions_write_access_sql(schema: &str, table: &str, versions_table: &str) -> String {
    let can_edit = format!("{HELPER_SCHEMA}.{}", quoted(&can_edit_function_name(table)));
    let insert_policy = format!("{versions_table}_insert");
    let update_policy = format!("{versions_table}_update");
    let insert_comment = crate::managed::managed_comment("rls_policy", versions_table, &["insert"]);
    let update_comment = crate::managed::managed_comment("rls_policy", versions_table, &["update"]);
    let guard = format!("{versions_table}_guard");

    format!(
        "DROP POLICY IF EXISTS {insert_q} ON {schema_q}.{versions_q};\n\
         CREATE POLICY {insert_q} ON {schema_q}.{versions_q}\n  \
         FOR INSERT WITH CHECK ({can_edit}(\"record_id\"));\n\
         COMMENT ON POLICY {insert_q} ON {schema_q}.{versions_q} IS '{insert_comment}';\n\n\
         DROP POLICY IF EXISTS {update_q} ON {schema_q}.{versions_q};\n\
         CREATE POLICY {update_q} ON {schema_q}.{versions_q}\n  \
         FOR UPDATE USING ({can_edit}(\"record_id\")) WITH CHECK ({can_edit}(\"record_id\"));\n\
         COMMENT ON POLICY {update_q} ON {schema_q}.{versions_q} IS '{update_comment}';\n\n\
         GRANT INSERT, UPDATE ON {schema_q}.{versions_q} TO authenticated;\n\n\
         {trigger}",
        insert_q = quoted(&insert_policy),
        update_q = quoted(&update_policy),
        schema_q = quoted(schema),
        versions_q = quoted(versions_table),
        trigger = versions_guard_trigger_sql(schema, versions_table, &guard),
    )
}

/// The trigger that assigns a version row's own fields and refuses to let history be rewritten.
///
/// **`SECURITY DEFINER`**, and only for the version number. `MAX(version)` under the caller's own
/// row level security counts the versions the *caller* can see, and a signed-in user with no Studio
/// membership sees only their own drafts: their next version number would collide with someone
/// else's and the insert would fail with `23505` on `(record_id, version)`. Numbering is a property
/// of the record, not of who is looking at it.
///
/// It bypasses nothing else. A `BEFORE` trigger runs before the executor evaluates the insert's
/// `WITH CHECK`, so the policy still decides whether the write happens; this only fills in fields on
/// the row being written, and every reference is schema-qualified under an empty `search_path`.
fn versions_guard_trigger_sql(schema: &str, versions_table: &str, guard: &str) -> String {
    format!(
        r#"CREATE OR REPLACE FUNCTION {helper}.{guard_q}() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $fn$
  BEGIN
    IF TG_OP = 'INSERT' THEN
      -- Assigned here, not accepted from the caller. The snapshot table is exposed like any other
      -- table in the managed schema, so a direct insert has to be a draft save and nothing else:
      -- no forged published version, no renumbering over someone else's, no borrowed authorship.
      SELECT COALESCE(MAX(v."version"), 0) + 1 INTO NEW."version"
        FROM {schema_q}.{versions_q} v WHERE v."record_id" = NEW."record_id";
      NEW."created_by" := {helper}.caller_id();
      -- A version is born a draft. Publishing it is `supatype.publish`, which is a separate act with
      -- a separate permission check.
      NEW."status" := 'draft';
      RETURN NEW;
    END IF;

    -- Only the publishing state may move: `status`, `published_locales`, `scheduled_locales`. A caller
    -- who can still edit the record must not be able to rewrite what an earlier version said, or
    -- the history stops being evidence of anything.
    NEW."data" := OLD."data";
    NEW."created_by" := OLD."created_by";
    NEW."created_at" := OLD."created_at";
    NEW."version" := OLD."version";
    NEW."record_id" := OLD."record_id";
    RETURN NEW;
  END;
  $fn$;

DROP TRIGGER IF EXISTS {guard_q} ON {schema_q}.{versions_q};
CREATE TRIGGER {guard_q} BEFORE INSERT OR UPDATE ON {schema_q}.{versions_q}
  FOR EACH ROW EXECUTE FUNCTION {helper}.{guard_q}();

"#,
        helper = HELPER_SCHEMA,
        guard_q = quoted(guard),
        schema_q = quoted(schema),
        versions_q = quoted(versions_table),
    )
}

/// The trigger that records every write as a version, for a model that keeps history without
/// withholding writes.
///
/// `versions: { drafts: false }` is the audit-trail case: writes go straight to the table as they
/// always did, and each one leaves a snapshot behind. Without this the model would get a snapshot
/// table that nothing ever writes to, because `create_draft` is the only other writer and it refuses
/// a model with drafts off.
///
/// `AFTER`, so a write that fails a constraint or a policy leaves no version claiming it happened.
/// `SECURITY DEFINER` because the caller holds no privilege on the snapshot table on this path: they
/// are not drafting, they are writing the table, and the history is the system's record rather than
/// theirs to compose.
fn audit_trigger_sql(
    schema: &str,
    table: &str,
    versions_table: &str,
    primary_key: &str,
) -> String {
    let audit = format!("{versions_table}_audit");
    format!(
        r#"CREATE OR REPLACE FUNCTION {helper}.{audit_q}() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $fn$
  DECLARE
    next_version integer;
  BEGIN
    SELECT COALESCE(MAX(v."version"), 0) + 1 INTO next_version
      FROM {schema_q}.{versions_q} v WHERE v."record_id" = NEW.{pk_q};
    INSERT INTO {schema_q}.{versions_q}
      ("record_id", "version", "status", "data", "created_by")
    VALUES (NEW.{pk_q}, next_version, 'published', to_jsonb(NEW), auth.uid());
    RETURN NULL;
  END;
  $fn$;

DROP TRIGGER IF EXISTS {audit_q} ON {schema_q}.{table_q};
CREATE TRIGGER {audit_q} AFTER INSERT OR UPDATE ON {schema_q}.{table_q}
  FOR EACH ROW EXECUTE FUNCTION {helper}.{audit_q}();

"#,
        helper = HELPER_SCHEMA,
        audit_q = quoted(&audit),
        schema_q = quoted(schema),
        table_q = quoted(table),
        versions_q = quoted(versions_table),
        pk_q = quoted(primary_key),
    )
}

// ─── The publish functions ────────────────────────────────────────────────────

/// `supatype.create_draft`, `publish`, `unpublish` and `restore_version`.
///
/// One set for every model, taking the table name as a parameter and checked against the registry,
/// so PostgREST exposes four endpoints rather than four per model.
///
/// **All four are `SECURITY INVOKER`.** Every write they make is a write the caller could have made
/// themselves: an insert into the snapshot table, gated by that table's policy, and an update of the
/// model's row, gated by the model's own `update` rule. Nothing runs with borrowed privilege, so
/// there is no second permission model to keep in step with the first — which was the whole reason
/// to generate these rather than write them in application code.
/// The search path a function that writes a user's table must run under.
///
/// **Not `''`, and that distinction cost a real schema.** An empty search path is right for SQL that
/// only ever names its own objects, and every reference in these functions is fully qualified — but
/// the `UPDATE` they perform fires the *user's* triggers, and those inherit it. A generated slug
/// trigger calling `unaccent(...)` unqualified, which is how it is written and how it works for an
/// ordinary write, then fails with `function unaccent(text) does not exist` and takes the publish
/// with it.
///
/// A write made on the caller's behalf has to run in the environment their own write would, so this
/// is what PostgREST gives an ordinary request, with the managed schema named explicitly.
fn write_search_path(schema: &str) -> String {
    if schema == "public" {
        return "pg_catalog, public, extensions".to_string();
    }
    format!("pg_catalog, {}, public, extensions", quoted(schema))
}

fn rpc_functions_sql(schema: &str) -> String {
    let write_path = write_search_path(schema);
    let helper = HELPER_SCHEMA;
    let rpc = RPC_SCHEMA;
    format!(
        r#"CREATE SCHEMA IF NOT EXISTS "{rpc}";
GRANT USAGE ON SCHEMA "{rpc}" TO anon, authenticated, service_role;

-- The registry row for a table, or an error naming what was asked for.
--
-- Every function below starts here, so a table name never reaches `format()` unchecked.
CREATE OR REPLACE FUNCTION {helper}.versioned_model(p_table text)
  RETURNS {helper}.versioned_models LANGUAGE plpgsql STABLE SECURITY DEFINER
  SET search_path = '' AS $fn$
  DECLARE
    entry {helper}.versioned_models;
  BEGIN
    SELECT * INTO entry FROM {helper}.versioned_models WHERE "table_name" = p_table;
    IF entry."table_name" IS NULL THEN
      RAISE EXCEPTION 'no versioned model for table %', p_table
        USING ERRCODE = '22023',
              HINT = 'Add `versions` to the model in your schema and push, or check the table name.';
    END IF;
    RETURN entry;
  END;
  $fn$;

-- Save a draft: the newest snapshot merged with the submitted fields, or the live row when there is
-- no snapshot yet.
--
-- Merging onto the newest snapshot rather than the live row is what makes successive edits
-- accumulate instead of each starting again from what is published. Reading it needs the snapshot
-- table's SELECT policy to pass, which for anyone entitled to edit the record it does: draft
-- visibility covers every Studio role precisely so that an editor cannot save over a pending draft
-- they were not shown.
CREATE OR REPLACE FUNCTION "{rpc}".create_draft(model_table text, record_id text, data jsonb)
  RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path = {write_path} AS $fn$
  DECLARE
    entry {helper}.versioned_models := {helper}.versioned_model(model_table);
    base jsonb;
    saved record;
  BEGIN
    IF NOT entry."drafts" THEN
      RAISE EXCEPTION 'model % keeps history but does not withhold writes, so it has no drafts', entry."model_name"
        USING ERRCODE = '22023',
              HINT = 'Write to the table directly; every change is recorded as a version.';
    END IF;

    EXECUTE format(
      'SELECT v.%I FROM %I.%I v WHERE v.%I = $1::%s ORDER BY v.%I DESC LIMIT 1',
      'data', entry."schema_name", entry."versions_table", 'record_id',
      entry."primary_key_type", 'version')
      INTO base USING record_id;

    IF base IS NULL THEN
      EXECUTE format('SELECT to_jsonb(t) FROM %I.%I t WHERE t.%I = $1::%s',
        entry."schema_name", entry."table_name", entry."primary_key", entry."primary_key_type")
        INTO base USING record_id;
    END IF;

    IF base IS NULL THEN
      RAISE EXCEPTION 'no such record % in %', record_id, model_table USING ERRCODE = '02000';
    END IF;

    -- `version`, `created_by` and `status` are the guard trigger's to assign.
    EXECUTE format(
      'INSERT INTO %I.%I (%I, %I) VALUES ($1::%s, $2) RETURNING %I, %I, %I',
      entry."schema_name", entry."versions_table", 'record_id', 'data',
      entry."primary_key_type", 'version', 'status', 'created_at')
      INTO saved USING record_id, base || COALESCE(data, '{{}}'::jsonb);

    RETURN jsonb_build_object(
      'record_id', record_id, 'version', saved."version",
      'status', saved."status", 'created_at', saved."created_at");
  END;
  $fn$;

-- Promote a version into the live row, for some or all of its locales.
--
-- **Two arguments beyond the record, both optional.** `version` defaults to the newest, so the
-- ordinary case is unchanged. `locales` defaults to every locale the project declares, so a project
-- that translates before publishing never sees this.
--
-- **Per locale, because a localized field is one `jsonb` column keyed by locale.** Publishing `en`
-- merges the `en` key of every localized column and leaves the rest of the column exactly as it was,
-- so an unpublished translation is simply *absent* from the live row. That is what makes this
-- enforceable at all: row level security cannot hide one key of a column, and nothing has to,
-- because the value was never written.
--
-- **The shared, non-localized columns go live with whichever locale is published.** They belong to
-- no locale, so the alternative is that a change to one could only ever go live by publishing every
-- translation, which would make the feature useless to the team it exists for.
--
-- The `UPDATE` runs under the caller's own rules, so the policy that already governs editing governs
-- publishing and there is nothing new to keep in step.
CREATE OR REPLACE FUNCTION "{rpc}".publish(
  model_table text, record_id text, version integer DEFAULT NULL, locales text[] DEFAULT NULL)
  RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path = {write_path} AS $fn$
  DECLARE
    entry {helper}.versioned_models := {helper}.versioned_model(model_table);
    target record;
    want text[];
    pending text[];
    assignments text[] := ARRAY[]::text[];
    col text;
    stamp timestamptz := now();
    updated integer;
  BEGIN
    -- The version to promote: the one named, or the newest.
    IF version IS NULL THEN
      EXECUTE format(
        'SELECT v.%I AS version, v.%I AS data, v.%I AS published_locales FROM %I.%I v
          WHERE v.%I = $1::%s ORDER BY v.%I DESC LIMIT 1',
        'version', 'data', 'published_locales', entry."schema_name", entry."versions_table",
        'record_id', entry."primary_key_type", 'version')
        INTO target USING record_id;
    ELSE
      EXECUTE format(
        'SELECT v.%I AS version, v.%I AS data, v.%I AS published_locales FROM %I.%I v
          WHERE v.%I = $1::%s AND v.%I = $2',
        'version', 'data', 'published_locales', entry."schema_name", entry."versions_table",
        'record_id', entry."primary_key_type", 'version')
        INTO target USING record_id, version;
    END IF;

    IF target IS NULL THEN
      RAISE EXCEPTION 'no version to publish for % in %', record_id, model_table
        USING ERRCODE = '02000',
              HINT = 'Save a draft first, or name a version that exists.';
    END IF;

    -- `*` stands for the whole record on a model with no localized column, so the state map has one
    -- shape rather than two.
    want := COALESCE(locales, {helper}.default_locales(entry));

    -- Only the locales this version is not already live for. That is also what makes a repeat
    -- publish a refusal rather than a silent no-op, and it replaced an earlier check that looked for
    -- the newest *draft* and would fall back to an older one, putting stale content live.
    SELECT array_agg(l) INTO pending
      FROM unnest(want) AS l
     WHERE NOT (target.published_locales ? l);

    IF pending IS NULL THEN
      RAISE EXCEPTION 'version % of % in % is already live for %',
        target.version, record_id, model_table, array_to_string(want, ', ')
        USING ERRCODE = '02000',
              HINT = 'The live row already says what this version says.';
    END IF;

    -- Shared columns, taken wholesale from the snapshot. The primary key is excluded: publishing a
    -- draft must not be able to move a record's identity.
    SELECT array_agg(format('%I = (src.r).%I', c.column_name, c.column_name))
      INTO assignments
      FROM information_schema.columns c
     WHERE c.table_schema = entry."schema_name"
       AND c.table_name = entry."table_name"
       AND c.column_name <> entry."primary_key"
       AND NOT (c.column_name = ANY (entry."localized_columns"))
       AND c.is_generated = 'NEVER';
    assignments := COALESCE(assignments, ARRAY[]::text[]);

    -- Localized columns, merged key by key for the locales being published.
    -- `jsonb_each` raises on anything but an object, and a localized column the author has not
    -- filled in is JSON `null` in the snapshot rather than absent. Found by running it: every
    -- publish failed `22023` the moment the fixture gained a localized field nobody had set.
    FOREACH col IN ARRAY entry."localized_columns" LOOP
      assignments := assignments || format(
        '%I = COALESCE(%I, ''{{}}''::jsonb) || (
           SELECT COALESCE(jsonb_object_agg(e.key, e.value), ''{{}}''::jsonb)
             FROM jsonb_each(CASE WHEN jsonb_typeof($2 -> %L) = ''object''
                                  THEN $2 -> %L ELSE ''{{}}''::jsonb END) e
            WHERE e.key = ANY ($3))',
        col, col, col, col);
    END LOOP;

    EXECUTE format(
      'UPDATE %I.%I SET %s FROM (SELECT jsonb_populate_record(NULL::%I.%I, $2) AS r) src
        WHERE %I = $1::%s',
      entry."schema_name", entry."table_name", array_to_string(assignments, ', '),
      entry."schema_name", entry."table_name",
      entry."primary_key", entry."primary_key_type")
      USING record_id, target.data, pending;
    GET DIAGNOSTICS updated = ROW_COUNT;

    IF updated = 0 THEN
      RAISE EXCEPTION 'not permitted to publish % in %', record_id, model_table
        USING ERRCODE = '42501',
              HINT = 'Publishing a record requires the same permission as editing it.';
    END IF;

    IF entry."published_at_column" IS NOT NULL THEN
      EXECUTE format('UPDATE %I.%I SET %I = COALESCE(%I, $2) WHERE %I = $1::%s',
        entry."schema_name", entry."table_name",
        entry."published_at_column", entry."published_at_column",
        entry."primary_key", entry."primary_key_type")
        USING record_id, stamp;
    END IF;

    -- Exactly one version claims a locale, so publishing takes it off every other version. Without
    -- this, "which version is live for fr" would have several answers after a restore.
    EXECUTE format(
      'UPDATE %I.%I SET %I = %I - $3, %I = CASE WHEN (%I - $3) = ''{{}}''::jsonb
          THEN ''draft'' ELSE ''published'' END
        WHERE %I = $1::%s AND %I <> $2 AND %I ?| $3',
      entry."schema_name", entry."versions_table",
      'published_locales', 'published_locales', 'status', 'published_locales',
      'record_id', entry."primary_key_type", 'version', 'published_locales')
      USING record_id, target.version, pending;

    EXECUTE format(
      'UPDATE %I.%I SET %I = %I || $3, %I = ''published''
        WHERE %I = $1::%s AND %I = $2',
      entry."schema_name", entry."versions_table",
      'published_locales', 'published_locales', 'status',
      'record_id', entry."primary_key_type", 'version')
      USING record_id, target.version,
            (SELECT jsonb_object_agg(l, stamp) FROM unnest(pending) AS l);

    RETURN jsonb_build_object(
      'record_id', record_id, 'version', target.version,
      'status', 'published', 'locales', to_jsonb(pending));
  END;
  $fn$;

-- Take some or all locales out of publication.
--
-- Removing a locale's keys from the live columns is what actually hides it, for the same reason
-- publishing writes them: an absent translation needs no policy. The remaining locales are
-- untouched, and `published_at` is cleared only when nothing is left published, so a record with one
-- locale still live stays readable to a rule that compares `published_at`.
--
-- On a model with no localized column this is the whole record, and the content stays in the row:
-- withdrawing publication is not the same as reverting an edit, and blanking the row would lose the
-- thing a later publish would restore.
CREATE OR REPLACE FUNCTION "{rpc}".unpublish(
  model_table text, record_id text, locales text[] DEFAULT NULL)
  RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path = {write_path} AS $fn$
  DECLARE
    entry {helper}.versioned_models := {helper}.versioned_model(model_table);
    want text[];
    assignments text[] := ARRAY[]::text[];
    col text;
    remaining boolean;
    updated integer;
  BEGIN
    want := COALESCE(locales, {helper}.default_locales(entry));

    FOREACH col IN ARRAY entry."localized_columns" LOOP
      assignments := assignments || format('%I = COALESCE(%I, ''{{}}''::jsonb) - $2', col, col);
    END LOOP;

    IF cardinality(assignments) > 0 THEN
      EXECUTE format('UPDATE %I.%I SET %s WHERE %I = $1::%s',
        entry."schema_name", entry."table_name", array_to_string(assignments, ', '),
        entry."primary_key", entry."primary_key_type")
        USING record_id, want;
      GET DIAGNOSTICS updated = ROW_COUNT;
      IF updated = 0 THEN
        RAISE EXCEPTION 'not permitted to unpublish % in %, or no such record', record_id, model_table
          USING ERRCODE = '42501';
      END IF;
    END IF;

    EXECUTE format(
      'UPDATE %I.%I SET %I = %I - $2, %I = CASE WHEN (%I - $2) = ''{{}}''::jsonb
          THEN ''draft'' ELSE ''published'' END
        WHERE %I = $1::%s AND %I ?| $2',
      entry."schema_name", entry."versions_table",
      'published_locales', 'published_locales', 'status', 'published_locales',
      'record_id', entry."primary_key_type", 'published_locales')
      USING record_id, want;

    EXECUTE format(
      'SELECT EXISTS (SELECT 1 FROM %I.%I v WHERE v.%I = $1::%s AND v.%I <> ''{{}}''::jsonb)',
      entry."schema_name", entry."versions_table", 'record_id', entry."primary_key_type",
      'published_locales')
      INTO remaining USING record_id;

    IF entry."published_at_column" IS NOT NULL AND NOT remaining THEN
      EXECUTE format('UPDATE %I.%I SET %I = NULL WHERE %I = $1::%s',
        entry."schema_name", entry."table_name", entry."published_at_column",
        entry."primary_key", entry."primary_key_type")
        USING record_id;
      GET DIAGNOSTICS updated = ROW_COUNT;
      IF updated = 0 THEN
        RAISE EXCEPTION 'not permitted to unpublish % in %, or no such record', record_id, model_table
          USING ERRCODE = '42501';
      END IF;
    END IF;

    RETURN jsonb_build_object(
      'record_id', record_id, 'status',
      CASE WHEN remaining THEN 'partially_published' ELSE 'unpublished' END,
      'locales', to_jsonb(want));
  END;
  $fn$;

-- Restore an earlier version as a **new draft**, never as an immediate publish.
--
-- Nothing goes live without publishing, so restoring is an editing act with a preview and a second
-- decision behind it, not a way to change what the world sees in one call.
CREATE OR REPLACE FUNCTION "{rpc}".restore_version(model_table text, record_id text, version integer)
  RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path = {write_path} AS $fn$
  DECLARE
    entry {helper}.versioned_models := {helper}.versioned_model(model_table);
    snapshot jsonb;
  BEGIN
    EXECUTE format('SELECT v.%I FROM %I.%I v WHERE v.%I = $1::%s AND v.%I = $2',
      'data', entry."schema_name", entry."versions_table",
      'record_id', entry."primary_key_type", 'version')
      INTO snapshot USING record_id, version;

    IF snapshot IS NULL THEN
      RAISE EXCEPTION 'no version % of % in %', version, record_id, model_table
        USING ERRCODE = '02000';
    END IF;

    RETURN "{rpc}".create_draft(model_table, record_id, snapshot);
  END;
  $fn$;

-- The locales a call means when it names none: every locale the project declares, or the single key
-- `*` on a model with no localized column, so the state maps have one shape rather than two.
CREATE OR REPLACE FUNCTION {helper}.default_locales(entry {helper}.versioned_models)
  RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path = '' AS $fn$
    SELECT CASE
      WHEN cardinality(entry."localized_columns") = 0 OR cardinality(entry."locales") = 0
        THEN ARRAY['*'] ELSE entry."locales" END;
  $fn$;

-- Schedule some or all of a version's locales to go live later.
--
-- **A real change from how scheduled publishing used to work.** Without versions, a schedule needed
-- no scheduler: the access rule compared `published_at <= now()`, so a future timestamp simply hid
-- the row until it arrived. That trick works only while the content is already in the live row. Once
-- publishing means copying a draft in, something has to do the copying, which is what the job below
-- is for.
--
-- `SECURITY INVOKER`, and it writes the version row, so the same `can_edit` gate that governs
-- drafting governs scheduling. Nothing is published here: this records an intent, and the job acts
-- on it.
CREATE OR REPLACE FUNCTION "{rpc}".schedule_publish(
  model_table text, record_id text, at timestamptz,
  version integer DEFAULT NULL, locales text[] DEFAULT NULL)
  RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path = {write_path} AS $fn$
  DECLARE
    entry {helper}.versioned_models := {helper}.versioned_model(model_table);
    target integer;
    want text[];
    updated integer;
  BEGIN
    IF at IS NULL THEN
      RAISE EXCEPTION 'schedule_publish needs a time' USING ERRCODE = '22023';
    END IF;

    target := version;
    IF target IS NULL THEN
      EXECUTE format('SELECT v.%I FROM %I.%I v WHERE v.%I = $1::%s ORDER BY v.%I DESC LIMIT 1',
        'version', entry."schema_name", entry."versions_table",
        'record_id', entry."primary_key_type", 'version')
        INTO target USING record_id;
    END IF;

    IF target IS NULL THEN
      RAISE EXCEPTION 'no version to schedule for % in %', record_id, model_table
        USING ERRCODE = '02000', HINT = 'Save a draft first.';
    END IF;

    want := COALESCE(locales, {helper}.default_locales(entry));

    EXECUTE format(
      'UPDATE %I.%I SET %I = %I || $3 WHERE %I = $1::%s AND %I = $2',
      entry."schema_name", entry."versions_table", 'scheduled_locales', 'scheduled_locales',
      'record_id', entry."primary_key_type", 'version')
      USING record_id, target,
            (SELECT jsonb_object_agg(l, at) FROM unnest(want) AS l);
    GET DIAGNOSTICS updated = ROW_COUNT;

    IF updated = 0 THEN
      RAISE EXCEPTION 'not permitted to schedule % in %, or no such version', record_id, model_table
        USING ERRCODE = '42501';
    END IF;

    RETURN jsonb_build_object(
      'record_id', record_id, 'version', target, 'at', at, 'locales', to_jsonb(want));
  END;
  $fn$;

-- Withdraw a schedule without publishing anything.
CREATE OR REPLACE FUNCTION "{rpc}".unschedule_publish(
  model_table text, record_id text, version integer DEFAULT NULL, locales text[] DEFAULT NULL)
  RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path = {write_path} AS $fn$
  DECLARE
    entry {helper}.versioned_models := {helper}.versioned_model(model_table);
    want text[] := COALESCE(locales, {helper}.default_locales(entry));
  BEGIN
    IF version IS NULL THEN
      EXECUTE format('UPDATE %I.%I SET %I = %I - $2 WHERE %I = $1::%s AND %I ?| $2',
        entry."schema_name", entry."versions_table", 'scheduled_locales', 'scheduled_locales',
        'record_id', entry."primary_key_type", 'scheduled_locales')
        USING record_id, want;
    ELSE
      EXECUTE format(
        'UPDATE %I.%I SET %I = %I - $3 WHERE %I = $1::%s AND %I = $2',
        entry."schema_name", entry."versions_table", 'scheduled_locales', 'scheduled_locales',
        'record_id', entry."primary_key_type", 'version')
        USING record_id, version, want;
    END IF;

    RETURN jsonb_build_object('record_id', record_id, 'locales', to_jsonb(want));
  END;
  $fn$;

GRANT EXECUTE ON FUNCTION "{rpc}".schedule_publish(text, text, timestamptz, integer, text[])
  TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION "{rpc}".unschedule_publish(text, text, integer, text[])
  TO authenticated, service_role;

-- Publish everything whose scheduled time has arrived.
--
-- **`SECURITY INVOKER`, and that is what makes it correct in two places at once.** Run by the
-- scheduler it executes as the job's owner, which bypasses row level security, so a schedule set
-- last week still fires when its author is nowhere near. Called by an ordinary caller it executes as
-- them, so they can only publish what they could have published by hand. One implementation, no
-- second permission model, and no privilege to escalate through.
--
-- Each record is published in its own block so one failure — a constraint the draft violates, a
-- record deleted since — does not strand every other schedule behind it. The failure is reported as
-- a warning and the schedule cleared, because a schedule that cannot be honoured will not start
-- working on the next tick and retrying it every minute for ever is worse than saying so once.
CREATE OR REPLACE FUNCTION {helper}.run_due_publishes(now_at timestamptz DEFAULT now())
  RETURNS integer LANGUAGE plpgsql SECURITY INVOKER SET search_path = {write_path} AS $fn$
  DECLARE
    entry {helper}.versioned_models;
    due record;
    published integer := 0;
  BEGIN
    FOR entry IN SELECT * FROM {helper}.versioned_models WHERE "drafts" LOOP
      FOR due IN
        EXECUTE format(
          'SELECT v.%I AS record_id, v.%I AS version,
                  array_agg(e.key) AS locales
             FROM %I.%I v, jsonb_each_text(v.%I) e
            WHERE (e.value)::timestamptz <= $1
            GROUP BY v.%I, v.%I',
          'record_id', 'version', entry."schema_name", entry."versions_table",
          'scheduled_locales', 'record_id', 'version')
          USING now_at
      LOOP
        BEGIN
          PERFORM "{rpc}".publish(
            entry."table_name", due.record_id::text, due.version, due.locales);
          published := published + 1;
        EXCEPTION WHEN OTHERS THEN
          RAISE WARNING 'scheduled publish failed for % version % in %: %',
            due.record_id, due.version, entry."table_name", SQLERRM;
        END;

        EXECUTE format('UPDATE %I.%I SET %I = %I - $3 WHERE %I = $1::%s AND %I = $2',
          entry."schema_name", entry."versions_table", 'scheduled_locales', 'scheduled_locales',
          'record_id', entry."primary_key_type", 'version')
          USING due.record_id::text, due.version, due.locales;
      END LOOP;
    END LOOP;
    RETURN published;
  END;
  $fn$;

-- Prune history beyond each model's retention.
--
-- Unbounded history is a slow leak on a busy table. Two rows are never pruned whatever the
-- retention says: the newest, which is what a draft read and a publish both work from, and any
-- version that claims a live locale, which is the only record of what the world is currently seeing.
--
-- `SECURITY DEFINER`, unlike everything else here. Retention is the system's housekeeping rather
-- than any caller's act, and the API roles hold no `DELETE` on the snapshot tables at all: history
-- is append-only to them, and this is the one thing that removes rows.
CREATE OR REPLACE FUNCTION {helper}.prune_versions()
  RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $fn$
  DECLARE
    entry {helper}.versioned_models;
    removed integer := 0;
    n integer;
  BEGIN
    FOR entry IN SELECT * FROM {helper}.versioned_models LOOP
      EXECUTE format(
        'DELETE FROM %I.%I v
          WHERE v.%I IN (
            SELECT id FROM (
              SELECT k.%I AS id,
                     row_number() OVER (PARTITION BY k.%I ORDER BY k.%I DESC) AS rank,
                     k.%I AS live
                FROM %I.%I k
            ) ranked
            WHERE ranked.rank > $1 AND ranked.live = ''{{}}''::jsonb
          )',
        entry."schema_name", entry."versions_table",
        'id', 'id', 'record_id', 'version', 'published_locales',
        entry."schema_name", entry."versions_table")
        USING entry."keep";
      GET DIAGNOSTICS n = ROW_COUNT;
      removed := removed + n;
    END LOOP;
    RETURN removed;
  END;
  $fn$;

-- Postgres grants EXECUTE on a new function to PUBLIC, so USAGE on this schema would otherwise
-- hand every role the maintenance functions: `prune_versions` is SECURITY DEFINER and deletes
-- history, and `run_due_publishes` publishes. Neither is a caller's to invoke. The API roles need
-- USAGE here only so a draft policy can resolve the helper it calls, and that helper is granted
-- deliberately, one line at a time.
REVOKE ALL ON FUNCTION {helper}.prune_versions() FROM PUBLIC;
REVOKE ALL ON FUNCTION {helper}.run_due_publishes(timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION {helper}.draft_visibility_roles() FROM PUBLIC;
REVOKE ALL ON FUNCTION {helper}.versioned_model(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION {helper}.sees_all_drafts() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION {helper}.preview_allows(text, text) TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION {helper}.preview_epoch() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION {helper}.caller_id() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION {helper}.versioned_model(text) TO authenticated, service_role;

GRANT EXECUTE ON FUNCTION "{rpc}".create_draft(text, text, jsonb) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION "{rpc}".publish(text, text, integer, text[]) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION "{rpc}".unpublish(text, text, text[]) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION "{rpc}".restore_version(text, text, integer) TO authenticated, service_role;

"#
    )
}
/// The two scheduled jobs, when this database can run them.
///
/// **Degrades rather than refuses**, the same tier split as field masking and `pg_net`. `pg_cron`
/// needs `shared_preload_libraries` and a restart, which is not something a managed provider will
/// do, so a database without it gets the whole feature except the clock: drafts, publishing,
/// history, restore and preview all work, and a scheduled publish sits waiting until something calls
/// `_supatype.run_due_publishes()`. That is deliberately callable by hand, so an operator with a
/// cron of their own, or a worker, can drive it.
///
/// The gate is `pg_extension`, not `pg_available_extensions`: available means the files are on disk,
/// installed means it works here. `pg_cron` also lives in exactly one database per cluster, so being
/// available is no promise that `cron.schedule` exists in *this* one.
///
/// `IF NOT EXISTS` on the extension and an upsert on the schedule, so re-emission on every push is
/// free and a changed schedule converges rather than accumulating jobs.
fn cron_jobs_sql() -> String {
    let helper = HELPER_SCHEMA;
    format!(
        r#"-- Scheduled publishing and retention, if this database has a scheduler.
DO $cron$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
    RAISE NOTICE 'pg_cron is not installed here, so scheduled publishing and version pruning will not run on a timer. Everything else works. Call {helper}.run_due_publishes() and {helper}.prune_versions() from a scheduler of your own.';
    RETURN;
  END IF;

  -- Replaced rather than added to, so a push converges on one job per purpose instead of stacking a
  -- new one every time.
  PERFORM cron.unschedule(jobname)
     FROM cron.job
    WHERE jobname IN ('supatype-scheduled-publish', 'supatype-prune-versions');

  -- Every minute: the smallest useful granularity for "publish at nine", and the job does nothing
  -- but one indexed scan per versioned model when there is nothing due.
  PERFORM cron.schedule('supatype-scheduled-publish', '* * * * *',
    'SELECT {helper}.run_due_publishes()');

  -- Hourly: pruning is housekeeping, and running it every minute would spend more on the scan than
  -- it reclaims.
  PERFORM cron.schedule('supatype-prune-versions', '0 * * * *',
    'SELECT {helper}.prune_versions()');
END;
$cron$;

"#
    )
}

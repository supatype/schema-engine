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
         \"publish_at\" TIMESTAMPTZ,\n    \
         \"created_at\" TIMESTAMPTZ NOT NULL DEFAULT now(),\n    \
         \"created_by\" UUID,\n    \
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
        r#"-- The visibility list in force: Studio's override when set, otherwise the pushed config.
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
    caller uuid := auth.uid();
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
         \"created_by\" = auth.uid()\n    \
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
    out.push_str(&draft_schema_preamble());

    for model in &models {
        let table = db_table_name(model);
        let versions_table = versions_table_name(table);
        out.push_str(&versions_table_access_sql(schema, table, &versions_table));
        // A model that keeps history without withholding writes has no pending version to read, so
        // it gets no draft view. Asking for one answers PGRST106, which is the honest answer.
        if versions_of(model).is_some_and(|v| v.drafts) {
            out.push_str(&draft_view_sql(schema, table, &versions_table));
        }
    }

    Ok(out)
}

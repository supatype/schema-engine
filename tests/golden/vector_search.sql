-- ============================================================
-- FORWARD MIGRATION
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE EXTENSION IF NOT EXISTS "vector";

CREATE EXTENSION IF NOT EXISTS "unaccent";

CREATE SCHEMA IF NOT EXISTS _platform;
GRANT USAGE ON SCHEMA _platform TO PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA _platform GRANT EXECUTE ON FUNCTIONS TO PUBLIC;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA _platform TO PUBLIC;

-- Claim readers the generated access rules call
CREATE SCHEMA IF NOT EXISTS _supatype;

-- jwt_claims(): the verified claims, or an empty object for an anonymous request.
CREATE OR REPLACE FUNCTION _supatype.jwt_claims() RETURNS jsonb AS $$
  SELECT COALESCE(
    NULLIF(current_setting('request.jwt.claims', true), '')::jsonb,
    '{}'::jsonb
  );
$$ LANGUAGE sql STABLE;

-- jwt_uid(): the caller's user id, or NULL when the request has no subject.
CREATE OR REPLACE FUNCTION _supatype.jwt_uid() RETURNS uuid AS $$
  SELECT NULLIF(_supatype.jwt_claims() ->> 'sub', '')::uuid;
$$ LANGUAGE sql STABLE;

-- jwt_role(): application role for access rules.
--
-- Reads `app_metadata.role` first, falling back to the top-level `role` claim.
-- The top-level claim is the one PostgREST uses to pick the Postgres role it
-- runs the request as, so it can only ever be anon / authenticated /
-- service_role; application roles (admin, editor, etc.) live in app_metadata,
-- which only the Auth admin API can write. Never `user_metadata`, which the
-- user can edit themselves.
CREATE OR REPLACE FUNCTION _supatype.jwt_role() RETURNS text AS $$
  SELECT COALESCE(
    _supatype.jwt_claims() -> 'app_metadata' ->> 'role',
    _supatype.jwt_claims() ->> 'role',
    'anon'
  );
$$ LANGUAGE sql STABLE;

-- jwt_claim(path): nested JWT claim by dotted path, e.g. 'app_metadata.tier'.
CREATE OR REPLACE FUNCTION _supatype.jwt_claim(claim_path text) RETURNS jsonb AS $$
  SELECT _supatype.jwt_claims() #> string_to_array(claim_path, '.');
$$ LANGUAGE sql STABLE;

-- jwt_claim_text(path): the same claim as text, for scalar comparisons.
CREATE OR REPLACE FUNCTION _supatype.jwt_claim_text(claim_path text) RETURNS text AS $$
  SELECT _supatype.jwt_claims() #>> string_to_array(claim_path, '.');
$$ LANGUAGE sql STABLE;

DO $claims_access$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'GRANT USAGE ON SCHEMA "_supatype" TO anon';
    EXECUTE 'GRANT EXECUTE ON FUNCTION "_supatype".jwt_claims() TO anon';
    EXECUTE 'GRANT EXECUTE ON FUNCTION "_supatype".jwt_uid() TO anon';
    EXECUTE 'GRANT EXECUTE ON FUNCTION "_supatype".jwt_role() TO anon';
    EXECUTE 'GRANT EXECUTE ON FUNCTION "_supatype".jwt_claim(text) TO anon';
    EXECUTE 'GRANT EXECUTE ON FUNCTION "_supatype".jwt_claim_text(text) TO anon';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'GRANT USAGE ON SCHEMA "_supatype" TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION "_supatype".jwt_claims() TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION "_supatype".jwt_uid() TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION "_supatype".jwt_role() TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION "_supatype".jwt_claim(text) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION "_supatype".jwt_claim_text(text) TO authenticated';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
    EXECUTE 'GRANT USAGE ON SCHEMA "_supatype" TO service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION "_supatype".jwt_claims() TO service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION "_supatype".jwt_uid() TO service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION "_supatype".jwt_role() TO service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION "_supatype".jwt_claim(text) TO service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION "_supatype".jwt_claim_text(text) TO service_role';
  END IF;
END
$claims_access$;

-- auth.* aliases of the claim readers, for hand-written rules (project: )
CREATE SCHEMA IF NOT EXISTS auth;

DO $auth_schema_usage$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'GRANT USAGE ON SCHEMA "auth" TO anon';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'GRANT USAGE ON SCHEMA "auth" TO authenticated';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
    EXECUTE 'GRANT USAGE ON SCHEMA "auth" TO service_role';
  END IF;
END
$auth_schema_usage$;

CREATE OR REPLACE FUNCTION auth.jwt() RETURNS jsonb AS $$
  SELECT _supatype.jwt_claims();
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid AS $$
  SELECT _supatype.jwt_uid();
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION auth.role() RETURNS text AS $$
  SELECT _supatype.jwt_role();
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION auth.email() RETURNS text AS $$
  SELECT COALESCE(_supatype.jwt_claims() ->> 'email', '');
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION auth.claim(claim_path text) RETURNS jsonb AS $$
  SELECT _supatype.jwt_claim(claim_path);
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION auth.claim_text(claim_path text) RETURNS text AS $$
  SELECT _supatype.jwt_claim_text(claim_path);
$$ LANGUAGE sql STABLE;

-- auth.roles(): the `roles` claim as a text array.
CREATE OR REPLACE FUNCTION auth.roles() RETURNS text[]
  LANGUAGE sql STABLE AS $$
    SELECT ARRAY(
      SELECT jsonb_array_elements_text(
        COALESCE(_supatype.jwt_claims() -> 'roles', '[]'::jsonb)
      )
    );
  $$;

BEGIN;

-- Constraint helper functions (idempotent)
CREATE SCHEMA IF NOT EXISTS _supatype;

CREATE OR REPLACE FUNCTION _supatype.richtext_text(v jsonb)
RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT AS $fn$
  SELECT coalesce(string_agg(t, ''), '')
  FROM jsonb_path_query(v, 'strict $.**.text ? (@.type() == "string")') AS q(j),
       LATERAL (SELECT j #>> '{}') AS s(t)
$fn$;

CREATE OR REPLACE FUNCTION _supatype.localized_length_max(v jsonb, n integer)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT AS $fn$
  SELECT bool_and(char_length(value) <= n) FROM jsonb_each_text(v)
$fn$;

CREATE OR REPLACE FUNCTION _supatype.localized_length_min(v jsonb, n integer)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT AS $fn$
  SELECT bool_and(char_length(value) >= n) FROM jsonb_each_text(v)
$fn$;

CREATE OR REPLACE FUNCTION _supatype.localized_richtext_length_max(v jsonb, n integer)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT AS $fn$
  SELECT bool_and(char_length(_supatype.richtext_text(value::jsonb)) <= n) FROM jsonb_each_text(v)
$fn$;

CREATE OR REPLACE FUNCTION _supatype.localized_richtext_length_min(v jsonb, n integer)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT AS $fn$
  SELECT bool_and(char_length(_supatype.richtext_text(value::jsonb)) >= n) FROM jsonb_each_text(v)
$fn$;

CREATE OR REPLACE FUNCTION _supatype.localized_items_max(v jsonb, n integer)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT AS $fn$
  SELECT bool_and(jsonb_array_length(value::jsonb) <= n) FROM jsonb_each_text(v)
$fn$;

CREATE OR REPLACE FUNCTION _supatype.localized_items_min(v jsonb, n integer)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT AS $fn$
  SELECT bool_and(jsonb_array_length(value::jsonb) >= n) FROM jsonb_each_text(v)
$fn$;

CREATE OR REPLACE FUNCTION _supatype.localized_number_max(v jsonb, n numeric)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT AS $fn$
  SELECT bool_and(value::numeric <= n) FROM jsonb_each_text(v)
$fn$;

CREATE OR REPLACE FUNCTION _supatype.localized_number_min(v jsonb, n numeric)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT AS $fn$
  SELECT bool_and(value::numeric >= n) FROM jsonb_each_text(v)
$fn$;

CREATE OR REPLACE FUNCTION _supatype.localized_temporal_max(v jsonb, n text)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT AS $fn$
  SELECT bool_and(value::timestamptz <= n::timestamptz) FROM jsonb_each_text(v)
$fn$;

CREATE OR REPLACE FUNCTION _supatype.localized_temporal_min(v jsonb, n text)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT AS $fn$
  SELECT bool_and(value::timestamptz >= n::timestamptz) FROM jsonb_each_text(v)
$fn$;

-- Drop draft views before column changes; recreated at the end of this migration.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'draft') THEN
    EXECUTE 'DROP VIEW IF EXISTS "draft"."documents"';
  END IF;
END $$;

-- [safe] Create table: documents
CREATE TABLE IF NOT EXISTS "public"."documents" (
    "id" UUID CONSTRAINT "documents_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "title" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "embedding" vector(1536),
    "metadata" JSONB,
    "source" TEXT,
    "score" DOUBLE PRECISION,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS "documents_embedding_idx" ON "public"."documents" USING hnsw ("embedding");

-- Row-level affordance functions (PostgREST computed columns)
CREATE OR REPLACE FUNCTION "public"."can_read_documents"("documents" "public"."documents")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT TRUE
      FROM (SELECT ($1).*) AS "documents";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_documents"("documents" "public"."documents")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT _supatype.jwt_role()) = ANY(ARRAY['admin', 'ingest'])
      FROM (SELECT ($1).*) AS "documents";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_documents"("documents" "public"."documents")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT _supatype.jwt_role()) = 'admin'
      FROM (SELECT ($1).*) AS "documents";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_documents"("documents" "public"."documents")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT _supatype.jwt_role()) = 'admin'
      FROM (SELECT ($1).*) AS "documents";
  $can$;

-- reconciled objects
CREATE SCHEMA IF NOT EXISTS "_platform";
CREATE SCHEMA IF NOT EXISTS "supatype";
CREATE OR REPLACE FUNCTION _platform.set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION _platform.slugify(val TEXT)
RETURNS TEXT AS $$
BEGIN
  RETURN lower(
    regexp_replace(
      regexp_replace(
        unaccent(trim(val)),
        '[^a-zA-Z0-9\s-]', '', 'g'
      ),
      '[\s-]+', '-', 'g'
    )
  );
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE TRIGGER "documents_updated_at_trigger"
BEFORE UPDATE ON "public"."documents"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE POLICY "documents_delete" ON "public"."documents"
FOR DELETE USING (
    (SELECT _supatype.jwt_role()) = 'admin'
  );
CREATE POLICY "documents_insert" ON "public"."documents"
FOR INSERT WITH CHECK (
    (SELECT _supatype.jwt_role()) = ANY(ARRAY['admin', 'ingest'])
  );
CREATE POLICY "documents_select" ON "public"."documents"
FOR SELECT USING (
    TRUE
  );
CREATE POLICY "documents_update" ON "public"."documents"
FOR UPDATE USING (
    (SELECT _supatype.jwt_role()) = 'admin'
  ) WITH CHECK (
    (SELECT _supatype.jwt_role()) = 'admin'
  );
ALTER TABLE "public"."documents" ENABLE ROW LEVEL SECURITY;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."documents" FROM anon';
    EXECUTE 'GRANT SELECT ON "public"."documents" TO anon';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."documents" FROM authenticated';
    EXECUTE 'GRANT DELETE, INSERT, SELECT, UPDATE ON "public"."documents" TO authenticated';
  END IF;
END
$grants$;

COMMIT;
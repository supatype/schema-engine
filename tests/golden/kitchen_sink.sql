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
    EXECUTE 'DROP VIEW IF EXISTS "draft"."kitchen_sink"';
  END IF;
END $$;

-- [safe] Create table: kitchen_sink
CREATE TABLE IF NOT EXISTS "public"."kitchen_sink" (
    "id" UUID CONSTRAINT "kitchen_sink_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "textField" TEXT NOT NULL,
    "emailField" TEXT CONSTRAINT "kitchen_sink_emailField_key" UNIQUE CONSTRAINT "kitchen_sink_emailField_check" CHECK ("emailField" ~* '^[^@]+@[^@]+\.[^@]+$'),
    "intField" INTEGER NOT NULL DEFAULT 0,
    "floatField" DOUBLE PRECISION,
    "boolField" BOOLEAN NOT NULL DEFAULT false,
    "datetimeField" TIMESTAMPTZ,
    "dateField" DATE,
    "bigintField" BIGINT,
    "smallintField" SMALLINT,
    "decimalField" NUMERIC(18, 4),
    "jsonbField" JSONB,
    "enumField" TEXT NOT NULL CONSTRAINT "kitchen_sink_enumField_check" CHECK ("enumField" IN ('a', 'b', 'c')) DEFAULT 'a',
    "slugField" TEXT CONSTRAINT "kitchen_sink_slugField_key" UNIQUE,
    "richTextField" JSONB,
    "bytesField" BYTEA,
    "urlField" TEXT CONSTRAINT "kitchen_sink_urlField_check" CHECK ("urlField" ~* '^https?://'),
    "ipField" INET,
    "intervalField" INTERVAL,
    "arrayField" TEXT[],
    "vectorField" vector(512),
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "deleted_at" TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS "kitchen_sink_jsonb_field_idx" ON "public"."kitchen_sink" USING gin ("jsonb_field");

CREATE INDEX IF NOT EXISTS "kitchen_sink_vector_field_idx" ON "public"."kitchen_sink" USING hnsw ("vector_field");

CREATE INDEX IF NOT EXISTS "kitchen_sink_deleted_at_idx" ON "public"."kitchen_sink" USING btree ("deleted_at");

-- Row-level affordance functions (PostgREST computed columns)
CREATE OR REPLACE FUNCTION "public"."can_read_kitchen_sink"("kitchen_sink" "public"."kitchen_sink")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "kitchen_sink";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_read_kitchen_sink"("public"."kitchen_sink") FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_read_kitchen_sink"("public"."kitchen_sink") TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_create_kitchen_sink"("kitchen_sink" "public"."kitchen_sink")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "kitchen_sink";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_create_kitchen_sink"("public"."kitchen_sink") FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_create_kitchen_sink"("public"."kitchen_sink") TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_update_kitchen_sink"("kitchen_sink" "public"."kitchen_sink")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "kitchen_sink";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_update_kitchen_sink"("public"."kitchen_sink") FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_update_kitchen_sink"("public"."kitchen_sink") TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_delete_kitchen_sink"("kitchen_sink" "public"."kitchen_sink")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "kitchen_sink";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_delete_kitchen_sink"("public"."kitchen_sink") FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_delete_kitchen_sink"("public"."kitchen_sink") TO anon, authenticated, service_role;

-- reconciled objects
CREATE SCHEMA IF NOT EXISTS "_platform";
CREATE SCHEMA IF NOT EXISTS "supatype";
CREATE OR REPLACE FUNCTION _platform.normalise_kitchen_sink_rich_text()
RETURNS TRIGGER AS $$
BEGIN
  NEW."richTextField" := CASE WHEN NEW."richTextField" IS NULL THEN NULL WHEN NEW."richTextField" ? 'root' THEN NEW."richTextField" WHEN jsonb_typeof(NEW."richTextField") = 'string' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', (NEW."richTextField" #>> '{}')::text)))))) WHEN jsonb_typeof(NEW."richTextField") = 'array' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', COALESCE((SELECT string_agg(CASE jsonb_typeof(elem) WHEN 'string' THEN elem #>> '{}' ELSE elem::text END, E'\n') FROM jsonb_array_elements(NEW."richTextField") AS elem), '')::text)))))) ELSE jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', NEW."richTextField"::text::text)))))) END;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION _platform.set_kitchen_sink_slugfield()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW."slugField" IS NULL OR BTRIM(NEW."slugField"::TEXT) = '' THEN
      NEW."slugField" = _platform.slugify(NEW."textField"::TEXT);
    END IF;
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW."textField" IS DISTINCT FROM OLD."textField" THEN
      IF OLD."slugField" IS NOT DISTINCT FROM _platform.slugify(OLD."textField"::TEXT) THEN
        NEW."slugField" = _platform.slugify(NEW."textField"::TEXT);
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

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

CREATE OR REPLACE TRIGGER "kitchen_sink_rich_text_trigger"
BEFORE INSERT OR UPDATE ON "public"."kitchen_sink"
FOR EACH ROW EXECUTE FUNCTION _platform.normalise_kitchen_sink_rich_text();

CREATE OR REPLACE TRIGGER "kitchen_sink_slugField_trigger"
BEFORE INSERT OR UPDATE ON "public"."kitchen_sink"
FOR EACH ROW EXECUTE FUNCTION _platform.set_kitchen_sink_slugfield();

CREATE OR REPLACE TRIGGER "kitchen_sink_updated_at_trigger"
BEFORE UPDATE ON "public"."kitchen_sink"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

ALTER TABLE "public"."kitchen_sink" ENABLE ROW LEVEL SECURITY;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."kitchen_sink" FROM anon';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."kitchen_sink" FROM authenticated';
  END IF;
END
$grants$;

COMMIT;
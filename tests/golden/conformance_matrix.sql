-- ============================================================
-- FORWARD MIGRATION
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE EXTENSION IF NOT EXISTS "vector";

CREATE EXTENSION IF NOT EXISTS "postgis";

CREATE EXTENSION IF NOT EXISTS "unaccent";

CREATE SCHEMA IF NOT EXISTS _platform;
GRANT USAGE ON SCHEMA _platform TO PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA _platform GRANT EXECUTE ON FUNCTIONS TO PUBLIC;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA _platform TO PUBLIC;

-- Auth helper functions for project: 
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

-- auth.jwt() -- the verified claims, or an empty object for an anonymous request.
CREATE OR REPLACE FUNCTION auth.jwt() RETURNS jsonb AS $$
  SELECT COALESCE(
    NULLIF(current_setting('request.jwt.claims', true), '')::jsonb,
    '{}'::jsonb
  );
$$ LANGUAGE sql STABLE;

-- auth.uid() -- the caller's user id, or NULL when the request has no subject.
CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid AS $$
  SELECT NULLIF(auth.jwt() ->> 'sub', '')::uuid;
$$ LANGUAGE sql STABLE;

-- auth.role() -- application role for access rules.
--
-- Reads `app_metadata.role` first, falling back to the top-level `role` claim.
-- The top-level claim is the one PostgREST uses to pick the Postgres role it
-- runs the request as, so it can only ever be anon / authenticated /
-- service_role; application roles (admin, editor, etc.) live in app_metadata,
-- which only the Auth admin API can write -- never `user_metadata`, which the
-- user can edit themselves.
CREATE OR REPLACE FUNCTION auth.role() RETURNS text AS $$
  SELECT COALESCE(
    auth.jwt() -> 'app_metadata' ->> 'role',
    auth.jwt() ->> 'role',
    'anon'
  );
$$ LANGUAGE sql STABLE;

-- auth.email() -- extracts email from JWT claims
CREATE OR REPLACE FUNCTION auth.email() RETURNS text AS $$
  SELECT COALESCE(auth.jwt() ->> 'email', '');
$$ LANGUAGE sql STABLE;

-- auth.claim(path) -- nested JWT claim by dotted path, e.g. 'app_metadata.tier'
CREATE OR REPLACE FUNCTION auth.claim(claim_path text) RETURNS jsonb AS $$
  SELECT auth.jwt() #> string_to_array(claim_path, '.');
$$ LANGUAGE sql STABLE;

-- auth.claim_text(path) -- the same claim as text, for scalar comparisons.
CREATE OR REPLACE FUNCTION auth.claim_text(claim_path text) RETURNS text AS $$
  SELECT auth.jwt() #>> string_to_array(claim_path, '.');
$$ LANGUAGE sql STABLE;

-- auth.roles() -- the `roles` claim as a text array.
CREATE OR REPLACE FUNCTION auth.roles() RETURNS text[]
  LANGUAGE sql STABLE AS $$
    SELECT ARRAY(
      SELECT jsonb_array_elements_text(
        COALESCE(current_setting('request.jwt.claims', true)::jsonb->'roles', '[]'::jsonb)
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
    EXECUTE 'DROP VIEW IF EXISTS "draft"."every"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."every_localised"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."every_required"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."every_defaulted"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."every_read_only"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."relations"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."composites"';
  END IF;
END $$;

-- [safe] Create table: every
CREATE TABLE IF NOT EXISTS "public"."every" (
    "id" UUID CONSTRAINT "every_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "text_plain" TEXT,
    "richText_plain" JSONB,
    "integer_plain" INTEGER,
    "float_plain" DOUBLE PRECISION,
    "boolean_plain" BOOLEAN,
    "datetime_plain" TIMESTAMPTZ,
    "uuid_plain" UUID,
    "email_plain" TEXT CONSTRAINT "every_email_plain_check" CHECK ("email_plain" ~* '^[^@]+@[^@]+\.[^@]+$'),
    "bigInt_plain" BIGINT,
    "bytes_plain" BYTEA,
    "smallInt_plain" SMALLINT,
    "date_plain" DATE,
    "timestamp_plain" TIMESTAMP,
    "money_plain" NUMERIC(19,4),
    "url_plain" TEXT CONSTRAINT "every_url_plain_check" CHECK ("url_plain" ~* '^https?://'),
    "ip_plain" INET,
    "cidr_plain" CIDR,
    "macaddr_plain" MACADDR,
    "interval_plain" INTERVAL,
    "tsQuery_plain" TSQUERY,
    "tsVector_plain" TSVECTOR,
    "xml_plain" XML,
    "color_plain" TEXT,
    "slug_plain" TEXT CONSTRAINT "every_slug_plain_key" UNIQUE,
    "enum_plain" TEXT CONSTRAINT "every_enum_plain_check" CHECK ("enum_plain" IN ('a', 'b', 'c')),
    "json_plain" JSONB,
    "button_plain" JSONB,
    "decimal_plain" NUMERIC(18, 4),
    "image_plain" JSONB,
    "file_plain" JSONB,
    "blocks_plain" JSONB,
    "serial_plain" SERIAL,
    "bigSerial_plain" BIGSERIAL,
    "array_plain" TEXT[],
    "geo_plain" GEOGRAPHY(POINT, 4326),
    "vector_plain" vector(8)
);

COMMENT ON CONSTRAINT "every_slug_plain_key" ON "public"."every" IS 'supatype:managed;kind=unique_constraint;table=every;fields=slug_plain;v=1';

CREATE INDEX IF NOT EXISTS "every_blocks_plain_gin_idx" ON "public"."every" USING gin ("blocks_plain");

COMMENT ON TABLE "public"."every" IS 'supatype:managed;kind=table;table=every;fields=;v=1';

-- [safe] Create table: every_localised
CREATE TABLE IF NOT EXISTS "public"."every_localised" (
    "id" UUID CONSTRAINT "every_localised_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "text_plain" TEXT,
    "text_loc" JSONB,
    "richText_loc" JSONB,
    "integer_loc" JSONB,
    "float_loc" JSONB,
    "boolean_loc" JSONB,
    "datetime_loc" JSONB,
    "uuid_loc" JSONB,
    "email_loc" JSONB CONSTRAINT "every_localised_email_loc_check" CHECK ("email_loc" ~* '^[^@]+@[^@]+\.[^@]+$'),
    "bigInt_loc" JSONB,
    "bytes_loc" JSONB,
    "smallInt_loc" JSONB,
    "date_loc" JSONB,
    "timestamp_loc" JSONB,
    "money_loc" JSONB,
    "url_loc" JSONB CONSTRAINT "every_localised_url_loc_check" CHECK ("url_loc" ~* '^https?://'),
    "ip_loc" JSONB,
    "cidr_loc" JSONB,
    "macaddr_loc" JSONB,
    "interval_loc" JSONB,
    "tsQuery_loc" JSONB,
    "tsVector_loc" TSVECTOR,
    "xml_loc" JSONB,
    "color_loc" JSONB,
    "slug_loc" TEXT CONSTRAINT "every_localised_slug_loc_key" UNIQUE,
    "enum_loc" TEXT CONSTRAINT "every_localised_enum_loc_check" CHECK ("enum_loc" IN ('a', 'b', 'c')),
    "json_loc" JSONB,
    "button_loc" JSONB,
    "decimal_loc" NUMERIC(18, 4),
    "image_loc" JSONB,
    "file_loc" JSONB,
    "blocks_loc" JSONB
);

COMMENT ON CONSTRAINT "every_localised_slug_loc_key" ON "public"."every_localised" IS 'supatype:managed;kind=unique_constraint;table=every_localised;fields=slug_loc;v=1';

CREATE INDEX IF NOT EXISTS "every_localised_blocks_loc_gin_idx" ON "public"."every_localised" USING gin ("blocks_loc");

COMMENT ON TABLE "public"."every_localised" IS 'supatype:managed;kind=table;table=every_localised;fields=;v=1';

-- [safe] Create table: every_required
CREATE TABLE IF NOT EXISTS "public"."every_required" (
    "id" UUID CONSTRAINT "every_required_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "text_plain" TEXT,
    "text_req" TEXT NOT NULL,
    "richText_req" JSONB NOT NULL,
    "integer_req" INTEGER NOT NULL,
    "float_req" DOUBLE PRECISION NOT NULL,
    "boolean_req" BOOLEAN NOT NULL,
    "datetime_req" TIMESTAMPTZ NOT NULL,
    "uuid_req" UUID NOT NULL,
    "email_req" TEXT NOT NULL CONSTRAINT "every_required_email_req_check" CHECK ("email_req" ~* '^[^@]+@[^@]+\.[^@]+$'),
    "bigInt_req" BIGINT NOT NULL,
    "bytes_req" BYTEA NOT NULL,
    "smallInt_req" SMALLINT NOT NULL,
    "date_req" DATE NOT NULL,
    "timestamp_req" TIMESTAMP NOT NULL,
    "money_req" NUMERIC(19,4) NOT NULL,
    "url_req" TEXT NOT NULL CONSTRAINT "every_required_url_req_check" CHECK ("url_req" ~* '^https?://'),
    "ip_req" INET NOT NULL,
    "cidr_req" CIDR NOT NULL,
    "macaddr_req" MACADDR NOT NULL,
    "interval_req" INTERVAL NOT NULL,
    "tsQuery_req" TSQUERY NOT NULL,
    "tsVector_req" TSVECTOR NOT NULL,
    "xml_req" XML NOT NULL,
    "color_req" TEXT NOT NULL,
    "slug_req" TEXT NOT NULL CONSTRAINT "every_required_slug_req_key" UNIQUE,
    "enum_req" TEXT NOT NULL CONSTRAINT "every_required_enum_req_check" CHECK ("enum_req" IN ('a', 'b', 'c')),
    "json_req" JSONB NOT NULL,
    "button_req" JSONB NOT NULL,
    "decimal_req" NUMERIC(18, 4) NOT NULL,
    "image_req" JSONB NOT NULL,
    "file_req" JSONB NOT NULL,
    "blocks_req" JSONB NOT NULL,
    "serial_req" SERIAL,
    "bigSerial_req" BIGSERIAL,
    "array_req" TEXT[] NOT NULL,
    "geo_req" GEOGRAPHY(POINT, 4326) NOT NULL,
    "vector_req" vector(8) NOT NULL
);

COMMENT ON CONSTRAINT "every_required_slug_req_key" ON "public"."every_required" IS 'supatype:managed;kind=unique_constraint;table=every_required;fields=slug_req;v=1';

CREATE INDEX IF NOT EXISTS "every_required_blocks_req_gin_idx" ON "public"."every_required" USING gin ("blocks_req");

COMMENT ON TABLE "public"."every_required" IS 'supatype:managed;kind=table;table=every_required;fields=;v=1';

-- [safe] Create table: every_defaulted
CREATE TABLE IF NOT EXISTS "public"."every_defaulted" (
    "id" UUID CONSTRAINT "every_defaulted_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "text_plain" TEXT,
    "text_def" TEXT DEFAULT 'x',
    "richText_def" JSONB DEFAULT jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', 'x'::text)))))),
    "integer_def" INTEGER DEFAULT 1,
    "float_def" DOUBLE PRECISION DEFAULT 1.5,
    "boolean_def" BOOLEAN DEFAULT true,
    "datetime_def" TIMESTAMPTZ DEFAULT 'x',
    "uuid_def" UUID DEFAULT 'x',
    "email_def" TEXT DEFAULT 'x' CONSTRAINT "every_defaulted_email_def_check" CHECK ("email_def" ~* '^[^@]+@[^@]+\.[^@]+$'),
    "bigInt_def" BIGINT DEFAULT 1,
    "bytes_def" BYTEA DEFAULT 'x',
    "smallInt_def" SMALLINT DEFAULT 1,
    "date_def" DATE DEFAULT 'x',
    "timestamp_def" TIMESTAMP DEFAULT 'x',
    "money_def" NUMERIC(19,4) DEFAULT 1,
    "url_def" TEXT DEFAULT 'x' CONSTRAINT "every_defaulted_url_def_check" CHECK ("url_def" ~* '^https?://'),
    "ip_def" INET DEFAULT 'x',
    "cidr_def" CIDR DEFAULT 'x',
    "macaddr_def" MACADDR DEFAULT 'x',
    "interval_def" INTERVAL DEFAULT 'x',
    "tsQuery_def" TSQUERY DEFAULT 'x',
    "tsVector_def" TSVECTOR,
    "xml_def" XML DEFAULT 'x',
    "color_def" TEXT DEFAULT 'x',
    "slug_def" TEXT CONSTRAINT "every_defaulted_slug_def_key" UNIQUE,
    "enum_def" TEXT CONSTRAINT "every_defaulted_enum_def_check" CHECK ("enum_def" IN ('a', 'b', 'c')) DEFAULT 'x',
    "json_def" JSONB,
    "button_def" JSONB,
    "decimal_def" NUMERIC(18, 4),
    "image_def" JSONB,
    "file_def" JSONB,
    "blocks_def" JSONB,
    "serial_def" SERIAL,
    "bigSerial_def" BIGSERIAL,
    "array_def" TEXT[],
    "geo_def" GEOGRAPHY(POINT, 4326),
    "vector_def" vector(8)
);

COMMENT ON CONSTRAINT "every_defaulted_slug_def_key" ON "public"."every_defaulted" IS 'supatype:managed;kind=unique_constraint;table=every_defaulted;fields=slug_def;v=1';

CREATE INDEX IF NOT EXISTS "every_defaulted_blocks_def_gin_idx" ON "public"."every_defaulted" USING gin ("blocks_def");

COMMENT ON TABLE "public"."every_defaulted" IS 'supatype:managed;kind=table;table=every_defaulted;fields=;v=1';

-- [safe] Create table: every_read_only
CREATE TABLE IF NOT EXISTS "public"."every_read_only" (
    "id" UUID CONSTRAINT "every_read_only_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "text_plain" TEXT,
    "text_ro" TEXT,
    "richText_ro" JSONB,
    "integer_ro" INTEGER,
    "float_ro" DOUBLE PRECISION,
    "boolean_ro" BOOLEAN,
    "datetime_ro" TIMESTAMPTZ,
    "uuid_ro" UUID,
    "email_ro" TEXT CONSTRAINT "every_read_only_email_ro_check" CHECK ("email_ro" ~* '^[^@]+@[^@]+\.[^@]+$'),
    "bigInt_ro" BIGINT,
    "bytes_ro" BYTEA,
    "smallInt_ro" SMALLINT,
    "date_ro" DATE,
    "timestamp_ro" TIMESTAMP,
    "money_ro" NUMERIC(19,4),
    "url_ro" TEXT CONSTRAINT "every_read_only_url_ro_check" CHECK ("url_ro" ~* '^https?://'),
    "ip_ro" INET,
    "cidr_ro" CIDR,
    "macaddr_ro" MACADDR,
    "interval_ro" INTERVAL,
    "tsQuery_ro" TSQUERY,
    "tsVector_ro" TSVECTOR,
    "xml_ro" XML,
    "color_ro" TEXT,
    "slug_ro" TEXT CONSTRAINT "every_read_only_slug_ro_key" UNIQUE,
    "enum_ro" TEXT CONSTRAINT "every_read_only_enum_ro_check" CHECK ("enum_ro" IN ('a', 'b', 'c')),
    "json_ro" JSONB,
    "button_ro" JSONB,
    "decimal_ro" NUMERIC(18, 4),
    "image_ro" JSONB,
    "file_ro" JSONB,
    "blocks_ro" JSONB,
    "serial_ro" SERIAL,
    "bigSerial_ro" BIGSERIAL,
    "array_ro" TEXT[],
    "geo_ro" GEOGRAPHY(POINT, 4326),
    "vector_ro" vector(8)
);

COMMENT ON CONSTRAINT "every_read_only_slug_ro_key" ON "public"."every_read_only" IS 'supatype:managed;kind=unique_constraint;table=every_read_only;fields=slug_ro;v=1';

CREATE INDEX IF NOT EXISTS "every_read_only_blocks_ro_gin_idx" ON "public"."every_read_only" USING gin ("blocks_ro");

COMMENT ON TABLE "public"."every_read_only" IS 'supatype:managed;kind=table;table=every_read_only;fields=;v=1';

-- [safe] Create table: relations
CREATE TABLE IF NOT EXISTS "public"."relations" (
    "id" UUID CONSTRAINT "relations_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "owner_id" UUID
);

COMMENT ON TABLE "public"."relations" IS 'supatype:managed;kind=table;table=relations;fields=;v=1';

-- [safe] Create table: composites
CREATE TABLE IF NOT EXISTS "public"."composites" (
    "id" UUID CONSTRAINT "composites_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "status" TEXT NOT NULL DEFAULT 'draft' CONSTRAINT "composites_status_check" CHECK ("status" IN ('draft', 'published', 'scheduled', 'archived')),
    "published_at" TIMESTAMPTZ,
    "scheduled_at" TIMESTAMPTZ,
    "deleted_at" TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS "composites_deleted_at_idx" ON "public"."composites" USING btree ("deleted_at");

COMMENT ON TABLE "public"."composites" IS 'supatype:managed;kind=table;table=composites;fields=;v=1';

-- [safe] Create junction table: relations_every
CREATE TABLE IF NOT EXISTS "public"."relations_every" (
    "relations_id" UUID NOT NULL CONSTRAINT "relations_every_relations_id_fkey" REFERENCES "public"."relations" ("id") ON DELETE CASCADE,
    "every_id" UUID NOT NULL CONSTRAINT "relations_every_every_id_fkey" REFERENCES "public"."every" ("id") ON DELETE CASCADE,
    CONSTRAINT "relations_every_pkey" PRIMARY KEY ("relations_id", "every_id")
);

COMMENT ON TABLE "public"."relations_every" IS 'supatype:managed;kind=table;table=relations_every;fields=;v=1';

-- [safe] Enable RLS: every
ALTER TABLE "public"."every" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: every_localised
ALTER TABLE "public"."every_localised" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: every_required
ALTER TABLE "public"."every_required" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: every_defaulted
ALTER TABLE "public"."every_defaulted" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: every_read_only
ALTER TABLE "public"."every_read_only" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: relations
ALTER TABLE "public"."relations" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: composites
ALTER TABLE "public"."composites" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: relations_every
ALTER TABLE "public"."relations_every" ENABLE ROW LEVEL SECURITY;

-- Row-level affordance functions (PostgREST computed columns)
CREATE OR REPLACE FUNCTION "public"."can_read_every"("every" "public"."every")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_every"("every" "public"."every")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_every"("every" "public"."every")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_every"("every" "public"."every")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_every_localised"("every_localised" "public"."every_localised")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every_localised";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_every_localised"("every_localised" "public"."every_localised")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every_localised";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_every_localised"("every_localised" "public"."every_localised")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every_localised";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_every_localised"("every_localised" "public"."every_localised")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every_localised";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_every_required"("every_required" "public"."every_required")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every_required";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_every_required"("every_required" "public"."every_required")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every_required";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_every_required"("every_required" "public"."every_required")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every_required";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_every_required"("every_required" "public"."every_required")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every_required";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_every_defaulted"("every_defaulted" "public"."every_defaulted")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every_defaulted";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_every_defaulted"("every_defaulted" "public"."every_defaulted")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every_defaulted";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_every_defaulted"("every_defaulted" "public"."every_defaulted")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every_defaulted";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_every_defaulted"("every_defaulted" "public"."every_defaulted")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every_defaulted";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_every_read_only"("every_read_only" "public"."every_read_only")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every_read_only";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_every_read_only"("every_read_only" "public"."every_read_only")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every_read_only";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_every_read_only"("every_read_only" "public"."every_read_only")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every_read_only";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_every_read_only"("every_read_only" "public"."every_read_only")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "every_read_only";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_relations"("relations" "public"."relations")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "relations";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_relations"("relations" "public"."relations")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "relations";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_relations"("relations" "public"."relations")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "relations";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_relations"("relations" "public"."relations")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "relations";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_composites"("composites" "public"."composites")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "composites";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_composites"("composites" "public"."composites")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "composites";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_composites"("composites" "public"."composites")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "composites";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_composites"("composites" "public"."composites")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "composites";
  $can$;

-- Table privileges derived from access rules (defence in depth)
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE SELECT ON "public"."every" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."every" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."every" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."every" FROM anon';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE SELECT ON "public"."every" FROM authenticated';
    EXECUTE 'REVOKE INSERT ON "public"."every" FROM authenticated';
    EXECUTE 'REVOKE UPDATE ON "public"."every" FROM authenticated';
    EXECUTE 'REVOKE DELETE ON "public"."every" FROM authenticated';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE SELECT ON "public"."every_localised" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."every_localised" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."every_localised" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."every_localised" FROM anon';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE SELECT ON "public"."every_localised" FROM authenticated';
    EXECUTE 'REVOKE INSERT ON "public"."every_localised" FROM authenticated';
    EXECUTE 'REVOKE UPDATE ON "public"."every_localised" FROM authenticated';
    EXECUTE 'REVOKE DELETE ON "public"."every_localised" FROM authenticated';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE SELECT ON "public"."every_required" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."every_required" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."every_required" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."every_required" FROM anon';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE SELECT ON "public"."every_required" FROM authenticated';
    EXECUTE 'REVOKE INSERT ON "public"."every_required" FROM authenticated';
    EXECUTE 'REVOKE UPDATE ON "public"."every_required" FROM authenticated';
    EXECUTE 'REVOKE DELETE ON "public"."every_required" FROM authenticated';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE SELECT ON "public"."every_defaulted" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."every_defaulted" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."every_defaulted" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."every_defaulted" FROM anon';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE SELECT ON "public"."every_defaulted" FROM authenticated';
    EXECUTE 'REVOKE INSERT ON "public"."every_defaulted" FROM authenticated';
    EXECUTE 'REVOKE UPDATE ON "public"."every_defaulted" FROM authenticated';
    EXECUTE 'REVOKE DELETE ON "public"."every_defaulted" FROM authenticated';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE SELECT ON "public"."every_read_only" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."every_read_only" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."every_read_only" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."every_read_only" FROM anon';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE SELECT ON "public"."every_read_only" FROM authenticated';
    EXECUTE 'REVOKE INSERT ON "public"."every_read_only" FROM authenticated';
    EXECUTE 'REVOKE UPDATE ON "public"."every_read_only" FROM authenticated';
    EXECUTE 'REVOKE DELETE ON "public"."every_read_only" FROM authenticated';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE SELECT ON "public"."relations" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."relations" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."relations" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."relations" FROM anon';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE SELECT ON "public"."relations" FROM authenticated';
    EXECUTE 'REVOKE INSERT ON "public"."relations" FROM authenticated';
    EXECUTE 'REVOKE UPDATE ON "public"."relations" FROM authenticated';
    EXECUTE 'REVOKE DELETE ON "public"."relations" FROM authenticated';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE SELECT ON "public"."composites" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."composites" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."composites" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."composites" FROM anon';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE SELECT ON "public"."composites" FROM authenticated';
    EXECUTE 'REVOKE INSERT ON "public"."composites" FROM authenticated';
    EXECUTE 'REVOKE UPDATE ON "public"."composites" FROM authenticated';
    EXECUTE 'REVOKE DELETE ON "public"."composites" FROM authenticated';
  END IF;
END
$grants$;

-- Field-level access: security labels read by supatype_mask
DO $mask_clear$
DECLARE
  stale record;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'supatype_mask') THEN
    RETURN;
  END IF;

  FOR stale IN
    SELECT c.relname AS tbl, a.attname AS col
      FROM pg_seclabel l
      JOIN pg_class c ON c.oid = l.objoid
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_attribute a ON a.attrelid = l.objoid AND a.attnum = l.objsubid
     WHERE l.provider = 'supatype'
       AND l.classoid = 'pg_class'::regclass
       AND n.nspname = 'public'
  LOOP
    EXECUTE format('SECURITY LABEL FOR supatype ON COLUMN %I.%I.%I IS NULL',
                   'public', stale.tbl, stale.col);
  END LOOP;
END
$mask_clear$;

-- reconciled objects
ALTER TABLE "public"."relations" ADD CONSTRAINT "relations_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "public"."every" ("id") ON DELETE RESTRICT ON UPDATE CASCADE;
CREATE OR REPLACE FUNCTION _platform.normalise_every_defaulted_rich_text()
RETURNS TRIGGER AS $$
BEGIN
  NEW."richText_def" := CASE WHEN NEW."richText_def" IS NULL THEN NULL WHEN NEW."richText_def" ? 'root' THEN NEW."richText_def" WHEN jsonb_typeof(NEW."richText_def") = 'string' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', (NEW."richText_def" #>> '{}')::text)))))) WHEN jsonb_typeof(NEW."richText_def") = 'array' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', COALESCE((SELECT string_agg(CASE jsonb_typeof(elem) WHEN 'string' THEN elem #>> '{}' ELSE elem::text END, E'\n') FROM jsonb_array_elements(NEW."richText_def") AS elem), '')::text)))))) ELSE jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', NEW."richText_def"::text::text)))))) END;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION _platform.normalise_every_localised_rich_text()
RETURNS TRIGGER AS $$
BEGIN
  NEW."richText_loc" := CASE WHEN NEW."richText_loc" IS NULL THEN NULL WHEN NEW."richText_loc" ? 'root' THEN NEW."richText_loc" WHEN jsonb_typeof(NEW."richText_loc") <> 'object' THEN CASE WHEN NEW."richText_loc" IS NULL THEN NULL WHEN NEW."richText_loc" ? 'root' THEN NEW."richText_loc" WHEN jsonb_typeof(NEW."richText_loc") = 'string' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', (NEW."richText_loc" #>> '{}')::text)))))) WHEN jsonb_typeof(NEW."richText_loc") = 'array' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', COALESCE((SELECT string_agg(CASE jsonb_typeof(elem) WHEN 'string' THEN elem #>> '{}' ELSE elem::text END, E'\n') FROM jsonb_array_elements(NEW."richText_loc") AS elem), '')::text)))))) ELSE jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', NEW."richText_loc"::text::text)))))) END ELSE COALESCE((SELECT jsonb_object_agg(locale.key, CASE WHEN locale.value IS NULL THEN NULL WHEN locale.value ? 'root' THEN locale.value WHEN jsonb_typeof(locale.value) = 'string' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', (locale.value #>> '{}')::text)))))) WHEN jsonb_typeof(locale.value) = 'array' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', COALESCE((SELECT string_agg(CASE jsonb_typeof(elem) WHEN 'string' THEN elem #>> '{}' ELSE elem::text END, E'\n') FROM jsonb_array_elements(locale.value) AS elem), '')::text)))))) ELSE jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', locale.value::text::text)))))) END) FROM jsonb_each(NEW."richText_loc") AS locale), NEW."richText_loc") END;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION _platform.normalise_every_read_only_rich_text()
RETURNS TRIGGER AS $$
BEGIN
  NEW."richText_ro" := CASE WHEN NEW."richText_ro" IS NULL THEN NULL WHEN NEW."richText_ro" ? 'root' THEN NEW."richText_ro" WHEN jsonb_typeof(NEW."richText_ro") = 'string' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', (NEW."richText_ro" #>> '{}')::text)))))) WHEN jsonb_typeof(NEW."richText_ro") = 'array' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', COALESCE((SELECT string_agg(CASE jsonb_typeof(elem) WHEN 'string' THEN elem #>> '{}' ELSE elem::text END, E'\n') FROM jsonb_array_elements(NEW."richText_ro") AS elem), '')::text)))))) ELSE jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', NEW."richText_ro"::text::text)))))) END;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION _platform.normalise_every_required_rich_text()
RETURNS TRIGGER AS $$
BEGIN
  NEW."richText_req" := CASE WHEN NEW."richText_req" IS NULL THEN NULL WHEN NEW."richText_req" ? 'root' THEN NEW."richText_req" WHEN jsonb_typeof(NEW."richText_req") = 'string' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', (NEW."richText_req" #>> '{}')::text)))))) WHEN jsonb_typeof(NEW."richText_req") = 'array' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', COALESCE((SELECT string_agg(CASE jsonb_typeof(elem) WHEN 'string' THEN elem #>> '{}' ELSE elem::text END, E'\n') FROM jsonb_array_elements(NEW."richText_req") AS elem), '')::text)))))) ELSE jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', NEW."richText_req"::text::text)))))) END;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION _platform.normalise_every_rich_text()
RETURNS TRIGGER AS $$
BEGIN
  NEW."richText_plain" := CASE WHEN NEW."richText_plain" IS NULL THEN NULL WHEN NEW."richText_plain" ? 'root' THEN NEW."richText_plain" WHEN jsonb_typeof(NEW."richText_plain") = 'string' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', (NEW."richText_plain" #>> '{}')::text)))))) WHEN jsonb_typeof(NEW."richText_plain") = 'array' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', COALESCE((SELECT string_agg(CASE jsonb_typeof(elem) WHEN 'string' THEN elem #>> '{}' ELSE elem::text END, E'\n') FROM jsonb_array_elements(NEW."richText_plain") AS elem), '')::text)))))) ELSE jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', NEW."richText_plain"::text::text)))))) END;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION _platform.set_every_defaulted_slug_def()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW."slug_def" IS NULL OR BTRIM(NEW."slug_def"::TEXT) = '' THEN
      NEW."slug_def" = _platform.slugify(NEW."text_plain"::TEXT);
    END IF;
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW."text_plain" IS DISTINCT FROM OLD."text_plain" THEN
      IF OLD."slug_def" IS NOT DISTINCT FROM _platform.slugify(OLD."text_plain"::TEXT) THEN
        NEW."slug_def" = _platform.slugify(NEW."text_plain"::TEXT);
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION _platform.set_every_localised_slug_loc()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW."slug_loc" IS NULL OR BTRIM(NEW."slug_loc"::TEXT) = '' THEN
      NEW."slug_loc" = _platform.slugify(NEW."text_plain"::TEXT);
    END IF;
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW."text_plain" IS DISTINCT FROM OLD."text_plain" THEN
      IF OLD."slug_loc" IS NOT DISTINCT FROM _platform.slugify(OLD."text_plain"::TEXT) THEN
        NEW."slug_loc" = _platform.slugify(NEW."text_plain"::TEXT);
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION _platform.set_every_read_only_slug_ro()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW."slug_ro" IS NULL OR BTRIM(NEW."slug_ro"::TEXT) = '' THEN
      NEW."slug_ro" = _platform.slugify(NEW."text_plain"::TEXT);
    END IF;
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW."text_plain" IS DISTINCT FROM OLD."text_plain" THEN
      IF OLD."slug_ro" IS NOT DISTINCT FROM _platform.slugify(OLD."text_plain"::TEXT) THEN
        NEW."slug_ro" = _platform.slugify(NEW."text_plain"::TEXT);
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION _platform.set_every_required_slug_req()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW."slug_req" IS NULL OR BTRIM(NEW."slug_req"::TEXT) = '' THEN
      NEW."slug_req" = _platform.slugify(NEW."text_plain"::TEXT);
    END IF;
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW."text_plain" IS DISTINCT FROM OLD."text_plain" THEN
      IF OLD."slug_req" IS NOT DISTINCT FROM _platform.slugify(OLD."text_plain"::TEXT) THEN
        NEW."slug_req" = _platform.slugify(NEW."text_plain"::TEXT);
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION _platform.set_every_slug_plain()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW."slug_plain" IS NULL OR BTRIM(NEW."slug_plain"::TEXT) = '' THEN
      NEW."slug_plain" = _platform.slugify(NEW."text_plain"::TEXT);
    END IF;
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW."text_plain" IS DISTINCT FROM OLD."text_plain" THEN
      IF OLD."slug_plain" IS NOT DISTINCT FROM _platform.slugify(OLD."text_plain"::TEXT) THEN
        NEW."slug_plain" = _platform.slugify(NEW."text_plain"::TEXT);
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

CREATE OR REPLACE TRIGGER "every_rich_text_trigger"
BEFORE INSERT OR UPDATE ON "public"."every"
FOR EACH ROW EXECUTE FUNCTION _platform.normalise_every_rich_text();

CREATE OR REPLACE TRIGGER "every_slug_plain_trigger"
BEFORE INSERT OR UPDATE ON "public"."every"
FOR EACH ROW EXECUTE FUNCTION _platform.set_every_slug_plain();

CREATE OR REPLACE TRIGGER "every_defaulted_rich_text_trigger"
BEFORE INSERT OR UPDATE ON "public"."every_defaulted"
FOR EACH ROW EXECUTE FUNCTION _platform.normalise_every_defaulted_rich_text();

CREATE OR REPLACE TRIGGER "every_defaulted_slug_def_trigger"
BEFORE INSERT OR UPDATE ON "public"."every_defaulted"
FOR EACH ROW EXECUTE FUNCTION _platform.set_every_defaulted_slug_def();

CREATE OR REPLACE TRIGGER "every_localised_rich_text_trigger"
BEFORE INSERT OR UPDATE ON "public"."every_localised"
FOR EACH ROW EXECUTE FUNCTION _platform.normalise_every_localised_rich_text();

CREATE OR REPLACE TRIGGER "every_localised_slug_loc_trigger"
BEFORE INSERT OR UPDATE ON "public"."every_localised"
FOR EACH ROW EXECUTE FUNCTION _platform.set_every_localised_slug_loc();

CREATE OR REPLACE TRIGGER "every_read_only_rich_text_trigger"
BEFORE INSERT OR UPDATE ON "public"."every_read_only"
FOR EACH ROW EXECUTE FUNCTION _platform.normalise_every_read_only_rich_text();

CREATE OR REPLACE TRIGGER "every_read_only_slug_ro_trigger"
BEFORE INSERT OR UPDATE ON "public"."every_read_only"
FOR EACH ROW EXECUTE FUNCTION _platform.set_every_read_only_slug_ro();

CREATE OR REPLACE TRIGGER "every_required_rich_text_trigger"
BEFORE INSERT OR UPDATE ON "public"."every_required"
FOR EACH ROW EXECUTE FUNCTION _platform.normalise_every_required_rich_text();

CREATE OR REPLACE TRIGGER "every_required_slug_req_trigger"
BEFORE INSERT OR UPDATE ON "public"."every_required"
FOR EACH ROW EXECUTE FUNCTION _platform.set_every_required_slug_req();


COMMIT;
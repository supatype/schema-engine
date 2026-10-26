-- ============================================================
-- FORWARD MIGRATION
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

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
    EXECUTE 'DROP VIEW IF EXISTS "draft"."students"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."courses"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."tags"';
  END IF;
END $$;

-- [safe] Create table: students
CREATE TABLE IF NOT EXISTS "public"."students" (
    "id" UUID CONSTRAINT "students_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL CONSTRAINT "students_email_key" UNIQUE CONSTRAINT "students_email_check" CHECK ("email" ~* '^[^@]+@[^@]+\.[^@]+$'),
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- [safe] Create table: courses
CREATE TABLE IF NOT EXISTS "public"."courses" (
    "id" UUID CONSTRAINT "courses_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "title" TEXT NOT NULL,
    "slug" TEXT NOT NULL CONSTRAINT "courses_slug_key" UNIQUE,
    "credits" SMALLINT NOT NULL DEFAULT 3,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- [safe] Create table: tags
CREATE TABLE IF NOT EXISTS "public"."tags" (
    "id" UUID CONSTRAINT "tags_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "name" TEXT NOT NULL CONSTRAINT "tags_name_key" UNIQUE
);

-- [safe] Create junction table: enrollments
CREATE TABLE IF NOT EXISTS "public"."enrollments" (
    "student_id" UUID NOT NULL CONSTRAINT "enrollments_student_id_fkey" REFERENCES "public"."students" ("id") ON DELETE CASCADE,
    "course_id" UUID NOT NULL CONSTRAINT "enrollments_course_id_fkey" REFERENCES "public"."courses" ("id") ON DELETE CASCADE,
    CONSTRAINT "enrollments_pkey" PRIMARY KEY ("student_id", "course_id")
);

-- [safe] Create junction table: course_tags
CREATE TABLE IF NOT EXISTS "public"."course_tags" (
    "tag_id" UUID NOT NULL CONSTRAINT "course_tags_tag_id_fkey" REFERENCES "public"."tags" ("id") ON DELETE CASCADE,
    "course_id" UUID NOT NULL CONSTRAINT "course_tags_course_id_fkey" REFERENCES "public"."courses" ("id") ON DELETE CASCADE,
    CONSTRAINT "course_tags_pkey" PRIMARY KEY ("tag_id", "course_id")
);

-- Row-level affordance functions (PostgREST computed columns)
CREATE OR REPLACE FUNCTION "public"."can_read_students"("students" "public"."students")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "students";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_read_students"("public"."students") FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_read_students"("public"."students") TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_create_students"("students" "public"."students")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "students";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_create_students"("public"."students") FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_create_students"("public"."students") TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_update_students"("students" "public"."students")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "students";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_update_students"("public"."students") FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_update_students"("public"."students") TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_delete_students"("students" "public"."students")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "students";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_delete_students"("public"."students") FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_delete_students"("public"."students") TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_read_courses"("courses" "public"."courses")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "courses";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_read_courses"("public"."courses") FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_read_courses"("public"."courses") TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_create_courses"("courses" "public"."courses")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "courses";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_create_courses"("public"."courses") FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_create_courses"("public"."courses") TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_update_courses"("courses" "public"."courses")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "courses";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_update_courses"("public"."courses") FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_update_courses"("public"."courses") TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_delete_courses"("courses" "public"."courses")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "courses";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_delete_courses"("public"."courses") FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_delete_courses"("public"."courses") TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_read_tags"("tags" "public"."tags")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "tags";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_read_tags"("public"."tags") FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_read_tags"("public"."tags") TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_create_tags"("tags" "public"."tags")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "tags";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_create_tags"("public"."tags") FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_create_tags"("public"."tags") TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_update_tags"("tags" "public"."tags")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "tags";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_update_tags"("public"."tags") FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_update_tags"("public"."tags") TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_delete_tags"("tags" "public"."tags")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "tags";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_delete_tags"("public"."tags") FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_delete_tags"("public"."tags") TO anon, authenticated, service_role;

-- reconciled objects
CREATE SCHEMA IF NOT EXISTS "_platform";
CREATE SCHEMA IF NOT EXISTS "supatype";
CREATE OR REPLACE FUNCTION _platform.set_courses_slug()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW."slug" IS NULL OR BTRIM(NEW."slug"::TEXT) = '' THEN
      NEW."slug" = _platform.slugify(NEW."title"::TEXT);
    END IF;
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW."title" IS DISTINCT FROM OLD."title" THEN
      IF OLD."slug" IS NOT DISTINCT FROM _platform.slugify(OLD."title"::TEXT) THEN
        NEW."slug" = _platform.slugify(NEW."title"::TEXT);
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

CREATE OR REPLACE TRIGGER "courses_slug_trigger"
BEFORE INSERT OR UPDATE ON "public"."courses"
FOR EACH ROW EXECUTE FUNCTION _platform.set_courses_slug();

CREATE OR REPLACE TRIGGER "courses_updated_at_trigger"
BEFORE UPDATE ON "public"."courses"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE OR REPLACE TRIGGER "students_updated_at_trigger"
BEFORE UPDATE ON "public"."students"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

ALTER TABLE "public"."course_tags" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."courses" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."enrollments" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."students" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."tags" ENABLE ROW LEVEL SECURITY;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."courses" FROM anon';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."courses" FROM authenticated';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."students" FROM anon';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."students" FROM authenticated';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."tags" FROM anon';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."tags" FROM authenticated';
  END IF;
END
$grants$;

COMMIT;
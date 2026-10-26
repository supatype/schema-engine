-- ============================================================
-- FORWARD MIGRATION
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

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

-- [safe] Create table: students
CREATE TABLE IF NOT EXISTS "public"."students" (
    "id" UUID CONSTRAINT "students_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL CONSTRAINT "students_email_key" UNIQUE CONSTRAINT "students_email_check" CHECK ("email" ~* '^[^@]+@[^@]+\.[^@]+$'),
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON CONSTRAINT "students_email_key" ON "public"."students" IS 'supatype:managed;kind=unique_constraint;table=students;fields=email;v=1';

COMMENT ON TABLE "public"."students" IS 'supatype:managed;kind=table;table=students;fields=;v=1';

-- [safe] Create table: courses
CREATE TABLE IF NOT EXISTS "public"."courses" (
    "id" UUID CONSTRAINT "courses_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "title" TEXT NOT NULL,
    "slug" TEXT NOT NULL CONSTRAINT "courses_slug_key" UNIQUE,
    "credits" SMALLINT NOT NULL DEFAULT 3,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON CONSTRAINT "courses_slug_key" ON "public"."courses" IS 'supatype:managed;kind=unique_constraint;table=courses;fields=slug;v=1';

COMMENT ON TABLE "public"."courses" IS 'supatype:managed;kind=table;table=courses;fields=;v=1';

-- [safe] Create table: tags
CREATE TABLE IF NOT EXISTS "public"."tags" (
    "id" UUID CONSTRAINT "tags_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "name" TEXT NOT NULL CONSTRAINT "tags_name_key" UNIQUE
);

COMMENT ON CONSTRAINT "tags_name_key" ON "public"."tags" IS 'supatype:managed;kind=unique_constraint;table=tags;fields=name;v=1';

COMMENT ON TABLE "public"."tags" IS 'supatype:managed;kind=table;table=tags;fields=;v=1';

-- [safe] Create junction table: enrollments
CREATE TABLE IF NOT EXISTS "public"."enrollments" (
    "student_id" UUID NOT NULL CONSTRAINT "enrollments_student_id_fkey" REFERENCES "public"."students" ("id") ON DELETE CASCADE,
    "course_id" UUID NOT NULL CONSTRAINT "enrollments_course_id_fkey" REFERENCES "public"."courses" ("id") ON DELETE CASCADE,
    CONSTRAINT "enrollments_pkey" PRIMARY KEY ("student_id", "course_id")
);

COMMENT ON TABLE "public"."enrollments" IS 'supatype:managed;kind=table;table=enrollments;fields=;v=1';

-- [safe] Create junction table: course_tags
CREATE TABLE IF NOT EXISTS "public"."course_tags" (
    "tag_id" UUID NOT NULL CONSTRAINT "course_tags_tag_id_fkey" REFERENCES "public"."tags" ("id") ON DELETE CASCADE,
    "course_id" UUID NOT NULL CONSTRAINT "course_tags_course_id_fkey" REFERENCES "public"."courses" ("id") ON DELETE CASCADE,
    CONSTRAINT "course_tags_pkey" PRIMARY KEY ("tag_id", "course_id")
);

COMMENT ON TABLE "public"."course_tags" IS 'supatype:managed;kind=table;table=course_tags;fields=;v=1';

-- [safe] Enable RLS: students
ALTER TABLE "public"."students" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: courses
ALTER TABLE "public"."courses" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: tags
ALTER TABLE "public"."tags" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: enrollments
ALTER TABLE "public"."enrollments" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: course_tags
ALTER TABLE "public"."course_tags" ENABLE ROW LEVEL SECURITY;

-- Row-level affordance functions (PostgREST computed columns)
CREATE OR REPLACE FUNCTION "public"."can_read_students"("students" "public"."students")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "students";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_students"("students" "public"."students")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "students";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_students"("students" "public"."students")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "students";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_students"("students" "public"."students")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "students";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_courses"("courses" "public"."courses")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "courses";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_courses"("courses" "public"."courses")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "courses";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_courses"("courses" "public"."courses")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "courses";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_courses"("courses" "public"."courses")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "courses";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_tags"("tags" "public"."tags")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "tags";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_tags"("tags" "public"."tags")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "tags";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_tags"("tags" "public"."tags")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "tags";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_tags"("tags" "public"."tags")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "tags";
  $can$;

-- Table privileges derived from access rules (defence in depth)
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE SELECT ON "public"."students" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."students" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."students" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."students" FROM anon';
    EXECUTE 'REVOKE SELECT ON "public"."courses" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."courses" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."courses" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."courses" FROM anon';
    EXECUTE 'REVOKE SELECT ON "public"."tags" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."tags" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."tags" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."tags" FROM anon';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE SELECT ON "public"."students" FROM authenticated';
    EXECUTE 'REVOKE INSERT ON "public"."students" FROM authenticated';
    EXECUTE 'REVOKE UPDATE ON "public"."students" FROM authenticated';
    EXECUTE 'REVOKE DELETE ON "public"."students" FROM authenticated';
    EXECUTE 'REVOKE SELECT ON "public"."courses" FROM authenticated';
    EXECUTE 'REVOKE INSERT ON "public"."courses" FROM authenticated';
    EXECUTE 'REVOKE UPDATE ON "public"."courses" FROM authenticated';
    EXECUTE 'REVOKE DELETE ON "public"."courses" FROM authenticated';
    EXECUTE 'REVOKE SELECT ON "public"."tags" FROM authenticated';
    EXECUTE 'REVOKE INSERT ON "public"."tags" FROM authenticated';
    EXECUTE 'REVOKE UPDATE ON "public"."tags" FROM authenticated';
    EXECUTE 'REVOKE DELETE ON "public"."tags" FROM authenticated';
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

COMMIT;

-- triggers
CREATE SCHEMA IF NOT EXISTS _platform;
GRANT USAGE ON SCHEMA _platform TO PUBLIC;


CREATE OR REPLACE FUNCTION _platform.set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;


CREATE EXTENSION IF NOT EXISTS "unaccent";

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

CREATE OR REPLACE TRIGGER "students_updated_at_trigger"
BEFORE UPDATE ON "public"."students"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE OR REPLACE TRIGGER "courses_updated_at_trigger"
BEFORE UPDATE ON "public"."courses"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

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

CREATE OR REPLACE TRIGGER "courses_slug_trigger"
BEFORE INSERT OR UPDATE ON "public"."courses"
FOR EACH ROW EXECUTE FUNCTION _platform.set_courses_slug();

GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA _platform TO PUBLIC;

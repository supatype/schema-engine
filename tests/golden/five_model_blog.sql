-- ============================================================
-- FORWARD MIGRATION
-- ============================================================

DO $extensions_schema$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'extensions') THEN
    CREATE SCHEMA extensions;
  END IF;
END
$extensions_schema$;
DO $extensions_schema_usage$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'GRANT USAGE ON SCHEMA extensions TO anon';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'GRANT USAGE ON SCHEMA extensions TO authenticated';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
    EXECUTE 'GRANT USAGE ON SCHEMA extensions TO service_role';
  END IF;
END
$extensions_schema_usage$;

CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA extensions;

CREATE EXTENSION IF NOT EXISTS "unaccent" WITH SCHEMA extensions;

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

SELECT pg_catalog.set_config('search_path', pg_catalog.current_setting('search_path') || ', extensions, public', true)
  WHERE NOT ARRAY['extensions', 'public']::name[] <@ pg_catalog.current_schemas(false);

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
    EXECUTE 'DROP VIEW IF EXISTS "draft"."users"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."categories"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."posts"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."comments"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."tags"';
  END IF;
END $$;

-- [safe] Create table: users
CREATE TABLE IF NOT EXISTS "public"."users" (
    "id" UUID CONSTRAINT "users_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "email" TEXT NOT NULL CONSTRAINT "users_email_key" UNIQUE CONSTRAINT "users_email_check" CHECK ("email" ~* '^[^@]+@[^@]+\.[^@]+$'),
    "name" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- [safe] Create table: categories
CREATE TABLE IF NOT EXISTS "public"."categories" (
    "id" UUID CONSTRAINT "categories_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "name" TEXT NOT NULL CONSTRAINT "categories_name_key" UNIQUE,
    "slug" TEXT NOT NULL CONSTRAINT "categories_slug_key" UNIQUE,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- [safe] Create table: posts
CREATE TABLE IF NOT EXISTS "public"."posts" (
    "id" UUID CONSTRAINT "posts_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "title" TEXT NOT NULL,
    "slug" TEXT NOT NULL CONSTRAINT "posts_slug_key" UNIQUE,
    "content" JSONB NOT NULL,
    "author_id" UUID,
    "category_id" UUID,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS "posts_author_id_idx" ON "public"."posts" USING btree ("author_id");

-- [safe] Create table: comments
CREATE TABLE IF NOT EXISTS "public"."comments" (
    "id" UUID CONSTRAINT "comments_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "body" TEXT NOT NULL,
    "post_id" UUID,
    "author_id" UUID,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- [safe] Create table: tags
CREATE TABLE IF NOT EXISTS "public"."tags" (
    "id" UUID CONSTRAINT "tags_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "name" TEXT NOT NULL CONSTRAINT "tags_name_key" UNIQUE
);

-- Row-level affordance functions (PostgREST computed columns)
CREATE OR REPLACE FUNCTION "public"."can_read_users"("users" "public"."users", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "users";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_read_users"("public"."users", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_read_users"("public"."users", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_create_users"("users" "public"."users", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "users";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_create_users"("public"."users", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_create_users"("public"."users", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_update_users"("users" "public"."users", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "users";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_update_users"("public"."users", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_update_users"("public"."users", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_delete_users"("users" "public"."users", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "users";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_delete_users"("public"."users", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_delete_users"("public"."users", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_read_categories"("categories" "public"."categories", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "categories";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_read_categories"("public"."categories", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_read_categories"("public"."categories", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_create_categories"("categories" "public"."categories", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "categories";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_create_categories"("public"."categories", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_create_categories"("public"."categories", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_update_categories"("categories" "public"."categories", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "categories";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_update_categories"("public"."categories", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_update_categories"("public"."categories", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_delete_categories"("categories" "public"."categories", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "categories";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_delete_categories"("public"."categories", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_delete_categories"("public"."categories", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_read_posts"("posts" "public"."posts", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "posts";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_read_posts"("public"."posts", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_read_posts"("public"."posts", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_create_posts"("posts" "public"."posts", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "posts";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_create_posts"("public"."posts", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_create_posts"("public"."posts", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_update_posts"("posts" "public"."posts", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "posts";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_update_posts"("public"."posts", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_update_posts"("public"."posts", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_delete_posts"("posts" "public"."posts", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "posts";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_delete_posts"("public"."posts", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_delete_posts"("public"."posts", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_read_comments"("comments" "public"."comments", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "comments";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_read_comments"("public"."comments", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_read_comments"("public"."comments", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_create_comments"("comments" "public"."comments", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "comments";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_create_comments"("public"."comments", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_create_comments"("public"."comments", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_update_comments"("comments" "public"."comments", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "comments";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_update_comments"("public"."comments", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_update_comments"("public"."comments", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_delete_comments"("comments" "public"."comments", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "comments";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_delete_comments"("public"."comments", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_delete_comments"("public"."comments", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_read_tags"("tags" "public"."tags", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "tags";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_read_tags"("public"."tags", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_read_tags"("public"."tags", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_create_tags"("tags" "public"."tags", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "tags";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_create_tags"("public"."tags", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_create_tags"("public"."tags", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_update_tags"("tags" "public"."tags", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "tags";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_update_tags"("public"."tags", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_update_tags"("public"."tags", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_delete_tags"("tags" "public"."tags", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "tags";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_delete_tags"("public"."tags", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_delete_tags"("public"."tags", boolean) TO anon, authenticated, service_role;

-- reconciled objects
CREATE SCHEMA IF NOT EXISTS "_platform";
CREATE SCHEMA IF NOT EXISTS "supatype";
ALTER TABLE "public"."comments" ADD CONSTRAINT "comments_author_id_fkey" FOREIGN KEY ("author_id") REFERENCES "public"."users" ("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "public"."comments" ADD CONSTRAINT "comments_post_id_fkey" FOREIGN KEY ("post_id") REFERENCES "public"."posts" ("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "public"."posts" ADD CONSTRAINT "posts_author_id_fkey" FOREIGN KEY ("author_id") REFERENCES "public"."users" ("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "public"."posts" ADD CONSTRAINT "posts_category_id_fkey" FOREIGN KEY ("category_id") REFERENCES "public"."categories" ("id") ON DELETE SET NULL ON UPDATE CASCADE;
CREATE OR REPLACE FUNCTION _platform.normalise_posts_rich_text()
RETURNS TRIGGER AS $$
BEGIN
  NEW."content" := CASE WHEN NEW."content" IS NULL THEN NULL WHEN NEW."content" ? 'root' THEN NEW."content" WHEN jsonb_typeof(NEW."content") = 'string' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', (NEW."content" #>> '{}')::text)))))) WHEN jsonb_typeof(NEW."content") = 'array' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', COALESCE((SELECT string_agg(CASE jsonb_typeof(elem) WHEN 'string' THEN elem #>> '{}' ELSE elem::text END, E'\n') FROM jsonb_array_elements(NEW."content") AS elem), '')::text)))))) ELSE jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', NEW."content"::text::text)))))) END;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION _platform.set_categories_slug()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW."slug" IS NULL OR BTRIM(NEW."slug"::TEXT) = '' THEN
      NEW."slug" = _platform.slugify(NEW."name"::TEXT);
    END IF;
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW."name" IS DISTINCT FROM OLD."name" THEN
      IF OLD."slug" IS NOT DISTINCT FROM _platform.slugify(OLD."name"::TEXT) THEN
        NEW."slug" = _platform.slugify(NEW."name"::TEXT);
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION _platform.set_posts_slug()
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
$$ LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, extensions, public;

CREATE OR REPLACE TRIGGER "categories_slug_trigger"
BEFORE INSERT OR UPDATE ON "public"."categories"
FOR EACH ROW EXECUTE FUNCTION _platform.set_categories_slug();

CREATE OR REPLACE TRIGGER "categories_updated_at_trigger"
BEFORE UPDATE ON "public"."categories"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE OR REPLACE TRIGGER "comments_updated_at_trigger"
BEFORE UPDATE ON "public"."comments"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE OR REPLACE TRIGGER "posts_rich_text_trigger"
BEFORE INSERT OR UPDATE ON "public"."posts"
FOR EACH ROW EXECUTE FUNCTION _platform.normalise_posts_rich_text();

CREATE OR REPLACE TRIGGER "posts_slug_trigger"
BEFORE INSERT OR UPDATE ON "public"."posts"
FOR EACH ROW EXECUTE FUNCTION _platform.set_posts_slug();

CREATE OR REPLACE TRIGGER "posts_updated_at_trigger"
BEFORE UPDATE ON "public"."posts"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE OR REPLACE TRIGGER "users_updated_at_trigger"
BEFORE UPDATE ON "public"."users"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

ALTER TABLE "public"."categories" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."comments" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."posts" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."tags" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."users" ENABLE ROW LEVEL SECURITY;
REVOKE ALL PRIVILEGES ON "public"."categories" FROM PUBLIC;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."categories" FROM anon';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."categories" FROM authenticated';
  END IF;
END
$grants$;
REVOKE ALL PRIVILEGES ON "public"."comments" FROM PUBLIC;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."comments" FROM anon';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."comments" FROM authenticated';
  END IF;
END
$grants$;
REVOKE ALL PRIVILEGES ON "public"."posts" FROM PUBLIC;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."posts" FROM anon';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."posts" FROM authenticated';
  END IF;
END
$grants$;
REVOKE ALL PRIVILEGES ON "public"."tags" FROM PUBLIC;
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
REVOKE ALL PRIVILEGES ON "public"."users" FROM PUBLIC;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."users" FROM anon';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."users" FROM authenticated';
  END IF;
END
$grants$;
ALTER TABLE "public"."categories" REPLICA IDENTITY FULL;
ALTER TABLE "public"."comments" REPLICA IDENTITY FULL;
ALTER TABLE "public"."posts" REPLICA IDENTITY FULL;
ALTER TABLE "public"."tags" REPLICA IDENTITY FULL;
ALTER TABLE "public"."users" REPLICA IDENTITY FULL;

COMMIT;
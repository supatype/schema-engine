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
    EXECUTE 'DROP VIEW IF EXISTS "draft"."authors"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."articles"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."tags"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."articles"';
  END IF;
END $$;

-- [safe] Create table: authors
CREATE TABLE IF NOT EXISTS "public"."authors" (
    "id" UUID CONSTRAINT "authors_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL CONSTRAINT "authors_email_key" UNIQUE CONSTRAINT "authors_email_check" CHECK ("email" ~* '^[^@]+@[^@]+\.[^@]+$'),
    "bio" TEXT,
    "avatar" JSONB,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- [safe] Create table: articles
CREATE TABLE IF NOT EXISTS "public"."articles" (
    "id" UUID CONSTRAINT "articles_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "title" TEXT NOT NULL,
    "slug" TEXT NOT NULL CONSTRAINT "articles_slug_key" UNIQUE,
    "body" JSONB NOT NULL,
    "excerpt" TEXT,
    "author_id" UUID,
    "searchVector" TSVECTOR,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "deleted_at" TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS "articles_search_vector_idx" ON "public"."articles" USING gin ("search_vector");

CREATE INDEX IF NOT EXISTS "articles_author_id_idx" ON "public"."articles" USING btree ("author_id");

CREATE INDEX IF NOT EXISTS "articles_deleted_at_idx" ON "public"."articles" USING btree ("deleted_at");

-- [safe] Create table: tags
CREATE TABLE IF NOT EXISTS "public"."tags" (
    "id" UUID CONSTRAINT "tags_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "name" TEXT NOT NULL CONSTRAINT "tags_name_key" UNIQUE,
    "slug" TEXT NOT NULL CONSTRAINT "tags_slug_key" UNIQUE
);

-- [safe] Create table: articles
CREATE TABLE IF NOT EXISTS "public"."articles" (
    "id" UUID CONSTRAINT "articles_pkey" PRIMARY KEY DEFAULT gen_random_uuid()
);

-- [safe] Create junction table: article_tags
CREATE TABLE IF NOT EXISTS "public"."article_tags" (
    "article_tag_id" UUID NOT NULL CONSTRAINT "article_tags_article_tag_id_fkey" REFERENCES "public"."articles" ("id") ON DELETE CASCADE,
    "tag_id" UUID NOT NULL CONSTRAINT "article_tags_tag_id_fkey" REFERENCES "public"."tags" ("id") ON DELETE CASCADE,
    CONSTRAINT "article_tags_pkey" PRIMARY KEY ("article_tag_id", "tag_id")
);

-- Row-level affordance functions (PostgREST computed columns)
CREATE OR REPLACE FUNCTION "public"."can_read_authors"("authors" "public"."authors", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "authors";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_read_authors"("public"."authors", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_read_authors"("public"."authors", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_create_authors"("authors" "public"."authors", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "authors";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_create_authors"("public"."authors", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_create_authors"("public"."authors", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_update_authors"("authors" "public"."authors", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "authors";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_update_authors"("public"."authors", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_update_authors"("public"."authors", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_delete_authors"("authors" "public"."authors", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "authors";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_delete_authors"("public"."authors", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_delete_authors"("public"."authors", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_read_articles"("articles" "public"."articles", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT TRUE
      FROM (SELECT ($1).*) AS "articles";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_read_articles"("public"."articles", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_read_articles"("public"."articles", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_create_articles"("articles" "public"."articles", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT _supatype.jwt_role()) = ANY(ARRAY['editor', 'admin'])
      FROM (SELECT ($1).*) AS "articles";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_create_articles"("public"."articles", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_create_articles"("public"."articles", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_update_articles"("articles" "public"."articles", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT _supatype.jwt_role()) = ANY(ARRAY['editor', 'admin'])
      FROM (SELECT ($1).*) AS "articles";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_update_articles"("public"."articles", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_update_articles"("public"."articles", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_delete_articles"("articles" "public"."articles", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT _supatype.jwt_role()) = 'admin'
      FROM (SELECT ($1).*) AS "articles";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_delete_articles"("public"."articles", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_delete_articles"("public"."articles", boolean) TO anon, authenticated, service_role;

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

CREATE OR REPLACE FUNCTION "public"."can_read_articles"("articles" "public"."articles", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "articles";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_read_articles"("public"."articles", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_read_articles"("public"."articles", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_create_articles"("articles" "public"."articles", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "articles";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_create_articles"("public"."articles", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_create_articles"("public"."articles", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_update_articles"("articles" "public"."articles", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "articles";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_update_articles"("public"."articles", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_update_articles"("public"."articles", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_delete_articles"("articles" "public"."articles", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "articles";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_delete_articles"("public"."articles", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_delete_articles"("public"."articles", boolean) TO anon, authenticated, service_role;

-- reconciled objects
CREATE SCHEMA IF NOT EXISTS "_platform";
CREATE SCHEMA IF NOT EXISTS "supatype";
ALTER TABLE "public"."articles" ADD CONSTRAINT "articles_author_id_fkey" FOREIGN KEY ("author_id") REFERENCES "public"."authors" ("id") ON DELETE RESTRICT ON UPDATE CASCADE;
CREATE OR REPLACE FUNCTION _platform.normalise_articles_rich_text()
RETURNS TRIGGER AS $$
BEGIN
  NEW."body" := CASE WHEN NEW."body" IS NULL THEN NULL WHEN NEW."body" ? 'root' THEN NEW."body" WHEN jsonb_typeof(NEW."body") = 'string' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', (NEW."body" #>> '{}')::text)))))) WHEN jsonb_typeof(NEW."body") = 'array' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', COALESCE((SELECT string_agg(CASE jsonb_typeof(elem) WHEN 'string' THEN elem #>> '{}' ELSE elem::text END, E'\n') FROM jsonb_array_elements(NEW."body") AS elem), '')::text)))))) ELSE jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', NEW."body"::text::text)))))) END;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION _platform.set_articles_slug()
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

CREATE OR REPLACE FUNCTION _platform.set_tags_slug()
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

CREATE OR REPLACE TRIGGER "articles_rich_text_trigger"
BEFORE INSERT OR UPDATE ON "public"."articles"
FOR EACH ROW EXECUTE FUNCTION _platform.normalise_articles_rich_text();

CREATE OR REPLACE TRIGGER "articles_slug_trigger"
BEFORE INSERT OR UPDATE ON "public"."articles"
FOR EACH ROW EXECUTE FUNCTION _platform.set_articles_slug();

CREATE OR REPLACE TRIGGER "articles_updated_at_trigger"
BEFORE UPDATE ON "public"."articles"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE OR REPLACE TRIGGER "authors_updated_at_trigger"
BEFORE UPDATE ON "public"."authors"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE OR REPLACE TRIGGER "tags_slug_trigger"
BEFORE INSERT OR UPDATE ON "public"."tags"
FOR EACH ROW EXECUTE FUNCTION _platform.set_tags_slug();

CREATE POLICY "article_tags_select" ON "public"."article_tags"
FOR SELECT USING (
    EXISTS (SELECT 1 FROM "public"."articles" WHERE "articles"."id" = "article_tags"."article_tag_id")
    AND EXISTS (SELECT 1 FROM "public"."tags" WHERE "tags"."id" = "article_tags"."tag_id")
  );
CREATE POLICY "articles_delete" ON "public"."articles"
FOR DELETE USING (
    (SELECT _supatype.jwt_role()) = 'admin'
  );
CREATE POLICY "articles_insert" ON "public"."articles"
FOR INSERT WITH CHECK (
    (SELECT _supatype.jwt_role()) = ANY(ARRAY['editor', 'admin'])
  );
CREATE POLICY "articles_select" ON "public"."articles"
FOR SELECT USING (
    TRUE
  );
CREATE POLICY "articles_update" ON "public"."articles"
FOR UPDATE USING (
    (SELECT _supatype.jwt_role()) = ANY(ARRAY['editor', 'admin'])
  ) WITH CHECK (
    (SELECT _supatype.jwt_role()) = ANY(ARRAY['editor', 'admin'])
  );
ALTER TABLE "public"."article_tags" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."articles" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."authors" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."tags" ENABLE ROW LEVEL SECURITY;
REVOKE ALL PRIVILEGES ON "public"."article_tags" FROM PUBLIC;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."article_tags" FROM anon';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."article_tags" FROM authenticated';
  END IF;
END
$grants$;
REVOKE ALL PRIVILEGES ON "public"."articles" FROM PUBLIC;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."articles" FROM anon';
    EXECUTE 'GRANT SELECT ON "public"."articles" TO anon';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."articles" FROM authenticated';
    EXECUTE 'GRANT DELETE, INSERT, SELECT, UPDATE ON "public"."articles" TO authenticated';
  END IF;
END
$grants$;
REVOKE ALL PRIVILEGES ON "public"."authors" FROM PUBLIC;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."authors" FROM anon';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."authors" FROM authenticated';
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
ALTER TABLE "public"."article_tags" REPLICA IDENTITY FULL;
ALTER TABLE "public"."articles" REPLICA IDENTITY FULL;
ALTER TABLE "public"."authors" REPLICA IDENTITY FULL;
ALTER TABLE "public"."tags" REPLICA IDENTITY FULL;

COMMIT;
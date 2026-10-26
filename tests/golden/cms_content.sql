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

COMMENT ON CONSTRAINT "authors_email_key" ON "public"."authors" IS 'supatype:managed;kind=unique_constraint;table=authors;fields=email;v=1';

COMMENT ON TABLE "public"."authors" IS 'supatype:managed;kind=table;table=authors;fields=;v=1';

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

COMMENT ON CONSTRAINT "articles_slug_key" ON "public"."articles" IS 'supatype:managed;kind=unique_constraint;table=articles;fields=slug;v=1';

CREATE INDEX IF NOT EXISTS "articles_search_vector_idx" ON "public"."articles" USING gin ("search_vector");

CREATE INDEX IF NOT EXISTS "articles_author_id_idx" ON "public"."articles" USING btree ("author_id");

CREATE INDEX IF NOT EXISTS "articles_deleted_at_idx" ON "public"."articles" USING btree ("deleted_at");

COMMENT ON TABLE "public"."articles" IS 'supatype:managed;kind=table;table=articles;fields=;v=1';

-- [safe] Create table: tags
CREATE TABLE IF NOT EXISTS "public"."tags" (
    "id" UUID CONSTRAINT "tags_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "name" TEXT NOT NULL CONSTRAINT "tags_name_key" UNIQUE,
    "slug" TEXT NOT NULL CONSTRAINT "tags_slug_key" UNIQUE
);

COMMENT ON CONSTRAINT "tags_name_key" ON "public"."tags" IS 'supatype:managed;kind=unique_constraint;table=tags;fields=name;v=1';

COMMENT ON CONSTRAINT "tags_slug_key" ON "public"."tags" IS 'supatype:managed;kind=unique_constraint;table=tags;fields=slug;v=1';

COMMENT ON TABLE "public"."tags" IS 'supatype:managed;kind=table;table=tags;fields=;v=1';

-- [safe] Create table: articles
CREATE TABLE IF NOT EXISTS "public"."articles" (
    "id" UUID CONSTRAINT "articles_pkey" PRIMARY KEY DEFAULT gen_random_uuid()
);

COMMENT ON TABLE "public"."articles" IS 'supatype:managed;kind=table;table=articles;fields=;v=1';

-- [safe] Create junction table: article_tags
CREATE TABLE IF NOT EXISTS "public"."article_tags" (
    "article_tag_id" UUID NOT NULL CONSTRAINT "article_tags_article_tag_id_fkey" REFERENCES "public"."articles" ("id") ON DELETE CASCADE,
    "tag_id" UUID NOT NULL CONSTRAINT "article_tags_tag_id_fkey" REFERENCES "public"."tags" ("id") ON DELETE CASCADE,
    CONSTRAINT "article_tags_pkey" PRIMARY KEY ("article_tag_id", "tag_id")
);

COMMENT ON TABLE "public"."article_tags" IS 'supatype:managed;kind=table;table=article_tags;fields=;v=1';

-- [safe] Enable RLS: authors
ALTER TABLE "public"."authors" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: articles
ALTER TABLE "public"."articles" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: tags
ALTER TABLE "public"."tags" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: articles
ALTER TABLE "public"."articles" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: article_tags
ALTER TABLE "public"."article_tags" ENABLE ROW LEVEL SECURITY;

-- [safe] Create RLS policy: articles.articles_select
DROP POLICY IF EXISTS "articles_select" ON "public"."articles";
CREATE POLICY "articles_select" ON "public"."articles"
FOR SELECT USING (
    TRUE
  );

COMMENT ON POLICY "articles_select" ON "public"."articles" IS 'supatype:managed;kind=rls_policy;table=articles;fields=select;v=1';


-- [safe] Create RLS policy: articles.articles_insert
DROP POLICY IF EXISTS "articles_insert" ON "public"."articles";
CREATE POLICY "articles_insert" ON "public"."articles"
FOR INSERT WITH CHECK (
    (SELECT auth.role()) = ANY(ARRAY['editor', 'admin'])
  );

COMMENT ON POLICY "articles_insert" ON "public"."articles" IS 'supatype:managed;kind=rls_policy;table=articles;fields=insert;v=1';


-- [safe] Create RLS policy: articles.articles_update
DROP POLICY IF EXISTS "articles_update" ON "public"."articles";
CREATE POLICY "articles_update" ON "public"."articles"
FOR UPDATE USING (
    (SELECT auth.role()) = ANY(ARRAY['editor', 'admin'])
  ) WITH CHECK (
    (SELECT auth.role()) = ANY(ARRAY['editor', 'admin'])
  );

COMMENT ON POLICY "articles_update" ON "public"."articles" IS 'supatype:managed;kind=rls_policy;table=articles;fields=update;v=1';


-- [safe] Create RLS policy: articles.articles_delete
DROP POLICY IF EXISTS "articles_delete" ON "public"."articles";
CREATE POLICY "articles_delete" ON "public"."articles"
FOR DELETE USING (
    (SELECT auth.role()) = 'admin'
  );

COMMENT ON POLICY "articles_delete" ON "public"."articles" IS 'supatype:managed;kind=rls_policy;table=articles;fields=delete;v=1';


-- Row-level affordance functions (PostgREST computed columns)
CREATE OR REPLACE FUNCTION "public"."can_read_authors"("authors" "public"."authors")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "authors";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_authors"("authors" "public"."authors")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "authors";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_authors"("authors" "public"."authors")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "authors";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_authors"("authors" "public"."authors")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "authors";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_articles"("articles" "public"."articles")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT TRUE
      FROM (SELECT ($1).*) AS "articles";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_articles"("articles" "public"."articles")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = ANY(ARRAY['editor', 'admin'])
      FROM (SELECT ($1).*) AS "articles";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_articles"("articles" "public"."articles")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = ANY(ARRAY['editor', 'admin'])
      FROM (SELECT ($1).*) AS "articles";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_articles"("articles" "public"."articles")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'admin'
      FROM (SELECT ($1).*) AS "articles";
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

CREATE OR REPLACE FUNCTION "public"."can_read_articles"("articles" "public"."articles")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "articles";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_articles"("articles" "public"."articles")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "articles";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_articles"("articles" "public"."articles")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "articles";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_articles"("articles" "public"."articles")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "articles";
  $can$;

-- Table privileges derived from access rules (defence in depth)
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE SELECT ON "public"."authors" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."authors" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."authors" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."authors" FROM anon';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE SELECT ON "public"."authors" FROM authenticated';
    EXECUTE 'REVOKE INSERT ON "public"."authors" FROM authenticated';
    EXECUTE 'REVOKE UPDATE ON "public"."authors" FROM authenticated';
    EXECUTE 'REVOKE DELETE ON "public"."authors" FROM authenticated';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'GRANT SELECT ON "public"."articles" TO anon';
    EXECUTE 'REVOKE INSERT ON "public"."articles" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."articles" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."articles" FROM anon';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'GRANT SELECT ON "public"."articles" TO authenticated';
    EXECUTE 'GRANT INSERT ON "public"."articles" TO authenticated';
    EXECUTE 'GRANT UPDATE ON "public"."articles" TO authenticated';
    EXECUTE 'GRANT DELETE ON "public"."articles" TO authenticated';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE SELECT ON "public"."tags" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."tags" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."tags" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."tags" FROM anon';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE SELECT ON "public"."tags" FROM authenticated';
    EXECUTE 'REVOKE INSERT ON "public"."tags" FROM authenticated';
    EXECUTE 'REVOKE UPDATE ON "public"."tags" FROM authenticated';
    EXECUTE 'REVOKE DELETE ON "public"."tags" FROM authenticated';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE SELECT ON "public"."articles" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."articles" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."articles" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."articles" FROM anon';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE SELECT ON "public"."articles" FROM authenticated';
    EXECUTE 'REVOKE INSERT ON "public"."articles" FROM authenticated';
    EXECUTE 'REVOKE UPDATE ON "public"."articles" FROM authenticated';
    EXECUTE 'REVOKE DELETE ON "public"."articles" FROM authenticated';
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
$$ LANGUAGE plpgsql IMMUTABLE;

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


COMMIT;
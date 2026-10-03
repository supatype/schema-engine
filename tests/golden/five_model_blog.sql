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

-- [safe] Create table: users
CREATE TABLE IF NOT EXISTS "public"."users" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "email" TEXT NOT NULL UNIQUE CHECK ("email" ~* '^[^@]+@[^@]+\.[^@]+$'),
    "name" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON CONSTRAINT "users_email_key" ON "public"."users" IS 'supatype:managed;kind=unique_constraint;table=users;fields=email;v=1';

COMMENT ON TABLE "public"."users" IS 'supatype:managed;kind=table;table=users;fields=;v=1';

-- [safe] Create table: categories
CREATE TABLE IF NOT EXISTS "public"."categories" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "name" TEXT NOT NULL UNIQUE,
    "slug" TEXT NOT NULL UNIQUE,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON CONSTRAINT "categories_name_key" ON "public"."categories" IS 'supatype:managed;kind=unique_constraint;table=categories;fields=name;v=1';

COMMENT ON CONSTRAINT "categories_slug_key" ON "public"."categories" IS 'supatype:managed;kind=unique_constraint;table=categories;fields=slug;v=1';

COMMENT ON TABLE "public"."categories" IS 'supatype:managed;kind=table;table=categories;fields=;v=1';

-- [safe] Create table: posts
CREATE TABLE IF NOT EXISTS "public"."posts" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "title" TEXT NOT NULL,
    "slug" TEXT NOT NULL UNIQUE,
    "content" JSONB NOT NULL,
    "author_id" UUID,
    "category_id" UUID,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON CONSTRAINT "posts_slug_key" ON "public"."posts" IS 'supatype:managed;kind=unique_constraint;table=posts;fields=slug;v=1';

DROP INDEX IF EXISTS "public"."posts_author_id_idx";
CREATE INDEX IF NOT EXISTS "posts_author_id_idx" ON "public"."posts" USING btree ("author_id");
COMMENT ON INDEX "public"."posts_author_id_idx" IS 'supatype:managed;kind=index;table=posts;fields=author_id;v=1';

COMMENT ON TABLE "public"."posts" IS 'supatype:managed;kind=table;table=posts;fields=;v=1';

-- [safe] Create table: comments
CREATE TABLE IF NOT EXISTS "public"."comments" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "body" TEXT NOT NULL,
    "post_id" UUID,
    "author_id" UUID,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE "public"."comments" IS 'supatype:managed;kind=table;table=comments;fields=;v=1';

-- [safe] Create table: tags
CREATE TABLE IF NOT EXISTS "public"."tags" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "name" TEXT NOT NULL UNIQUE
);

COMMENT ON CONSTRAINT "tags_name_key" ON "public"."tags" IS 'supatype:managed;kind=unique_constraint;table=tags;fields=name;v=1';

COMMENT ON TABLE "public"."tags" IS 'supatype:managed;kind=table;table=tags;fields=;v=1';

-- [safe] Add FK: posts -> User
ALTER TABLE "public"."posts" ADD CONSTRAINT "posts_author_id_fkey" FOREIGN KEY ("author_id") REFERENCES "public"."users" ("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- [safe] Add FK: posts -> Category
ALTER TABLE "public"."posts" ADD CONSTRAINT "posts_category_id_fkey" FOREIGN KEY ("category_id") REFERENCES "public"."categories" ("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- [safe] Add FK: comments -> Post
ALTER TABLE "public"."comments" ADD CONSTRAINT "comments_post_id_fkey" FOREIGN KEY ("post_id") REFERENCES "public"."posts" ("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- [safe] Add FK: comments -> User
ALTER TABLE "public"."comments" ADD CONSTRAINT "comments_author_id_fkey" FOREIGN KEY ("author_id") REFERENCES "public"."users" ("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- [safe] Add index on: posts(author_id)
DROP INDEX IF EXISTS "public"."posts_author_id_idx";
CREATE INDEX IF NOT EXISTS "posts_author_id_idx" ON "public"."posts" USING btree ("author_id");
COMMENT ON INDEX "public"."posts_author_id_idx" IS 'supatype:managed;kind=index;table=posts;fields=author_id;v=1';

-- [safe] Enable RLS: users
ALTER TABLE "public"."users" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: categories
ALTER TABLE "public"."categories" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: posts
ALTER TABLE "public"."posts" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: comments
ALTER TABLE "public"."comments" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: tags
ALTER TABLE "public"."tags" ENABLE ROW LEVEL SECURITY;

-- Row-level affordance functions (PostgREST computed columns)
CREATE OR REPLACE FUNCTION "public"."can_read_users"("users" "public"."users")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "users";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_users"("users" "public"."users")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "users";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_users"("users" "public"."users")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "users";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_users"("users" "public"."users")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "users";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_categories"("categories" "public"."categories")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "categories";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_categories"("categories" "public"."categories")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "categories";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_categories"("categories" "public"."categories")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "categories";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_categories"("categories" "public"."categories")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "categories";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_posts"("posts" "public"."posts")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "posts";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_posts"("posts" "public"."posts")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "posts";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_posts"("posts" "public"."posts")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "posts";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_posts"("posts" "public"."posts")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "posts";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_comments"("comments" "public"."comments")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "comments";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_comments"("comments" "public"."comments")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "comments";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_comments"("comments" "public"."comments")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "comments";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_comments"("comments" "public"."comments")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "comments";
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
    EXECUTE 'REVOKE SELECT ON "public"."users" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."users" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."users" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."users" FROM anon';
    EXECUTE 'REVOKE SELECT ON "public"."categories" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."categories" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."categories" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."categories" FROM anon';
    EXECUTE 'REVOKE SELECT ON "public"."posts" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."posts" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."posts" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."posts" FROM anon';
    EXECUTE 'REVOKE SELECT ON "public"."comments" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."comments" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."comments" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."comments" FROM anon';
    EXECUTE 'REVOKE SELECT ON "public"."tags" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."tags" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."tags" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."tags" FROM anon';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE SELECT ON "public"."users" FROM authenticated';
    EXECUTE 'REVOKE INSERT ON "public"."users" FROM authenticated';
    EXECUTE 'REVOKE UPDATE ON "public"."users" FROM authenticated';
    EXECUTE 'REVOKE DELETE ON "public"."users" FROM authenticated';
    EXECUTE 'REVOKE SELECT ON "public"."categories" FROM authenticated';
    EXECUTE 'REVOKE INSERT ON "public"."categories" FROM authenticated';
    EXECUTE 'REVOKE UPDATE ON "public"."categories" FROM authenticated';
    EXECUTE 'REVOKE DELETE ON "public"."categories" FROM authenticated';
    EXECUTE 'REVOKE SELECT ON "public"."posts" FROM authenticated';
    EXECUTE 'REVOKE INSERT ON "public"."posts" FROM authenticated';
    EXECUTE 'REVOKE UPDATE ON "public"."posts" FROM authenticated';
    EXECUTE 'REVOKE DELETE ON "public"."posts" FROM authenticated';
    EXECUTE 'REVOKE SELECT ON "public"."comments" FROM authenticated';
    EXECUTE 'REVOKE INSERT ON "public"."comments" FROM authenticated';
    EXECUTE 'REVOKE UPDATE ON "public"."comments" FROM authenticated';
    EXECUTE 'REVOKE DELETE ON "public"."comments" FROM authenticated';
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

CREATE OR REPLACE TRIGGER "users_updated_at_trigger"
BEFORE UPDATE ON "public"."users"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE OR REPLACE TRIGGER "categories_updated_at_trigger"
BEFORE UPDATE ON "public"."categories"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

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

CREATE OR REPLACE TRIGGER "categories_slug_trigger"
BEFORE INSERT OR UPDATE ON "public"."categories"
FOR EACH ROW EXECUTE FUNCTION _platform.set_categories_slug();

CREATE OR REPLACE TRIGGER "posts_updated_at_trigger"
BEFORE UPDATE ON "public"."posts"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

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

CREATE OR REPLACE TRIGGER "posts_slug_trigger"
BEFORE INSERT OR UPDATE ON "public"."posts"
FOR EACH ROW EXECUTE FUNCTION _platform.set_posts_slug();

CREATE OR REPLACE FUNCTION _platform.normalise_posts_rich_text()
RETURNS TRIGGER AS $$
BEGIN
  NEW."content" := CASE WHEN NEW."content" IS NULL THEN NULL WHEN NEW."content" ? 'root' THEN NEW."content" WHEN jsonb_typeof(NEW."content") = 'string' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', (NEW."content" #>> '{}')::text)))))) WHEN jsonb_typeof(NEW."content") = 'array' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', COALESCE((SELECT string_agg(CASE jsonb_typeof(elem) WHEN 'string' THEN elem #>> '{}' ELSE elem::text END, E'\n') FROM jsonb_array_elements(NEW."content") AS elem), '')::text)))))) ELSE jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', NEW."content"::text::text)))))) END;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER "posts_rich_text_trigger"
BEFORE INSERT OR UPDATE ON "public"."posts"
FOR EACH ROW EXECUTE FUNCTION _platform.normalise_posts_rich_text();

CREATE OR REPLACE TRIGGER "comments_updated_at_trigger"
BEFORE UPDATE ON "public"."comments"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA _platform TO PUBLIC;

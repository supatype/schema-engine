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
    EXECUTE 'DROP VIEW IF EXISTS "draft"."article_tag"';
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

-- [safe] Create table: article_tag
CREATE TABLE IF NOT EXISTS "public"."article_tag" (
    "id" UUID CONSTRAINT "article_tag_pkey" PRIMARY KEY DEFAULT gen_random_uuid()
);

-- [safe] Create junction table: article_tags
CREATE TABLE IF NOT EXISTS "public"."article_tags" (
    "article_tag_id" UUID NOT NULL CONSTRAINT "article_tags_article_tag_id_fkey" REFERENCES "public"."article_tag" ("id") ON DELETE CASCADE,
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

CREATE OR REPLACE FUNCTION "public"."can_read_article_tag"("article_tag" "public"."article_tag", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "article_tag";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_read_article_tag"("public"."article_tag", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_read_article_tag"("public"."article_tag", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_create_article_tag"("article_tag" "public"."article_tag", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "article_tag";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_create_article_tag"("public"."article_tag", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_create_article_tag"("public"."article_tag", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_update_article_tag"("article_tag" "public"."article_tag", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "article_tag";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_update_article_tag"("public"."article_tag", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_update_article_tag"("public"."article_tag", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_delete_article_tag"("article_tag" "public"."article_tag", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "article_tag";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_delete_article_tag"("public"."article_tag", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_delete_article_tag"("public"."article_tag", boolean) TO anon, authenticated, service_role;

-- Private realtime channels: access functions, mode, outbox and realtime_send
CREATE TABLE IF NOT EXISTS "_supatype"."realtime_outbox" (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  topic text NOT NULL,
  event text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  sender uuid,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE "_supatype"."realtime_outbox" ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON "_supatype"."realtime_outbox" FROM PUBLIC, anon;
GRANT INSERT, SELECT, DELETE ON "_supatype"."realtime_outbox" TO authenticated;
GRANT ALL ON "_supatype"."realtime_outbox" TO service_role;
CREATE OR REPLACE FUNCTION "_supatype"."realtime_channel_access"(topic text)
  RETURNS TABLE (channel text, pattern text, fits boolean, param_error text, can_join boolean, can_send boolean, can_track boolean) LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = '' AS $rt$
#variable_conflict use_column
BEGIN
  IF pg_catalog.char_length($1) > 255 THEN
    RETURN;
  END IF;

  RETURN;
END;
$rt$;
REVOKE ALL ON FUNCTION "_supatype"."realtime_channel_access"(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "_supatype"."realtime_channel_access"(text) TO anon, authenticated, service_role;
CREATE OR REPLACE FUNCTION "_supatype"."realtime_channel_mode"()
  RETURNS text LANGUAGE sql STABLE SET search_path = '' AS $rt$ SELECT 'open'::text $rt$;
REVOKE ALL ON FUNCTION "_supatype"."realtime_channel_mode"() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "_supatype"."realtime_channel_mode"() TO anon, authenticated, service_role;
CREATE OR REPLACE FUNCTION "_supatype"."realtime_channel_send_checks"()
  RETURNS TABLE (channel text, checks jsonb) LANGUAGE sql STABLE SET search_path = '' AS $rt$
  SELECT NULL::text, NULL::jsonb
  WHERE FALSE
$rt$;
REVOKE ALL ON FUNCTION "_supatype"."realtime_channel_send_checks"() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "_supatype"."realtime_channel_send_checks"() TO anon, authenticated, service_role;
CREATE OR REPLACE FUNCTION "_supatype"."realtime_channel_dependencies"()
  RETURNS TABLE (channel text, table_schema text, table_name text) LANGUAGE sql STABLE SET search_path = '' AS $rt$
  SELECT NULL::text, NULL::text, NULL::text
  WHERE FALSE
$rt$;
REVOKE ALL ON FUNCTION "_supatype"."realtime_channel_dependencies"() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "_supatype"."realtime_channel_dependencies"() TO anon, authenticated, service_role;
CREATE OR REPLACE FUNCTION "_supatype"."realtime_channel_content_ok"(channel text, event text, payload jsonb)
  RETURNS boolean LANGUAGE sql STABLE SET search_path = '' AS $rt$ SELECT TRUE $rt$;
REVOKE ALL ON FUNCTION "_supatype"."realtime_channel_content_ok"(text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "_supatype"."realtime_channel_content_ok"(text, text, jsonb) TO authenticated, service_role;
CREATE OR REPLACE FUNCTION "_supatype"."realtime_send_refusal"(topic text, event text, payload jsonb)
  RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path = '' AS $rt$
  SELECT CASE
      WHEN (current_user = 'service_role' OR COALESCE((SELECT r.rolsuper FROM pg_catalog.pg_roles AS r WHERE r.rolname = current_user), FALSE)) THEN NULL
      WHEN a.channel IS NULL THEN
        CASE WHEN "_supatype".realtime_channel_mode() = 'declared' THEN
          $1 || ' matches no declared channel, and this project refuses broadcast and presence on undeclared channels (realtime.channels is "declared")'
        END
      WHEN NOT a.fits THEN $1 || ' does not fit ' || a.pattern || ': ' || a.param_error
      WHEN a.can_send IS NULL THEN a.channel || ' declares no send rule, so only the service role may broadcast on ' || $1
      WHEN NOT a.can_send THEN 'not allowed to broadcast on ' || $1 || ': the send rule of ' || a.channel || ' denied it'
      WHEN NOT "_supatype".realtime_channel_content_ok(a.channel, $2, $3) THEN
        'not allowed to broadcast ' || $2 || ' on ' || $1 || ': the send rule of ' || a.channel || ' refused the payload'
    END
    FROM (SELECT 1) AS one
    LEFT JOIN "_supatype".realtime_channel_access($1) AS a ON TRUE
  $rt$;
REVOKE ALL ON FUNCTION "_supatype"."realtime_send_refusal"(text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "_supatype"."realtime_send_refusal"(text, text, jsonb) TO authenticated, service_role;
CREATE OR REPLACE FUNCTION "_supatype"."realtime_send"(topic text, event text, payload jsonb DEFAULT '{}'::jsonb)
  RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = '' AS $rt$
DECLARE
  refusal text := "_supatype".realtime_send_refusal(topic, event, payload);
BEGIN
  IF refusal IS NOT NULL THEN
    RAISE EXCEPTION '%', refusal USING ERRCODE = '42501';
  END IF;
  INSERT INTO "_supatype"."realtime_outbox" (topic, event, payload, sender)
    VALUES (topic, event, payload, "_supatype".jwt_uid());
END;
$rt$;
REVOKE ALL ON FUNCTION "_supatype"."realtime_send"(text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "_supatype"."realtime_send"(text, text, jsonb) TO authenticated, service_role;
CREATE OR REPLACE FUNCTION "_supatype"."realtime_outbox_delete_row"()
  RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = '' AS $rt$
BEGIN
  DELETE FROM "_supatype"."realtime_outbox" WHERE id = NEW.id;
  RETURN NULL;
END;
$rt$;
REVOKE ALL ON FUNCTION "_supatype"."realtime_outbox_delete_row"() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "_supatype"."realtime_outbox_delete_row"() TO authenticated, service_role;
DO $rt_policy$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy WHERE polrelid = '"_supatype"."realtime_outbox"'::regclass AND polname = 'realtime_outbox_insert') THEN
    ALTER POLICY "realtime_outbox_insert" ON "_supatype"."realtime_outbox" TO authenticated WITH CHECK ("_supatype".realtime_send_refusal(topic, event, payload) IS NULL AND sender IS NOT DISTINCT FROM (SELECT "_supatype".jwt_uid()));
  ELSE
    CREATE POLICY "realtime_outbox_insert" ON "_supatype"."realtime_outbox" AS PERMISSIVE FOR INSERT TO authenticated WITH CHECK ("_supatype".realtime_send_refusal(topic, event, payload) IS NULL AND sender IS NOT DISTINCT FROM (SELECT "_supatype".jwt_uid()));
  END IF;
END;
$rt_policy$;
DO $rt_policy$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy WHERE polrelid = '"_supatype"."realtime_outbox"'::regclass AND polname = 'realtime_outbox_select') THEN
    ALTER POLICY "realtime_outbox_select" ON "_supatype"."realtime_outbox" TO authenticated USING (sender IS NOT DISTINCT FROM (SELECT "_supatype".jwt_uid()));
  ELSE
    CREATE POLICY "realtime_outbox_select" ON "_supatype"."realtime_outbox" AS PERMISSIVE FOR SELECT TO authenticated USING (sender IS NOT DISTINCT FROM (SELECT "_supatype".jwt_uid()));
  END IF;
END;
$rt_policy$;
DO $rt_policy$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy WHERE polrelid = '"_supatype"."realtime_outbox"'::regclass AND polname = 'realtime_outbox_delete') THEN
    ALTER POLICY "realtime_outbox_delete" ON "_supatype"."realtime_outbox" TO authenticated USING (sender IS NOT DISTINCT FROM (SELECT "_supatype".jwt_uid()));
  ELSE
    CREATE POLICY "realtime_outbox_delete" ON "_supatype"."realtime_outbox" AS PERMISSIVE FOR DELETE TO authenticated USING (sender IS NOT DISTINCT FROM (SELECT "_supatype".jwt_uid()));
  END IF;
END;
$rt_policy$;
DO $rt_policy$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy WHERE polrelid = '"_supatype"."realtime_outbox"'::regclass AND polname = 'realtime_outbox_service') THEN
    ALTER POLICY "realtime_outbox_service" ON "_supatype"."realtime_outbox" TO service_role USING (TRUE);
  ELSE
    CREATE POLICY "realtime_outbox_service" ON "_supatype"."realtime_outbox" AS PERMISSIVE FOR ALL TO service_role USING (TRUE);
  END IF;
END;
$rt_policy$;
DO $rt_trigger$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_trigger
    WHERE tgrelid = '"_supatype"."realtime_outbox"'::regclass AND tgname = 'realtime_outbox_delete_row'
      AND tgfoid = '"_supatype"."realtime_outbox_delete_row"'::regproc AND tgenabled = 'A' AND tgtype = 5
  ) THEN
    CREATE OR REPLACE TRIGGER "realtime_outbox_delete_row" AFTER INSERT ON "_supatype"."realtime_outbox"
      FOR EACH ROW EXECUTE FUNCTION "_supatype"."realtime_outbox_delete_row"();
    ALTER TABLE "_supatype"."realtime_outbox" ENABLE ALWAYS TRIGGER "realtime_outbox_delete_row";
  END IF;
END;
$rt_trigger$;

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
  IF NEW."slug" IS NULL OR BTRIM(NEW."slug"::TEXT) = '' THEN
    NEW."slug" = _platform.slugify(NEW."title"::TEXT);
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
  IF NEW."slug" IS NULL OR BTRIM(NEW."slug"::TEXT) = '' THEN
    NEW."slug" = _platform.slugify(NEW."name"::TEXT);
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

CREATE POLICY "article_tag_studio_read" ON "public"."article_tag"
AS PERMISSIVE FOR SELECT USING (
    (SELECT _supatype.jwt_claim_text('supatype_studio')) IN ('read', 'write')
    AND current_setting('supatype.in_rule', true) IS DISTINCT FROM 'on'
  );
CREATE POLICY "article_tag_studio_write" ON "public"."article_tag"
AS PERMISSIVE FOR ALL USING (
    (SELECT _supatype.jwt_claim_text('supatype_studio')) = 'write'
    AND current_setting('supatype.in_rule', true) IS DISTINCT FROM 'on'
  ) WITH CHECK (
    (SELECT _supatype.jwt_claim_text('supatype_studio')) = 'write'
    AND current_setting('supatype.in_rule', true) IS DISTINCT FROM 'on'
  );
CREATE POLICY "article_tags_select" ON "public"."article_tags"
FOR SELECT USING (
    EXISTS (SELECT 1 FROM "public"."article_tag" WHERE "article_tag"."id" = "article_tags"."article_tag_id")
    AND EXISTS (SELECT 1 FROM "public"."tags" WHERE "tags"."id" = "article_tags"."tag_id")
  );
CREATE POLICY "article_tags_studio_read" ON "public"."article_tags"
AS PERMISSIVE FOR SELECT USING (
    (SELECT _supatype.jwt_claim_text('supatype_studio')) IN ('read', 'write')
    AND current_setting('supatype.in_rule', true) IS DISTINCT FROM 'on'
  );
CREATE POLICY "article_tags_studio_write" ON "public"."article_tags"
AS PERMISSIVE FOR ALL USING (
    (SELECT _supatype.jwt_claim_text('supatype_studio')) = 'write'
    AND current_setting('supatype.in_rule', true) IS DISTINCT FROM 'on'
  ) WITH CHECK (
    (SELECT _supatype.jwt_claim_text('supatype_studio')) = 'write'
    AND current_setting('supatype.in_rule', true) IS DISTINCT FROM 'on'
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
CREATE POLICY "articles_studio_read" ON "public"."articles"
AS PERMISSIVE FOR SELECT USING (
    (SELECT _supatype.jwt_claim_text('supatype_studio')) IN ('read', 'write')
    AND current_setting('supatype.in_rule', true) IS DISTINCT FROM 'on'
  );
CREATE POLICY "articles_studio_write" ON "public"."articles"
AS PERMISSIVE FOR ALL USING (
    (SELECT _supatype.jwt_claim_text('supatype_studio')) = 'write'
    AND current_setting('supatype.in_rule', true) IS DISTINCT FROM 'on'
  ) WITH CHECK (
    (SELECT _supatype.jwt_claim_text('supatype_studio')) = 'write'
    AND current_setting('supatype.in_rule', true) IS DISTINCT FROM 'on'
  );
CREATE POLICY "articles_update" ON "public"."articles"
FOR UPDATE USING (
    (SELECT _supatype.jwt_role()) = ANY(ARRAY['editor', 'admin'])
  ) WITH CHECK (
    (SELECT _supatype.jwt_role()) = ANY(ARRAY['editor', 'admin'])
  );
CREATE POLICY "authors_studio_read" ON "public"."authors"
AS PERMISSIVE FOR SELECT USING (
    (SELECT _supatype.jwt_claim_text('supatype_studio')) IN ('read', 'write')
    AND current_setting('supatype.in_rule', true) IS DISTINCT FROM 'on'
  );
CREATE POLICY "authors_studio_write" ON "public"."authors"
AS PERMISSIVE FOR ALL USING (
    (SELECT _supatype.jwt_claim_text('supatype_studio')) = 'write'
    AND current_setting('supatype.in_rule', true) IS DISTINCT FROM 'on'
  ) WITH CHECK (
    (SELECT _supatype.jwt_claim_text('supatype_studio')) = 'write'
    AND current_setting('supatype.in_rule', true) IS DISTINCT FROM 'on'
  );
CREATE POLICY "tags_studio_read" ON "public"."tags"
AS PERMISSIVE FOR SELECT USING (
    (SELECT _supatype.jwt_claim_text('supatype_studio')) IN ('read', 'write')
    AND current_setting('supatype.in_rule', true) IS DISTINCT FROM 'on'
  );
CREATE POLICY "tags_studio_write" ON "public"."tags"
AS PERMISSIVE FOR ALL USING (
    (SELECT _supatype.jwt_claim_text('supatype_studio')) = 'write'
    AND current_setting('supatype.in_rule', true) IS DISTINCT FROM 'on'
  ) WITH CHECK (
    (SELECT _supatype.jwt_claim_text('supatype_studio')) = 'write'
    AND current_setting('supatype.in_rule', true) IS DISTINCT FROM 'on'
  );
ALTER TABLE "public"."article_tag" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."article_tags" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."articles" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."authors" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."tags" ENABLE ROW LEVEL SECURITY;
REVOKE ALL PRIVILEGES ON "public"."article_tag" FROM PUBLIC;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."article_tag" FROM anon';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."article_tag" FROM authenticated';
  END IF;
END
$grants$;
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
ALTER TABLE "public"."article_tag" REPLICA IDENTITY FULL;
ALTER TABLE "public"."article_tags" REPLICA IDENTITY FULL;
ALTER TABLE "public"."articles" REPLICA IDENTITY FULL;
ALTER TABLE "public"."authors" REPLICA IDENTITY FULL;
ALTER TABLE "public"."tags" REPLICA IDENTITY FULL;

-- GraphQL relation names, as the schema declares them
DO $graphql_names$
DECLARE
  k record;
  wanted text;
BEGIN
  FOR k IN
    SELECT c.conname, c.conrelid::regclass AS rel,
           obj_description(c.oid, 'pg_constraint') AS old, d.directive
    FROM (VALUES
      ('"public"."articles"', 'author_id', '@graphql({"foreign_name":"authorId"})')
    ) AS d(rel, col, directive)
    JOIN pg_constraint c ON c.conrelid = to_regclass(d.rel) AND c.contype = 'f'
    JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attname = d.col
     AND c.conkey = ARRAY[a.attnum]
  LOOP
    SELECT concat_ws(E'\n', string_agg(l.line, E'\n' ORDER BY l.n), k.directive) INTO wanted
      FROM regexp_split_to_table(k.old, E'\n') WITH ORDINALITY AS l(line, n)
     WHERE l.line NOT LIKE '@graphql(%';
    IF wanted IS DISTINCT FROM k.old THEN
      EXECUTE format('COMMENT ON CONSTRAINT %I ON %s IS %L', k.conname, k.rel, wanted);
    END IF;
  END LOOP;
END
$graphql_names$;

COMMIT;
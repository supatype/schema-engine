-- ============================================================
-- FORWARD MIGRATION
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE EXTENSION IF NOT EXISTS "vector";

CREATE EXTENSION IF NOT EXISTS "postgis";

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
    EXECUTE 'DROP VIEW IF EXISTS "draft"."page"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."speaker"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."talk"';
  END IF;
END $$;

-- [safe] Create table: page
CREATE TABLE IF NOT EXISTS "public"."page" (
    "id" UUID CONSTRAINT "page_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "title" JSONB NOT NULL,
    "slug" TEXT NOT NULL CONSTRAINT "page_slug_key" UNIQUE,
    "summary" TEXT CONSTRAINT "page_summary_bounds" CHECK (char_length("summary") <= 200),
    "body" JSONB NOT NULL CONSTRAINT "page_body_bounds" CHECK (jsonb_typeof("body") = 'array' AND jsonb_array_length("body") <= 20),
    "published_at" TIMESTAMPTZ,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON CONSTRAINT "page_slug_key" ON "public"."page" IS 'supatype:managed;kind=unique_constraint;table=page;fields=slug;v=1';

COMMENT ON CONSTRAINT "page_summary_bounds" ON "public"."page" IS 'supatype:managed;kind=check;table=page;fields=summary;v=1;bounds=8d6775ae9759124d';

COMMENT ON CONSTRAINT "page_body_bounds" ON "public"."page" IS 'supatype:managed;kind=check;table=page;fields=body;v=1;bounds=8867b90b357fc427';

DROP INDEX IF EXISTS "public"."page_body_gin_idx";
CREATE INDEX IF NOT EXISTS "page_body_gin_idx" ON "public"."page" USING gin ("body");
COMMENT ON INDEX "public"."page_body_gin_idx" IS 'supatype:managed;kind=index;table=page;fields=body;v=1';

COMMENT ON TABLE "public"."page" IS 'supatype:managed;kind=table;table=page;fields=;v=1';

-- [safe] Create table: speaker
CREATE TABLE IF NOT EXISTS "public"."speaker" (
    "id" UUID CONSTRAINT "speaker_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL CONSTRAINT "speaker_slug_key" UNIQUE,
    "bio" JSONB,
    "headshot" JSONB,
    "links" JSONB,
    "email" TEXT CONSTRAINT "speaker_email_check" CHECK ("email" ~* '^[^@]+@[^@]+\.[^@]+$'),
    "published_at" TIMESTAMPTZ,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON CONSTRAINT "speaker_slug_key" ON "public"."speaker" IS 'supatype:managed;kind=unique_constraint;table=speaker;fields=slug;v=1';

COMMENT ON TABLE "public"."speaker" IS 'supatype:managed;kind=table;table=speaker;fields=;v=1';

-- [safe] Create table: room
CREATE TABLE IF NOT EXISTS "public"."room" (
    "id" UUID CONSTRAINT "room_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "name" TEXT NOT NULL,
    "capacity" INTEGER NOT NULL CONSTRAINT "room_capacity_bounds" CHECK (("capacity" >= 10) AND ("capacity" <= 2000)),
    "location" GEOGRAPHY(POINT, 4326),
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON CONSTRAINT "room_capacity_bounds" ON "public"."room" IS 'supatype:managed;kind=check;table=room;fields=capacity;v=1;bounds=3cc86cef79bee327';

COMMENT ON TABLE "public"."room" IS 'supatype:managed;kind=table;table=room;fields=;v=1';

-- [safe] Create table: talk
CREATE TABLE IF NOT EXISTS "public"."talk" (
    "id" UUID CONSTRAINT "talk_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "title" TEXT NOT NULL,
    "slug" TEXT NOT NULL CONSTRAINT "talk_slug_key" UNIQUE,
    "abstract" JSONB,
    "speaker_id" UUID,
    "room_id" UUID,
    "day" DATE NOT NULL,
    "starts_at" TIMESTAMPTZ NOT NULL,
    "ends_at" TIMESTAMPTZ NOT NULL,
    "length" JSONB NOT NULL,
    "embedding" vector(384),
    "published_at" TIMESTAMPTZ,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON CONSTRAINT "talk_slug_key" ON "public"."talk" IS 'supatype:managed;kind=unique_constraint;table=talk;fields=slug;v=1';

ALTER TABLE "public"."talk" ADD CONSTRAINT "talk_check_1" CHECK ("starts_at" <= "ends_at");

COMMENT ON CONSTRAINT "talk_check_1" ON "public"."talk" IS 'supatype:managed;kind=check;table=talk;fields=starts_at,ends_at;v=1;bounds=6c5aa357a67eaba5';

DROP INDEX IF EXISTS "public"."talk_day_starts_at_idx";
CREATE INDEX IF NOT EXISTS "talk_day_starts_at_idx" ON "public"."talk" USING btree ("day", "starts_at");
COMMENT ON INDEX "public"."talk_day_starts_at_idx" IS 'supatype:managed;kind=index;table=talk;fields=day,starts_at;v=1';

DROP INDEX IF EXISTS "public"."talk_starts_at_idx";
CREATE INDEX IF NOT EXISTS "talk_starts_at_idx" ON "public"."talk" USING btree ("starts_at");
COMMENT ON INDEX "public"."talk_starts_at_idx" IS 'supatype:managed;kind=index;table=talk;fields=starts_at;v=1';

COMMENT ON TABLE "public"."talk" IS 'supatype:managed;kind=table;table=talk;fields=;v=1';

-- [safe] Create table: sponsor
CREATE TABLE IF NOT EXISTS "public"."sponsor" (
    "id" UUID CONSTRAINT "sponsor_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "name" TEXT NOT NULL CONSTRAINT "sponsor_name_key" UNIQUE,
    "tier" TEXT NOT NULL CONSTRAINT "sponsor_tier_check" CHECK ("tier" IN ('platinum', 'gold', 'community')),
    "brandColor" TEXT,
    "logo" JSONB,
    "website" TEXT CONSTRAINT "sponsor_website_check" CHECK ("website" ~* '^https?://'),
    "blurb" JSONB,
    "contactPhone" TEXT,
    "published_at" TIMESTAMPTZ,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON CONSTRAINT "sponsor_name_key" ON "public"."sponsor" IS 'supatype:managed;kind=unique_constraint;table=sponsor;fields=name;v=1';

COMMENT ON TABLE "public"."sponsor" IS 'supatype:managed;kind=table;table=sponsor;fields=;v=1';

-- [safe] Create table: attendee
CREATE TABLE IF NOT EXISTS "public"."attendee" (
    "id" UUID CONSTRAINT "attendee_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "displayName" TEXT NOT NULL CONSTRAINT "attendee_displayName_bounds" CHECK (char_length("displayName") <= 80),
    "avatar" JSONB,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON CONSTRAINT "attendee_displayName_bounds" ON "public"."attendee" IS 'supatype:managed;kind=check;table=attendee;fields=displayName;v=1;bounds=6626eb29bcdd3164';

COMMENT ON TABLE "public"."attendee" IS 'supatype:managed;kind=table;table=attendee;fields=;v=1';

-- [safe] Create table: ticket
CREATE TABLE IF NOT EXISTS "public"."ticket" (
    "id" UUID CONSTRAINT "ticket_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "auth_user_id" UUID,
    "attendee_id" UUID,
    "reference" TEXT NOT NULL CONSTRAINT "ticket_reference_key" UNIQUE,
    "price" JSONB NOT NULL,
    "vatRate" NUMERIC(5, 2) NOT NULL,
    "pdf" JSONB,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON CONSTRAINT "ticket_reference_key" ON "public"."ticket" IS 'supatype:managed;kind=unique_constraint;table=ticket;fields=reference;v=1';

COMMENT ON TABLE "public"."ticket" IS 'supatype:managed;kind=table;table=ticket;fields=;v=1';

-- [safe] Create table: chat_message
CREATE TABLE IF NOT EXISTS "public"."chat_message" (
    "id" UUID CONSTRAINT "chat_message_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "room" TEXT NOT NULL,
    "body" TEXT NOT NULL CONSTRAINT "chat_message_body_bounds" CHECK (char_length("body") <= 500),
    "auth_user_id" UUID,
    "authorName" TEXT,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON CONSTRAINT "chat_message_body_bounds" ON "public"."chat_message" IS 'supatype:managed;kind=check;table=chat_message;fields=body;v=1;bounds=f673add49cedc30f';

ALTER TABLE "public"."chat_message" ADD CONSTRAINT "chat_message_check_1" CHECK (char_length("body") >= 2);

COMMENT ON CONSTRAINT "chat_message_check_1" ON "public"."chat_message" IS 'supatype:managed;kind=check;table=chat_message;fields=body;v=1;bounds=f3a60a89afcd22bb';

DROP INDEX IF EXISTS "public"."chat_message_room_idx";
CREATE INDEX IF NOT EXISTS "chat_message_room_idx" ON "public"."chat_message" USING btree ("room");
COMMENT ON INDEX "public"."chat_message_room_idx" IS 'supatype:managed;kind=index;table=chat_message;fields=room;v=1';

COMMENT ON TABLE "public"."chat_message" IS 'supatype:managed;kind=table;table=chat_message;fields=;v=1';

-- [safe] Create table: _global_site_settings
CREATE TABLE IF NOT EXISTS "public"."_global_site_settings" (
    "id" UUID CONSTRAINT "_global_site_settings_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "conferenceName" TEXT NOT NULL,
    "tagline" JSONB,
    "venue" GEOGRAPHY(POINT, 4326),
    "supportEmail" TEXT NOT NULL CONSTRAINT "_global_site_settings_supportEmail_check" CHECK ("supportEmail" ~* '^[^@]+@[^@]+\.[^@]+$'),
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS "_global_site_settings_singleton_idx" ON "public"."_global_site_settings" ((TRUE));

COMMENT ON INDEX "public"."_global_site_settings_singleton_idx" IS 'supatype:managed;kind=unique_index;table=_global_site_settings;fields=;v=1';

COMMENT ON TABLE "public"."_global_site_settings" IS 'supatype:managed;kind=table;table=_global_site_settings;fields=;v=1';

-- [safe] Create versions table: page_versions
CREATE TABLE IF NOT EXISTS "public"."page_versions" (
    "id" UUID CONSTRAINT "page_versions_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "record_id" UUID NOT NULL CONSTRAINT "page_versions_record_id_fkey" REFERENCES "public"."page" ("id") ON DELETE CASCADE,
    "version" INTEGER NOT NULL,
    "status" TEXT NOT NULL CONSTRAINT "page_versions_status_check" CHECK ("status" IN ('draft', 'published')),
    "data" JSONB NOT NULL,
    -- When each locale is due to go live, if it has been scheduled.
    -- Per locale rather than one `publish_at` for the row, because publishing is per locale:
    -- a single column could not say: English at nine, the translation when it lands.
    "scheduled_locales" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
    "created_by" UUID,
    -- Which locales this version is live for, and when each went live.
    -- One key per published locale, or the single key `*` for a model with no localized
    -- column. Publication state lives here rather than on the model's row because the
    -- column differ drops columns the schema does not declare, and rather than in a table of
    -- its own because this row already carries the policies and the guard that protect it.
    "published_locales" JSONB NOT NULL DEFAULT '{}',
    CONSTRAINT "page_versions_record_id_version_key" UNIQUE ("record_id", "version")
);

COMMENT ON TABLE "public"."page_versions" IS 'supatype:managed;kind=table;table=page_versions;fields=;v=1';

CREATE INDEX IF NOT EXISTS "page_versions_record_idx" ON "public"."page_versions" ("record_id", "version" DESC);

-- [safe] Create versions table: speaker_versions
CREATE TABLE IF NOT EXISTS "public"."speaker_versions" (
    "id" UUID CONSTRAINT "speaker_versions_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "record_id" UUID NOT NULL CONSTRAINT "speaker_versions_record_id_fkey" REFERENCES "public"."speaker" ("id") ON DELETE CASCADE,
    "version" INTEGER NOT NULL,
    "status" TEXT NOT NULL CONSTRAINT "speaker_versions_status_check" CHECK ("status" IN ('draft', 'published')),
    "data" JSONB NOT NULL,
    -- When each locale is due to go live, if it has been scheduled.
    -- Per locale rather than one `publish_at` for the row, because publishing is per locale:
    -- a single column could not say: English at nine, the translation when it lands.
    "scheduled_locales" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
    "created_by" UUID,
    -- Which locales this version is live for, and when each went live.
    -- One key per published locale, or the single key `*` for a model with no localized
    -- column. Publication state lives here rather than on the model's row because the
    -- column differ drops columns the schema does not declare, and rather than in a table of
    -- its own because this row already carries the policies and the guard that protect it.
    "published_locales" JSONB NOT NULL DEFAULT '{}',
    CONSTRAINT "speaker_versions_record_id_version_key" UNIQUE ("record_id", "version")
);

COMMENT ON TABLE "public"."speaker_versions" IS 'supatype:managed;kind=table;table=speaker_versions;fields=;v=1';

CREATE INDEX IF NOT EXISTS "speaker_versions_record_idx" ON "public"."speaker_versions" ("record_id", "version" DESC);

-- [safe] Create versions table: talk_versions
CREATE TABLE IF NOT EXISTS "public"."talk_versions" (
    "id" UUID CONSTRAINT "talk_versions_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "record_id" UUID NOT NULL CONSTRAINT "talk_versions_record_id_fkey" REFERENCES "public"."talk" ("id") ON DELETE CASCADE,
    "version" INTEGER NOT NULL,
    "status" TEXT NOT NULL CONSTRAINT "talk_versions_status_check" CHECK ("status" IN ('draft', 'published')),
    "data" JSONB NOT NULL,
    -- When each locale is due to go live, if it has been scheduled.
    -- Per locale rather than one `publish_at` for the row, because publishing is per locale:
    -- a single column could not say: English at nine, the translation when it lands.
    "scheduled_locales" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
    "created_by" UUID,
    -- Which locales this version is live for, and when each went live.
    -- One key per published locale, or the single key `*` for a model with no localized
    -- column. Publication state lives here rather than on the model's row because the
    -- column differ drops columns the schema does not declare, and rather than in a table of
    -- its own because this row already carries the policies and the guard that protect it.
    "published_locales" JSONB NOT NULL DEFAULT '{}',
    CONSTRAINT "talk_versions_record_id_version_key" UNIQUE ("record_id", "version")
);

COMMENT ON TABLE "public"."talk_versions" IS 'supatype:managed;kind=table;table=talk_versions;fields=;v=1';

CREATE INDEX IF NOT EXISTS "talk_versions_record_idx" ON "public"."talk_versions" ("record_id", "version" DESC);

-- [safe] Add FK: talk -> Speaker
ALTER TABLE "public"."talk" ADD CONSTRAINT "talk_speaker_id_fkey" FOREIGN KEY ("speaker_id") REFERENCES "public"."speaker" ("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- [safe] Add FK: talk -> Room
ALTER TABLE "public"."talk" ADD CONSTRAINT "talk_room_id_fkey" FOREIGN KEY ("room_id") REFERENCES "public"."room" ("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- [safe] Add FK: ticket -> supatype:user
ALTER TABLE "public"."ticket" ADD CONSTRAINT "ticket_auth_user_id_fkey" FOREIGN KEY ("auth_user_id") REFERENCES "auth"."users" ("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- [safe] Add FK: ticket -> Attendee
ALTER TABLE "public"."ticket" ADD CONSTRAINT "ticket_attendee_id_fkey" FOREIGN KEY ("attendee_id") REFERENCES "public"."attendee" ("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- [safe] Add FK: chat_message -> supatype:user
ALTER TABLE "public"."chat_message" ADD CONSTRAINT "chat_message_auth_user_id_fkey" FOREIGN KEY ("auth_user_id") REFERENCES "auth"."users" ("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- [safe] Add index on: talk(day, starts_at)
DROP INDEX IF EXISTS "public"."talk_day_starts_at_idx";
CREATE INDEX IF NOT EXISTS "talk_day_starts_at_idx" ON "public"."talk" USING btree ("day", "starts_at");
COMMENT ON INDEX "public"."talk_day_starts_at_idx" IS 'supatype:managed;kind=index;table=talk;fields=day,starts_at;v=1';

-- [safe] Enable RLS: page
ALTER TABLE "public"."page" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: speaker
ALTER TABLE "public"."speaker" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: room
ALTER TABLE "public"."room" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: talk
ALTER TABLE "public"."talk" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: sponsor
ALTER TABLE "public"."sponsor" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: attendee
ALTER TABLE "public"."attendee" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: ticket
ALTER TABLE "public"."ticket" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: chat_message
ALTER TABLE "public"."chat_message" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: _global_site_settings
ALTER TABLE "public"."_global_site_settings" ENABLE ROW LEVEL SECURITY;

-- [safe] Create RLS policy: page.page_select
DROP POLICY IF EXISTS "page_select" ON "public"."page";
CREATE POLICY "page_select" ON "public"."page"
FOR SELECT USING (
    "published_at" <= (SELECT now())
  );

COMMENT ON POLICY "page_select" ON "public"."page" IS 'supatype:managed;kind=rls_policy;table=page;fields=select;v=1';


-- [safe] Create RLS policy: page.page_insert
DROP POLICY IF EXISTS "page_insert" ON "public"."page";
CREATE POLICY "page_insert" ON "public"."page"
FOR INSERT WITH CHECK (
    (SELECT auth.role()) = 'editor'
  );

COMMENT ON POLICY "page_insert" ON "public"."page" IS 'supatype:managed;kind=rls_policy;table=page;fields=insert;v=1';


-- [safe] Create RLS policy: page.page_update
DROP POLICY IF EXISTS "page_update" ON "public"."page";
CREATE POLICY "page_update" ON "public"."page"
FOR UPDATE USING (
    (SELECT auth.role()) = 'editor'
  ) WITH CHECK (
    (SELECT auth.role()) = 'editor'
  );

COMMENT ON POLICY "page_update" ON "public"."page" IS 'supatype:managed;kind=rls_policy;table=page;fields=update;v=1';


-- [safe] Create RLS policy: page.page_delete
DROP POLICY IF EXISTS "page_delete" ON "public"."page";
CREATE POLICY "page_delete" ON "public"."page"
FOR DELETE USING (
    (SELECT auth.role()) = 'editor'
  );

COMMENT ON POLICY "page_delete" ON "public"."page" IS 'supatype:managed;kind=rls_policy;table=page;fields=delete;v=1';


-- [safe] Create RLS policy: speaker.speaker_select
DROP POLICY IF EXISTS "speaker_select" ON "public"."speaker";
CREATE POLICY "speaker_select" ON "public"."speaker"
FOR SELECT USING (
    "published_at" <= (SELECT now())
  );

COMMENT ON POLICY "speaker_select" ON "public"."speaker" IS 'supatype:managed;kind=rls_policy;table=speaker;fields=select;v=1';


-- [safe] Create RLS policy: speaker.speaker_insert
DROP POLICY IF EXISTS "speaker_insert" ON "public"."speaker";
CREATE POLICY "speaker_insert" ON "public"."speaker"
FOR INSERT WITH CHECK (
    (SELECT auth.role()) = 'editor'
  );

COMMENT ON POLICY "speaker_insert" ON "public"."speaker" IS 'supatype:managed;kind=rls_policy;table=speaker;fields=insert;v=1';


-- [safe] Create RLS policy: speaker.speaker_update
DROP POLICY IF EXISTS "speaker_update" ON "public"."speaker";
CREATE POLICY "speaker_update" ON "public"."speaker"
FOR UPDATE USING (
    (SELECT auth.role()) = 'editor'
  ) WITH CHECK (
    (SELECT auth.role()) = 'editor'
  );

COMMENT ON POLICY "speaker_update" ON "public"."speaker" IS 'supatype:managed;kind=rls_policy;table=speaker;fields=update;v=1';


-- [safe] Create RLS policy: speaker.speaker_delete
DROP POLICY IF EXISTS "speaker_delete" ON "public"."speaker";
CREATE POLICY "speaker_delete" ON "public"."speaker"
FOR DELETE USING (
    (SELECT auth.role()) = 'editor'
  );

COMMENT ON POLICY "speaker_delete" ON "public"."speaker" IS 'supatype:managed;kind=rls_policy;table=speaker;fields=delete;v=1';


-- [safe] Create RLS policy: room.room_select
DROP POLICY IF EXISTS "room_select" ON "public"."room";
CREATE POLICY "room_select" ON "public"."room"
FOR SELECT USING (
    TRUE
  );

COMMENT ON POLICY "room_select" ON "public"."room" IS 'supatype:managed;kind=rls_policy;table=room;fields=select;v=1';


-- [safe] Create RLS policy: room.room_insert
DROP POLICY IF EXISTS "room_insert" ON "public"."room";
CREATE POLICY "room_insert" ON "public"."room"
FOR INSERT WITH CHECK (
    (SELECT auth.role()) = 'editor'
  );

COMMENT ON POLICY "room_insert" ON "public"."room" IS 'supatype:managed;kind=rls_policy;table=room;fields=insert;v=1';


-- [safe] Create RLS policy: room.room_update
DROP POLICY IF EXISTS "room_update" ON "public"."room";
CREATE POLICY "room_update" ON "public"."room"
FOR UPDATE USING (
    (SELECT auth.role()) = 'editor'
  ) WITH CHECK (
    (SELECT auth.role()) = 'editor'
  );

COMMENT ON POLICY "room_update" ON "public"."room" IS 'supatype:managed;kind=rls_policy;table=room;fields=update;v=1';


-- [safe] Create RLS policy: room.room_delete
DROP POLICY IF EXISTS "room_delete" ON "public"."room";
CREATE POLICY "room_delete" ON "public"."room"
FOR DELETE USING (
    (SELECT auth.role()) = 'editor'
  );

COMMENT ON POLICY "room_delete" ON "public"."room" IS 'supatype:managed;kind=rls_policy;table=room;fields=delete;v=1';


-- [safe] Create RLS policy: talk.talk_select
DROP POLICY IF EXISTS "talk_select" ON "public"."talk";
CREATE POLICY "talk_select" ON "public"."talk"
FOR SELECT USING (
    "published_at" <= (SELECT now())
  );

COMMENT ON POLICY "talk_select" ON "public"."talk" IS 'supatype:managed;kind=rls_policy;table=talk;fields=select;v=1';


-- [safe] Create RLS policy: talk.talk_insert
DROP POLICY IF EXISTS "talk_insert" ON "public"."talk";
CREATE POLICY "talk_insert" ON "public"."talk"
FOR INSERT WITH CHECK (
    (SELECT auth.role()) = 'editor'
  );

COMMENT ON POLICY "talk_insert" ON "public"."talk" IS 'supatype:managed;kind=rls_policy;table=talk;fields=insert;v=1';


-- [safe] Create RLS policy: talk.talk_update
DROP POLICY IF EXISTS "talk_update" ON "public"."talk";
CREATE POLICY "talk_update" ON "public"."talk"
FOR UPDATE USING (
    (SELECT auth.role()) = 'editor'
  ) WITH CHECK (
    (SELECT auth.role()) = 'editor'
  );

COMMENT ON POLICY "talk_update" ON "public"."talk" IS 'supatype:managed;kind=rls_policy;table=talk;fields=update;v=1';


-- [safe] Create RLS policy: talk.talk_delete
DROP POLICY IF EXISTS "talk_delete" ON "public"."talk";
CREATE POLICY "talk_delete" ON "public"."talk"
FOR DELETE USING (
    (SELECT auth.role()) = 'editor'
  );

COMMENT ON POLICY "talk_delete" ON "public"."talk" IS 'supatype:managed;kind=rls_policy;table=talk;fields=delete;v=1';


-- [safe] Create RLS policy: sponsor.sponsor_select
DROP POLICY IF EXISTS "sponsor_select" ON "public"."sponsor";
CREATE POLICY "sponsor_select" ON "public"."sponsor"
FOR SELECT USING (
    "published_at" <= (SELECT now())
  );

COMMENT ON POLICY "sponsor_select" ON "public"."sponsor" IS 'supatype:managed;kind=rls_policy;table=sponsor;fields=select;v=1';


-- [safe] Create RLS policy: sponsor.sponsor_insert
DROP POLICY IF EXISTS "sponsor_insert" ON "public"."sponsor";
CREATE POLICY "sponsor_insert" ON "public"."sponsor"
FOR INSERT WITH CHECK (
    (SELECT auth.role()) = 'editor'
  );

COMMENT ON POLICY "sponsor_insert" ON "public"."sponsor" IS 'supatype:managed;kind=rls_policy;table=sponsor;fields=insert;v=1';


-- [safe] Create RLS policy: sponsor.sponsor_update
DROP POLICY IF EXISTS "sponsor_update" ON "public"."sponsor";
CREATE POLICY "sponsor_update" ON "public"."sponsor"
FOR UPDATE USING (
    (SELECT auth.role()) = 'editor'
  ) WITH CHECK (
    (SELECT auth.role()) = 'editor'
  );

COMMENT ON POLICY "sponsor_update" ON "public"."sponsor" IS 'supatype:managed;kind=rls_policy;table=sponsor;fields=update;v=1';


-- [safe] Create RLS policy: sponsor.sponsor_delete
DROP POLICY IF EXISTS "sponsor_delete" ON "public"."sponsor";
CREATE POLICY "sponsor_delete" ON "public"."sponsor"
FOR DELETE USING (
    (SELECT auth.role()) = 'editor'
  );

COMMENT ON POLICY "sponsor_delete" ON "public"."sponsor" IS 'supatype:managed;kind=rls_policy;table=sponsor;fields=delete;v=1';


-- [safe] Create RLS policy: attendee.attendee_select
DROP POLICY IF EXISTS "attendee_select" ON "public"."attendee";
CREATE POLICY "attendee_select" ON "public"."attendee"
FOR SELECT USING (
    (SELECT auth.uid()) IS NOT NULL
  );

COMMENT ON POLICY "attendee_select" ON "public"."attendee" IS 'supatype:managed;kind=rls_policy;table=attendee;fields=select;v=1';


-- [safe] Create RLS policy: attendee.attendee_insert
DROP POLICY IF EXISTS "attendee_insert" ON "public"."attendee";
CREATE POLICY "attendee_insert" ON "public"."attendee"
FOR INSERT WITH CHECK (
    (SELECT auth.uid()) IS NOT NULL
  );

COMMENT ON POLICY "attendee_insert" ON "public"."attendee" IS 'supatype:managed;kind=rls_policy;table=attendee;fields=insert;v=1';


-- [safe] Create RLS policy: attendee.attendee_update
DROP POLICY IF EXISTS "attendee_update" ON "public"."attendee";
CREATE POLICY "attendee_update" ON "public"."attendee"
FOR UPDATE USING (
    (SELECT auth.uid()) = "id"
  ) WITH CHECK (
    (SELECT auth.uid()) = "id"
  );

COMMENT ON POLICY "attendee_update" ON "public"."attendee" IS 'supatype:managed;kind=rls_policy;table=attendee;fields=update;v=1';


-- [safe] Create RLS policy: attendee.attendee_delete
DROP POLICY IF EXISTS "attendee_delete" ON "public"."attendee";
CREATE POLICY "attendee_delete" ON "public"."attendee"
FOR DELETE USING (
    (SELECT auth.uid()) = "id"
  );

COMMENT ON POLICY "attendee_delete" ON "public"."attendee" IS 'supatype:managed;kind=rls_policy;table=attendee;fields=delete;v=1';


-- [safe] Create RLS policy: ticket.ticket_select
DROP POLICY IF EXISTS "ticket_select" ON "public"."ticket";
CREATE POLICY "ticket_select" ON "public"."ticket"
FOR SELECT USING (
    (SELECT auth.uid()) = "auth_user_id"
  );

COMMENT ON POLICY "ticket_select" ON "public"."ticket" IS 'supatype:managed;kind=rls_policy;table=ticket;fields=select;v=1';


-- [safe] Create RLS policy: ticket.ticket_insert
DROP POLICY IF EXISTS "ticket_insert" ON "public"."ticket";
CREATE POLICY "ticket_insert" ON "public"."ticket"
FOR INSERT WITH CHECK (
    (SELECT auth.uid()) IS NOT NULL
  );

COMMENT ON POLICY "ticket_insert" ON "public"."ticket" IS 'supatype:managed;kind=rls_policy;table=ticket;fields=insert;v=1';


-- [safe] Create RLS policy: ticket.ticket_update
DROP POLICY IF EXISTS "ticket_update" ON "public"."ticket";
CREATE POLICY "ticket_update" ON "public"."ticket"
FOR UPDATE USING (
    (SELECT auth.uid()) = "auth_user_id"
  ) WITH CHECK (
    (SELECT auth.uid()) = "auth_user_id"
  );

COMMENT ON POLICY "ticket_update" ON "public"."ticket" IS 'supatype:managed;kind=rls_policy;table=ticket;fields=update;v=1';


-- [safe] Create RLS policy: ticket.ticket_delete
DROP POLICY IF EXISTS "ticket_delete" ON "public"."ticket";
CREATE POLICY "ticket_delete" ON "public"."ticket"
FOR DELETE USING (
    (SELECT auth.uid()) = "auth_user_id"
  );

COMMENT ON POLICY "ticket_delete" ON "public"."ticket" IS 'supatype:managed;kind=rls_policy;table=ticket;fields=delete;v=1';


-- [safe] Create RLS policy: chat_message.chat_message_select
DROP POLICY IF EXISTS "chat_message_select" ON "public"."chat_message";
CREATE POLICY "chat_message_select" ON "public"."chat_message"
FOR SELECT USING (
    (SELECT auth.uid()) IS NOT NULL
  );

COMMENT ON POLICY "chat_message_select" ON "public"."chat_message" IS 'supatype:managed;kind=rls_policy;table=chat_message;fields=select;v=1';


-- [safe] Create RLS policy: chat_message.chat_message_insert
DROP POLICY IF EXISTS "chat_message_insert" ON "public"."chat_message";
CREATE POLICY "chat_message_insert" ON "public"."chat_message"
FOR INSERT WITH CHECK (
    (SELECT auth.uid()) IS NOT NULL
  );

COMMENT ON POLICY "chat_message_insert" ON "public"."chat_message" IS 'supatype:managed;kind=rls_policy;table=chat_message;fields=insert;v=1';


-- [safe] Create RLS policy: chat_message.chat_message_update
DROP POLICY IF EXISTS "chat_message_update" ON "public"."chat_message";
CREATE POLICY "chat_message_update" ON "public"."chat_message"
FOR UPDATE USING (
    (SELECT auth.uid()) = "auth_user_id"
  ) WITH CHECK (
    (SELECT auth.uid()) = "auth_user_id"
  );

COMMENT ON POLICY "chat_message_update" ON "public"."chat_message" IS 'supatype:managed;kind=rls_policy;table=chat_message;fields=update;v=1';


-- [safe] Create RLS policy: chat_message.chat_message_delete
DROP POLICY IF EXISTS "chat_message_delete" ON "public"."chat_message";
CREATE POLICY "chat_message_delete" ON "public"."chat_message"
FOR DELETE USING (
    (SELECT auth.uid()) = "auth_user_id"
  );

COMMENT ON POLICY "chat_message_delete" ON "public"."chat_message" IS 'supatype:managed;kind=rls_policy;table=chat_message;fields=delete;v=1';


-- [safe] Create RLS policy: _global_site_settings._global_site_settings_select
DROP POLICY IF EXISTS "_global_site_settings_select" ON "public"."_global_site_settings";
CREATE POLICY "_global_site_settings_select" ON "public"."_global_site_settings"
FOR SELECT USING (
    TRUE
  );

COMMENT ON POLICY "_global_site_settings_select" ON "public"."_global_site_settings" IS 'supatype:managed;kind=rls_policy;table=_global_site_settings;fields=select;v=1';


-- [safe] Create RLS policy: _global_site_settings._global_site_settings_insert
DROP POLICY IF EXISTS "_global_site_settings_insert" ON "public"."_global_site_settings";
CREATE POLICY "_global_site_settings_insert" ON "public"."_global_site_settings"
FOR INSERT WITH CHECK (
    (SELECT auth.role()) = 'editor'
  );

COMMENT ON POLICY "_global_site_settings_insert" ON "public"."_global_site_settings" IS 'supatype:managed;kind=rls_policy;table=_global_site_settings;fields=insert;v=1';


-- [safe] Create RLS policy: _global_site_settings._global_site_settings_update
DROP POLICY IF EXISTS "_global_site_settings_update" ON "public"."_global_site_settings";
CREATE POLICY "_global_site_settings_update" ON "public"."_global_site_settings"
FOR UPDATE USING (
    (SELECT auth.role()) = 'editor'
  ) WITH CHECK (
    (SELECT auth.role()) = 'editor'
  );

COMMENT ON POLICY "_global_site_settings_update" ON "public"."_global_site_settings" IS 'supatype:managed;kind=rls_policy;table=_global_site_settings;fields=update;v=1';


-- [safe] Create RLS policy: _global_site_settings._global_site_settings_delete
DROP POLICY IF EXISTS "_global_site_settings_delete" ON "public"."_global_site_settings";
CREATE POLICY "_global_site_settings_delete" ON "public"."_global_site_settings"
FOR DELETE USING (
    (SELECT auth.role()) = 'editor'
  );

COMMENT ON POLICY "_global_site_settings_delete" ON "public"."_global_site_settings" IS 'supatype:managed;kind=rls_policy;table=_global_site_settings;fields=delete;v=1';


-- Row-level affordance functions (PostgREST computed columns)
CREATE OR REPLACE FUNCTION "public"."can_read_page"("page" "public"."page")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT "published_at" <= (SELECT now())
      FROM (SELECT ($1).*) AS "page";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_page"("page" "public"."page")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'editor'
      FROM (SELECT ($1).*) AS "page";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_page"("page" "public"."page")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'editor'
      FROM (SELECT ($1).*) AS "page";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_page"("page" "public"."page")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'editor'
      FROM (SELECT ($1).*) AS "page";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_speaker"("speaker" "public"."speaker")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT "published_at" <= (SELECT now())
      FROM (SELECT ($1).*) AS "speaker";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_speaker"("speaker" "public"."speaker")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'editor'
      FROM (SELECT ($1).*) AS "speaker";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_speaker"("speaker" "public"."speaker")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'editor'
      FROM (SELECT ($1).*) AS "speaker";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_speaker"("speaker" "public"."speaker")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'editor'
      FROM (SELECT ($1).*) AS "speaker";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_room"("room" "public"."room")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT TRUE
      FROM (SELECT ($1).*) AS "room";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_room"("room" "public"."room")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'editor'
      FROM (SELECT ($1).*) AS "room";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_room"("room" "public"."room")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'editor'
      FROM (SELECT ($1).*) AS "room";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_room"("room" "public"."room")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'editor'
      FROM (SELECT ($1).*) AS "room";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_talk"("talk" "public"."talk")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT "published_at" <= (SELECT now())
      FROM (SELECT ($1).*) AS "talk";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_talk"("talk" "public"."talk")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'editor'
      FROM (SELECT ($1).*) AS "talk";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_talk"("talk" "public"."talk")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'editor'
      FROM (SELECT ($1).*) AS "talk";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_talk"("talk" "public"."talk")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'editor'
      FROM (SELECT ($1).*) AS "talk";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_sponsor"("sponsor" "public"."sponsor")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT "published_at" <= (SELECT now())
      FROM (SELECT ($1).*) AS "sponsor";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_sponsor"("sponsor" "public"."sponsor")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'editor'
      FROM (SELECT ($1).*) AS "sponsor";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_sponsor"("sponsor" "public"."sponsor")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'editor'
      FROM (SELECT ($1).*) AS "sponsor";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_sponsor"("sponsor" "public"."sponsor")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'editor'
      FROM (SELECT ($1).*) AS "sponsor";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_attendee"("attendee" "public"."attendee")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.uid()) IS NOT NULL
      FROM (SELECT ($1).*) AS "attendee";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_attendee"("attendee" "public"."attendee")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.uid()) IS NOT NULL
      FROM (SELECT ($1).*) AS "attendee";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_attendee"("attendee" "public"."attendee")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.uid()) = "id"
      FROM (SELECT ($1).*) AS "attendee";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_attendee"("attendee" "public"."attendee")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.uid()) = "id"
      FROM (SELECT ($1).*) AS "attendee";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_ticket"("ticket" "public"."ticket")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.uid()) = "auth_user_id"
      FROM (SELECT ($1).*) AS "ticket";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_ticket"("ticket" "public"."ticket")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.uid()) IS NOT NULL
      FROM (SELECT ($1).*) AS "ticket";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_ticket"("ticket" "public"."ticket")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.uid()) = "auth_user_id"
      FROM (SELECT ($1).*) AS "ticket";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_ticket"("ticket" "public"."ticket")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.uid()) = "auth_user_id"
      FROM (SELECT ($1).*) AS "ticket";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_chat_message"("chat_message" "public"."chat_message")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.uid()) IS NOT NULL
      FROM (SELECT ($1).*) AS "chat_message";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_chat_message"("chat_message" "public"."chat_message")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.uid()) IS NOT NULL
      FROM (SELECT ($1).*) AS "chat_message";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_chat_message"("chat_message" "public"."chat_message")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.uid()) = "auth_user_id"
      FROM (SELECT ($1).*) AS "chat_message";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_chat_message"("chat_message" "public"."chat_message")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.uid()) = "auth_user_id"
      FROM (SELECT ($1).*) AS "chat_message";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read__global_site_settings"("_global_site_settings" "public"."_global_site_settings")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT TRUE
      FROM (SELECT ($1).*) AS "_global_site_settings";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create__global_site_settings"("_global_site_settings" "public"."_global_site_settings")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'editor'
      FROM (SELECT ($1).*) AS "_global_site_settings";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update__global_site_settings"("_global_site_settings" "public"."_global_site_settings")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'editor'
      FROM (SELECT ($1).*) AS "_global_site_settings";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete__global_site_settings"("_global_site_settings" "public"."_global_site_settings")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'editor'
      FROM (SELECT ($1).*) AS "_global_site_settings";
  $can$;

-- Table privileges derived from access rules (defence in depth)
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'GRANT SELECT ON "public"."page" TO anon';
    EXECUTE 'REVOKE INSERT ON "public"."page" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."page" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."page" FROM anon';
    EXECUTE 'GRANT SELECT ON "public"."speaker" TO anon';
    EXECUTE 'REVOKE INSERT ON "public"."speaker" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."speaker" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."speaker" FROM anon';
    EXECUTE 'GRANT SELECT ON "public"."room" TO anon';
    EXECUTE 'REVOKE INSERT ON "public"."room" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."room" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."room" FROM anon';
    EXECUTE 'GRANT SELECT ON "public"."talk" TO anon';
    EXECUTE 'REVOKE INSERT ON "public"."talk" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."talk" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."talk" FROM anon';
    EXECUTE 'GRANT SELECT ON "public"."sponsor" TO anon';
    EXECUTE 'REVOKE INSERT ON "public"."sponsor" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."sponsor" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."sponsor" FROM anon';
    EXECUTE 'REVOKE SELECT ON "public"."attendee" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."attendee" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."attendee" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."attendee" FROM anon';
    EXECUTE 'REVOKE SELECT ON "public"."ticket" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."ticket" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."ticket" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."ticket" FROM anon';
    EXECUTE 'REVOKE SELECT ON "public"."chat_message" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."chat_message" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."chat_message" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."chat_message" FROM anon';
    EXECUTE 'GRANT SELECT ON "public"."_global_site_settings" TO anon';
    EXECUTE 'REVOKE INSERT ON "public"."_global_site_settings" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."_global_site_settings" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."_global_site_settings" FROM anon';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'GRANT SELECT ON "public"."page" TO authenticated';
    EXECUTE 'GRANT INSERT ON "public"."page" TO authenticated';
    EXECUTE 'GRANT UPDATE ON "public"."page" TO authenticated';
    EXECUTE 'GRANT DELETE ON "public"."page" TO authenticated';
    EXECUTE 'GRANT SELECT ON "public"."speaker" TO authenticated';
    EXECUTE 'GRANT INSERT ON "public"."speaker" TO authenticated';
    EXECUTE 'GRANT UPDATE ON "public"."speaker" TO authenticated';
    EXECUTE 'GRANT DELETE ON "public"."speaker" TO authenticated';
    EXECUTE 'GRANT SELECT ON "public"."room" TO authenticated';
    EXECUTE 'GRANT INSERT ON "public"."room" TO authenticated';
    EXECUTE 'GRANT UPDATE ON "public"."room" TO authenticated';
    EXECUTE 'GRANT DELETE ON "public"."room" TO authenticated';
    EXECUTE 'GRANT SELECT ON "public"."talk" TO authenticated';
    EXECUTE 'GRANT INSERT ON "public"."talk" TO authenticated';
    EXECUTE 'GRANT UPDATE ON "public"."talk" TO authenticated';
    EXECUTE 'GRANT DELETE ON "public"."talk" TO authenticated';
    EXECUTE 'GRANT SELECT ON "public"."sponsor" TO authenticated';
    EXECUTE 'GRANT INSERT ON "public"."sponsor" TO authenticated';
    EXECUTE 'GRANT UPDATE ON "public"."sponsor" TO authenticated';
    EXECUTE 'GRANT DELETE ON "public"."sponsor" TO authenticated';
    EXECUTE 'GRANT SELECT ON "public"."attendee" TO authenticated';
    EXECUTE 'GRANT INSERT ON "public"."attendee" TO authenticated';
    EXECUTE 'GRANT UPDATE ON "public"."attendee" TO authenticated';
    EXECUTE 'GRANT DELETE ON "public"."attendee" TO authenticated';
    EXECUTE 'GRANT SELECT ON "public"."ticket" TO authenticated';
    EXECUTE 'GRANT INSERT ON "public"."ticket" TO authenticated';
    EXECUTE 'GRANT UPDATE ON "public"."ticket" TO authenticated';
    EXECUTE 'GRANT DELETE ON "public"."ticket" TO authenticated';
    EXECUTE 'GRANT SELECT ON "public"."chat_message" TO authenticated';
    EXECUTE 'GRANT INSERT ON "public"."chat_message" TO authenticated';
    EXECUTE 'GRANT UPDATE ON "public"."chat_message" TO authenticated';
    EXECUTE 'GRANT DELETE ON "public"."chat_message" TO authenticated';
    EXECUTE 'GRANT SELECT ON "public"."_global_site_settings" TO authenticated';
    EXECUTE 'GRANT INSERT ON "public"."_global_site_settings" TO authenticated';
    EXECUTE 'GRANT UPDATE ON "public"."_global_site_settings" TO authenticated';
    EXECUTE 'GRANT DELETE ON "public"."_global_site_settings" TO authenticated';
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

-- Drafts, version history and publishing
CREATE SCHEMA IF NOT EXISTS "draft";

CREATE SCHEMA IF NOT EXISTS _supatype;

-- The API roles need to *resolve* names here, because the draft policies on the model
-- tables call helpers in this schema and a policy expression runs as the caller. Without
-- it an anonymous read of a versioned model fails `42501 permission denied for schema
-- _supatype`, on published content, which is most of what a reader asks for.
--
-- USAGE alone discloses nothing: every table here still requires its own grant and none
-- is given. Functions are the exception, and the reason for the revokes below.
GRANT USAGE ON SCHEMA _supatype TO anon, authenticated, service_role;

CREATE TABLE IF NOT EXISTS _supatype.publishing_settings (
    "singleton" BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK ("singleton"),
    "configured_visibility" TEXT[] NOT NULL DEFAULT '{}',
    "override_visibility" TEXT[],
    "preview_epoch" INTEGER NOT NULL DEFAULT 1,
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO _supatype.publishing_settings ("singleton") VALUES (TRUE)
  ON CONFLICT ("singleton") DO NOTHING;

-- Only when it actually differs, so a steady-state push does not touch `updated_at` and
-- make every push look like a settings change.
UPDATE _supatype.publishing_settings
   SET "configured_visibility" = ARRAY['admin', 'developer', 'editor']::text[], "updated_at" = now()
 WHERE "singleton" AND "configured_visibility" IS DISTINCT FROM ARRAY['admin', 'developer', 'editor']::text[];


CREATE TABLE IF NOT EXISTS _supatype.preview_links (
  "id" TEXT PRIMARY KEY,
  -- A hash, never the secret. Comparison happens in the server, in constant time.
  "secret_hash" TEXT NOT NULL,
  "scope" TEXT NOT NULL CHECK ("scope" IN ('record', 'project')),
  "model" TEXT,
  "record_id" TEXT,
  "epoch" INTEGER NOT NULL,
  "created_by" UUID,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
  "expires_at" TIMESTAMPTZ NOT NULL,
  "revoked_at" TIMESTAMPTZ,
  -- A record link that names no record would be a project link wearing the wrong label, and it
  -- would resolve to a claim matching nothing.
  CONSTRAINT "preview_links_record_is_named"
    CHECK ("scope" <> 'record' OR ("model" IS NOT NULL AND "record_id" IS NOT NULL))
);

-- Listing the live links for one record, which is what the share control asks on every open.
CREATE INDEX IF NOT EXISTS "preview_links_live_for_record"
  ON _supatype.preview_links ("model", "record_id")
  WHERE "revoked_at" IS NULL;

-- The schema grants USAGE to the API roles so draft policies can resolve their helpers, and a
-- table still needs its own grant, which this never gets. Said explicitly anyway: a project that
-- runs a blanket `GRANT ALL ON ALL TABLES IN SCHEMA` would otherwise hand out the hashes.
REVOKE ALL ON _supatype.preview_links FROM PUBLIC;
REVOKE ALL ON _supatype.preview_links FROM anon, authenticated, service_role;

-- The caller's user id, or NULL when the request has no subject.
--
-- A thin alias for `auth.uid()`, which is what it now means. It was its own implementation while
-- `auth.uid()` fell back to the nil UUID for a subject-less request, and that gap was a hole rather
-- than a nicety: two kinds of request legitimately have no subject, a `service_role` call and a
-- preview link, so a draft saved through Studio was stamped with the nil UUID and every other
-- subject-less caller then satisfied `created_by = auth.uid()`.
--
-- `auth.uid()` answers NULL now, so this exists only to keep the policies below reading as one
-- thought. It is not a second definition to keep in step.
CREATE OR REPLACE FUNCTION _supatype.caller_id() RETURNS uuid
  LANGUAGE sql STABLE SET search_path = '' AS $fn$
    SELECT auth.uid();
  $fn$;

CREATE OR REPLACE FUNCTION _supatype.draft_visibility_roles() RETURNS text[]
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $fn$
    SELECT COALESCE(s."override_visibility", s."configured_visibility")
      FROM _supatype.publishing_settings s WHERE s."singleton";
  $fn$;

-- SECURITY DEFINER because `_supatype` is deliberately unreachable through the data plane: the
-- membership table is not something an API caller may read. This returns one boolean about the
-- caller themselves, so it discloses nothing they could not already infer.
--
-- An absent membership table means no elevated readers rather than an error, so a deployment that
-- has never bootstrapped Studio still has working drafts, visible to their creators.
CREATE OR REPLACE FUNCTION _supatype.sees_all_drafts() RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = '' AS $fn$
  DECLARE
    caller uuid := _supatype.caller_id();
    caller_role text;
  BEGIN
    IF caller IS NULL THEN
      RETURN false;
    END IF;
    SELECT m.role INTO caller_role FROM _supatype.studio_members m WHERE m.user_id = caller;
    IF caller_role IS NULL THEN
      RETURN false;
    END IF;
    RETURN caller_role = ANY (COALESCE(_supatype.draft_visibility_roles(), ARRAY[]::text[]));
  EXCEPTION WHEN undefined_table THEN
    RETURN false;
  END;
  $fn$;

CREATE OR REPLACE FUNCTION _supatype.preview_epoch() RETURNS integer
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $fn$
    SELECT s."preview_epoch" FROM _supatype.publishing_settings s WHERE s."singleton";
  $fn$;

-- Whether the caller holds a live preview link covering this record.
--
-- **Expiry is not checked here, and does not need to be.** A link is a JWT signed with the project's
-- own secret, so PostgREST verifies the signature and the expiry and rejects the request before any
-- of this runs: an expired link never reaches a policy. What this adds is scope and revocation.
--
-- The claims setting is written by PostgREST from a verified token, so it is valid JSON or absent.
CREATE OR REPLACE FUNCTION _supatype.preview_allows(target_model text, target_record text)
  RETURNS boolean LANGUAGE sql STABLE SET search_path = '' AS $fn$
    SELECT CASE
      WHEN c.claim IS NULL THEN false
      -- A bumped epoch withdraws every link minted before it.
      WHEN (c.claim->>'epoch') IS DISTINCT FROM _supatype.preview_epoch()::text THEN false
      WHEN c.claim->>'scope' = 'project' THEN true
      WHEN c.claim->>'scope' = 'record'
        THEN c.claim->>'model' = target_model AND c.claim->>'record_id' = target_record
      ELSE false
    END
    FROM (
      SELECT (nullif(current_setting('request.jwt.claims', true), '')::jsonb -> 'preview') AS claim
    ) c;
  $fn$;

CREATE TABLE IF NOT EXISTS _supatype.versioned_models (
    "table_name" TEXT PRIMARY KEY,
    "schema_name" TEXT NOT NULL,
    "model_name" TEXT NOT NULL,
    "versions_table" TEXT NOT NULL,
    "primary_key" TEXT NOT NULL,
    "primary_key_type" TEXT NOT NULL,
    "published_at_column" TEXT,
    -- The columns holding one value per locale, and the project's locale list. Publishing one
    -- locale merges its keys into these columns and leaves the others as they were.
    "localized_columns" TEXT[] NOT NULL DEFAULT '{}',
    "locales" TEXT[] NOT NULL DEFAULT '{}',
    "drafts" BOOLEAN NOT NULL,
    "keep" INTEGER NOT NULL
);

-- `WHERE TRUE` is not decoration: `supatype/postgres` preloads the safe-update guard,
-- which refuses an unqualified DELETE outright. Found by running this, not by reading it.
DELETE FROM _supatype.versioned_models WHERE TRUE;
INSERT INTO _supatype.versioned_models
  ("table_name", "schema_name", "model_name", "versions_table", "primary_key", "primary_key_type", "published_at_column", "localized_columns", "locales", "drafts", "keep")
VALUES ('page', 'public', 'Page', 'page_versions', 'id', 'UUID', 'published_at', ARRAY['title']::text[], ARRAY['en', 'fr']::text[], true, 20);
INSERT INTO _supatype.versioned_models
  ("table_name", "schema_name", "model_name", "versions_table", "primary_key", "primary_key_type", "published_at_column", "localized_columns", "locales", "drafts", "keep")
VALUES ('speaker', 'public', 'Speaker', 'speaker_versions', 'id', 'UUID', 'published_at', ARRAY['bio']::text[], ARRAY['en', 'fr']::text[], true, 20);
INSERT INTO _supatype.versioned_models
  ("table_name", "schema_name", "model_name", "versions_table", "primary_key", "primary_key_type", "published_at_column", "localized_columns", "locales", "drafts", "keep")
VALUES ('talk', 'public', 'Talk', 'talk_versions', 'id', 'UUID', 'published_at', ARRAY['abstract']::text[], ARRAY['en', 'fr']::text[], true, 10);

CREATE SCHEMA IF NOT EXISTS "supatype";
GRANT USAGE ON SCHEMA "supatype" TO anon, authenticated, service_role;

-- The registry row for a table, or an error naming what was asked for.
--
-- Every function below starts here, so a table name never reaches `format()` unchecked.
CREATE OR REPLACE FUNCTION _supatype.versioned_model(p_table text)
  RETURNS _supatype.versioned_models LANGUAGE plpgsql STABLE SECURITY DEFINER
  SET search_path = '' AS $fn$
  DECLARE
    entry _supatype.versioned_models;
  BEGIN
    SELECT * INTO entry FROM _supatype.versioned_models WHERE "table_name" = p_table;
    IF entry."table_name" IS NULL THEN
      RAISE EXCEPTION 'no versioned model for table %', p_table
        USING ERRCODE = '22023',
              HINT = 'Add `versions` to the model in your schema and push, or check the table name.';
    END IF;
    RETURN entry;
  END;
  $fn$;

-- Save a draft: the newest snapshot merged with the submitted fields, or the live row when there is
-- no snapshot yet.
--
-- Merging onto the newest snapshot rather than the live row is what makes successive edits
-- accumulate instead of each starting again from what is published. Reading it needs the snapshot
-- table's SELECT policy to pass, which for anyone entitled to edit the record it does: draft
-- visibility covers every Studio role precisely so that an editor cannot save over a pending draft
-- they were not shown.
CREATE OR REPLACE FUNCTION "supatype".create_draft(model_table text, record_id text, data jsonb)
  RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public, extensions AS $fn$
  DECLARE
    entry _supatype.versioned_models := _supatype.versioned_model(model_table);
    base jsonb;
    saved record;
  BEGIN
    IF NOT entry."drafts" THEN
      RAISE EXCEPTION 'model % keeps history but does not withhold writes, so it has no drafts', entry."model_name"
        USING ERRCODE = '22023',
              HINT = 'Write to the table directly; every change is recorded as a version.';
    END IF;

    EXECUTE format(
      'SELECT v.%I FROM %I.%I v WHERE v.%I = $1::%s ORDER BY v.%I DESC LIMIT 1',
      'data', entry."schema_name", entry."versions_table", 'record_id',
      entry."primary_key_type", 'version')
      INTO base USING record_id;

    IF base IS NULL THEN
      EXECUTE format('SELECT to_jsonb(t) FROM %I.%I t WHERE t.%I = $1::%s',
        entry."schema_name", entry."table_name", entry."primary_key", entry."primary_key_type")
        INTO base USING record_id;
    END IF;

    IF base IS NULL THEN
      RAISE EXCEPTION 'no such record % in %', record_id, model_table USING ERRCODE = '02000';
    END IF;

    -- `version`, `created_by` and `status` are the guard trigger's to assign.
    EXECUTE format(
      'INSERT INTO %I.%I (%I, %I) VALUES ($1::%s, $2) RETURNING %I, %I, %I',
      entry."schema_name", entry."versions_table", 'record_id', 'data',
      entry."primary_key_type", 'version', 'status', 'created_at')
      INTO saved USING record_id, base || COALESCE(data, '{}'::jsonb);

    RETURN jsonb_build_object(
      'record_id', record_id, 'version', saved."version",
      'status', saved."status", 'created_at', saved."created_at");
  END;
  $fn$;

-- Promote a version into the live row, for some or all of its locales.
--
-- **Two arguments beyond the record, both optional.** `version` defaults to the newest, so the
-- ordinary case is unchanged. `locales` defaults to every locale the project declares, so a project
-- that translates before publishing never sees this.
--
-- **Per locale, because a localized field is one `jsonb` column keyed by locale.** Publishing `en`
-- merges the `en` key of every localized column and leaves the rest of the column exactly as it was,
-- so an unpublished translation is simply *absent* from the live row. That is what makes this
-- enforceable at all: row level security cannot hide one key of a column, and nothing has to,
-- because the value was never written.
--
-- **The shared, non-localized columns go live with whichever locale is published.** They belong to
-- no locale, so the alternative is that a change to one could only ever go live by publishing every
-- translation, which would make the feature useless to the team it exists for.
--
-- The `UPDATE` runs under the caller's own rules, so the policy that already governs editing governs
-- publishing and there is nothing new to keep in step.
CREATE OR REPLACE FUNCTION "supatype".publish(
  model_table text, record_id text, version integer DEFAULT NULL, locales text[] DEFAULT NULL)
  RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public, extensions AS $fn$
  DECLARE
    entry _supatype.versioned_models := _supatype.versioned_model(model_table);
    target record;
    want text[];
    pending text[];
    assignments text[] := ARRAY[]::text[];
    col text;
    stamp timestamptz := now();
    updated integer;
  BEGIN
    -- The version to promote: the one named, or the newest.
    IF version IS NULL THEN
      EXECUTE format(
        'SELECT v.%I AS version, v.%I AS data, v.%I AS published_locales FROM %I.%I v
          WHERE v.%I = $1::%s ORDER BY v.%I DESC LIMIT 1',
        'version', 'data', 'published_locales', entry."schema_name", entry."versions_table",
        'record_id', entry."primary_key_type", 'version')
        INTO target USING record_id;
    ELSE
      EXECUTE format(
        'SELECT v.%I AS version, v.%I AS data, v.%I AS published_locales FROM %I.%I v
          WHERE v.%I = $1::%s AND v.%I = $2',
        'version', 'data', 'published_locales', entry."schema_name", entry."versions_table",
        'record_id', entry."primary_key_type", 'version')
        INTO target USING record_id, version;
    END IF;

    IF target IS NULL THEN
      RAISE EXCEPTION 'no version to publish for % in %', record_id, model_table
        USING ERRCODE = '02000',
              HINT = 'Save a draft first, or name a version that exists.';
    END IF;

    -- `*` stands for the whole record on a model with no localized column, so the state map has one
    -- shape rather than two.
    want := COALESCE(locales, _supatype.default_locales(entry));

    -- Only the locales this version is not already live for. That is also what makes a repeat
    -- publish a refusal rather than a silent no-op, and it replaced an earlier check that looked for
    -- the newest *draft* and would fall back to an older one, putting stale content live.
    SELECT array_agg(l) INTO pending
      FROM unnest(want) AS l
     WHERE NOT (target.published_locales ? l);

    IF pending IS NULL THEN
      RAISE EXCEPTION 'version % of % in % is already live for %',
        target.version, record_id, model_table, array_to_string(want, ', ')
        USING ERRCODE = '02000',
              HINT = 'The live row already says what this version says.';
    END IF;

    -- Shared columns, taken wholesale from the snapshot. The primary key is excluded: publishing a
    -- draft must not be able to move a record's identity.
    SELECT array_agg(format('%I = (src.r).%I', c.column_name, c.column_name))
      INTO assignments
      FROM information_schema.columns c
     WHERE c.table_schema = entry."schema_name"
       AND c.table_name = entry."table_name"
       AND c.column_name <> entry."primary_key"
       AND NOT (c.column_name = ANY (entry."localized_columns"))
       AND c.is_generated = 'NEVER';
    assignments := COALESCE(assignments, ARRAY[]::text[]);

    -- Localized columns, merged key by key for the locales being published.
    -- `jsonb_each` raises on anything but an object, and a localized column the author has not
    -- filled in is JSON `null` in the snapshot rather than absent. Found by running it: every
    -- publish failed `22023` the moment the fixture gained a localized field nobody had set.
    FOREACH col IN ARRAY entry."localized_columns" LOOP
      assignments := assignments || format(
        '%I = COALESCE(%I, ''{}''::jsonb) || (
           SELECT COALESCE(jsonb_object_agg(e.key, e.value), ''{}''::jsonb)
             FROM jsonb_each(CASE WHEN jsonb_typeof($2 -> %L) = ''object''
                                  THEN $2 -> %L ELSE ''{}''::jsonb END) e
            WHERE e.key = ANY ($3))',
        col, col, col, col);
    END LOOP;

    EXECUTE format(
      'UPDATE %I.%I SET %s FROM (SELECT jsonb_populate_record(NULL::%I.%I, $2) AS r) src
        WHERE %I = $1::%s',
      entry."schema_name", entry."table_name", array_to_string(assignments, ', '),
      entry."schema_name", entry."table_name",
      entry."primary_key", entry."primary_key_type")
      USING record_id, target.data, pending;
    GET DIAGNOSTICS updated = ROW_COUNT;

    IF updated = 0 THEN
      RAISE EXCEPTION 'not permitted to publish % in %', record_id, model_table
        USING ERRCODE = '42501',
              HINT = 'Publishing a record requires the same permission as editing it.';
    END IF;

    IF entry."published_at_column" IS NOT NULL THEN
      EXECUTE format('UPDATE %I.%I SET %I = COALESCE(%I, $2) WHERE %I = $1::%s',
        entry."schema_name", entry."table_name",
        entry."published_at_column", entry."published_at_column",
        entry."primary_key", entry."primary_key_type")
        USING record_id, stamp;
    END IF;

    -- Exactly one version claims a locale, so publishing takes it off every other version. Without
    -- this, "which version is live for fr" would have several answers after a restore.
    EXECUTE format(
      'UPDATE %I.%I SET %I = %I - $3, %I = CASE WHEN (%I - $3) = ''{}''::jsonb
          THEN ''draft'' ELSE ''published'' END
        WHERE %I = $1::%s AND %I <> $2 AND %I ?| $3',
      entry."schema_name", entry."versions_table",
      'published_locales', 'published_locales', 'status', 'published_locales',
      'record_id', entry."primary_key_type", 'version', 'published_locales')
      USING record_id, target.version, pending;

    EXECUTE format(
      'UPDATE %I.%I SET %I = %I || $3, %I = ''published''
        WHERE %I = $1::%s AND %I = $2',
      entry."schema_name", entry."versions_table",
      'published_locales', 'published_locales', 'status',
      'record_id', entry."primary_key_type", 'version')
      USING record_id, target.version,
            (SELECT jsonb_object_agg(l, stamp) FROM unnest(pending) AS l);

    RETURN jsonb_build_object(
      'record_id', record_id, 'version', target.version,
      'status', 'published', 'locales', to_jsonb(pending));
  END;
  $fn$;

-- Take some or all locales out of publication.
--
-- Removing a locale's keys from the live columns is what actually hides it, for the same reason
-- publishing writes them: an absent translation needs no policy. The remaining locales are
-- untouched, and `published_at` is cleared only when nothing is left published, so a record with one
-- locale still live stays readable to a rule that compares `published_at`.
--
-- On a model with no localized column this is the whole record, and the content stays in the row:
-- withdrawing publication is not the same as reverting an edit, and blanking the row would lose the
-- thing a later publish would restore.
CREATE OR REPLACE FUNCTION "supatype".unpublish(
  model_table text, record_id text, locales text[] DEFAULT NULL)
  RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public, extensions AS $fn$
  DECLARE
    entry _supatype.versioned_models := _supatype.versioned_model(model_table);
    want text[];
    assignments text[] := ARRAY[]::text[];
    col text;
    remaining boolean;
    updated integer;
  BEGIN
    want := COALESCE(locales, _supatype.default_locales(entry));

    FOREACH col IN ARRAY entry."localized_columns" LOOP
      assignments := assignments || format('%I = COALESCE(%I, ''{}''::jsonb) - $2', col, col);
    END LOOP;

    IF cardinality(assignments) > 0 THEN
      EXECUTE format('UPDATE %I.%I SET %s WHERE %I = $1::%s',
        entry."schema_name", entry."table_name", array_to_string(assignments, ', '),
        entry."primary_key", entry."primary_key_type")
        USING record_id, want;
      GET DIAGNOSTICS updated = ROW_COUNT;
      IF updated = 0 THEN
        RAISE EXCEPTION 'not permitted to unpublish % in %, or no such record', record_id, model_table
          USING ERRCODE = '42501';
      END IF;
    END IF;

    EXECUTE format(
      'UPDATE %I.%I SET %I = %I - $2, %I = CASE WHEN (%I - $2) = ''{}''::jsonb
          THEN ''draft'' ELSE ''published'' END
        WHERE %I = $1::%s AND %I ?| $2',
      entry."schema_name", entry."versions_table",
      'published_locales', 'published_locales', 'status', 'published_locales',
      'record_id', entry."primary_key_type", 'published_locales')
      USING record_id, want;

    EXECUTE format(
      'SELECT EXISTS (SELECT 1 FROM %I.%I v WHERE v.%I = $1::%s AND v.%I <> ''{}''::jsonb)',
      entry."schema_name", entry."versions_table", 'record_id', entry."primary_key_type",
      'published_locales')
      INTO remaining USING record_id;

    IF entry."published_at_column" IS NOT NULL AND NOT remaining THEN
      EXECUTE format('UPDATE %I.%I SET %I = NULL WHERE %I = $1::%s',
        entry."schema_name", entry."table_name", entry."published_at_column",
        entry."primary_key", entry."primary_key_type")
        USING record_id;
      GET DIAGNOSTICS updated = ROW_COUNT;
      IF updated = 0 THEN
        RAISE EXCEPTION 'not permitted to unpublish % in %, or no such record', record_id, model_table
          USING ERRCODE = '42501';
      END IF;
    END IF;

    RETURN jsonb_build_object(
      'record_id', record_id, 'status',
      CASE WHEN remaining THEN 'partially_published' ELSE 'unpublished' END,
      'locales', to_jsonb(want));
  END;
  $fn$;

-- Restore an earlier version as a **new draft**, never as an immediate publish.
--
-- Nothing goes live without publishing, so restoring is an editing act with a preview and a second
-- decision behind it, not a way to change what the world sees in one call.
CREATE OR REPLACE FUNCTION "supatype".restore_version(model_table text, record_id text, version integer)
  RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public, extensions AS $fn$
  DECLARE
    entry _supatype.versioned_models := _supatype.versioned_model(model_table);
    snapshot jsonb;
  BEGIN
    EXECUTE format('SELECT v.%I FROM %I.%I v WHERE v.%I = $1::%s AND v.%I = $2',
      'data', entry."schema_name", entry."versions_table",
      'record_id', entry."primary_key_type", 'version')
      INTO snapshot USING record_id, version;

    IF snapshot IS NULL THEN
      RAISE EXCEPTION 'no version % of % in %', version, record_id, model_table
        USING ERRCODE = '02000';
    END IF;

    RETURN "supatype".create_draft(model_table, record_id, snapshot);
  END;
  $fn$;

-- The locales a call means when it names none: every locale the project declares, or the single key
-- `*` on a model with no localized column, so the state maps have one shape rather than two.
CREATE OR REPLACE FUNCTION _supatype.default_locales(entry _supatype.versioned_models)
  RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path = '' AS $fn$
    SELECT CASE
      WHEN cardinality(entry."localized_columns") = 0 OR cardinality(entry."locales") = 0
        THEN ARRAY['*'] ELSE entry."locales" END;
  $fn$;

-- Schedule some or all of a version's locales to go live later.
--
-- **A real change from how scheduled publishing used to work.** Without versions, a schedule needed
-- no scheduler: the access rule compared `published_at <= now()`, so a future timestamp simply hid
-- the row until it arrived. That trick works only while the content is already in the live row. Once
-- publishing means copying a draft in, something has to do the copying, which is what the job below
-- is for.
--
-- `SECURITY INVOKER`, and it writes the version row, so the same `can_edit` gate that governs
-- drafting governs scheduling. Nothing is published here: this records an intent, and the job acts
-- on it.
CREATE OR REPLACE FUNCTION "supatype".schedule_publish(
  model_table text, record_id text, at timestamptz,
  version integer DEFAULT NULL, locales text[] DEFAULT NULL)
  RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public, extensions AS $fn$
  DECLARE
    entry _supatype.versioned_models := _supatype.versioned_model(model_table);
    target integer;
    want text[];
    updated integer;
  BEGIN
    IF at IS NULL THEN
      RAISE EXCEPTION 'schedule_publish needs a time' USING ERRCODE = '22023';
    END IF;

    target := version;
    IF target IS NULL THEN
      EXECUTE format('SELECT v.%I FROM %I.%I v WHERE v.%I = $1::%s ORDER BY v.%I DESC LIMIT 1',
        'version', entry."schema_name", entry."versions_table",
        'record_id', entry."primary_key_type", 'version')
        INTO target USING record_id;
    END IF;

    IF target IS NULL THEN
      RAISE EXCEPTION 'no version to schedule for % in %', record_id, model_table
        USING ERRCODE = '02000', HINT = 'Save a draft first.';
    END IF;

    want := COALESCE(locales, _supatype.default_locales(entry));

    EXECUTE format(
      'UPDATE %I.%I SET %I = %I || $3 WHERE %I = $1::%s AND %I = $2',
      entry."schema_name", entry."versions_table", 'scheduled_locales', 'scheduled_locales',
      'record_id', entry."primary_key_type", 'version')
      USING record_id, target,
            (SELECT jsonb_object_agg(l, at) FROM unnest(want) AS l);
    GET DIAGNOSTICS updated = ROW_COUNT;

    IF updated = 0 THEN
      RAISE EXCEPTION 'not permitted to schedule % in %, or no such version', record_id, model_table
        USING ERRCODE = '42501';
    END IF;

    RETURN jsonb_build_object(
      'record_id', record_id, 'version', target, 'at', at, 'locales', to_jsonb(want));
  END;
  $fn$;

-- Withdraw a schedule without publishing anything.
CREATE OR REPLACE FUNCTION "supatype".unschedule_publish(
  model_table text, record_id text, version integer DEFAULT NULL, locales text[] DEFAULT NULL)
  RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public, extensions AS $fn$
  DECLARE
    entry _supatype.versioned_models := _supatype.versioned_model(model_table);
    want text[] := COALESCE(locales, _supatype.default_locales(entry));
  BEGIN
    IF version IS NULL THEN
      EXECUTE format('UPDATE %I.%I SET %I = %I - $2 WHERE %I = $1::%s AND %I ?| $2',
        entry."schema_name", entry."versions_table", 'scheduled_locales', 'scheduled_locales',
        'record_id', entry."primary_key_type", 'scheduled_locales')
        USING record_id, want;
    ELSE
      EXECUTE format(
        'UPDATE %I.%I SET %I = %I - $3 WHERE %I = $1::%s AND %I = $2',
        entry."schema_name", entry."versions_table", 'scheduled_locales', 'scheduled_locales',
        'record_id', entry."primary_key_type", 'version')
        USING record_id, version, want;
    END IF;

    RETURN jsonb_build_object('record_id', record_id, 'locales', to_jsonb(want));
  END;
  $fn$;

GRANT EXECUTE ON FUNCTION "supatype".schedule_publish(text, text, timestamptz, integer, text[])
  TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION "supatype".unschedule_publish(text, text, integer, text[])
  TO authenticated, service_role;

-- Publish everything whose scheduled time has arrived.
--
-- **`SECURITY INVOKER`, and that is what makes it correct in two places at once.** Run by the
-- scheduler it executes as the job's owner, which bypasses row level security, so a schedule set
-- last week still fires when its author is nowhere near. Called by an ordinary caller it executes as
-- them, so they can only publish what they could have published by hand. One implementation, no
-- second permission model, and no privilege to escalate through.
--
-- Each record is published in its own block so one failure (a constraint the draft violates, a
-- record deleted since) does not strand every other schedule behind it. The failure is reported as
-- a warning and the schedule cleared, because a schedule that cannot be honoured will not start
-- working on the next tick and retrying it every minute for ever is worse than saying so once.
CREATE OR REPLACE FUNCTION _supatype.run_due_publishes(now_at timestamptz DEFAULT now())
  RETURNS integer LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public, extensions AS $fn$
  DECLARE
    entry _supatype.versioned_models;
    due record;
    published integer := 0;
  BEGIN
    FOR entry IN SELECT * FROM _supatype.versioned_models WHERE "drafts" LOOP
      FOR due IN
        EXECUTE format(
          'SELECT v.%I AS record_id, v.%I AS version,
                  array_agg(e.key) AS locales
             FROM %I.%I v, jsonb_each_text(v.%I) e
            WHERE (e.value)::timestamptz <= $1
            GROUP BY v.%I, v.%I',
          'record_id', 'version', entry."schema_name", entry."versions_table",
          'scheduled_locales', 'record_id', 'version')
          USING now_at
      LOOP
        BEGIN
          PERFORM "supatype".publish(
            entry."table_name", due.record_id::text, due.version, due.locales);
          published := published + 1;
        EXCEPTION WHEN OTHERS THEN
          RAISE WARNING 'scheduled publish failed for % version % in %: %',
            due.record_id, due.version, entry."table_name", SQLERRM;
        END;

        EXECUTE format('UPDATE %I.%I SET %I = %I - $3 WHERE %I = $1::%s AND %I = $2',
          entry."schema_name", entry."versions_table", 'scheduled_locales', 'scheduled_locales',
          'record_id', entry."primary_key_type", 'version')
          USING due.record_id::text, due.version, due.locales;
      END LOOP;
    END LOOP;
    RETURN published;
  END;
  $fn$;

-- Prune history beyond each model's retention.
--
-- Unbounded history is a slow leak on a busy table. Two rows are never pruned whatever the
-- retention says: the newest, which is what a draft read and a publish both work from, and any
-- version that claims a live locale, which is the only record of what the world is currently seeing.
--
-- `SECURITY DEFINER`, unlike everything else here. Retention is the system's housekeeping rather
-- than any caller's act, and the API roles hold no `DELETE` on the snapshot tables at all: history
-- is append-only to them, and this is the one thing that removes rows.
CREATE OR REPLACE FUNCTION _supatype.prune_versions()
  RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $fn$
  DECLARE
    entry _supatype.versioned_models;
    removed integer := 0;
    n integer;
  BEGIN
    FOR entry IN SELECT * FROM _supatype.versioned_models LOOP
      EXECUTE format(
        'DELETE FROM %I.%I v
          WHERE v.%I IN (
            SELECT id FROM (
              SELECT k.%I AS id,
                     row_number() OVER (PARTITION BY k.%I ORDER BY k.%I DESC) AS rank,
                     k.%I AS live
                FROM %I.%I k
            ) ranked
            WHERE ranked.rank > $1 AND ranked.live = ''{}''::jsonb
          )',
        entry."schema_name", entry."versions_table",
        'id', 'id', 'record_id', 'version', 'published_locales',
        entry."schema_name", entry."versions_table")
        USING entry."keep";
      GET DIAGNOSTICS n = ROW_COUNT;
      removed := removed + n;
    END LOOP;
    RETURN removed;
  END;
  $fn$;

-- Expired and revoked links, cleared out once they can no longer resolve.
--
-- Kept for a week past death rather than deleted the moment they expire: "why did that link stop
-- working" is asked after the fact, and a row that says `revoked_at` answers it where an absent row
-- looks the same as a link that never existed.
CREATE OR REPLACE FUNCTION _supatype.prune_preview_links()
  RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $fn$
  DECLARE
    removed integer;
  BEGIN
    DELETE FROM _supatype.preview_links
     WHERE COALESCE("revoked_at", "expires_at") < now() - interval '7 days';
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
  END;
  $fn$;

-- Postgres grants EXECUTE on a new function to PUBLIC, so USAGE on this schema would otherwise
-- hand every role the maintenance functions: `prune_versions` is SECURITY DEFINER and deletes
-- history, and `run_due_publishes` publishes. Neither is a caller's to invoke. The API roles need
-- USAGE here only so a draft policy can resolve the helper it calls, and that helper is granted
-- deliberately, one line at a time.
REVOKE ALL ON FUNCTION _supatype.prune_versions() FROM PUBLIC;
REVOKE ALL ON FUNCTION _supatype.prune_preview_links() FROM PUBLIC;
REVOKE ALL ON FUNCTION _supatype.run_due_publishes(timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION _supatype.draft_visibility_roles() FROM PUBLIC;
REVOKE ALL ON FUNCTION _supatype.versioned_model(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION _supatype.sees_all_drafts() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION _supatype.preview_allows(text, text) TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION _supatype.preview_epoch() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION _supatype.caller_id() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION _supatype.versioned_model(text) TO authenticated, service_role;

GRANT EXECUTE ON FUNCTION "supatype".create_draft(text, text, jsonb) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION "supatype".publish(text, text, integer, text[]) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION "supatype".unpublish(text, text, text[]) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION "supatype".restore_version(text, text, integer) TO authenticated, service_role;

REVOKE ALL ON SCHEMA "draft" FROM anon;
GRANT USAGE ON SCHEMA "draft" TO authenticated, service_role;

ALTER TABLE "public"."page_versions" ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "page_versions_select" ON "public"."page_versions";
CREATE POLICY "page_versions_select" ON "public"."page_versions"
  FOR SELECT USING (
    ("created_by" IS NOT NULL AND "created_by" = _supatype.caller_id())
    -- Wrapped in a SELECT so it is evaluated once per statement, not once per row.
    OR (SELECT _supatype.sees_all_drafts())
    OR _supatype.preview_allows('page', "record_id"::text)
  );
COMMENT ON POLICY "page_versions_select" ON "public"."page_versions" IS 'supatype:managed;kind=rls_policy;table=page_versions;fields=select;v=1';

REVOKE ALL PRIVILEGES ON "public"."page_versions" FROM anon;
REVOKE ALL PRIVILEGES ON "public"."page_versions" FROM authenticated;
GRANT SELECT ON "public"."page_versions" TO authenticated;
GRANT ALL ON "public"."page_versions" TO service_role;

CREATE OR REPLACE FUNCTION _supatype."can_edit_page"(p_record UUID)
  RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER AS $fn$
    SELECT EXISTS (
      SELECT 1 FROM "public"."page"
       WHERE "id" = p_record AND ((SELECT auth.role()) = 'editor')
    );
  $fn$;
GRANT EXECUTE ON FUNCTION _supatype."can_edit_page"(UUID) TO authenticated, service_role;

CREATE OR REPLACE FUNCTION _supatype."sees_draft_page"(p_record text)
  RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $fn$
    SELECT EXISTS (
      SELECT 1 FROM "public"."page_versions" v
       WHERE v."record_id"::text = p_record
         AND (
           (v."created_by" IS NOT NULL AND v."created_by" = _supatype.caller_id())
           OR (SELECT _supatype.sees_all_drafts())
           OR _supatype.preview_allows('page', v."record_id"::text)
         )
    );
  $fn$;
GRANT EXECUTE ON FUNCTION _supatype."sees_draft_page"(text) TO anon, authenticated, service_role;

DROP POLICY IF EXISTS "page_draft_select" ON "public"."page";
CREATE POLICY "page_draft_select" ON "public"."page"
  FOR SELECT USING (_supatype."sees_draft_page"("id"::text));
COMMENT ON POLICY "page_draft_select" ON "public"."page" IS 'supatype:managed;kind=rls_policy;table=page;fields=draft_select;v=1';

DROP POLICY IF EXISTS "page_versions_insert" ON "public"."page_versions";
CREATE POLICY "page_versions_insert" ON "public"."page_versions"
  FOR INSERT WITH CHECK (_supatype."can_edit_page"("record_id"));
COMMENT ON POLICY "page_versions_insert" ON "public"."page_versions" IS 'supatype:managed;kind=rls_policy;table=page_versions;fields=insert;v=1';

DROP POLICY IF EXISTS "page_versions_update" ON "public"."page_versions";
CREATE POLICY "page_versions_update" ON "public"."page_versions"
  FOR UPDATE USING (_supatype."can_edit_page"("record_id")) WITH CHECK (_supatype."can_edit_page"("record_id"));
COMMENT ON POLICY "page_versions_update" ON "public"."page_versions" IS 'supatype:managed;kind=rls_policy;table=page_versions;fields=update;v=1';

GRANT INSERT, UPDATE ON "public"."page_versions" TO authenticated;

CREATE OR REPLACE FUNCTION _supatype."page_versions_guard"() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $fn$
  BEGIN
    IF TG_OP = 'INSERT' THEN
      -- Assigned here, not accepted from the caller. The snapshot table is exposed like any other
      -- table in the managed schema, so a direct insert has to be a draft save and nothing else:
      -- no forged published version, no renumbering over someone else's, no borrowed authorship.
      SELECT COALESCE(MAX(v."version"), 0) + 1 INTO NEW."version"
        FROM "public"."page_versions" v WHERE v."record_id" = NEW."record_id";
      NEW."created_by" := _supatype.caller_id();
      -- A version is born a draft. Publishing it is `supatype.publish`, which is a separate act with
      -- a separate permission check.
      NEW."status" := 'draft';
      RETURN NEW;
    END IF;

    -- Only the publishing state may move: `status`, `published_locales`, `scheduled_locales`. A caller
    -- who can still edit the record must not be able to rewrite what an earlier version said, or
    -- the history stops being evidence of anything.
    NEW."data" := OLD."data";
    NEW."created_by" := OLD."created_by";
    NEW."created_at" := OLD."created_at";
    NEW."version" := OLD."version";
    NEW."record_id" := OLD."record_id";
    RETURN NEW;
  END;
  $fn$;

DROP TRIGGER IF EXISTS "page_versions_guard" ON "public"."page_versions";
CREATE TRIGGER "page_versions_guard" BEFORE INSERT OR UPDATE ON "public"."page_versions"
  FOR EACH ROW EXECUTE FUNCTION _supatype."page_versions_guard"();

DROP VIEW IF EXISTS "draft"."page";
CREATE VIEW "draft"."page" WITH (security_invoker = true) AS
SELECT (jsonb_populate_record(NULL::"public"."page", v."data")).*
  FROM (
    SELECT DISTINCT ON (pv."record_id") pv."record_id", pv."data"
      FROM "public"."page_versions" pv
     ORDER BY pv."record_id", pv."version" DESC
  ) v;
GRANT SELECT ON "draft"."page" TO authenticated, service_role;

ALTER TABLE "public"."speaker_versions" ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "speaker_versions_select" ON "public"."speaker_versions";
CREATE POLICY "speaker_versions_select" ON "public"."speaker_versions"
  FOR SELECT USING (
    ("created_by" IS NOT NULL AND "created_by" = _supatype.caller_id())
    -- Wrapped in a SELECT so it is evaluated once per statement, not once per row.
    OR (SELECT _supatype.sees_all_drafts())
    OR _supatype.preview_allows('speaker', "record_id"::text)
  );
COMMENT ON POLICY "speaker_versions_select" ON "public"."speaker_versions" IS 'supatype:managed;kind=rls_policy;table=speaker_versions;fields=select;v=1';

REVOKE ALL PRIVILEGES ON "public"."speaker_versions" FROM anon;
REVOKE ALL PRIVILEGES ON "public"."speaker_versions" FROM authenticated;
GRANT SELECT ON "public"."speaker_versions" TO authenticated;
GRANT ALL ON "public"."speaker_versions" TO service_role;

CREATE OR REPLACE FUNCTION _supatype."can_edit_speaker"(p_record UUID)
  RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER AS $fn$
    SELECT EXISTS (
      SELECT 1 FROM "public"."speaker"
       WHERE "id" = p_record AND ((SELECT auth.role()) = 'editor')
    );
  $fn$;
GRANT EXECUTE ON FUNCTION _supatype."can_edit_speaker"(UUID) TO authenticated, service_role;

CREATE OR REPLACE FUNCTION _supatype."sees_draft_speaker"(p_record text)
  RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $fn$
    SELECT EXISTS (
      SELECT 1 FROM "public"."speaker_versions" v
       WHERE v."record_id"::text = p_record
         AND (
           (v."created_by" IS NOT NULL AND v."created_by" = _supatype.caller_id())
           OR (SELECT _supatype.sees_all_drafts())
           OR _supatype.preview_allows('speaker', v."record_id"::text)
         )
    );
  $fn$;
GRANT EXECUTE ON FUNCTION _supatype."sees_draft_speaker"(text) TO anon, authenticated, service_role;

DROP POLICY IF EXISTS "speaker_draft_select" ON "public"."speaker";
CREATE POLICY "speaker_draft_select" ON "public"."speaker"
  FOR SELECT USING (_supatype."sees_draft_speaker"("id"::text));
COMMENT ON POLICY "speaker_draft_select" ON "public"."speaker" IS 'supatype:managed;kind=rls_policy;table=speaker;fields=draft_select;v=1';

DROP POLICY IF EXISTS "speaker_versions_insert" ON "public"."speaker_versions";
CREATE POLICY "speaker_versions_insert" ON "public"."speaker_versions"
  FOR INSERT WITH CHECK (_supatype."can_edit_speaker"("record_id"));
COMMENT ON POLICY "speaker_versions_insert" ON "public"."speaker_versions" IS 'supatype:managed;kind=rls_policy;table=speaker_versions;fields=insert;v=1';

DROP POLICY IF EXISTS "speaker_versions_update" ON "public"."speaker_versions";
CREATE POLICY "speaker_versions_update" ON "public"."speaker_versions"
  FOR UPDATE USING (_supatype."can_edit_speaker"("record_id")) WITH CHECK (_supatype."can_edit_speaker"("record_id"));
COMMENT ON POLICY "speaker_versions_update" ON "public"."speaker_versions" IS 'supatype:managed;kind=rls_policy;table=speaker_versions;fields=update;v=1';

GRANT INSERT, UPDATE ON "public"."speaker_versions" TO authenticated;

CREATE OR REPLACE FUNCTION _supatype."speaker_versions_guard"() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $fn$
  BEGIN
    IF TG_OP = 'INSERT' THEN
      -- Assigned here, not accepted from the caller. The snapshot table is exposed like any other
      -- table in the managed schema, so a direct insert has to be a draft save and nothing else:
      -- no forged published version, no renumbering over someone else's, no borrowed authorship.
      SELECT COALESCE(MAX(v."version"), 0) + 1 INTO NEW."version"
        FROM "public"."speaker_versions" v WHERE v."record_id" = NEW."record_id";
      NEW."created_by" := _supatype.caller_id();
      -- A version is born a draft. Publishing it is `supatype.publish`, which is a separate act with
      -- a separate permission check.
      NEW."status" := 'draft';
      RETURN NEW;
    END IF;

    -- Only the publishing state may move: `status`, `published_locales`, `scheduled_locales`. A caller
    -- who can still edit the record must not be able to rewrite what an earlier version said, or
    -- the history stops being evidence of anything.
    NEW."data" := OLD."data";
    NEW."created_by" := OLD."created_by";
    NEW."created_at" := OLD."created_at";
    NEW."version" := OLD."version";
    NEW."record_id" := OLD."record_id";
    RETURN NEW;
  END;
  $fn$;

DROP TRIGGER IF EXISTS "speaker_versions_guard" ON "public"."speaker_versions";
CREATE TRIGGER "speaker_versions_guard" BEFORE INSERT OR UPDATE ON "public"."speaker_versions"
  FOR EACH ROW EXECUTE FUNCTION _supatype."speaker_versions_guard"();

DROP VIEW IF EXISTS "draft"."speaker";
CREATE VIEW "draft"."speaker" WITH (security_invoker = true) AS
SELECT (jsonb_populate_record(NULL::"public"."speaker", v."data")).*
  FROM (
    SELECT DISTINCT ON (pv."record_id") pv."record_id", pv."data"
      FROM "public"."speaker_versions" pv
     ORDER BY pv."record_id", pv."version" DESC
  ) v;
GRANT SELECT ON "draft"."speaker" TO authenticated, service_role;

ALTER TABLE "public"."talk_versions" ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "talk_versions_select" ON "public"."talk_versions";
CREATE POLICY "talk_versions_select" ON "public"."talk_versions"
  FOR SELECT USING (
    ("created_by" IS NOT NULL AND "created_by" = _supatype.caller_id())
    -- Wrapped in a SELECT so it is evaluated once per statement, not once per row.
    OR (SELECT _supatype.sees_all_drafts())
    OR _supatype.preview_allows('talk', "record_id"::text)
  );
COMMENT ON POLICY "talk_versions_select" ON "public"."talk_versions" IS 'supatype:managed;kind=rls_policy;table=talk_versions;fields=select;v=1';

REVOKE ALL PRIVILEGES ON "public"."talk_versions" FROM anon;
REVOKE ALL PRIVILEGES ON "public"."talk_versions" FROM authenticated;
GRANT SELECT ON "public"."talk_versions" TO authenticated;
GRANT ALL ON "public"."talk_versions" TO service_role;

CREATE OR REPLACE FUNCTION _supatype."can_edit_talk"(p_record UUID)
  RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER AS $fn$
    SELECT EXISTS (
      SELECT 1 FROM "public"."talk"
       WHERE "id" = p_record AND ((SELECT auth.role()) = 'editor')
    );
  $fn$;
GRANT EXECUTE ON FUNCTION _supatype."can_edit_talk"(UUID) TO authenticated, service_role;

CREATE OR REPLACE FUNCTION _supatype."sees_draft_talk"(p_record text)
  RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $fn$
    SELECT EXISTS (
      SELECT 1 FROM "public"."talk_versions" v
       WHERE v."record_id"::text = p_record
         AND (
           (v."created_by" IS NOT NULL AND v."created_by" = _supatype.caller_id())
           OR (SELECT _supatype.sees_all_drafts())
           OR _supatype.preview_allows('talk', v."record_id"::text)
         )
    );
  $fn$;
GRANT EXECUTE ON FUNCTION _supatype."sees_draft_talk"(text) TO anon, authenticated, service_role;

DROP POLICY IF EXISTS "talk_draft_select" ON "public"."talk";
CREATE POLICY "talk_draft_select" ON "public"."talk"
  FOR SELECT USING (_supatype."sees_draft_talk"("id"::text));
COMMENT ON POLICY "talk_draft_select" ON "public"."talk" IS 'supatype:managed;kind=rls_policy;table=talk;fields=draft_select;v=1';

DROP POLICY IF EXISTS "talk_versions_insert" ON "public"."talk_versions";
CREATE POLICY "talk_versions_insert" ON "public"."talk_versions"
  FOR INSERT WITH CHECK (_supatype."can_edit_talk"("record_id"));
COMMENT ON POLICY "talk_versions_insert" ON "public"."talk_versions" IS 'supatype:managed;kind=rls_policy;table=talk_versions;fields=insert;v=1';

DROP POLICY IF EXISTS "talk_versions_update" ON "public"."talk_versions";
CREATE POLICY "talk_versions_update" ON "public"."talk_versions"
  FOR UPDATE USING (_supatype."can_edit_talk"("record_id")) WITH CHECK (_supatype."can_edit_talk"("record_id"));
COMMENT ON POLICY "talk_versions_update" ON "public"."talk_versions" IS 'supatype:managed;kind=rls_policy;table=talk_versions;fields=update;v=1';

GRANT INSERT, UPDATE ON "public"."talk_versions" TO authenticated;

CREATE OR REPLACE FUNCTION _supatype."talk_versions_guard"() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $fn$
  BEGIN
    IF TG_OP = 'INSERT' THEN
      -- Assigned here, not accepted from the caller. The snapshot table is exposed like any other
      -- table in the managed schema, so a direct insert has to be a draft save and nothing else:
      -- no forged published version, no renumbering over someone else's, no borrowed authorship.
      SELECT COALESCE(MAX(v."version"), 0) + 1 INTO NEW."version"
        FROM "public"."talk_versions" v WHERE v."record_id" = NEW."record_id";
      NEW."created_by" := _supatype.caller_id();
      -- A version is born a draft. Publishing it is `supatype.publish`, which is a separate act with
      -- a separate permission check.
      NEW."status" := 'draft';
      RETURN NEW;
    END IF;

    -- Only the publishing state may move: `status`, `published_locales`, `scheduled_locales`. A caller
    -- who can still edit the record must not be able to rewrite what an earlier version said, or
    -- the history stops being evidence of anything.
    NEW."data" := OLD."data";
    NEW."created_by" := OLD."created_by";
    NEW."created_at" := OLD."created_at";
    NEW."version" := OLD."version";
    NEW."record_id" := OLD."record_id";
    RETURN NEW;
  END;
  $fn$;

DROP TRIGGER IF EXISTS "talk_versions_guard" ON "public"."talk_versions";
CREATE TRIGGER "talk_versions_guard" BEFORE INSERT OR UPDATE ON "public"."talk_versions"
  FOR EACH ROW EXECUTE FUNCTION _supatype."talk_versions_guard"();

DROP VIEW IF EXISTS "draft"."talk";
CREATE VIEW "draft"."talk" WITH (security_invoker = true) AS
SELECT (jsonb_populate_record(NULL::"public"."talk", v."data")).*
  FROM (
    SELECT DISTINCT ON (pv."record_id") pv."record_id", pv."data"
      FROM "public"."talk_versions" pv
     ORDER BY pv."record_id", pv."version" DESC
  ) v;
GRANT SELECT ON "draft"."talk" TO authenticated, service_role;

-- Scheduled publishing and retention, if this database has a scheduler.
DO $cron$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
    RAISE NOTICE 'pg_cron is not installed here, so scheduled publishing and version pruning will not run on a timer. Everything else works. Call _supatype.run_due_publishes(), _supatype.prune_versions() and _supatype.prune_preview_links() from a scheduler of your own.';
    RETURN;
  END IF;

  -- Replaced rather than added to, so a push converges on one job per purpose instead of stacking a
  -- new one every time.
  PERFORM cron.unschedule(jobname)
     FROM cron.job
    WHERE jobname IN ('supatype-scheduled-publish', 'supatype-prune-versions');

  -- Every minute: the smallest useful granularity for "publish at nine", and the job does nothing
  -- but one indexed scan per versioned model when there is nothing due.
  PERFORM cron.schedule('supatype-scheduled-publish', '* * * * *',
    'SELECT _supatype.run_due_publishes()');

  -- Hourly: pruning is housekeeping, and running it every minute would spend more on the scan than
  -- it reclaims.
  -- One job for both kinds of housekeeping: they run at the same cadence and a second timer
  -- would be a second thing to notice had stopped.
  PERFORM cron.schedule('supatype-prune-versions', '0 * * * *',
    'SELECT _supatype.prune_versions(), _supatype.prune_preview_links()');
END;
$cron$;

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

CREATE OR REPLACE TRIGGER "page_updated_at_trigger"
BEFORE UPDATE ON "public"."page"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE OR REPLACE FUNCTION _platform.set_page_slug()
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

CREATE OR REPLACE TRIGGER "page_slug_trigger"
BEFORE INSERT OR UPDATE ON "public"."page"
FOR EACH ROW EXECUTE FUNCTION _platform.set_page_slug();

CREATE OR REPLACE TRIGGER "speaker_updated_at_trigger"
BEFORE UPDATE ON "public"."speaker"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE OR REPLACE FUNCTION _platform.set_speaker_slug()
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

CREATE OR REPLACE TRIGGER "speaker_slug_trigger"
BEFORE INSERT OR UPDATE ON "public"."speaker"
FOR EACH ROW EXECUTE FUNCTION _platform.set_speaker_slug();

CREATE OR REPLACE FUNCTION _platform.normalise_speaker_rich_text()
RETURNS TRIGGER AS $$
BEGIN
  NEW."bio" := CASE WHEN NEW."bio" IS NULL THEN NULL WHEN NEW."bio" ? 'root' THEN NEW."bio" WHEN jsonb_typeof(NEW."bio") <> 'object' THEN CASE WHEN NEW."bio" IS NULL THEN NULL WHEN NEW."bio" ? 'root' THEN NEW."bio" WHEN jsonb_typeof(NEW."bio") = 'string' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', (NEW."bio" #>> '{}')::text)))))) WHEN jsonb_typeof(NEW."bio") = 'array' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', COALESCE((SELECT string_agg(CASE jsonb_typeof(elem) WHEN 'string' THEN elem #>> '{}' ELSE elem::text END, E'\n') FROM jsonb_array_elements(NEW."bio") AS elem), '')::text)))))) ELSE jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', NEW."bio"::text::text)))))) END ELSE COALESCE((SELECT jsonb_object_agg(locale.key, CASE WHEN locale.value IS NULL THEN NULL WHEN locale.value ? 'root' THEN locale.value WHEN jsonb_typeof(locale.value) = 'string' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', (locale.value #>> '{}')::text)))))) WHEN jsonb_typeof(locale.value) = 'array' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', COALESCE((SELECT string_agg(CASE jsonb_typeof(elem) WHEN 'string' THEN elem #>> '{}' ELSE elem::text END, E'\n') FROM jsonb_array_elements(locale.value) AS elem), '')::text)))))) ELSE jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', locale.value::text::text)))))) END) FROM jsonb_each(NEW."bio") AS locale), NEW."bio") END;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER "speaker_rich_text_trigger"
BEFORE INSERT OR UPDATE ON "public"."speaker"
FOR EACH ROW EXECUTE FUNCTION _platform.normalise_speaker_rich_text();

CREATE OR REPLACE TRIGGER "room_updated_at_trigger"
BEFORE UPDATE ON "public"."room"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE OR REPLACE TRIGGER "talk_updated_at_trigger"
BEFORE UPDATE ON "public"."talk"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE OR REPLACE FUNCTION _platform.set_talk_slug()
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

CREATE OR REPLACE TRIGGER "talk_slug_trigger"
BEFORE INSERT OR UPDATE ON "public"."talk"
FOR EACH ROW EXECUTE FUNCTION _platform.set_talk_slug();

CREATE OR REPLACE FUNCTION _platform.normalise_talk_rich_text()
RETURNS TRIGGER AS $$
BEGIN
  NEW."abstract" := CASE WHEN NEW."abstract" IS NULL THEN NULL WHEN NEW."abstract" ? 'root' THEN NEW."abstract" WHEN jsonb_typeof(NEW."abstract") <> 'object' THEN CASE WHEN NEW."abstract" IS NULL THEN NULL WHEN NEW."abstract" ? 'root' THEN NEW."abstract" WHEN jsonb_typeof(NEW."abstract") = 'string' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', (NEW."abstract" #>> '{}')::text)))))) WHEN jsonb_typeof(NEW."abstract") = 'array' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', COALESCE((SELECT string_agg(CASE jsonb_typeof(elem) WHEN 'string' THEN elem #>> '{}' ELSE elem::text END, E'\n') FROM jsonb_array_elements(NEW."abstract") AS elem), '')::text)))))) ELSE jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', NEW."abstract"::text::text)))))) END ELSE COALESCE((SELECT jsonb_object_agg(locale.key, CASE WHEN locale.value IS NULL THEN NULL WHEN locale.value ? 'root' THEN locale.value WHEN jsonb_typeof(locale.value) = 'string' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', (locale.value #>> '{}')::text)))))) WHEN jsonb_typeof(locale.value) = 'array' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', COALESCE((SELECT string_agg(CASE jsonb_typeof(elem) WHEN 'string' THEN elem #>> '{}' ELSE elem::text END, E'\n') FROM jsonb_array_elements(locale.value) AS elem), '')::text)))))) ELSE jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', locale.value::text::text)))))) END) FROM jsonb_each(NEW."abstract") AS locale), NEW."abstract") END;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER "talk_rich_text_trigger"
BEFORE INSERT OR UPDATE ON "public"."talk"
FOR EACH ROW EXECUTE FUNCTION _platform.normalise_talk_rich_text();

CREATE OR REPLACE TRIGGER "sponsor_updated_at_trigger"
BEFORE UPDATE ON "public"."sponsor"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE OR REPLACE TRIGGER "attendee_updated_at_trigger"
BEFORE UPDATE ON "public"."attendee"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE OR REPLACE TRIGGER "ticket_updated_at_trigger"
BEFORE UPDATE ON "public"."ticket"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE OR REPLACE TRIGGER "_global_site_settings_updated_at_trigger"
BEFORE UPDATE ON "public"."_global_site_settings"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA _platform TO PUBLIC;

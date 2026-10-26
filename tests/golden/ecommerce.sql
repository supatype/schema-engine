-- ============================================================
-- FORWARD MIGRATION
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

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
    EXECUTE 'DROP VIEW IF EXISTS "draft"."customers"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."products"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."orders"';
    EXECUTE 'DROP VIEW IF EXISTS "draft"."order_items"';
  END IF;
END $$;

-- [safe] Create table: customers
CREATE TABLE IF NOT EXISTS "public"."customers" (
    "id" UUID CONSTRAINT "customers_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "email" TEXT NOT NULL CONSTRAINT "customers_email_key" UNIQUE CONSTRAINT "customers_email_check" CHECK ("email" ~* '^[^@]+@[^@]+\.[^@]+$'),
    "name" TEXT NOT NULL,
    "phone" TEXT,
    "address" JSONB,
    "stripeId" TEXT CONSTRAINT "customers_stripeId_key" UNIQUE,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "deleted_at" TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS "customers_deleted_at_idx" ON "public"."customers" USING btree ("deleted_at");

-- [safe] Create table: products
CREATE TABLE IF NOT EXISTS "public"."products" (
    "id" UUID CONSTRAINT "products_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL CONSTRAINT "products_slug_key" UNIQUE,
    "description" JSONB,
    "price" NUMERIC(10, 2) NOT NULL,
    "stock" INTEGER NOT NULL DEFAULT 0,
    "status" TEXT NOT NULL CONSTRAINT "products_status_check" CHECK ("status" IN ('active', 'archived', 'draft')) DEFAULT 'draft',
    "images" JSONB,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS "products_status_idx" ON "public"."products" USING btree ("status");

-- [safe] Create table: orders
CREATE TABLE IF NOT EXISTS "public"."orders" (
    "id" UUID CONSTRAINT "orders_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "customer_id" UUID,
    "status" TEXT NOT NULL CONSTRAINT "orders_status_check" CHECK ("status" IN ('pending', 'paid', 'shipped', 'delivered', 'cancelled')) DEFAULT 'pending',
    "total" NUMERIC(10, 2) NOT NULL,
    "notes" TEXT,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS "orders_customer_id_status_idx" ON "public"."orders" USING btree ("customer_id", "status");

-- [safe] Create table: order_items
CREATE TABLE IF NOT EXISTS "public"."order_items" (
    "id" UUID CONSTRAINT "order_items_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "order_id" UUID,
    "product_id" UUID,
    "quantity" INTEGER NOT NULL,
    "unitPrice" NUMERIC(10, 2) NOT NULL
);

-- Row-level affordance functions (PostgREST computed columns)
CREATE OR REPLACE FUNCTION "public"."can_read_customers"("customers" "public"."customers", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT _supatype.jwt_uid()) = "id"
      FROM (SELECT ($1).*) AS "customers";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_read_customers"("public"."customers", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_read_customers"("public"."customers", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_create_customers"("customers" "public"."customers", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT TRUE
      FROM (SELECT ($1).*) AS "customers";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_create_customers"("public"."customers", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_create_customers"("public"."customers", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_update_customers"("customers" "public"."customers", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT _supatype.jwt_uid()) = "id"
      FROM (SELECT ($1).*) AS "customers";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_update_customers"("public"."customers", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_update_customers"("public"."customers", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_delete_customers"("customers" "public"."customers", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT _supatype.jwt_role()) = 'admin'
      FROM (SELECT ($1).*) AS "customers";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_delete_customers"("public"."customers", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_delete_customers"("public"."customers", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_read_products"("products" "public"."products", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT TRUE
      FROM (SELECT ($1).*) AS "products";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_read_products"("public"."products", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_read_products"("public"."products", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_create_products"("products" "public"."products", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT _supatype.jwt_role()) = 'admin'
      FROM (SELECT ($1).*) AS "products";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_create_products"("public"."products", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_create_products"("public"."products", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_update_products"("products" "public"."products", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT _supatype.jwt_role()) = 'admin'
      FROM (SELECT ($1).*) AS "products";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_update_products"("public"."products", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_update_products"("public"."products", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_delete_products"("products" "public"."products", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT _supatype.jwt_role()) = 'admin'
      FROM (SELECT ($1).*) AS "products";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_delete_products"("public"."products", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_delete_products"("public"."products", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_read_orders"("orders" "public"."orders", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT EXISTS (SELECT 1 FROM "customers" WHERE "customers"."id" = "customer_id" AND (SELECT _supatype.jwt_uid()) = "customers"."id")
      FROM (SELECT ($1).*) AS "orders";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_read_orders"("public"."orders", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_read_orders"("public"."orders", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_create_orders"("orders" "public"."orders", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT EXISTS (SELECT 1 FROM "customers" WHERE "customers"."id" = "customer_id" AND (SELECT _supatype.jwt_uid()) = "customers"."id")
      FROM (SELECT ($1).*) AS "orders";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_create_orders"("public"."orders", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_create_orders"("public"."orders", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_update_orders"("orders" "public"."orders", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT _supatype.jwt_role()) = 'admin'
      FROM (SELECT ($1).*) AS "orders";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_update_orders"("public"."orders", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_update_orders"("public"."orders", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_delete_orders"("orders" "public"."orders", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT _supatype.jwt_role()) = 'admin'
      FROM (SELECT ($1).*) AS "orders";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_delete_orders"("public"."orders", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_delete_orders"("public"."orders", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_read_order_items"("order_items" "public"."order_items", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "order_items";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_read_order_items"("public"."order_items", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_read_order_items"("public"."order_items", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_create_order_items"("order_items" "public"."order_items", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "order_items";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_create_order_items"("public"."order_items", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_create_order_items"("public"."order_items", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_update_order_items"("order_items" "public"."order_items", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "order_items";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_update_order_items"("public"."order_items", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_update_order_items"("public"."order_items", boolean) TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION "public"."can_delete_order_items"("order_items" "public"."order_items", "not_in_graphql" boolean DEFAULT NULL)
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "order_items";
  $can$;
REVOKE ALL ON FUNCTION "public"."can_delete_order_items"("public"."order_items", boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "public"."can_delete_order_items"("public"."order_items", boolean) TO anon, authenticated, service_role;

-- reconciled objects
CREATE SCHEMA IF NOT EXISTS "_platform";
CREATE SCHEMA IF NOT EXISTS "supatype";
ALTER TABLE "public"."order_items" ADD CONSTRAINT "order_items_order_id_fkey" FOREIGN KEY ("order_id") REFERENCES "public"."orders" ("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "public"."order_items" ADD CONSTRAINT "order_items_product_id_fkey" FOREIGN KEY ("product_id") REFERENCES "public"."products" ("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "public"."orders" ADD CONSTRAINT "orders_customer_id_fkey" FOREIGN KEY ("customer_id") REFERENCES "public"."customers" ("id") ON DELETE RESTRICT ON UPDATE CASCADE;
CREATE OR REPLACE FUNCTION _platform.normalise_products_rich_text()
RETURNS TRIGGER AS $$
BEGIN
  NEW."description" := CASE WHEN NEW."description" IS NULL THEN NULL WHEN NEW."description" ? 'root' THEN NEW."description" WHEN jsonb_typeof(NEW."description") = 'string' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', (NEW."description" #>> '{}')::text)))))) WHEN jsonb_typeof(NEW."description") = 'array' THEN jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', COALESCE((SELECT string_agg(CASE jsonb_typeof(elem) WHEN 'string' THEN elem #>> '{}' ELSE elem::text END, E'\n') FROM jsonb_array_elements(NEW."description") AS elem), '')::text)))))) ELSE jsonb_build_object('root', jsonb_build_object('type', 'root', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'paragraph', 'version', 1, 'direction', 'ltr', 'format', '', 'indent', 0, 'children', jsonb_build_array(jsonb_build_object('type', 'text', 'version', 1, 'detail', 0, 'format', 0, 'mode', 'normal', 'style', '', 'text', NEW."description"::text::text)))))) END;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION _platform.set_products_slug()
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

CREATE OR REPLACE TRIGGER "customers_updated_at_trigger"
BEFORE UPDATE ON "public"."customers"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE OR REPLACE TRIGGER "orders_updated_at_trigger"
BEFORE UPDATE ON "public"."orders"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE OR REPLACE TRIGGER "products_rich_text_trigger"
BEFORE INSERT OR UPDATE ON "public"."products"
FOR EACH ROW EXECUTE FUNCTION _platform.normalise_products_rich_text();

CREATE OR REPLACE TRIGGER "products_slug_trigger"
BEFORE INSERT OR UPDATE ON "public"."products"
FOR EACH ROW EXECUTE FUNCTION _platform.set_products_slug();

CREATE OR REPLACE TRIGGER "products_updated_at_trigger"
BEFORE UPDATE ON "public"."products"
FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();

CREATE POLICY "customers_delete" ON "public"."customers"
FOR DELETE USING (
    (SELECT _supatype.jwt_role()) = 'admin'
  );
CREATE POLICY "customers_insert" ON "public"."customers"
FOR INSERT WITH CHECK (
    TRUE
  );
CREATE POLICY "customers_select" ON "public"."customers"
FOR SELECT USING (
    (SELECT _supatype.jwt_uid()) = "id"
  );
CREATE POLICY "customers_update" ON "public"."customers"
FOR UPDATE USING (
    (SELECT _supatype.jwt_uid()) = "id"
  ) WITH CHECK (
    (SELECT _supatype.jwt_uid()) = "id"
  );
CREATE POLICY "orders_delete" ON "public"."orders"
FOR DELETE USING (
    (SELECT _supatype.jwt_role()) = 'admin'
  );
CREATE POLICY "orders_insert" ON "public"."orders"
FOR INSERT WITH CHECK (
    EXISTS (SELECT 1 FROM "customers" WHERE "customers"."id" = "customer_id" AND (SELECT _supatype.jwt_uid()) = "customers"."id")
  );
CREATE POLICY "orders_select" ON "public"."orders"
FOR SELECT USING (
    EXISTS (SELECT 1 FROM "customers" WHERE "customers"."id" = "customer_id" AND (SELECT _supatype.jwt_uid()) = "customers"."id")
  );
CREATE POLICY "orders_update" ON "public"."orders"
FOR UPDATE USING (
    (SELECT _supatype.jwt_role()) = 'admin'
  ) WITH CHECK (
    (SELECT _supatype.jwt_role()) = 'admin'
  );
CREATE POLICY "products_delete" ON "public"."products"
FOR DELETE USING (
    (SELECT _supatype.jwt_role()) = 'admin'
  );
CREATE POLICY "products_insert" ON "public"."products"
FOR INSERT WITH CHECK (
    (SELECT _supatype.jwt_role()) = 'admin'
  );
CREATE POLICY "products_select" ON "public"."products"
FOR SELECT USING (
    TRUE
  );
CREATE POLICY "products_update" ON "public"."products"
FOR UPDATE USING (
    (SELECT _supatype.jwt_role()) = 'admin'
  ) WITH CHECK (
    (SELECT _supatype.jwt_role()) = 'admin'
  );
ALTER TABLE "public"."customers" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."order_items" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."orders" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."products" ENABLE ROW LEVEL SECURITY;
REVOKE ALL PRIVILEGES ON "public"."customers" FROM PUBLIC;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."customers" FROM anon';
    EXECUTE 'GRANT INSERT ON "public"."customers" TO anon';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."customers" FROM authenticated';
    EXECUTE 'GRANT DELETE, INSERT, SELECT, UPDATE ON "public"."customers" TO authenticated';
  END IF;
END
$grants$;
REVOKE ALL PRIVILEGES ON "public"."order_items" FROM PUBLIC;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."order_items" FROM anon';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."order_items" FROM authenticated';
  END IF;
END
$grants$;
REVOKE ALL PRIVILEGES ON "public"."orders" FROM PUBLIC;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."orders" FROM anon';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."orders" FROM authenticated';
    EXECUTE 'GRANT DELETE, INSERT, SELECT, UPDATE ON "public"."orders" TO authenticated';
  END IF;
END
$grants$;
REVOKE ALL PRIVILEGES ON "public"."products" FROM PUBLIC;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."products" FROM anon';
    EXECUTE 'GRANT SELECT ON "public"."products" TO anon';
  END IF;
END
$grants$;
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON "public"."products" FROM authenticated';
    EXECUTE 'GRANT DELETE, INSERT, SELECT, UPDATE ON "public"."products" TO authenticated';
  END IF;
END
$grants$;
ALTER TABLE "public"."customers" REPLICA IDENTITY FULL;
ALTER TABLE "public"."order_items" REPLICA IDENTITY FULL;
ALTER TABLE "public"."orders" REPLICA IDENTITY FULL;
ALTER TABLE "public"."products" REPLICA IDENTITY FULL;

COMMIT;
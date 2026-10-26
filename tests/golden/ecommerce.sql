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

COMMENT ON CONSTRAINT "customers_email_key" ON "public"."customers" IS 'supatype:managed;kind=unique_constraint;table=customers;fields=email;v=1';

COMMENT ON CONSTRAINT "customers_stripeId_key" ON "public"."customers" IS 'supatype:managed;kind=unique_constraint;table=customers;fields=stripeId;v=1';

CREATE INDEX IF NOT EXISTS "customers_deleted_at_idx" ON "public"."customers" USING btree ("deleted_at");

COMMENT ON TABLE "public"."customers" IS 'supatype:managed;kind=table;table=customers;fields=;v=1';

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

COMMENT ON CONSTRAINT "products_slug_key" ON "public"."products" IS 'supatype:managed;kind=unique_constraint;table=products;fields=slug;v=1';

CREATE INDEX IF NOT EXISTS "products_status_idx" ON "public"."products" USING btree ("status");

COMMENT ON TABLE "public"."products" IS 'supatype:managed;kind=table;table=products;fields=;v=1';

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

COMMENT ON TABLE "public"."orders" IS 'supatype:managed;kind=table;table=orders;fields=;v=1';

-- [safe] Create table: order_items
CREATE TABLE IF NOT EXISTS "public"."order_items" (
    "id" UUID CONSTRAINT "order_items_pkey" PRIMARY KEY DEFAULT gen_random_uuid(),
    "order_id" UUID,
    "product_id" UUID,
    "quantity" INTEGER NOT NULL,
    "unitPrice" NUMERIC(10, 2) NOT NULL
);

COMMENT ON TABLE "public"."order_items" IS 'supatype:managed;kind=table;table=order_items;fields=;v=1';

-- [safe] Enable RLS: customers
ALTER TABLE "public"."customers" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: products
ALTER TABLE "public"."products" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: orders
ALTER TABLE "public"."orders" ENABLE ROW LEVEL SECURITY;

-- [safe] Enable RLS: order_items
ALTER TABLE "public"."order_items" ENABLE ROW LEVEL SECURITY;

-- [safe] Create RLS policy: customers.customers_select
DROP POLICY IF EXISTS "customers_select" ON "public"."customers";
CREATE POLICY "customers_select" ON "public"."customers"
FOR SELECT USING (
    (SELECT auth.uid()) = "id"
  );

COMMENT ON POLICY "customers_select" ON "public"."customers" IS 'supatype:managed;kind=rls_policy;table=customers;fields=select;v=1';


-- [safe] Create RLS policy: customers.customers_insert
DROP POLICY IF EXISTS "customers_insert" ON "public"."customers";
CREATE POLICY "customers_insert" ON "public"."customers"
FOR INSERT WITH CHECK (
    TRUE
  );

COMMENT ON POLICY "customers_insert" ON "public"."customers" IS 'supatype:managed;kind=rls_policy;table=customers;fields=insert;v=1';


-- [safe] Create RLS policy: customers.customers_update
DROP POLICY IF EXISTS "customers_update" ON "public"."customers";
CREATE POLICY "customers_update" ON "public"."customers"
FOR UPDATE USING (
    (SELECT auth.uid()) = "id"
  ) WITH CHECK (
    (SELECT auth.uid()) = "id"
  );

COMMENT ON POLICY "customers_update" ON "public"."customers" IS 'supatype:managed;kind=rls_policy;table=customers;fields=update;v=1';


-- [safe] Create RLS policy: customers.customers_delete
DROP POLICY IF EXISTS "customers_delete" ON "public"."customers";
CREATE POLICY "customers_delete" ON "public"."customers"
FOR DELETE USING (
    (SELECT auth.role()) = 'admin'
  );

COMMENT ON POLICY "customers_delete" ON "public"."customers" IS 'supatype:managed;kind=rls_policy;table=customers;fields=delete;v=1';


-- [safe] Create RLS policy: products.products_select
DROP POLICY IF EXISTS "products_select" ON "public"."products";
CREATE POLICY "products_select" ON "public"."products"
FOR SELECT USING (
    TRUE
  );

COMMENT ON POLICY "products_select" ON "public"."products" IS 'supatype:managed;kind=rls_policy;table=products;fields=select;v=1';


-- [safe] Create RLS policy: products.products_insert
DROP POLICY IF EXISTS "products_insert" ON "public"."products";
CREATE POLICY "products_insert" ON "public"."products"
FOR INSERT WITH CHECK (
    (SELECT auth.role()) = 'admin'
  );

COMMENT ON POLICY "products_insert" ON "public"."products" IS 'supatype:managed;kind=rls_policy;table=products;fields=insert;v=1';


-- [safe] Create RLS policy: products.products_update
DROP POLICY IF EXISTS "products_update" ON "public"."products";
CREATE POLICY "products_update" ON "public"."products"
FOR UPDATE USING (
    (SELECT auth.role()) = 'admin'
  ) WITH CHECK (
    (SELECT auth.role()) = 'admin'
  );

COMMENT ON POLICY "products_update" ON "public"."products" IS 'supatype:managed;kind=rls_policy;table=products;fields=update;v=1';


-- [safe] Create RLS policy: products.products_delete
DROP POLICY IF EXISTS "products_delete" ON "public"."products";
CREATE POLICY "products_delete" ON "public"."products"
FOR DELETE USING (
    (SELECT auth.role()) = 'admin'
  );

COMMENT ON POLICY "products_delete" ON "public"."products" IS 'supatype:managed;kind=rls_policy;table=products;fields=delete;v=1';


-- [safe] Create RLS policy: orders.orders_select
DROP POLICY IF EXISTS "orders_select" ON "public"."orders";
CREATE POLICY "orders_select" ON "public"."orders"
FOR SELECT USING (
    EXISTS (SELECT 1 FROM "customers" WHERE "customers"."id" = "customer_id" AND (SELECT auth.uid()) = "customers"."id")
  );

COMMENT ON POLICY "orders_select" ON "public"."orders" IS 'supatype:managed;kind=rls_policy;table=orders;fields=select;v=1';


-- [safe] Create RLS policy: orders.orders_insert
DROP POLICY IF EXISTS "orders_insert" ON "public"."orders";
CREATE POLICY "orders_insert" ON "public"."orders"
FOR INSERT WITH CHECK (
    EXISTS (SELECT 1 FROM "customers" WHERE "customers"."id" = "customer_id" AND (SELECT auth.uid()) = "customers"."id")
  );

COMMENT ON POLICY "orders_insert" ON "public"."orders" IS 'supatype:managed;kind=rls_policy;table=orders;fields=insert;v=1';


-- [safe] Create RLS policy: orders.orders_update
DROP POLICY IF EXISTS "orders_update" ON "public"."orders";
CREATE POLICY "orders_update" ON "public"."orders"
FOR UPDATE USING (
    (SELECT auth.role()) = 'admin'
  ) WITH CHECK (
    (SELECT auth.role()) = 'admin'
  );

COMMENT ON POLICY "orders_update" ON "public"."orders" IS 'supatype:managed;kind=rls_policy;table=orders;fields=update;v=1';


-- [safe] Create RLS policy: orders.orders_delete
DROP POLICY IF EXISTS "orders_delete" ON "public"."orders";
CREATE POLICY "orders_delete" ON "public"."orders"
FOR DELETE USING (
    (SELECT auth.role()) = 'admin'
  );

COMMENT ON POLICY "orders_delete" ON "public"."orders" IS 'supatype:managed;kind=rls_policy;table=orders;fields=delete;v=1';


-- Row-level affordance functions (PostgREST computed columns)
CREATE OR REPLACE FUNCTION "public"."can_read_customers"("customers" "public"."customers")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.uid()) = "id"
      FROM (SELECT ($1).*) AS "customers";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_customers"("customers" "public"."customers")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT TRUE
      FROM (SELECT ($1).*) AS "customers";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_customers"("customers" "public"."customers")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.uid()) = "id"
      FROM (SELECT ($1).*) AS "customers";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_customers"("customers" "public"."customers")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'admin'
      FROM (SELECT ($1).*) AS "customers";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_products"("products" "public"."products")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT TRUE
      FROM (SELECT ($1).*) AS "products";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_products"("products" "public"."products")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'admin'
      FROM (SELECT ($1).*) AS "products";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_products"("products" "public"."products")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'admin'
      FROM (SELECT ($1).*) AS "products";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_products"("products" "public"."products")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'admin'
      FROM (SELECT ($1).*) AS "products";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_orders"("orders" "public"."orders")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT EXISTS (SELECT 1 FROM "customers" WHERE "customers"."id" = "customer_id" AND (SELECT auth.uid()) = "customers"."id")
      FROM (SELECT ($1).*) AS "orders";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_orders"("orders" "public"."orders")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT EXISTS (SELECT 1 FROM "customers" WHERE "customers"."id" = "customer_id" AND (SELECT auth.uid()) = "customers"."id")
      FROM (SELECT ($1).*) AS "orders";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_orders"("orders" "public"."orders")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'admin'
      FROM (SELECT ($1).*) AS "orders";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_orders"("orders" "public"."orders")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT (SELECT auth.role()) = 'admin'
      FROM (SELECT ($1).*) AS "orders";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_read_order_items"("order_items" "public"."order_items")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "order_items";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_create_order_items"("order_items" "public"."order_items")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "order_items";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_update_order_items"("order_items" "public"."order_items")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "order_items";
  $can$;

CREATE OR REPLACE FUNCTION "public"."can_delete_order_items"("order_items" "public"."order_items")
  RETURNS boolean LANGUAGE sql STABLE AS $can$
    SELECT FALSE
      FROM (SELECT ($1).*) AS "order_items";
  $can$;

-- Table privileges derived from access rules (defence in depth)
DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE SELECT ON "public"."customers" FROM anon';
    EXECUTE 'GRANT INSERT ON "public"."customers" TO anon';
    EXECUTE 'REVOKE UPDATE ON "public"."customers" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."customers" FROM anon';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'GRANT SELECT ON "public"."customers" TO authenticated';
    EXECUTE 'GRANT INSERT ON "public"."customers" TO authenticated';
    EXECUTE 'GRANT UPDATE ON "public"."customers" TO authenticated';
    EXECUTE 'GRANT DELETE ON "public"."customers" TO authenticated';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'GRANT SELECT ON "public"."products" TO anon';
    EXECUTE 'REVOKE INSERT ON "public"."products" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."products" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."products" FROM anon';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'GRANT SELECT ON "public"."products" TO authenticated';
    EXECUTE 'GRANT INSERT ON "public"."products" TO authenticated';
    EXECUTE 'GRANT UPDATE ON "public"."products" TO authenticated';
    EXECUTE 'GRANT DELETE ON "public"."products" TO authenticated';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE SELECT ON "public"."orders" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."orders" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."orders" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."orders" FROM anon';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'GRANT SELECT ON "public"."orders" TO authenticated';
    EXECUTE 'GRANT INSERT ON "public"."orders" TO authenticated';
    EXECUTE 'GRANT UPDATE ON "public"."orders" TO authenticated';
    EXECUTE 'GRANT DELETE ON "public"."orders" TO authenticated';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    EXECUTE 'REVOKE SELECT ON "public"."order_items" FROM anon';
    EXECUTE 'REVOKE INSERT ON "public"."order_items" FROM anon';
    EXECUTE 'REVOKE UPDATE ON "public"."order_items" FROM anon';
    EXECUTE 'REVOKE DELETE ON "public"."order_items" FROM anon';
  END IF;
END
$grants$;

DO $grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    EXECUTE 'REVOKE SELECT ON "public"."order_items" FROM authenticated';
    EXECUTE 'REVOKE INSERT ON "public"."order_items" FROM authenticated';
    EXECUTE 'REVOKE UPDATE ON "public"."order_items" FROM authenticated';
    EXECUTE 'REVOKE DELETE ON "public"."order_items" FROM authenticated';
  END IF;
END
$grants$;

-- reconciled objects
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


COMMIT;
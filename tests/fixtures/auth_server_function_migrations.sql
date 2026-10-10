-- The auth server's own replacements of the auth.* helpers, as it applies them on first boot.
--
-- Copied from supatype-auth (commit 87a0939d) `migrations/`, with `{{ index .Options "Namespace" }}`
-- rendered as its default, `auth`:
--   20220224000811_update_auth_functions.up.sql  (uid, role, email)
--   20220531120530_add_auth_jwt_function.up.sql  (jwt)
-- On a fresh stack these run about ten seconds after the engine's first push, so whatever the push
-- installed under these names is replaced by this.

-- 20220224000811_update_auth_functions

create or replace function auth.uid()
returns uuid
language sql stable
as $$
  select
  coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;

create or replace function auth.role()
returns text
language sql stable
as $$
  select
  coalesce(
    nullif(current_setting('request.jwt.claim.role', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role')
  )::text
$$;

create or replace function auth.email()
returns text
language sql stable
as $$
  select
  coalesce(
    nullif(current_setting('request.jwt.claim.email', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'email')
  )::text
$$;

-- 20220531120530_add_auth_jwt_function

comment on function auth.uid() is 'Deprecated. Use auth.jwt() -> ''sub'' instead.';
comment on function auth.role() is 'Deprecated. Use auth.jwt() -> ''role'' instead.';
comment on function auth.email() is 'Deprecated. Use auth.jwt() -> ''email'' instead.';

create or replace function auth.jwt()
returns jsonb
language sql stable
as $$
  select
    coalesce(
        nullif(current_setting('request.jwt.claim', true), ''),
        nullif(current_setting('request.jwt.claims', true), '')
    )::jsonb
$$;

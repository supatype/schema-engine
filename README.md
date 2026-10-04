# Supatype Schema Engine

The schema engine that powers [Supatype](https://supatype.com): **define your types, we generate your backend.**

Built in Rust. The engine consumes an **AST v2** JSON document and turns it into Postgres migrations,
RLS policies, table grants and column privileges, typed client code in seven languages, an OpenAPI
spec, PostgREST and Kong config, Studio metadata and admin panel config.

The AST is not written by hand. A developer writes TypeScript types using the primitives in
`@supatype/types`, and `@supatype/cli` extracts them into the wire format this engine reads
(`type-extractor.ts` builds it, `schema-ast-v2.ts` defines and emits it). The CLI then invokes this
binary as a subprocess, writing the AST to a temp file and passing it with `--input`.

## How it works

```
AST v2 JSON ──► v2::deserialize ──► validator ──► resolver ──► normaliser ──► SchemaAst
                                                                                  │
                                                                                  ├──► generators (SQL, TS, SDKs, OpenAPI, config, Studio)
                                                                                  │
Database  ◄── push/migrate ◄── differ ◄────────────────────────────────────────────┤
                                 ▲                                                │
                    introspector ─┴── DatabaseState ◄─────────────────────────────┘
```

1. **Parse** (`src/parser`). Deserialise AST v2, validate it, resolve relations into junction tables
   and `image`/`file` fields into storage buckets, then normalise: snake-case table names, fill
   defaults.
2. **Introspect** (`src/introspector`). Read the live database: tables, columns, indexes,
   constraints, enums, RLS policies, triggers, extensions.
3. **Diff** (`src/differ`). Compare desired schema against database state to produce operations,
   each tagged `safe`, `cautious` or `destructive`. Column renames are detected with Jaro-Winkler
   similarity, and operations are topologically sorted (petgraph).
4. **Apply** (`push`) or **render** (`migrate`). `push` runs the migration inside a transaction and
   records it in migration history; `migrate` prints the SQL and applies nothing.
5. **Generate**. Emit code and config from the AST alone, with no database needed.

### Annotation namespaces

AST v2 separates what a field *is* from what each consumer does with it. `kind`, `required`,
`default` and relation facts live on the field; everything else sits under `annotations`:

* `annotations.db`: `pgType`, `tableName`, `unique`, `index`, `foreignKey`, `indexes`, and
  model-level `constraints`.
* `annotations.platform`: `access` rules, editor hints, field-level access.

The helpers in `src/parser/accessors.rs` are the sanctioned way to reach into them.

## What the engine owns

Objects the engine creates carry a `supatype:managed` Postgres comment (`src/managed.rs`). This is
load-bearing rather than decorative: it is how `doctor` distinguishes an index the engine created
from one a developer added by hand, and it is why the engine will not silently drop or reshape
objects that are not its own. Managed check constraints also carry a **fingerprint** of the
generated expression, because Postgres rewrites check expressions on read-back and comparing SQL
text would report a spurious difference on every push.

Reserved schemas:

| Schema | Contents |
|---|---|
| `_supatype` | Migration history, schema state cache, schema source snapshots. Never introspected or diffed. |
| `supatype` | Studio state (dashboard views) and stats functions. Reachable through PostgREST when listed in `db-schemas`. |
| `auth` | Auth helper functions (`auth.uid`, `auth.role`, `auth.email`, `auth.jwt`). Schema name is configurable. |
| `_sso` | SSO / OIDC provider tables and their RLS. |
| `api` | Generated masking views, when field masking runs in tier 2 (see below). |
| `draft` | `security_invoker` views reconstructing a versioned model's shape from its snapshot. |

## Commands

Two binaries ship from this crate: `supatype-engine`, which the Supatype CLI shells out to, and
`supatype-engine-server`, an HTTP wrapper over the same code.

### Database commands

| Command | Description |
|---|---|
| `introspect` | Read current database state as JSON |
| `diff` | Compute operations between the AST and the database |
| `migrate` | Render migration SQL without applying it |
| `push` | Apply the schema and record it in migration history |
| `migrations` | List recorded migrations, or fetch one migration's schema source snapshot |
| `rollback` | Roll back the last applied migration |
| `doctor` | Report drift between the AST and the live database (read only) |
| `adopt` | Stamp managed comments on existing objects that match the AST |

### Compute-only commands

These read the AST and need no database connection.

| Command | Description |
|---|---|
| `parse` | Parse and validate an AST, printing the resolved form |
| `generate` | Typed client code. `--lang typescript` (default), `python`, `go`, `php`, `swift`, `kotlin`, `dart` |
| `rls` | RLS policy SQL plus auth helpers |
| `triggers` | Trigger SQL (`updated_at`, slug generation) |
| `storage` | Storage bucket DDL and storage RLS |
| `postgrest` | PostgREST configuration |
| `admin` | Admin panel configuration JSON |
| `auth-functions` | Auth helper SQL functions, with `--project-ref` and `--auth-schema` |
| `sso` | SSO / OIDC provider schema SQL |
| `studio` | Studio metadata JSON for the Visual Schema Designer |
| `openapi` | OpenAPI 3.0 specification |

Table grants, column privileges and check constraints have no subcommand of their own: they are
emitted as part of `push` and `migrate`. Run `supatype-engine --help` for the authoritative list.

## Usage

Input is read from a file (`-i path`) or stdin (the default). Output goes to stdout.

```bash
# Parse and validate a schema
supatype-engine parse -i schema.json

# Diff against a live database
supatype-engine diff -i schema.json --database-url "$DATABASE_URL"

# Render a migration without applying it
supatype-engine migrate -i schema.json --database-url "$DATABASE_URL"

# Apply the schema and record it
supatype-engine push -i schema.json --database-url "$DATABASE_URL" --name "add posts"

# Apply in CI: no prompts, fail on any residual drift
supatype-engine push -i schema.json --database-url "$DATABASE_URL" --non-interactive --strict

# Report drift, exit non-zero when managed objects are missing or stale
supatype-engine doctor -i schema.json --database-url "$DATABASE_URL" --strict

# Take ownership of pre-existing tables that match the schema
supatype-engine adopt -i schema.json --database-url "$DATABASE_URL" --yes

# Generate typed clients
supatype-engine generate -i schema.json
supatype-engine generate -i schema.json --lang swift
```

### Global flags

| Flag | Description |
|---|---|
| `-i, --input <path>` | Input file path, or `-` for stdin (default) |
| `-o, --output <path>` | Output file path, or `-` for stdout (default) |
| `--log <level>` | Log level filter, written to stderr (default `warn`) |
| `--license <key>` | License key for gated features |

Database commands take `--database-url`, which also reads `DATABASE_URL`. All of them except
`migrations` also take `--schema` (default `public`).

### Push flags

| Flag | Description |
|---|---|
| `--force` | Allow destructive operations without prompting |
| `--non-interactive` | Skip rename and risk confirmation prompts, for CI |
| `--name <name>` | Human-readable name for the migration record |
| `--no-cache` | Bypass the schema state cache and do a full introspection |
| `--strict` | Fail the push when post-apply drift remains |
| `--schema-sources-gz <path>` | Gzipped tar of the schema source files, stored with the migration |
| `--schema-sources-manifest <path>` | Manifest JSON describing those sources |

Push reads `DatabaseState` from the `_supatype` schema state cache unless `--no-cache` is given, and
loads the previous AST snapshot from the same place. That previous snapshot is what makes kind-only
migrations possible: `json` to `richText` leaves the column JSONB, so nothing in the database itself
says the kind changed.

## Column type migrations

Every column type or kind change is classified through the conversion registry
(`src/generator/sql/column_conversion.rs`):

| Strategy | Risk | Behaviour |
|---|---|---|
| `SafeCast` | safe | Widening casts (`int2` to `int8`, `varchar` to `text`) |
| `TransformCast` | cautious | A custom `USING` preserves or reshapes the data (`text` to `richText`, `integer` to `json` via `to_jsonb`) |
| `KindMigrate` | cautious | Postgres type unchanged: `UPDATE` the rows, then a no-op `ALTER` (`json` to `richText` on JSONB) |
| `RecreateColumn` | destructive | Drop FKs and indexes, drop the column, add it back empty. Data loss. |
| `Blocked` | n/a | The diff bails with the reason rather than producing an operation (`richText` to `blocks`). Reached only when the Postgres type also changes. |

An interactive `push` prompts for cautious and destructive conversions. Non-interactive callers need
`--force` for anything destructive.

The conversion matrix is covered by `tests/evolution_tests.rs`,
`tests/migration_conversion_integration.rs` and `tests/column_type_match_tests.rs`.

## Field-level access

Model access rules (`read`, `create`, `update`, `delete`) compile to RLS policies. Rules declared on
individual fields compile to masking, and which mechanism enforces it is decided from the
introspected extension list rather than from configuration:

* **Tier 1**, when `supatype_mask` is installed: the extension rewrites references to the base table
  in the planner. It needs `shared_preload_libraries` and a restart, so it is available on
  Supatype's own Postgres image and not on a managed provider.
* **Tier 2**, otherwise: the same masking expression goes into `api` schema view definitions, and
  PostgREST is pointed at `api` instead of the managed schema.

Both tiers are held to one behavioural contract, written once in
`tests/field_access_contract_tests.rs` and run per tier. The one place they diverge is aggregates
over a masked column, documented in `src/generator/sql/field_views.rs` along with why that
divergence is unreachable through the API.

Table grants are derived from the same rules (`src/generator/sql/grants.rs`). A privilege is revoked
only when the rules prove it can never be used, and `service_role` is never touched.

`src/differ/field_access_diff.rs` refuses a diff where a required column has no default and no rule
that permits writing it, because the runtime symptom is a not-null violation pointing at the one
thing that is not the problem.

## Versions, drafts and publishing

A model that declares `versions` keeps its own table as the **published** state and stores snapshots
in a companion `<table>_versions` table, one of which may be a newer draft. Constraints, foreign
keys, indexes, access rules and realtime on the model's table are therefore untouched, which is what
lets a published version stay live while an unpublished newer one exists.

Draft visibility is not the model's `read` rule and not its `update` rule. It is the record's
creator, plus the Studio roles the project nominates, plus the bearer of a signed preview link. See
`src/generator/sql/versions.rs`.

## Server binary

`supatype-engine-server` exposes the same operations over HTTP.

```bash
ENGINE_ADMIN_TOKEN=<token> supatype-engine-server
```

| Variable | Default | Purpose |
|---|---|---|
| `ENGINE_PORT` | `7500` | Listen port |
| `ENGINE_BIND` | `127.0.0.1` | Bind address |
| `ENGINE_ADMIN_TOKEN` | none | Required. Every route rejects a request without a matching `X-Engine-Admin-Token`, and returns `503` when the variable is unset. |
| `RUST_LOG` | `info` | Tracing filter |

Routes mirror the subcommands. Compute only: `/parse`, `/generate`, `/triggers`, `/rls`, `/storage`,
`/postgrest`, `/auth-functions`, `/sso`, `/admin`, `/studio`, `/openapi`. Database backed:
`/introspect`, `/diff`, `/migrate`, `/push`, `/migrations`, `/rollback`, `/doctor`,
`/adopt`, `/studio-config`, `/sql`. `/health` sits behind the admin token as well.

A Docker image is published as `supatype/schema-engine`, built from the `Dockerfile` in this repo
and entrypointed on the server binary.

## WASM

The library compiles to `wasm32-unknown-unknown` so the compute-only path can run in a browser.
`src/wasm.rs` exports `wasm_parse`, `wasm_generate_typescript`, `wasm_generate_openapi` and the SDK
generators, all JSON in and string out. `differ`, `introspector`, `state` and `server` are gated off
that target because they depend on sqlx and tokio, and CI checks the WASM build so the gating cannot
rot.

## Schema AST format

`astVersion` is `2`. A minimal example, matching `tests/fixtures/basic_blog.json`:

```json
{
  "astVersion": 2,
  "models": [
    {
      "name": "Post",
      "fields": {
        "id": {
          "kind": "uuid",
          "required": true,
          "default": { "kind": "genRandomUuid" },
          "annotations": { "db": { "pgType": "UUID", "unique": false, "index": false } }
        },
        "title": {
          "kind": "text",
          "required": true,
          "annotations": { "db": { "pgType": "TEXT", "unique": false, "index": false } }
        },
        "slug": {
          "kind": "slug",
          "required": true,
          "from": "title",
          "annotations": { "db": { "pgType": "TEXT", "unique": true } }
        },
        "authorId": {
          "kind": "relation",
          "cardinality": "belongsTo",
          "target": "User",
          "onDelete": "cascade",
          "annotations": { "db": { "foreignKey": "author_id" } }
        }
      },
      "options": { "timestamps": true, "softDelete": false },
      "annotations": {
        "db": { "tableName": "posts", "indexes": [] },
        "platform": {
          "access": {
            "read": { "type": "public" },
            "create": { "type": "role", "roles": ["admin", "editor"] },
            "update": { "type": "owner", "field": "authorId" },
            "delete": { "type": "role", "roles": ["admin"] }
          }
        }
      }
    }
  ]
}
```

The top-level document also carries `junctionTables` and `storageBuckets` (both inferred by the
resolver rather than written by the user), `locales` and `defaultLocale`, `plugins`, `sso`,
`publishing` and `warnings`.

**Field kinds** are a closed registry, defined as `FIELD_KINDS` in the CLI's `schema-ast-v2.ts`:

```
text email url slug color xml ip cidr macaddr tsQuery tsVector richText bytes
integer smallInt bigInt float serial bigSerial decimal money
datetime timestamp date interval
array blocks json button enum boolean uuid image file geo vector
relation custom timestamps publishable softDelete
```

Relations support `belongsTo`, `hasMany`, `hasOne` and `manyToMany`. Junction tables for
many-to-many are inferred automatically.

Fixtures under `tests/fixtures/` cover the harder shapes: `many_to_many`, `self_referential`,
`saas_multi_tenant`, `rls_access_rules`, `rls_field_rules`, `versioned_blog`, `vector_search`,
`geospatial`, `soft_delete`, `cms_content`, `ecommerce`, `kitchen_sink`.

## Project structure

```
src/
├── main.rs                CLI entry point
├── server_main.rs         HTTP server entry point (admin-token middleware, routing)
├── lib.rs                 Library root, WASM gating
├── wasm.rs                WASM exports
├── managed.rs             supatype:managed comments, naming, check fingerprints
├── parser/                AST v2 JSON to SchemaAst
│   ├── v2.rs              Wire format deserialise and serialise
│   ├── ast.rs             Core types (SchemaAst, ModelAst, FieldAst, VersionsAst, …)
│   ├── annotations.rs     db / platform annotation namespaces
│   ├── accessors.rs       Sanctioned reads into annotations
│   ├── validator.rs       Schema validation rules
│   ├── resolver.rs        Junction tables, storage buckets, plugin API compatibility
│   └── normaliser.rs      Snake-case table names, fill defaults
├── introspector/          Postgres to DatabaseState (tables, columns, indexes,
│                          constraints, enums, RLS, triggers, extensions)
├── differ/                SchemaAst x DatabaseState to DiffOutput
│   ├── table_diff.rs         Create and drop tables
│   ├── column_diff.rs        Add, drop, rename, retype columns
│   ├── enum_diff.rs          Enum type changes
│   ├── index_diff.rs         Index changes
│   ├── constraint_diff.rs    Constraint changes
│   ├── check_diff.rs         Field bound and model constraint changes
│   ├── rls_diff.rs           RLS policy changes
│   ├── field_access_diff.rs  Unwritable required columns
│   ├── trigger_diff.rs       Trigger changes
│   ├── ordering.rs           Topological sort (petgraph)
│   ├── risk_analyser.rs      Pre-flight safety validation
│   ├── doctor.rs             Drift report: missing, stale managed, unmanaged
│   └── integrity.rs          Post-push drift warnings
├── generator/
│   ├── sql/               Migration DDL, RLS, grants, constraints, triggers, storage,
│   │                      auth functions, SSO, field views, versions, rollback,
│   │                      column conversion registry
│   ├── typescript/        Row and Insert types, client, admin config
│   ├── sdk/               python, go, php, swift, kotlin, dart
│   ├── openapi/           OpenAPI 3.0 spec
│   ├── studio/            Studio metadata JSON
│   └── config/            PostgREST, Kong
├── state/                 DatabaseState, target state, migration history, Studio state
├── server/                Axum route handlers and request / response types
└── licensing/             Tier definitions (Community / Pro / Enterprise)
```

Licensing currently resolves every key to `Community`; key validation is not implemented, so no
feature is gated in practice. `src/licensing/features.rs` holds the intended tier per feature.

## Building

Requires the stable Rust toolchain, pinned by `rust-toolchain.toml`.

```bash
cargo build --release
```

The release profile uses thin LTO, four codegen units and symbol stripping.

### Cross-compilation targets

`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`,
`aarch64-apple-darwin`, `x86_64-pc-windows-msvc`.

## Testing

```bash
# Unit and library tests
cargo test --lib

# One suite
cargo test --test evolution_tests

# Integration suites (need a database)
DATABASE_URL=postgres://supatype_admin:postgres@localhost:5432/postgres \
SUPATYPE_FORCE_INTEGRATION_TESTS=1 \
  cargo test --test integration_test
```

Integration tests run against **`supatype/postgres`**, the same image as local dev and self-host,
because they need PostGIS, pgvector and `supatype_mask`. Override the tag with
`INTEGRATION_POSTGRES_IMAGE`.

* When `DATABASE_URL` is set, each test gets an ephemeral database via `CREATE DATABASE` /
  `DROP DATABASE`. The user needs `CREATEDB`.
* Otherwise the harness starts `supatype/postgres` through testcontainers, which needs Docker.
* `SUPATYPE_FORCE_INTEGRATION_TESTS=1` turns a skip into a failure. Without it, a suite that cannot
  reach a database returns early and reports green having asserted nothing. CI always sets it.

`tests/ci_coverage_tests.rs` fails the build when a file in `tests/` is not named in a CI job's
`--test` list, because `cargo test --test X` builds only the targets it names, and 15 of 24 suites
were once silently dead on main for exactly that reason. Adding a suite means adding it to a job and
choosing which: the unit job has no database, the integration job does.

## CI / CD

**CI** (`.github/workflows/ci.yml`), on every push and PR to `main`:

| Job | What it runs |
|---|---|
| Check & Lint | `cargo check --all-targets`, `cargo fmt --check`, `cargo clippy -- -D warnings`, and `cargo check --lib --target wasm32-unknown-unknown` |
| Unit & Evolution Tests | `cargo test --lib` plus every non-database suite |
| SDK Exec Tests | Generated SDKs compiled and executed on Linux and macOS against real Python, Go, PHP, Swift, Kotlin and Dart toolchains |
| Integration Tests | Every database suite against `supatype/postgres:17-latest` |

**Release** (`.github/workflows/release.yml`), triggered by `v*` tags:

1. Refuse to proceed unless the tag matches the `Cargo.toml` version. `ENGINE_VERSION` is baked in
   from `CARGO_PKG_VERSION` by `build.rs` and reported by both binaries, so a drift between tag and
   manifest is a lie the CLI would believe.
2. Run the test suite.
3. Build all five targets (Linux arm64 via `cross`) and strip them.
4. Generate `checksums.sha256` and sign it with minisign.
5. Upload binaries, checksums and signature to the CDN under `engine/v<version>/`, then rewrite
   `engine/latest.json`.
6. Create the GitHub Release, marking any tag containing `-` as a prerelease.
7. Publish the multi-platform Docker image.

See `docs/release-process.md` for the checklist and minisign key handling.

## License

Proprietary. All rights reserved.

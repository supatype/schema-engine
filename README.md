# Supatype Schema Engine

The schema engine that powers [Supatype](https://supatype.com) — **define your types, we generate your backend.**

Built in Rust, the engine consumes a JSON AST produced by the `@supatype/schema` TypeScript package and turns it into Postgres migrations, TypeScript types, RLS policies, PostgREST config, and admin panel config. It targets frontend developers who think in data shapes rather than SQL.

## How It Works

```
Schema JSON AST ──► Parser ──► Validator ──► Resolver ──► Normaliser ──► SchemaAst
                                                                            │
Database  ◄── Migrate ◄── Diff ◄────────────────────────────────────────────┤
                                                                            │
                           Introspector ──► DatabaseState ──────────────────►┘
```

1. **Parse** — Deserialise and validate the JSON AST that `@supatype/schema` emits.
2. **Introspect** — Read the live Postgres database (tables, columns, indexes, constraints, RLS, triggers, extensions).
3. **Diff** — Compare the desired schema against the current database state to produce a set of operations, each tagged with a risk level (safe / cautious / destructive). Column renames are detected via Jaro–Winkler similarity, and operations are topologically sorted.
4. **Migrate** — Generate a forward SQL migration (wrapped in a transaction, SHA-256 hashed) from the diff.
5. **Generate** — Emit TypeScript `Row` and `Insert` interfaces, RLS policy SQL, PostgREST config, or admin panel JSON.

## Commands

| Command | Description |
|---|---|
| `parse` | Parse and validate a schema AST |
| `introspect` | Read current database state |
| `diff` | Compute diff between target schema and database |
| `migrate` | Generate and apply SQL migration from diff |
| `generate` | Generate TypeScript type definitions |
| `rls` | Generate RLS policy SQL |
| `postgrest` | Generate PostgREST configuration |
| `admin` | Generate admin panel configuration JSON |
| `validate` | Validate a migration is safe to apply |

## Usage

Input is read from a file (`-i path`) or stdin (default). Output goes to stdout.

```bash
# Parse and validate a schema
supatype-engine parse -i schema.json

# Diff against a live database
supatype-engine diff -i schema.json --database-url "$DATABASE_URL"

# Generate a migration
supatype-engine migrate -i schema.json --database-url "$DATABASE_URL"

# Allow destructive operations without prompting
supatype-engine migrate -i schema.json --database-url "$DATABASE_URL" --force

# Generate TypeScript types
supatype-engine generate -i schema.json

# Generate RLS policies
supatype-engine rls -i schema.json

# Introspect an existing database
supatype-engine introspect --database-url "$DATABASE_URL"
```

Global flags:

| Flag | Description |
|---|---|
| `-i, --input <path>` | Input file path, or `-` for stdin (default) |
| `-o, --output <path>` | Output file path, or `-` for stdout (default) |
| `--log <level>` | Log level filter (default: `warn`) |
| `--license <key>` | License key for gated features |

## Schema Format

Schemas are defined in TypeScript with `@supatype/schema` and compiled to a JSON AST that the engine consumes. A minimal example:

```json
{
  "models": [
    {
      "name": "User",
      "tableName": "users",
      "fields": {
        "id": { "kind": "uuid", "pgType": "UUID", "required": true, "unique": false, "default": { "kind": "genRandomUuid" } },
        "email": { "kind": "email", "pgType": "TEXT", "required": true, "unique": true },
        "name": { "kind": "text", "pgType": "TEXT", "required": true }
      },
      "access": {
        "read": { "type": "public" },
        "create": { "type": "role", "roles": ["admin"] },
        "update": { "type": "owner", "field": "id" },
        "delete": { "type": "role", "roles": ["admin"] }
      },
      "indexes": [],
      "options": { "timestamps": true, "softDelete": false }
    }
  ]
}
```

Supported field kinds include `text`, `uuid`, `email`, `richText`, `slug`, `relation`, `image`, `file`, `vector`, and more. Relations support `belongsTo`, `hasMany`, `hasOne`, and `manyToMany` cardinalities — junction tables are inferred automatically for many-to-many.

## Project Structure

```
src/
├── main.rs               CLI entry point
├── lib.rs                 Library root
├── parser/                JSON AST → SchemaAst pipeline
│   ├── ast.rs             Core types (SchemaAst, ModelAst, FieldAst, …)
│   ├── validator.rs       Schema validation rules
│   ├── resolver.rs        Infer junction tables, storage buckets
│   └── normaliser.rs      Snake-case table names, fill defaults
├── introspector/          Postgres → DatabaseState via information_schema
├── differ/                SchemaAst × DatabaseState → DiffOutput
│   ├── table_diff.rs      Create / drop tables
│   ├── column_diff.rs     Add / drop / rename columns
│   ├── index_diff.rs      Index changes
│   ├── rls_diff.rs        RLS policy changes
│   ├── trigger_diff.rs    Trigger changes
│   ├── constraint_diff.rs Constraint changes
│   ├── ordering.rs        Topological sort (petgraph)
│   └── risk_analyser.rs   Pre-flight safety validation
├── generator/
│   ├── sql/               Migration DDL, RLS, triggers, rollback
│   ├── typescript/        Row/Insert types, admin config
│   └── config/            PostgREST, Kong
├── state/                 DatabaseState, target state, migration history
└── licensing/             Tier-gated features (Community / Pro / Enterprise)
```

## Building

Requires the Rust toolchain (stable channel). The project pins its toolchain via `rust-toolchain.toml`.

```bash
cargo build --release
```

The release profile enables LTO, single codegen unit, and symbol stripping for a small binary.

### Cross-compilation targets

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

## Testing

```bash
# Unit and library tests
cargo test --lib

# Integration tests (requires Docker for testcontainers)
cargo test --test integration_test
```

Integration tests spin up Postgres (14, 15, 16) via testcontainers, apply a multi-model blog schema, and verify the full parse → diff → migrate → introspect → idempotency pipeline.

## CI / CD

**CI** (`.github/workflows/ci.yml`) — runs on every push and PR to `main`:
- `cargo check`, `cargo fmt --check`, `cargo clippy -- -D warnings`
- Library tests
- Integration tests across Postgres 14 / 15 / 16

**Release** (`.github/workflows/release.yml`) — triggered by `v*` tags:
- Builds binaries for all five targets (Linux via `cross`)
- Publishes a GitHub Release with binaries and SHA-256 checksums

## License

Proprietary — all rights reserved.

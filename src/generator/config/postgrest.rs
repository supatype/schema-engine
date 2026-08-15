use crate::parser::ast::SchemaAst;
use anyhow::Result;
use serde_json::{json, Value};

/// Extra schemas PostgREST resolves unqualified names against, beyond the request schema.
///
/// `extensions` is where a Supatype database installs its extensions; `public` covers a plain
/// Postgres where `CREATE EXTENSION` without `SCHEMA` put them there instead — a column default of
/// `uuid_generate_v4()` stops resolving without it.
const EXTRA_SEARCH_PATH: &str = "public, extensions";

/// Generate PostgREST configuration from the schema.
/// PostgREST reads from the database directly but we generate
/// the schema exposure config and any custom overrides.
///
/// `schema` is the schema Supatype manages. It was a literal `"public"` here, so this endpoint
/// described a stack that did not exist for any project using `schema.pg_schema`.
pub fn generate(ast: &SchemaAst, schema: &str) -> Result<Value> {
    let tables: Vec<Value> = ast
        .models
        .iter()
        .map(|m| {
            json!({
                "schema": schema,
                "table": m.table_name(),
            })
        })
        .collect();

    Ok(json!({
        "db-schemas": [schema],
        "db-extra-search-path": EXTRA_SEARCH_PATH,
        "tables": tables,
    }))
}

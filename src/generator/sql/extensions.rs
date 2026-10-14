//! Where a push installs the Postgres extensions a schema needs: the `extensions` schema, as
//! Supabase installs them, and never `public`.
//!
//! `CREATE EXTENSION` with no schema puts an extension's objects in the first schema of the
//! session's path, which is `public`. PostGIS and pgvector add about 940 functions there, PostgREST
//! serves each one it can call as `/rest/v1/rpc/*` and lists them in the OpenAPI root, and
//! PostgREST 14 lists them with a query that plans badly on the catalog statistics a push has just
//! made stale, so the root timed out for up to a minute after the push that created them.
//!
//! The generated SQL never names the schema an extension's objects live in: a column is
//! `vector(3)`, not `extensions.vector(3)`. A push resolves those names through a search path that
//! reaches both `extensions` and `public` ([`search_path_sql`]), which keeps working for a project
//! whose PostGIS stayed in `public` (it cannot be moved with `ALTER EXTENSION`), and keeps every
//! statement the ledger records the same text wherever the extension lives, so moving one replaces
//! nothing. A function body, resolved when it runs rather than when it is created, carries its own
//! path ([`OBJECT_SEARCH_PATH`]) instead.

use super::auth_functions::for_each_api_role;
use crate::introspector::extensions::InstalledExtension;
use crate::sql_quote::quote_ident;

/// The schema a push creates extensions in.
pub const EXTENSIONS_SCHEMA: &str = "extensions";

/// The extensions a push creates, and so the ones it moves out of the API's schema when an older
/// engine left them there.
pub const MANAGED: [&str; 4] = ["pgcrypto", "postgis", "unaccent", "vector"];

/// The dollar tag of the block that creates [`EXTENSIONS_SCHEMA`] when it is missing.
pub const SCHEMA_TAG: &str = "extensions_schema";

/// The dollar tag of the block granting the API roles usage on [`EXTENSIONS_SCHEMA`].
pub const SCHEMA_USAGE_TAG: &str = "extensions_schema_usage";

/// The path a function body that calls an extension's function runs under: where a push installs
/// extensions, then where an older engine did.
pub const OBJECT_SEARCH_PATH: &str = "pg_catalog, extensions, public";

/// [`EXTENSIONS_SCHEMA`], created when missing, and usage on it for each API role that exists: a
/// request runs as one of them, and resolving a column's type or a filter's operator needs it.
///
/// Created only when missing rather than with `CREATE SCHEMA IF NOT EXISTS`, which asks for
/// `CREATE` on the database before it looks: on `supatype/postgres` the schema is the image's. A
/// role that does not own it cannot grant on it, which Postgres reports as a warning, not an error.
pub fn schema_sql() -> String {
    let create = format!(
        "DO ${SCHEMA_TAG}$\nBEGIN\n  IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = '{EXTENSIONS_SCHEMA}') THEN\n    CREATE SCHEMA {EXTENSIONS_SCHEMA};\n  END IF;\nEND\n${SCHEMA_TAG}$;"
    );
    let usage = for_each_api_role(SCHEMA_USAGE_TAG, |role| {
        vec![format!(
            "GRANT USAGE ON SCHEMA {EXTENSIONS_SCHEMA} TO {role}"
        )]
    });
    format!("{create}\n{usage}")
}

/// `CREATE EXTENSION` for one extension, in [`EXTENSIONS_SCHEMA`]. A no-op where it is already
/// installed, wherever that is.
pub fn create_sql(name: &str) -> String {
    format!(
        "CREATE EXTENSION IF NOT EXISTS {} WITH SCHEMA {EXTENSIONS_SCHEMA};",
        quote_ident(name)
    )
}

/// Moves an extension's objects to `to`. Its columns, indexes and the rows in them are untouched:
/// a column records its type by OID, not by name.
pub fn relocate_sql(name: &str, to: &str) -> String {
    format!(
        "ALTER EXTENSION {} SET SCHEMA {};",
        quote_ident(name),
        quote_ident(to)
    )
}

/// Adds `extensions` and `public` to the transaction's search path when either is missing, so the
/// statements after it resolve an extension's types wherever it is installed. Local to the
/// transaction, and a no-op on a session whose path already reaches both, so a connection that goes
/// back to a pool is not left with a longer path each push.
pub fn search_path_sql() -> String {
    format!(
        "SELECT pg_catalog.set_config('search_path', pg_catalog.current_setting('search_path') || ', {EXTENSIONS_SCHEMA}, public', true)\n  \
         WHERE NOT ARRAY['{EXTENSIONS_SCHEMA}', 'public']::name[] <@ pg_catalog.current_schemas(false);"
    )
}

/// The schemas an extension in which is reachable from the API: `public`, and the project's own.
fn exposed(extension: &InstalledExtension, schema: &str) -> bool {
    extension.schema == "public" || extension.schema == schema
}

/// The extensions this engine manages that sit in a schema the API serves, in name order:
/// `(movable, stuck)`, by whether `ALTER EXTENSION ... SET SCHEMA` can move them.
pub fn exposed_managed<'a>(
    installed: &'a [InstalledExtension],
    schema: &str,
) -> (Vec<&'a InstalledExtension>, Vec<&'a InstalledExtension>) {
    installed
        .iter()
        .filter(|e| MANAGED.contains(&e.name.as_str()) && exposed(e, schema))
        .partition(|e| e.relocatable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed(name: &str, schema: &str, relocatable: bool) -> InstalledExtension {
        InstalledExtension {
            name: name.into(),
            schema: schema.into(),
            relocatable,
        }
    }

    #[test]
    fn only_managed_extensions_in_an_exposed_schema_are_found() {
        let all = [
            installed("pg_trgm", "public", true),
            installed("pgcrypto", "extensions", true),
            installed("postgis", "public", false),
            installed("unaccent", "app", true),
            installed("vector", "public", true),
        ];
        let (movable, stuck) = exposed_managed(&all, "app");
        let names = |v: Vec<&InstalledExtension>| -> Vec<String> {
            v.into_iter().map(|e| e.name.clone()).collect()
        };
        assert_eq!(names(movable), ["unaccent", "vector"]);
        assert_eq!(names(stuck), ["postgis"]);
    }

    #[test]
    fn statements_name_the_extensions_schema() {
        assert_eq!(
            create_sql("vector"),
            "CREATE EXTENSION IF NOT EXISTS \"vector\" WITH SCHEMA extensions;"
        );
        assert_eq!(
            relocate_sql("vector", EXTENSIONS_SCHEMA),
            "ALTER EXTENSION \"vector\" SET SCHEMA \"extensions\";"
        );
        let schema = schema_sql();
        assert!(schema.contains("CREATE SCHEMA extensions;"), "{schema}");
        for role in ["anon", "authenticated", "service_role"] {
            assert!(
                schema.contains(&format!("GRANT USAGE ON SCHEMA extensions TO {role}")),
                "{schema}"
            );
        }
    }
}

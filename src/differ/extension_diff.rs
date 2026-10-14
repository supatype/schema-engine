//! Extensions an older engine created where the API serves them.
//!
//! An engine before this one created PostGIS, pgvector, `unaccent` and `pgcrypto` with no schema, so
//! they are in `public` on every project it pushed. Each one `ALTER EXTENSION ... SET SCHEMA` can
//! move is moved to `extensions` by the next push, as an operation of its own that the push lists
//! and asks consent for. PostGIS cannot be moved that way; it is named in a warning on every push,
//! with where to read how to move it, and everything keeps working with it where it is.

use super::{Operation, Risk};
use crate::generator::sql::extensions::{exposed_managed, EXTENSIONS_SCHEMA};
use crate::state::database_state::DatabaseState;

/// Where the manual steps for an extension a push cannot move are written down.
const UPGRADE_NOTES: &str = "UPGRADING.md, \"Extensions move to the extensions schema\"";

/// The moves `db` needs, and a warning for each extension that needs one and cannot have it.
pub fn diff(db: &DatabaseState, ops: &mut Vec<Operation>, warnings: &mut Vec<String>) {
    let (movable, stuck) = exposed_managed(&db.installed_extensions, &db.schema);
    for extension in movable {
        ops.push(Operation::RelocateExtension {
            name: extension.name.clone(),
            from: extension.schema.clone(),
            to: EXTENSIONS_SCHEMA.to_string(),
            warning: format!(
                "Move extension {} from {} to {EXTENSIONS_SCHEMA}, where the API does not serve \
                 its functions. Columns and data are untouched; SQL of your own that names one of \
                 its objects as {}.<name> must drop the prefix.",
                extension.name, extension.schema, extension.schema
            ),
            risk: Risk::Cautious,
        });
    }
    for extension in stuck {
        warnings.push(format!(
            "Extension `{}` is installed in `{}`, where the API serves its functions as \
             /rest/v1/rpc/* endpoints and lists them in the OpenAPI document. A push cannot move \
             it (`ALTER EXTENSION ... SET SCHEMA` is not supported for it), and everything keeps \
             working where it is. To move it to `{EXTENSIONS_SCHEMA}`, see {UPGRADE_NOTES}.",
            extension.name, extension.schema
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::introspector::extensions::InstalledExtension;

    fn db(installed: &[(&str, &str, bool)]) -> DatabaseState {
        DatabaseState {
            schema: "public".into(),
            installed_extensions: installed
                .iter()
                .map(|(name, schema, relocatable)| InstalledExtension {
                    name: (*name).into(),
                    schema: (*schema).into(),
                    relocatable: *relocatable,
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn a_relocatable_extension_in_public_is_moved_with_consent() {
        let (mut ops, mut warnings) = (Vec::new(), Vec::new());
        diff(
            &db(&[("vector", "public", true), ("unaccent", "extensions", true)]),
            &mut ops,
            &mut warnings,
        );
        assert!(warnings.is_empty(), "{warnings:?}");
        match ops.as_slice() {
            [Operation::RelocateExtension {
                name,
                from,
                to,
                risk,
                ..
            }] => {
                assert_eq!(
                    (name.as_str(), from.as_str(), to.as_str()),
                    ("vector", "public", "extensions")
                );
                assert_eq!(*risk, Risk::Cautious);
            }
            other => panic!("one move, of vector: {other:?}"),
        }
    }

    #[test]
    fn postgis_in_public_is_named_and_left() {
        let (mut ops, mut warnings) = (Vec::new(), Vec::new());
        diff(
            &db(&[("postgis", "public", false)]),
            &mut ops,
            &mut warnings,
        );
        assert!(ops.is_empty(), "{ops:?}");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("`postgis`") && warnings[0].contains("UPGRADING.md"));
    }

    #[test]
    fn an_extension_this_engine_does_not_create_is_left_alone() {
        let (mut ops, mut warnings) = (Vec::new(), Vec::new());
        diff(&db(&[("pg_trgm", "public", true)]), &mut ops, &mut warnings);
        assert!(ops.is_empty() && warnings.is_empty());
    }
}

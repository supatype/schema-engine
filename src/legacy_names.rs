//! The names engine 0.6.0 gave the objects on a model's table, so the first push after an upgrade
//! knows them as the engine's own (F8).
//!
//! 0.6.0 built each name with `format!` (`{table}_{column}_fkey`, `{table}_updated_at_trigger`) and
//! let Postgres cut anything past 63 bytes, where this engine fits a long name as Postgres fits the
//! names it chooses itself and keeps the label whole ([`crate::managed::make_object_name`]). The
//! two agree up to 63 bytes and differ beyond it, so an upgraded object with a long name was found
//! under neither the name this engine wants nor any it recognised: it stayed, unrecorded, and the
//! push created a second one beside it. These are the names 0.6.0 wrote, cut exactly as Postgres
//! cut them, for only the objects whose name it had to cut. The reconcile then treats such an
//! object as the engine's (section 7, by naming): renamed to the new name when its structure is
//! the one desired, dropped otherwise.
//!
//! Read from the 0.6.0 source (tag `v0.6.0`): `differ/table_diff.rs` and `generator/sql/migration.rs`
//! for foreign keys and indexes, `managed.rs` for unique, bounds and model-rule names, and
//! `generator/sql/triggers.rs` for the triggers and their `_platform` functions. Primary keys,
//! type checks and inline uniques 0.6.0 left unnamed, so Postgres named them as this engine does.

use std::collections::BTreeSet;

use crate::desired::ObjectKey;
use crate::generator::sql::triggers::{slug_fields, PLATFORM_SCHEMA};
use crate::introspector::fingerprint::ObjectKind;
use crate::managed::{clip_identifier, is_managed_comment, MAX_IDENTIFIER_BYTES};
use crate::parser::accessors::{
    column_names_for, db_foreign_key, default_foreign_key_column, implicit_model_indexes,
};
use crate::parser::ast::{FieldAst, IndexMethod, ModelAst, RelationCardinality, SchemaAst};

/// Every object on `ast`'s model tables (and their `_platform` functions) whose 0.6.0 name
/// Postgres had to cut, keyed under the name as cut.
pub fn engine_0_6_names(ast: &SchemaAst, schema: &str) -> BTreeSet<ObjectKey> {
    let mut out = BTreeSet::new();
    for model in &ast.models {
        let table = model.table_name();
        let on_table = |kind, name: String| (kind, schema.to_string(), table.to_string(), name);
        let names = foreign_keys(model)
            .into_iter()
            .map(|n| on_table(ObjectKind::ForeignKey, n))
            .chain(
                uniques(model)
                    .into_iter()
                    .map(|n| on_table(ObjectKind::Unique, n)),
            )
            .chain(
                checks(model)
                    .into_iter()
                    .map(|n| on_table(ObjectKind::Check, n)),
            )
            .chain(
                indexes(model)
                    .into_iter()
                    .map(|n| on_table(ObjectKind::Index, n)),
            )
            .chain(
                triggers(model)
                    .into_iter()
                    .map(|n| on_table(ObjectKind::Trigger, n)),
            )
            .chain(functions(model).into_iter().map(|n| {
                (
                    ObjectKind::Function,
                    PLATFORM_SCHEMA.to_string(),
                    String::new(),
                    n,
                )
            }));
        out.extend(names.filter_map(|(kind, schema, parent, name)| {
            cut(&name).map(|name| ObjectKey {
                kind,
                schema,
                parent,
                name,
            })
        }));
    }
    out
}

/// `name` as Postgres stored it, when it had to cut it; `None` when it fit, since then 0.6.0's
/// name is this engine's too. A function's key keeps its empty argument list after the cut.
fn cut(name: &str) -> Option<String> {
    let (ident, args) = match name.strip_suffix("()") {
        Some(ident) => (ident, "()"),
        None => (name, ""),
    };
    (ident.len() > MAX_IDENTIFIER_BYTES).then(|| format!("{}{args}", clip_identifier(ident)))
}

/// The fingerprint 0.6.0 stamped on a check it made, over the expression it generated: the first
/// 16 hex characters of its SHA-256 (`check_fingerprint` in its `managed.rs`).
pub fn engine_0_6_check_fingerprint(expression: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(expression.as_bytes())
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The fingerprint in a check's 0.6.0 stamp (`...;bounds=<fingerprint>`), if it carries one.
pub fn engine_0_6_stamp_fingerprint(comment: Option<&str>) -> Option<&str> {
    let comment = comment.filter(|c| is_managed_comment(Some(c)))?;
    comment
        .lines()
        .next()?
        .split(';')
        .find_map(|part| part.strip_prefix("bounds="))
}

/// `{table}_{column}_fkey` for each foreign key (`differ/table_diff.rs`, `migration.rs`).
fn foreign_keys(model: &ModelAst) -> Vec<String> {
    let table = model.table_name();
    model
        .fields
        .iter()
        .filter_map(|(field_name, field)| match field {
            FieldAst::Relation(rel)
                if matches!(rel.cardinality, RelationCardinality::BelongsTo) =>
            {
                let column = db_foreign_key(field, field_name)
                    .unwrap_or_else(|| default_foreign_key_column(field_name));
                Some(format!("{table}_{column}_fkey"))
            }
            _ => None,
        })
        .collect()
}

/// `{table}_{column}_key` for each unique column (`managed.rs`).
fn uniques(model: &ModelAst) -> Vec<String> {
    let table = model.table_name();
    crate::managed::unique_columns(model)
        .into_iter()
        .map(|column| format!("{table}_{column}_key"))
        .collect()
}

/// `{table}_{column}_bounds` for each column, and `{table}_check_{n}` for each model rule
/// (`managed.rs`).
fn checks(model: &ModelAst) -> Vec<String> {
    let table = model.table_name();
    let bounds = model.fields.iter().flat_map(|(field_name, field)| {
        column_names_for(field_name, field)
            .into_iter()
            .map(move |column| format!("{table}_{column}_bounds"))
    });
    let rules = (1..=model.annotations.db.constraints.len()).map(|n| format!("{table}_check_{n}"));
    bounds.chain(rules).collect()
}

/// `{table}_{fields}_idx` for each unnamed index, declared or implicit, `{table}_{field}_gin_idx`
/// for an indexed Blocks field and `{table}_singleton_idx` (`migration.rs`).
fn indexes(model: &ModelAst) -> Vec<String> {
    let table = model.table_name();
    let declared = model
        .indexes()
        .iter()
        .filter(|index| index.name.is_none())
        .map(|index| format!("{table}_{}_idx", index.fields.join("_")))
        .collect::<Vec<_>>();
    let implicit = implicit_model_indexes(model).into_iter().map(|index| {
        let fields = index.fields.join("_");
        match index.using {
            IndexMethod::Gin => format!("{table}_{fields}_gin_idx"),
            _ => format!("{table}_{fields}_idx"),
        }
    });
    let singleton = model
        .options
        .singleton
        .then(|| format!("{table}_singleton_idx"));
    declared
        .into_iter()
        .chain(implicit)
        .chain(singleton)
        .collect()
}

/// `{table}_updated_at_trigger`, `{table}_rich_text_trigger` and `{table}_{slug}_trigger`
/// (`triggers.rs`).
fn triggers(model: &ModelAst) -> Vec<String> {
    let table = model.table_name();
    let fixed = ["updated_at_trigger", "rich_text_trigger"]
        .into_iter()
        .map(|label| format!("{table}_{label}"));
    let slugs = slug_fields(model).map(|(slug, _)| format!("{table}_{slug}_trigger"));
    fixed.chain(slugs).collect()
}

/// `_platform.set_{table}_{slug}()` and `_platform.normalise_{table}_rich_text()`
/// (`triggers.rs`), keyed as the ledger keys a function.
fn functions(model: &ModelAst) -> Vec<String> {
    let table = model.table_name();
    let slugs = slug_fields(model).map(|(slug, _)| format!("set_{table}_{slug}()"));
    std::iter::once(format!("normalise_{table}_rich_text()"))
        .chain(slugs)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_listed_only_when_postgres_had_to_cut_it() {
        assert_eq!(cut("posts_author_id_fkey"), None);
        let long = format!("{}_updated_at_trigger", "t".repeat(50));
        assert_eq!(cut(&long).as_deref(), Some(&long[..63]));
        let function = format!("set_{}_slug()", "t".repeat(60));
        let kept = cut(&function).unwrap();
        assert_eq!(kept.len(), 63 + 2);
        assert!(kept.ends_with("()"));
    }
}

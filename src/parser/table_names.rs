//! Table names as Postgres keeps them.
//!
//! Postgres cuts a table's name past 63 bytes as it cuts a column's ([`super::column_names`]). A
//! model's table named past that, or a many-to-many's junction (the two tables' names joined,
//! which easily is), was created under the cut name and then looked up under the full one, so the
//! push could not find what it had just made. Each is given the name Postgres keeps once, here,
//! and every later step (the push, its rules and grants, the draft view, generated types, Studio's
//! config) names that one; names derived from a table, such as its versions table and its
//! constraints, are fitted from it. Two tables Postgres would cut to one name refuse the schema
//! instead of one silently taking the other's place.

use anyhow::{bail, Result};

use super::accessors::{versions_of, versions_table_name};
use super::ast::{JunctionTableAst, SchemaAst};
use crate::managed::{clip_identifier, KeptNames, MAX_IDENTIFIER_BYTES};

/// `ast` with every table name it states, and every junction's key columns, as Postgres keeps
/// them. Refused when two tables would be kept as one.
pub fn keep_as_postgres_does(mut ast: SchemaAst) -> Result<SchemaAst> {
    refuse_clashes(&ast)?;
    for model in &mut ast.models {
        let table = model.table_name_mut();
        *table = clip_identifier(table);
    }
    for junction in &mut ast.junction_tables {
        refuse_key_clash(junction)?;
        for name in [&mut junction.name, &mut junction.fk_a, &mut junction.fk_b] {
            *name = clip_identifier(name);
        }
    }
    Ok(ast)
}

/// Every table `ast` makes in its schema, as stated: each model's, each versioned model's
/// snapshot table and each junction.
fn tables(ast: &SchemaAst) -> Vec<String> {
    let models = ast.models.iter().map(|m| m.table_name().to_string());
    let versions = ast
        .models
        .iter()
        .filter(|m| versions_of(m).is_some())
        .map(|m| versions_table_name(&clip_identifier(m.table_name())));
    let junctions = ast.junction_tables.iter().map(|j| j.name.clone());
    models.chain(versions).chain(junctions).collect()
}

fn refuse_clashes(ast: &SchemaAst) -> Result<()> {
    let mut kept = KeptNames::default();
    for table in tables(ast) {
        if let Some(other) = kept.claim(&table) {
            bail!(
                "The schema names tables \"{other}\" and \"{table}\", which Postgres would both \
                 keep as \"{}\": it keeps only the first {MAX_IDENTIFIER_BYTES} bytes of a name. \
                 Rename one (a model's table name, or a many-to-many's `through`) so the two \
                 differ within their first {MAX_IDENTIFIER_BYTES} bytes.",
                clip_identifier(&table),
            );
        }
    }
    Ok(())
}

/// Refuses a junction whose two key columns, each named from its model, would be kept as one.
fn refuse_key_clash(junction: &JunctionTableAst) -> Result<()> {
    let mut kept = KeptNames::default();
    kept.claim(&junction.fk_a);
    if let Some(other) = kept.claim(&junction.fk_b) {
        bail!(
            "The many-to-many between '{}' and '{}' names its key columns \"{other}\" and \"{}\", \
             which Postgres would both keep as \"{}\": it keeps only the first \
             {MAX_IDENTIFIER_BYTES} bytes of a name. Rename one model so the two differ within \
             their first {MAX_IDENTIFIER_BYTES} bytes.",
            junction.model_a,
            junction.model_b,
            junction.fk_b,
            clip_identifier(&junction.fk_b),
        );
    }
    Ok(())
}

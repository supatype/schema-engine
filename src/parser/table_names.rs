//! Table names as Postgres keeps them.
//!
//! Postgres cuts a table's name past 63 bytes as it cuts a column's ([`super::column_names`]). A
//! model's table named past that, or a many-to-many's junction (the two tables' names joined,
//! which easily is), was created under the cut name and then looked up under the full one, so the
//! push could not find what it had just made. Each is given the name Postgres keeps once, here,
//! and every later step (the push, its rules and grants, the draft view, generated types, Studio's
//! config) names that one; names derived from a table, such as its versions table and its
//! constraints, are fitted from it. Two tables Postgres would cut to one name refuse the schema
//! instead of one silently taking the other's place, as do two sources naming one table outright
//! (a model's table named like another model's versions table, or like a junction).

use std::collections::HashMap;

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

/// A table the schema makes, as stated, and what makes it, for naming in a refusal.
struct Table {
    name: String,
    source: String,
}

/// Every table `ast` makes in its schema, as stated: each model's, each versioned model's
/// snapshot table and each junction.
fn tables(ast: &SchemaAst) -> Vec<Table> {
    let models = ast.models.iter().map(|m| Table {
        name: m.table_name().to_string(),
        source: format!("model '{}'", m.name),
    });
    let versions = ast
        .models
        .iter()
        .filter(|m| versions_of(m).is_some())
        .map(|m| Table {
            name: versions_table_name(&clip_identifier(m.table_name())),
            source: format!("the versions table of model '{}'", m.name),
        });
    let junctions = ast.junction_tables.iter().map(|j| Table {
        name: j.name.clone(),
        source: format!(
            "the many-to-many between '{}' and '{}'",
            j.model_a, j.model_b
        ),
    });
    models.chain(versions).chain(junctions).collect()
}

/// Refuses two tables named alike, or named apart but kept by Postgres as one: either way the
/// push would make one table for both, and one source would read and write the other's rows.
fn refuse_clashes(ast: &SchemaAst) -> Result<()> {
    let mut kept: HashMap<String, Table> = HashMap::new();
    for table in tables(ast) {
        let key = clip_identifier(&table.name);
        match kept.get(&key) {
            Some(other) if other.name == table.name => refuse_same_name(other, &table)?,
            Some(other) => refuse_same_kept_name(other, &table)?,
            None => {
                kept.insert(key, table);
            }
        }
    }
    Ok(())
}

fn refuse_same_name(first: &Table, second: &Table) -> Result<()> {
    bail!(
        "Two sources name the table \"{}\": {} and {}. The schema can hold only one table by \
         that name. Rename one (a model's table name, or a many-to-many's `through`).",
        second.name,
        first.source,
        second.source,
    );
}

fn refuse_same_kept_name(first: &Table, second: &Table) -> Result<()> {
    bail!(
        "The schema names tables \"{}\" ({}) and \"{}\" ({}), which Postgres would both keep as \
         \"{}\": it keeps only the first {MAX_IDENTIFIER_BYTES} bytes of a name. Rename one (a \
         model's table name, or a many-to-many's `through`) so the two differ within their first \
         {MAX_IDENTIFIER_BYTES} bytes.",
        first.name,
        first.source,
        second.name,
        second.source,
        clip_identifier(&second.name),
    );
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

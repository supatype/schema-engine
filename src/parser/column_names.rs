//! Column names as Postgres keeps them.
//!
//! Postgres cuts an identifier past 63 bytes to its first 63, on a character boundary, with no more
//! than a notice. A schema that names a column past that (a relation's foreign key column, derived
//! from long names, easily is) had the engine name the column one way and the catalog another: the
//! push made the column and then could not find it. So a column the schema names is given the name
//! Postgres keeps once, here, and every later step names and looks up that one, as the names of
//! constraints and indexes already are. Two columns Postgres would cut to one name refuse the
//! schema instead of one silently taking the other's place.

use std::collections::BTreeMap;

use anyhow::{bail, Result};

use super::accessors::{column_names_for, default_foreign_key_column};
use super::ast::{AccessAst, AccessRule, FieldAst, MembershipSource, ModelAst, Operand};
use crate::managed::{clip_identifier, MAX_IDENTIFIER_BYTES};

/// Refuses `model` when two of its columns have names Postgres would keep as one.
pub fn refuse_clashes(model: &ModelAst) -> Result<()> {
    let mut kept: BTreeMap<String, String> = BTreeMap::new();
    for (name, field) in &model.fields {
        for column in column_names_for(name, field) {
            let stored = clip_identifier(&column);
            match kept.get(&stored) {
                Some(other) if *other != column => bail!(
                    "Model '{}' declares columns \"{other}\" and \"{column}\", which Postgres would \
                     both keep as \"{stored}\": it keeps only the first {MAX_IDENTIFIER_BYTES} \
                     bytes of a name. Rename one so the two differ within their first \
                     {MAX_IDENTIFIER_BYTES} bytes.",
                    model.name,
                ),
                _ => {
                    kept.insert(stored, column);
                }
            }
        }
    }
    Ok(())
}

/// Every column name `model` states, as Postgres keeps it: its fields' own, its foreign keys, and
/// those its indexes, rules, constraints and search list name.
pub fn keep_as_postgres_does(model: &mut ModelAst) {
    model.fields = std::mem::take(&mut model.fields)
        .into_iter()
        .map(|(name, mut field)| {
            clip_relation_columns(&name, &mut field);
            (field_key(&name, &field), field)
        })
        .collect();
    for index in model.indexes_mut() {
        index.fields.iter_mut().for_each(clip);
    }
    model
        .annotations
        .platform
        .search_fields
        .iter_mut()
        .for_each(clip);
    model
        .annotations
        .db
        .constraints
        .iter_mut()
        .for_each(clip_rule);
    clip_access(model.access_mut());
}

/// A field's key, which is its column's name when the field is one column of its own name.
fn field_key(name: &str, field: &FieldAst) -> String {
    if column_names_for(name, field) == [name] {
        clip_identifier(name)
    } else {
        name.to_string()
    }
}

/// A relation's own foreign key column, and the column it references, as Postgres keeps them. A
/// key column too long to keep, stated or derived from the field's name, is written out cut in
/// both places the key is read from, so nothing derives the long name again.
fn clip_relation_columns(name: &str, field: &mut FieldAst) {
    let FieldAst::Relation(rel) = field else {
        return;
    };
    rel.references.iter_mut().for_each(clip);
    let stated = rel
        .annotations
        .db
        .foreign_key
        .clone()
        .filter(|k| !k.is_empty());
    let column = rel
        .foreign_key
        .clone()
        .or(stated)
        .unwrap_or_else(|| default_foreign_key_column(name));
    if column.len() > MAX_IDENTIFIER_BYTES {
        let kept = clip_identifier(&column);
        rel.foreign_key = Some(kept.clone());
        rel.annotations.db.foreign_key = Some(kept);
    }
}

fn clip_access(access: &mut AccessAst) {
    [
        &mut access.read,
        &mut access.create,
        &mut access.update,
        &mut access.update_check,
        &mut access.delete,
    ]
    .into_iter()
    .flatten()
    .for_each(clip_rule);
    access.fields = std::mem::take(&mut access.fields)
        .into_iter()
        .map(|(column, mut rules)| {
            rules.read.iter_mut().for_each(clip_rule);
            rules.write.iter_mut().for_each(clip_rule);
            (clip_identifier(&column), rules)
        })
        .collect();
}

/// Every column `rule` names, as Postgres keeps it.
fn clip_rule(rule: &mut AccessRule) {
    match rule {
        AccessRule::Matches { column, .. } => clip(column),
        AccessRule::Owner { field } => clip(field),
        AccessRule::Any { rules } | AccessRule::All { rules } => {
            rules.iter_mut().for_each(clip_rule)
        }
        AccessRule::Not { rule } => clip_rule(rule),
        AccessRule::Compare { left, right, .. } => {
            clip_operand(left);
            clip_operand(right);
        }
        AccessRule::In { column, source } => {
            clip(column);
            clip_source(source);
        }
        AccessRule::Exists { source } => clip_source(source),
        AccessRule::NullCheck { operand, .. } => clip_operand(operand),
        AccessRule::Public
        | AccessRule::Private
        | AccessRule::Authenticated
        | AccessRule::Role { .. } => {}
    }
}

fn clip_source(source: &mut MembershipSource) {
    if let MembershipSource::Rows { column, filter, .. } = source {
        clip(column);
        filter.iter_mut().for_each(|rule| clip_rule(rule));
    }
}

fn clip_operand(operand: &mut Operand) {
    match operand {
        Operand::Column { name: column }
        | Operand::Length { column, .. }
        | Operand::ItemCount { column, .. } => clip(column),
        Operand::After { base, .. } | Operand::Before { base, .. } => clip_operand(base),
        _ => {}
    }
}

fn clip(name: &mut String) {
    if name.len() > MAX_IDENTIFIER_BYTES {
        *name = clip_identifier(name);
    }
}

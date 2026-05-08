use super::ast::{AccessRule, FieldAst, RelationCardinality, SchemaAst};
use anyhow::{bail, Result};
use std::collections::HashSet;

pub fn validate(mut ast: SchemaAst) -> Result<SchemaAst> {
    let model_names: std::collections::HashSet<String> =
        ast.models.iter().map(|m| m.name.clone()).collect();

    for model in &mut ast.models {
        if model.name.is_empty() {
            bail!("Model name cannot be empty");
        }
        if model.table_name.is_empty() {
            bail!("Model '{}' has an empty table name", model.name);
        }

        // Validate that all relation targets reference a known model name.
        // A dangling target (e.g. after a model rename) would silently fall
        // back to using the target string as a raw table name and fail at the
        // database with a confusing "relation does not exist" error.
        for (field_name, field) in &model.fields {
            if let FieldAst::Relation(rel) = field {
                let is_owning = matches!(
                    rel.cardinality,
                    RelationCardinality::BelongsTo | RelationCardinality::ManyToMany
                );
                if is_owning
                    && !model_names.contains(&rel.target)
                    && super::resolver::resolve_system_ref(&rel.target).is_none()
                {
                    bail!(
                        "Model '{}': field '{}' references unknown model '{}'. \
                         Did you rename the model and forget to update this relation?",
                        model.name,
                        field_name,
                        rel.target,
                    );
                }
            }
        }

        validate_owner_rules(model)?;
    }

    Ok(ast)
}

fn validate_owner_rules(model: &mut super::ast::ModelAst) -> Result<()> {
    let mut relation_fk_columns: HashSet<String> = HashSet::new();
    for (field_name, field) in &model.fields {
        if let FieldAst::Relation(rel) = field {
            let is_owning = matches!(
                rel.cardinality,
                RelationCardinality::BelongsTo | RelationCardinality::ManyToMany
            );
            if is_owning {
                relation_fk_columns.insert(
                    rel.foreign_key
                        .clone()
                        .unwrap_or_else(|| format!("{}_id", super::resolver::to_snake_case(field_name))),
                );
            }
        }
    }

    normalize_and_validate_rule(
        &mut model.access.read,
        &model.name,
        &relation_fk_columns,
    )?;
    normalize_and_validate_rule(
        &mut model.access.create,
        &model.name,
        &relation_fk_columns,
    )?;
    normalize_and_validate_rule(
        &mut model.access.update,
        &model.name,
        &relation_fk_columns,
    )?;
    normalize_and_validate_rule(
        &mut model.access.delete,
        &model.name,
        &relation_fk_columns,
    )?;

    Ok(())
}

fn normalize_and_validate_rule(
    rule: &mut Option<AccessRule>,
    model_name: &str,
    relation_fk_columns: &HashSet<String>,
) -> Result<()> {
    let Some(rule) = rule else { return Ok(()) };
    normalize_and_validate_rule_inner(rule, model_name, relation_fk_columns)
}

fn normalize_and_validate_rule_inner(
    rule: &mut AccessRule,
    model_name: &str,
    relation_fk_columns: &HashSet<String>,
) -> Result<()> {
    match rule {
        AccessRule::Owner { field } => {
            let normalized = super::resolver::to_snake_case(field);
            if normalized == "id" {
                *field = normalized;
                return Ok(());
            }
            if !relation_fk_columns.contains(&normalized) {
                let mut candidates: Vec<String> = relation_fk_columns.iter().cloned().collect();
                candidates.push("id".to_string());
                candidates.sort();
                candidates.dedup();
                bail!(
                    "Model '{}': Owner<\"{}\"> is invalid. Owner fields must reference relation foreign keys. \
                     Use one of: [{}]",
                    model_name,
                    field,
                    candidates.join(", ")
                );
            }
            *field = normalized;
            Ok(())
        }
        AccessRule::Any { rules } => {
            for r in rules {
                normalize_and_validate_rule_inner(r, model_name, relation_fk_columns)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

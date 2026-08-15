use super::accessors::{db_foreign_key, platform_access_mut};
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
        if model.annotations.db.table_name.is_empty() {
            bail!("Model '{}' has an empty table name", model.name);
        }

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
    let model_name = model.name.clone();
    let mut owner_eligible: HashSet<String> = HashSet::new();
    owner_eligible.insert("id".to_string());

    for (field_name, field) in &model.fields {
        if let FieldAst::Relation(rel) = field {
            let is_owning = matches!(
                rel.cardinality,
                RelationCardinality::BelongsTo | RelationCardinality::ManyToMany
            );
            if is_owning {
                owner_eligible.insert(field_name.clone());
            }
        }
    }

    let access = platform_access_mut(model);
    normalize_and_validate_rule(&mut access.read, &model_name, &owner_eligible)?;
    normalize_and_validate_rule(&mut access.create, &model_name, &owner_eligible)?;
    normalize_and_validate_rule(&mut access.update, &model_name, &owner_eligible)?;
    normalize_and_validate_rule(&mut access.delete, &model_name, &owner_eligible)?;

    Ok(())
}

fn normalize_and_validate_rule(
    rule: &mut Option<AccessRule>,
    model_name: &str,
    owner_eligible: &HashSet<String>,
) -> Result<()> {
    let Some(rule) = rule else { return Ok(()) };
    normalize_and_validate_rule_inner(rule, model_name, owner_eligible)
}

fn normalize_and_validate_rule_inner(
    rule: &mut AccessRule,
    model_name: &str,
    owner_eligible: &HashSet<String>,
) -> Result<()> {
    match rule {
        AccessRule::Owner { field } => {
            if field == "id" {
                return Ok(());
            }
            if owner_eligible.contains(field.as_str()) {
                return Ok(());
            }
            // Accept FK column names: Owner<"created_by_id"> → normalize to Owner<"created_by">.
            // Users often write the column name; strip the _id suffix and re-check.
            if let Some(base) = field.strip_suffix("_id") {
                if owner_eligible.contains(base) {
                    *field = base.to_string();
                    return Ok(());
                }
            }
            let mut candidates: Vec<String> = owner_eligible.iter().cloned().collect();
            candidates.sort();
            bail!(
                "Model '{}': Owner<\"{}\"> is invalid. Owner fields must reference kernel field names \
                 (model fields or \"id\"). Use one of: [{}]",
                model_name,
                field,
                candidates.join(", ")
            );
        }
        AccessRule::Any { rules } | AccessRule::All { rules } => {
            for r in rules {
                normalize_and_validate_rule_inner(r, model_name, owner_eligible)?;
            }
            Ok(())
        }
        AccessRule::Not { rule } => {
            normalize_and_validate_rule_inner(rule, model_name, owner_eligible)
        }
        AccessRule::In { source, .. } => {
            if let crate::parser::ast::MembershipSource::Rows { filter: Some(f), .. } = source {
                normalize_and_validate_rule_inner(f, model_name, owner_eligible)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Collect relation FK column names for a model (db layer).
pub fn relation_fk_columns(model: &super::ast::ModelAst) -> HashSet<String> {
    let mut cols = HashSet::new();
    for (field_name, field) in &model.fields {
        if let FieldAst::Relation(rel) = field {
            let is_owning = matches!(
                rel.cardinality,
                RelationCardinality::BelongsTo | RelationCardinality::ManyToMany
            );
            if is_owning {
                cols.insert(
                    db_foreign_key(field, field_name).unwrap_or_else(|| {
                        super::accessors::default_foreign_key_column(field_name)
                    }),
                );
            }
        }
    }
    cols
}

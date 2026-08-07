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
            if !owner_eligible.contains(field) {
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
            Ok(())
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
        AccessRule::Custom { expression } => validate_custom_expression(model_name, expression),
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

/// Rejects a `Custom<>` predicate that is not a self-contained expression.
///
/// The string is interpolated into `USING ( … )` on a policy and into the body of
/// a `can_*` function. Both are *expression* positions, and neither is
/// parameterised — this is the developer's own SQL, and there is no runtime input
/// anywhere near it. So the risk is not injection in the usual sense; it is that a
/// string which reads like a predicate can quietly stop being one.
///
/// A stray `)` closes the enclosing clause and everything after it becomes
/// statement text that runs at push time with migration privileges. A `--` or an
/// unterminated `/*` swallows the closing paren. A `;` ends the statement. None of
/// these are visible as anything unusual in a schema diff, where a reviewer reads
/// `Custom<"…">` as a condition rather than as arbitrary SQL.
///
/// Anyone who can edit the schema can already write a migration, so this does not
/// draw a new trust boundary. What it does is make the boundary legible: a
/// `Custom<>` that would escape its expression is refused by name, at push, with
/// the reason, instead of executing.
pub(crate) fn validate_custom_expression(model_name: &str, expression: &str) -> Result<()> {
    let mut depth: i32 = 0;
    let mut in_string = false;
    let chars: Vec<char> = expression.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        if in_string {
            // '' is an escaped quote inside a literal, not the end of one.
            if c == '\'' {
                if chars.get(i + 1) == Some(&'\'') {
                    i += 2;
                    continue;
                }
                in_string = false;
            }
            i += 1;
            continue;
        }

        match c {
            '\'' => in_string = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    bail!(
                        "Model '{model_name}': Custom<\"{expression}\"> closes a parenthesis it \
                         did not open. The expression is placed inside `USING ( … )`, so an \
                         unbalanced `)` ends that clause and whatever follows runs as its own \
                         SQL when the migration is applied."
                    );
                }
            }
            ';' => bail!(
                "Model '{model_name}': Custom<\"{expression}\"> contains `;`. A rule is a single \
                 expression, and a statement separator here would append SQL to the migration \
                 that creates the policy."
            ),
            '-' if chars.get(i + 1) == Some(&'-') => bail!(
                "Model '{model_name}': Custom<\"{expression}\"> contains a `--` comment, which \
                 would comment out the rest of the generated statement, including the closing \
                 parenthesis of the clause it sits in."
            ),
            '/' if chars.get(i + 1) == Some(&'*') => bail!(
                "Model '{model_name}': Custom<\"{expression}\"> contains a block comment. Use a \
                 plain expression; comments risk swallowing the generated SQL around it."
            ),
            // A dollar-quoted string would terminate the `$can$…$can$` body of the
            // generated affordance function early.
            '$' => bail!(
                "Model '{model_name}': Custom<\"{expression}\"> contains `$`. Dollar quoting \
                 would end the body of the generated `can_*` function early. Call a function \
                 you define separately if the predicate needs one."
            ),
            _ => {}
        }
        i += 1;
    }

    if in_string {
        bail!(
            "Model '{model_name}': Custom<\"{expression}\"> has an unterminated string literal, \
             so the generated SQL would continue inside it."
        );
    }
    if depth != 0 {
        bail!(
            "Model '{model_name}': Custom<\"{expression}\"> leaves {depth} parenthesis(es) open."
        );
    }
    if expression.trim().is_empty() {
        bail!("Model '{model_name}': Custom<\"\"> is empty. Use Private to deny.");
    }
    Ok(())
}

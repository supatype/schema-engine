use super::column_diff;
use super::{Operation, Risk};
use crate::introspector::constraints::DbConstraintType;
use crate::parser::ast::{FieldAst, RelationCardinality, SchemaAst};
use crate::state::database_state::DatabaseState;
use anyhow::Result;
use strsim::jaro_winkler;

const RENAME_THRESHOLD: f64 = 0.7;
const EXTENSION_MANAGED_TABLES: &[&str] = &["spatial_ref_sys"];

fn is_extension_managed_table(name: &str) -> bool {
    EXTENSION_MANAGED_TABLES.contains(&name)
}

pub fn diff(
    ast: &SchemaAst,
    db: &DatabaseState,
    previous: Option<&SchemaAst>,
    ops: &mut Vec<Operation>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let db_table_names: std::collections::HashSet<&str> =
        db.tables.iter().map(|t| t.name.as_str()).collect();

    let schema_table_names: std::collections::HashSet<&str> =
        ast.models.iter().map(|m| m.table_name()).collect();

    // Build a set of existing FK constraint names for fast lookup
    let db_fk_names: std::collections::HashSet<&str> = db
        .constraints
        .iter()
        .filter(|c| c.constraint_type == DbConstraintType::ForeignKey)
        .map(|c| c.name.as_str())
        .collect();

    // Detect table renames: new tables (in schema, not in DB) vs removed tables (in DB, not in schema)
    let new_tables: Vec<&str> = ast
        .models
        .iter()
        .filter(|m| !db_table_names.contains(m.table_name()))
        .map(|m| m.table_name())
        .collect();

    let removed_tables: Vec<&str> = db
        .tables
        .iter()
        .filter(|t| {
            !schema_table_names.contains(t.name.as_str())
                && !is_extension_managed_table(t.name.as_str())
        })
        .map(|t| t.name.as_str())
        .collect();

    // For each removed table, find the best-matching new table by similarity.
    // If similarity >= threshold, treat as a rename (data preserved via ALTER TABLE RENAME).
    let mut renamed_from: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut renamed_to: std::collections::HashSet<String> = std::collections::HashSet::new();

    for &removed in &removed_tables {
        let best = new_tables
            .iter()
            .filter(|&&t| !renamed_to.contains(t))
            .map(|&t| (t, jaro_winkler(removed, t)))
            .filter(|(_, score)| *score >= RENAME_THRESHOLD)
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap());

        if let Some((matched_new, _)) = best {
            ops.push(Operation::RenameTable {
                from: removed.to_string(),
                to: matched_new.to_string(),
                risk: Risk::Cautious,
            });
            warnings.push(format!(
                "Table '{removed}' not found in schema but '{matched_new}' is new — \
                 treating as rename. Run with --force to skip confirmation."
            ));
            renamed_from.insert(removed.to_string());
            renamed_to.insert(matched_new.to_string());
        }
    }

    for model in &ast.models {
        if !db_table_names.contains(model.table_name()) {
            if renamed_to.contains(model.table_name()) {
                // This table is the target of a rename — diff columns against the source table
                let from_name = ops
                    .iter()
                    .find_map(|op| match op {
                        Operation::RenameTable { from, to, .. } if to == &model.table_name() => {
                            Some(from.clone())
                        }
                        _ => None,
                    })
                    .unwrap();
                let db_table = db.tables.iter().find(|t| t.name == from_name).unwrap();
                let prev_model = previous_model(previous, model.table_name());
                column_diff::diff(
                    model,
                    db_table,
                    db,
                    ops,
                    warnings,
                    ast.effective_default_locale(),
                    prev_model,
                )?;
                emit_fk_ops_for_model(model, ast, &db_fk_names, ops);
            } else {
                // Genuinely new table — create it + FK constraints
                ops.push(Operation::CreateTable {
                    table: model.table_name().to_string(),
                    model: Box::new(model.clone()),
                    risk: Risk::Safe,
                });
                emit_fk_ops_for_model(model, ast, &db_fk_names, ops);
            }
        } else {
            // Existing table — diff columns
            let db_table = db
                .tables
                .iter()
                .find(|t| t.name == model.table_name())
                .unwrap();
            let prev_model = previous_model(previous, model.table_name());
            column_diff::diff(
                model,
                db_table,
                db,
                ops,
                warnings,
                ast.effective_default_locale(),
                prev_model,
            )?;

            // Also diff FK relations (add new FKs, drop removed FKs)
            emit_fk_ops_for_model(model, ast, &db_fk_names, ops);
            drop_removed_fks(model, db, ops);
        }
    }

    for db_table in &db.tables {
        if !schema_table_names.contains(db_table.name.as_str())
            && !is_extension_managed_table(db_table.name.as_str())
            && !renamed_from.contains(db_table.name.as_str())
        {
            // Genuinely removed table — drop FKs then drop table
            for constraint in &db.constraints {
                if constraint.table == db_table.name
                    && constraint.constraint_type == DbConstraintType::ForeignKey
                {
                    ops.push(Operation::DropForeignKey {
                        table: db_table.name.clone(),
                        constraint: constraint.name.clone(),
                        risk: Risk::Destructive,
                    });
                }
            }
            ops.push(Operation::DropTable {
                table: db_table.name.clone(),
                risk: Risk::Destructive,
            });
        }
    }

    for jt in &ast.junction_tables {
        if !db_table_names.contains(jt.name.as_str()) {
            ops.push(Operation::CreateJunctionTable {
                table: jt.name.clone(),
                fk_a: jt.fk_a.clone(),
                table_a: jt.model_a.clone(),
                fk_b: jt.fk_b.clone(),
                table_b: jt.model_b.clone(),
                risk: Risk::Safe,
            });
        }
    }

    Ok(())
}

fn previous_model<'a>(previous: Option<&'a SchemaAst>, table_name: &str) -> Option<&'a crate::parser::ast::ModelAst> {
    previous?
        .models
        .iter()
        .find(|m| m.table_name() == table_name)
}

#[cfg(test)]
mod tests {
    use super::is_extension_managed_table;

    #[test]
    fn ignores_known_extension_managed_tables() {
        assert!(is_extension_managed_table("spatial_ref_sys"));
        assert!(!is_extension_managed_table("post"));
    }
}

/// Emit AddForeignKey ops for all belongsTo relations on a model that don't already exist in the DB.
fn emit_fk_ops_for_model(
    model: &crate::parser::ast::ModelAst,
    ast: &SchemaAst,
    db_fk_names: &std::collections::HashSet<&str>,
    ops: &mut Vec<Operation>,
) {
    for (field_name, field) in &model.fields {
        if let FieldAst::Relation(rel) = field {
            if matches!(rel.cardinality, RelationCardinality::BelongsTo) {
                let fk_col = rel
                    .foreign_key
                    .as_deref()
                    .unwrap_or_else(|| Box::leak(format!("{field_name}_id").into_boxed_str()));
                let constraint_name = format!("{}_{}_fkey", model.table_name(), fk_col);

                if !db_fk_names.contains(constraint_name.as_str()) {
                    let (ref_table, ref_schema) = if let Some((sys_schema, sys_table)) =
                        crate::parser::resolver::resolve_system_ref(&rel.target)
                    {
                        (sys_table.to_string(), Some(sys_schema.to_string()))
                    } else {
                        let t = ast
                            .models
                            .iter()
                            .find(|m| m.name == rel.target)
                            .map(|m| m.table_name().to_string())
                            .unwrap_or_else(|| crate::parser::resolver::to_snake_case(&rel.target));
                        (t, None)
                    };

                    ops.push(Operation::AddForeignKey {
                        table: model.table_name().to_string(),
                        field_name: field_name.clone(),
                        relation: Box::new(rel.clone()),
                        ref_table,
                        ref_schema,
                        risk: Risk::Safe,
                    });
                }
            }
        }
    }
}

/// Emit DropForeignKey for any DB FK on this table whose constraint name is no longer
/// derivable from the current schema's belongsTo relations.
fn drop_removed_fks(
    model: &crate::parser::ast::ModelAst,
    db: &DatabaseState,
    ops: &mut Vec<Operation>,
) {
    // Build the set of FK constraint names that should exist per the schema
    let expected_fks: std::collections::HashSet<String> = model
        .fields
        .iter()
        .filter_map(|(field_name, field)| {
            if let FieldAst::Relation(rel) = field {
                if matches!(rel.cardinality, RelationCardinality::BelongsTo) {
                    let fk_col = rel
                        .foreign_key
                        .as_deref()
                        .unwrap_or_else(|| Box::leak(format!("{field_name}_id").into_boxed_str()));
                    return Some(format!("{}_{}_fkey", model.table_name(), fk_col));
                }
            }
            None
        })
        .collect();

    for constraint in &db.constraints {
        if constraint.table == model.table_name()
            && constraint.constraint_type == DbConstraintType::ForeignKey
            && !expected_fks.contains(&constraint.name)
        {
            ops.push(Operation::DropForeignKey {
                table: model.table_name().to_string(),
                constraint: constraint.name.clone(),
                risk: Risk::Safe,
            });
        }
    }
}

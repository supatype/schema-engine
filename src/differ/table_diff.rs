use super::column_diff;
use super::{Operation, Risk};
use crate::introspector::constraints::DbConstraintType;
use crate::parser::ast::{FieldAst, RelationCardinality, SchemaAst};
use crate::state::database_state::DatabaseState;
use anyhow::Result;

pub fn diff(
    ast: &SchemaAst,
    db: &DatabaseState,
    ops: &mut Vec<Operation>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let db_table_names: std::collections::HashSet<&str> =
        db.tables.iter().map(|t| t.name.as_str()).collect();

    let schema_table_names: std::collections::HashSet<&str> =
        ast.models.iter().map(|m| m.table_name.as_str()).collect();

    // Build a set of existing FK constraint names for fast lookup
    let db_fk_names: std::collections::HashSet<&str> = db
        .constraints
        .iter()
        .filter(|c| c.constraint_type == DbConstraintType::ForeignKey)
        .map(|c| c.name.as_str())
        .collect();

    for model in &ast.models {
        if !db_table_names.contains(model.table_name.as_str()) {
            // New table — create it + FK constraints
            ops.push(Operation::CreateTable {
                table: model.table_name.clone(),
                model: Box::new(model.clone()),
                risk: Risk::Safe,
            });
            emit_fk_ops_for_model(model, ast, &db_fk_names, ops);
        } else {
            // Existing table — diff columns
            let db_table = db
                .tables
                .iter()
                .find(|t| t.name == model.table_name)
                .unwrap();
            column_diff::diff(
                model,
                db_table,
                ops,
                warnings,
                ast.effective_default_locale(),
            )?;

            // Also diff FK relations (add new FKs, drop removed FKs)
            emit_fk_ops_for_model(model, ast, &db_fk_names, ops);
            drop_removed_fks(model, db, ops);
        }
    }

    for db_table in &db.tables {
        if !schema_table_names.contains(db_table.name.as_str()) {
            // First drop FKs on this table, then drop the table
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
                let constraint_name = format!("{}_{}_fkey", model.table_name, fk_col);

                if !db_fk_names.contains(constraint_name.as_str()) {
                    let ref_table = ast
                        .models
                        .iter()
                        .find(|m| m.name == rel.target)
                        .map(|m| m.table_name.clone())
                        .unwrap_or_else(|| crate::parser::resolver::to_snake_case(&rel.target));

                    ops.push(Operation::AddForeignKey {
                        table: model.table_name.clone(),
                        relation: Box::new(rel.clone()),
                        ref_table,
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
                    return Some(format!("{}_{}_fkey", model.table_name, fk_col));
                }
            }
            None
        })
        .collect();

    for constraint in &db.constraints {
        if constraint.table == model.table_name
            && constraint.constraint_type == DbConstraintType::ForeignKey
            && !expected_fks.contains(&constraint.name)
        {
            ops.push(Operation::DropForeignKey {
                table: model.table_name.clone(),
                constraint: constraint.name.clone(),
                risk: Risk::Safe,
            });
        }
    }
}

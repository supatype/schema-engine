use anyhow::Result;
use crate::parser::ast::{FieldAst, RelationCardinality, SchemaAst};
use crate::state::database_state::DatabaseState;
use super::{Operation, Risk};
use super::column_diff;

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

    for model in &ast.models {
        if !db_table_names.contains(model.table_name.as_str()) {
            ops.push(Operation::CreateTable {
                table: model.table_name.clone(),
                model: Box::new(model.clone()),
                risk: Risk::Safe,
            });
            // Emit FK ops separately so they sort after all CreateTable ops.
            for field in model.fields.values() {
                if let FieldAst::Relation(rel) = field {
                    if matches!(rel.cardinality, RelationCardinality::BelongsTo) {
                        let ref_table = ast.models.iter()
                            .find(|m| m.name == rel.target)
                            .map(|m| m.table_name.clone())
                            .unwrap_or_else(|| rel.target.to_lowercase());
                        ops.push(Operation::AddForeignKey {
                            table: model.table_name.clone(),
                            relation: Box::new(rel.clone()),
                            ref_table,
                            risk: Risk::Safe,
                        });
                    }
                }
            }
        } else {
            let db_table = db.tables.iter().find(|t| t.name == model.table_name).unwrap();
            column_diff::diff(model, db_table, ops, warnings)?;
        }
    }

    for db_table in &db.tables {
        if !schema_table_names.contains(db_table.name.as_str()) {
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

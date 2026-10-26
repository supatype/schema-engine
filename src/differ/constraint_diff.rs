//! The single-column unique constraints a schema declares. Since Phase 4.11 the reconcile creates
//! and drops them from the desired set, judged by the ledger; this is what both read.

use crate::managed::expected_unique_constraint_name;
use crate::parser::accessors::{column_names_for, db_unique};
use crate::parser::ast::{FieldAst, SchemaAst};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ExpectedUnique {
    pub(crate) table: String,
    pub(crate) column: String,
    pub(crate) constraint_name: String,
}

pub(crate) fn expected_column_uniques(ast: &SchemaAst) -> Vec<ExpectedUnique> {
    let mut out = Vec::new();
    for model in &ast.models {
        let table = model.table_name().to_string();
        for (field_name, field) in &model.fields {
            if !db_unique(field) {
                continue;
            }
            if matches!(field, FieldAst::Relation(_)) {
                continue;
            }
            for col in column_names_for(field_name, field) {
                if col.is_empty() {
                    continue;
                }
                out.push(ExpectedUnique {
                    table: table.clone(),
                    column: col.clone(),
                    constraint_name: expected_unique_constraint_name(&table, &col),
                });
            }
        }
    }
    out
}

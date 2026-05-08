pub mod column_diff;
pub mod constraint_diff;
pub mod enum_diff;
pub mod index_diff;
pub mod ordering;
pub mod risk_analyser;
pub mod rls_diff;
pub mod table_diff;
pub mod trigger_diff;

use crate::parser::ast::{FieldAst, IndexAst, ModelAst, RelationFieldAst, SchemaAst};
use crate::state::database_state::DatabaseState;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffOutput {
    pub operations: Vec<Operation>,
    pub summary: DiffSummary,
    pub warnings: Vec<String>,
}

/// Each operation carries enough data for the SQL generator to produce DDL
/// without needing to re-query the AST.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Operation {
    CreateTable {
        table: String,
        /// Full model definition — SQL generator uses this to emit CREATE TABLE DDL.
        model: Box<ModelAst>,
        risk: Risk,
    },
    DropTable {
        table: String,
        risk: Risk,
    },
    RenameTable {
        from: String,
        to: String,
        risk: Risk,
    },
    AddColumn {
        table: String,
        column: String,
        field: Box<FieldAst>,
        risk: Risk,
    },
    DropColumn {
        table: String,
        column: String,
        risk: Risk,
    },
    RenameColumn {
        table: String,
        from: String,
        to: String,
        risk: Risk,
    },
    AlterColumn {
        table: String,
        column: String,
        changes: serde_json::Value,
        risk: Risk,
        warning: Option<String>,
    },
    AddIndex {
        table: String,
        index: Box<IndexAst>,
        risk: Risk,
    },
    DropIndex {
        index_name: String,
        risk: Risk,
    },
    AddForeignKey {
        table: String,
        /// Schema field name (e.g. "author") — used to derive FK column when `relation.foreign_key` is absent.
        field_name: String,
        relation: Box<RelationFieldAst>,
        ref_table: String,
        /// Override schema for cross-schema refs (e.g. `Some("auth")` for `supatype:user`).
        /// When `None`, the migration schema is used.
        ref_schema: Option<String>,
        risk: Risk,
    },
    DropForeignKey {
        table: String,
        constraint: String,
        risk: Risk,
    },
    CreateEnum {
        name: String,
        values: Vec<String>,
        risk: Risk,
    },
    DropEnum {
        name: String,
        risk: Risk,
    },
    AddEnumValue {
        enum_name: String,
        value: String,
        risk: Risk,
    },
    RemoveEnumValue {
        enum_name: String,
        value: String,
        /// All table.column pairs that use this enum type.
        affected_columns: Vec<(String, String)>,
        risk: Risk,
    },
    RenameEnumValue {
        enum_name: String,
        from: String,
        to: String,
        risk: Risk,
    },
    ReorderEnumValues {
        enum_name: String,
        old_values: Vec<String>,
        new_values: Vec<String>,
        /// All table.column pairs that use this enum type.
        affected_columns: Vec<(String, String)>,
        risk: Risk,
    },
    EnableRls {
        table: String,
        risk: Risk,
    },
    CreateRlsPolicy {
        table: String,
        policy: String,
        risk: Risk,
    },
    DropRlsPolicy {
        table: String,
        policy: String,
        risk: Risk,
    },
    CreateTrigger {
        table: String,
        trigger: String,
        risk: Risk,
    },
    DropTrigger {
        table: String,
        trigger: String,
        risk: Risk,
    },
    CreateJunctionTable {
        table: String,
        fk_a: String,
        table_a: String,
        fk_b: String,
        table_b: String,
        risk: Risk,
    },
    EnableExtension {
        name: String,
        risk: Risk,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Risk {
    Safe,
    Cautious,
    Destructive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffSummary {
    pub safe: usize,
    pub cautious: usize,
    pub destructive: usize,
    pub is_destructive: bool,
}

pub fn diff(ast: &SchemaAst, db: &DatabaseState) -> Result<DiffOutput> {
    let mut ops: Vec<Operation> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    enum_diff::diff(ast, db, &mut ops, &mut warnings)?;
    table_diff::diff(ast, db, &mut ops, &mut warnings)?;
    index_diff::diff(ast, db, &mut ops)?;
    rls_diff::diff(ast, db, &mut ops, &mut warnings)?;
    trigger_diff::diff(ast, db, &mut ops)?;

    let ordered_ops = ordering::topological_sort(ops)?;

    let safe = ordered_ops
        .iter()
        .filter(|o| matches!(risk_of(o), Risk::Safe))
        .count();
    let cautious = ordered_ops
        .iter()
        .filter(|o| matches!(risk_of(o), Risk::Cautious))
        .count();
    let destructive = ordered_ops
        .iter()
        .filter(|o| matches!(risk_of(o), Risk::Destructive))
        .count();

    Ok(DiffOutput {
        operations: ordered_ops,
        summary: DiffSummary {
            safe,
            cautious,
            destructive,
            is_destructive: destructive > 0,
        },
        warnings,
    })
}

pub fn risk_of(op: &Operation) -> &Risk {
    match op {
        Operation::CreateTable { risk, .. }
        | Operation::DropTable { risk, .. }
        | Operation::RenameTable { risk, .. }
        | Operation::AddColumn { risk, .. }
        | Operation::DropColumn { risk, .. }
        | Operation::RenameColumn { risk, .. }
        | Operation::AlterColumn { risk, .. }
        | Operation::AddIndex { risk, .. }
        | Operation::DropIndex { risk, .. }
        | Operation::AddForeignKey { risk, .. }
        | Operation::DropForeignKey { risk, .. }
        | Operation::CreateEnum { risk, .. }
        | Operation::DropEnum { risk, .. }
        | Operation::AddEnumValue { risk, .. }
        | Operation::RemoveEnumValue { risk, .. }
        | Operation::RenameEnumValue { risk, .. }
        | Operation::ReorderEnumValues { risk, .. }
        | Operation::EnableRls { risk, .. }
        | Operation::CreateRlsPolicy { risk, .. }
        | Operation::DropRlsPolicy { risk, .. }
        | Operation::CreateTrigger { risk, .. }
        | Operation::DropTrigger { risk, .. }
        | Operation::CreateJunctionTable { risk, .. }
        | Operation::EnableExtension { risk, .. } => risk,
    }
}

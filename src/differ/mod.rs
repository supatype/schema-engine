pub mod column_diff;
pub mod check_diff;
pub mod constraint_diff;
pub mod doctor;
pub mod enum_diff;
pub mod field_access_diff;
pub mod index_diff;
pub mod integrity;
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
    /// Tables a model declares that already exist **and** carry no ownership marker.
    ///
    /// Nothing that changes them may be emitted — not RLS, not policies, not grants, not security
    /// labels. Declaring a model is not permission to alter a table Supatype did not create: enabling
    /// row level security on it can stop another application reading its own data, and it is the same
    /// argument that would license dropping its columns.
    ///
    /// Computed here because the generators see only the AST, and the marker lives in the database.
    #[serde(default)]
    pub unmanaged_model_tables: Vec<String>,
    /// How field rules will be enforced on *this* database.
    ///
    /// Decided here for the same reason as above: the answer is a property of the database — is the
    /// masking extension installed? — and the generators only see the schema.
    #[serde(default)]
    pub field_masking: FieldMaskingTier,
    /// The tables tier 2's `api` layer has to cover, with their columns and keys.
    ///
    /// Read here because it comes from the database; rendered by the SQL generator, which is the only
    /// place that knows which schema the push was given.
    #[serde(default)]
    pub field_view_plan: Vec<crate::generator::sql::field_views::FieldViewTable>,
}

/// How a database enforces per-column rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum FieldMaskingTier {
    /// No column in the schema has a rule, so nothing has to enforce anything.
    #[default]
    None,
    /// `supatype_mask` rewrites references to the base table in the planner.
    Extension,
    /// Generated `api`-schema views carry the masking expression, and PostgREST is pointed at them.
    ///
    /// The fallback for a database that cannot load an extension — which is most managed Postgres, and
    /// therefore most of what `database.external` made possible.
    Views,
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
        field: Box<FieldAst>,
        changes: serde_json::Value,
        risk: Risk,
        warning: Option<String>,
    },
    /// Drop and re-add a column when type conversion is impossible (data loss).
    RecreateColumn {
        table: String,
        column: String,
        field: Box<FieldAst>,
        changes: serde_json::Value,
        dependencies: Vec<ColumnDependencySnapshot>,
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
    AddUniqueConstraint {
        table: String,
        column: String,
        constraint: String,
        risk: Risk,
    },
    /// Replace a column's declared bounds. Emitted as a drop and an add, because Postgres has no
    /// `ALTER CONSTRAINT` for a check expression.
    AddCheckConstraint {
        table: String,
        /// Columns the rule reads. One for a field's bounds, several for a cross-column constraint,
        /// and it is what lets a failure name the columns rather than a generated constraint name.
        columns: Vec<String>,
        constraint: String,
        expression: String,
        comment: String,
        risk: Risk,
    },
    DropCheckConstraint {
        table: String,
        constraint: String,
        risk: Risk,
    },
    DropUniqueConstraint {
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

/// FK / index metadata captured before a column is dropped and recreated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ColumnDependencySnapshot {
    pub kind: String,
    pub table: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub columns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub foreign_table: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub foreign_columns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_delete: Option<String>,
    #[serde(default)]
    pub unique: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_method: Option<String>,
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
    diff_with_previous(ast, db, None)
}

/// Diff against live DB state, optionally comparing field kinds to a previous schema snapshot.
pub fn diff_with_previous(
    ast: &SchemaAst,
    db: &DatabaseState,
    previous: Option<&SchemaAst>,
) -> Result<DiffOutput> {
    let mut ops: Vec<Operation> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    enum_diff::diff(ast, db, &mut ops, &mut warnings)?;
    table_diff::diff(ast, db, previous, &mut ops, &mut warnings)?;
    constraint_diff::diff(ast, db, &mut ops)?;
    check_diff::diff(ast, db, &mut ops)?;
    index_diff::diff(ast, db, &mut ops)?;
    rls_diff::diff(ast, db, &mut ops, &mut warnings)?;
    field_access_diff::validate(ast, db, &mut warnings)?;
    trigger_diff::diff(ast, db, &mut ops)?;

    let ordered_ops = ordering::topological_sort(ops)?;

    // Which mechanism will enforce the field rules here. `Views` is not a preference: it is what is
    // left when the extension is absent, and the alternative was refusing the push outright.
    let field_masking = if !crate::generator::sql::field_views::has_field_rules(ast) {
        FieldMaskingTier::None
    } else if db
        .extensions
        .iter()
        .any(|e| e == crate::generator::sql::rls::MASK_EXTENSION)
    {
        FieldMaskingTier::Extension
    } else {
        FieldMaskingTier::Views
    };
    let field_view_plan = match field_masking {
        FieldMaskingTier::Views => crate::generator::sql::field_views::field_view_plan(ast, db),
        _ => Vec::new(),
    };

    // Model tables that already exist without an ownership marker. The security apparatus — grants,
    // column privileges, field labels — is re-asserted from the AST alone on every push, so the
    // renderer has no way to know which tables are ours unless it is told.
    let unmanaged_model_tables: Vec<String> = ast
        .models
        .iter()
        .filter_map(|m| {
            db.tables
                .iter()
                .find(|t| t.name == m.table_name())
                .filter(|t| !crate::managed::is_managed_comment(t.comment.as_deref()))
                .map(|t| t.name.clone())
        })
        .collect();

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
        unmanaged_model_tables,
        field_masking,
        field_view_plan,
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
        | Operation::RecreateColumn { risk, .. }
        | Operation::AddIndex { risk, .. }
        | Operation::DropIndex { risk, .. }
        | Operation::AddForeignKey { risk, .. }
        | Operation::DropForeignKey { risk, .. }
        | Operation::AddUniqueConstraint { risk, .. }
        | Operation::DropUniqueConstraint { risk, .. }
        | Operation::AddCheckConstraint { risk, .. }
        | Operation::DropCheckConstraint { risk, .. }
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

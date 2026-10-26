pub mod column_diff;
pub mod constraint_diff;
pub mod doctor;
pub mod field_access_diff;
pub mod integrity;
pub mod ordering;
pub mod rls_diff;
pub mod table_diff;

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
    /// Tables a model declares that already exist **and** are not Supatype's.
    ///
    /// Nothing that changes them may be emitted: not RLS, not policies, not grants, not security
    /// labels. Declaring a model is not permission to alter a table Supatype did not create: enabling
    /// row level security on it can stop another application reading its own data, and it is the same
    /// argument that would license dropping its columns.
    ///
    /// Computed here because the generators see only the AST, and the marker lives in the database.
    #[serde(default)]
    pub unmanaged_model_tables: Vec<String>,
    /// How field rules will be enforced on *this* database.
    ///
    /// Decided here for the same reason as above: the answer is a property of the database (is the
    /// masking extension installed?) and the generators only see the schema.
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
    /// The fallback for a database that cannot load an extension, which is most managed Postgres, and
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
        /// Full model definition. The SQL generator uses this to emit CREATE TABLE DDL.
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
    AddForeignKey {
        table: String,
        /// Schema field name (e.g. "author"), used to derive the FK column when `relation.foreign_key` is absent.
        field_name: String,
        relation: Box<RelationFieldAst>,
        ref_table: String,
        /// Override schema for cross-schema refs (e.g. `Some("auth")` for `supatype:user`).
        /// When `None`, the migration schema is used.
        ref_schema: Option<String>,
        risk: Risk,
    },
    AddUniqueConstraint {
        table: String,
        column: String,
        constraint: String,
        risk: Risk,
    },
    CreateRlsPolicy {
        table: String,
        policy: String,
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
    /// The snapshot table behind a versioned model.
    ///
    /// Its own operation rather than a synthesised model, for the same reason a junction table has
    /// one: the engine owns it outright, its shape is fixed, and putting a model in `ast.models` for
    /// it would put it in the OpenAPI document, the generated types and Studio's navigation, none of
    /// which should list a table nobody declared.
    CreateVersionsTable {
        table: String,
        versions_table: String,
        /// Type of the model's primary key, which `record_id` has to match to reference it.
        record_id_type: String,
        /// Column name of that primary key.
        primary_key: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

    table_diff::diff(ast, db, previous, &mut ops, &mut warnings)?;
    rls_diff::diff(ast, db, &mut warnings)?;
    field_access_diff::validate(ast, db, &mut warnings)?;
    warnings.extend(crate::generator::sql::storage::rule_warnings(ast));

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

    // Model tables that already exist and are not Supatype's. The security apparatus (grants,
    // column privileges, field labels) is re-asserted from the AST alone on every push, so the
    // renderer has no way to know which tables are ours unless it is told.
    let unmanaged_model_tables: Vec<String> = ast
        .models
        .iter()
        .filter_map(|m| {
            db.tables
                .iter()
                .find(|t| t.name == m.table_name())
                .filter(|t| !db.owns_table(t))
                .map(|t| t.name.clone())
        })
        .collect();

    Ok(DiffOutput {
        summary: DiffSummary::of(&ordered_ops),
        operations: ordered_ops,
        unmanaged_model_tables,
        field_masking,
        field_view_plan,
        warnings,
    })
}

impl DiffSummary {
    /// How many of `operations` are safe, cautious and destructive.
    pub fn of(operations: &[Operation]) -> DiffSummary {
        let count = |risk: Risk| operations.iter().filter(|o| *risk_of(o) == risk).count();
        let destructive = count(Risk::Destructive);
        DiffSummary {
            safe: count(Risk::Safe),
            cautious: count(Risk::Cautious),
            destructive,
            is_destructive: destructive > 0,
        }
    }
}

impl DiffOutput {
    /// Withholds every column drop for a column `owned` does not say is ours (D4): a column someone
    /// added to a managed table is never the engine's to drop. Each is reported instead.
    pub fn keep_columns_not_ours(&mut self, owned: impl Fn(&str, &str) -> bool) {
        let mut kept = Vec::new();
        self.operations.retain(|op| match op {
            Operation::DropColumn { table, column, .. } if !owned(table, column) => {
                kept.push(format!("\"{table}\".\"{column}\""));
                false
            }
            _ => true,
        });
        if kept.is_empty() {
            return;
        }
        self.warnings.push(format!(
            "{} column(s) the schema does not declare are not Supatype's, so they are left in place: \
             {}. Declare a column in the schema to manage it, or drop it by hand.",
            kept.len(),
            kept.join(", ")
        ));
        self.summary = DiffSummary::of(&self.operations);
    }
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
        | Operation::AddForeignKey { risk, .. }
        | Operation::AddUniqueConstraint { risk, .. }
        | Operation::CreateRlsPolicy { risk, .. }
        | Operation::CreateJunctionTable { risk, .. }
        | Operation::CreateVersionsTable { risk, .. }
        | Operation::EnableExtension { risk, .. } => risk,
    }
}

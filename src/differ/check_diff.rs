//! Reconcile a column's declared bounds with the constraint the database holds.
//!
//! Bounds used to be create-only: emitted inline by `CREATE TABLE` and `ADD COLUMN`, never compared
//! again. Tightening `MaxLength<string, 320>` to `80` therefore produced no DDL at all, and the
//! database went on enforcing 320 while the schema and Studio both claimed 80. Nothing reported it,
//! because the differ only ever looked at unique and foreign-key constraints.
//!
//! **Comparison is by fingerprint, not by SQL text.** `pg_get_constraintdef` rewrites an expression
//! on read-back: it re-quotes identifiers, re-parenthesises and moves casts. Comparing that against
//! what we generated reports a difference on every push, which is precisely the trap the access-rule
//! work fell into three separate times. The fingerprint lives in the constraint's comment, is
//! written by us, and is rewritten by nobody, so equality means equality.
use super::{Operation, Risk};
use crate::differ::column_diff::column_names_for;
use crate::generator::sql::constraints::constraint_to_expr;
use crate::generator::sql::migration::field_check_expression;
use crate::introspector::constraints::{DbConstraint, DbConstraintType};
use crate::managed::{
    check_fingerprint, expected_check_constraint_name, expected_model_constraint_name,
    fingerprint_of, is_managed_comment, managed_check_comment,
};
use crate::parser::ast::columns_in;
use crate::parser::ast::SchemaAst;
use crate::state::database_state::DatabaseState;
use anyhow::Result;
use std::collections::HashSet;

struct ExpectedCheck {
    table: String,
    /// Columns the rule reads: one for a field's bounds, several for a cross-column constraint.
    columns: Vec<String>,
    /// The single column this belongs to, when it is a field's own bounds. `None` for a model-level
    /// constraint, which is what decides whether `ADD COLUMN` has already declared it inline.
    owning_column: Option<String>,
    constraint: String,
    expression: String,
}

fn expected_checks(ast: &SchemaAst) -> Vec<ExpectedCheck> {
    let mut out = Vec::new();
    for model in &ast.models {
        let table = model.table_name().to_string();

        // Field bounds: declared inline on the column, one constraint per column.
        for (field_name, field) in &model.fields {
            for col in column_names_for(field_name, field) {
                if col.is_empty() {
                    continue;
                }
                let Some(expression) = field_check_expression(field, &col) else {
                    continue;
                };
                out.push(ExpectedCheck {
                    constraint: expected_check_constraint_name(&table, &col),
                    table: table.clone(),
                    columns: vec![col.clone()],
                    owning_column: Some(col),
                    expression,
                });
            }
        }

        // Model-level constraints: named by position, because the author writes an expression and
        // not an identifier. Reordering therefore renames, which the fingerprint turns into a
        // recognised move rather than a spurious change.
        for (index, rule) in model.annotations.db.constraints.iter().enumerate() {
            let Ok(expression) = constraint_to_expr(rule) else {
                // A rule that cannot be rendered fails the migration, loudly, in the generator. The
                // differ's job is not to be the place that reports it.
                continue;
            };
            let mut columns = Vec::new();
            columns_in(rule, &mut columns);
            out.push(ExpectedCheck {
                constraint: expected_model_constraint_name(&table, index),
                table: table.clone(),
                columns,
                owning_column: None,
                expression,
            });
        }
    }
    out
}

/// Managed bounds constraints the database currently holds.
///
/// Unmanaged checks are ignored entirely. A `CHECK` someone added by hand, or one Postgres created
/// for an enum column, is not ours to reconcile, and dropping it because the schema does not mention
/// it would destroy a rule the database was relying on.
fn db_managed_checks(db: &DatabaseState) -> impl Iterator<Item = &DbConstraint> {
    db.constraints.iter().filter(|c| {
        c.constraint_type == DbConstraintType::Check && is_managed_comment(c.comment.as_deref())
    })
}

fn table_being_created(ops: &[Operation], table: &str) -> bool {
    ops.iter()
        .any(|op| matches!(op, Operation::CreateTable { table: t, .. } if t == table))
}

fn column_being_added(ops: &[Operation], table: &str, column: &str) -> bool {
    ops.iter().any(
        |op| matches!(op, Operation::AddColumn { table: t, column: c, .. } if t == table && c == column),
    )
}

pub fn diff(ast: &SchemaAst, db: &DatabaseState, ops: &mut Vec<Operation>) -> Result<()> {
    let expected = expected_checks(ast);
    let expected_names: HashSet<(&str, &str)> = expected
        .iter()
        .map(|e| (e.table.as_str(), e.constraint.as_str()))
        .collect();
    let schema_tables: HashSet<&str> = ast.models.iter().map(|m| m.table_name()).collect();

    for exp in &expected {
        // `CREATE TABLE` and `ADD COLUMN` already declare the constraint inline and stamp it, so
        // adding it again here would fail on the duplicate name.
        let inline_with_new_column = exp
            .owning_column
            .as_deref()
            .is_some_and(|col| column_being_added(ops, &exp.table, col));
        if table_being_created(ops, &exp.table) || inline_with_new_column {
            continue;
        }

        let existing = db
            .constraints
            .iter()
            .find(|c| c.table == exp.table && c.name == exp.constraint);

        let wanted = check_fingerprint(&exp.expression);
        match existing {
            // Unchanged: the database already enforces exactly this bound.
            Some(c) if fingerprint_of(c.comment.as_deref()) == Some(wanted.as_str()) => continue,
            // Present but different, or present without a fingerprint (created before bounds were
            // reconciled). Postgres has no `ALTER CONSTRAINT` for a check expression, so replacing
            // it means dropping and adding.
            Some(c) => ops.push(Operation::DropCheckConstraint {
                table: exp.table.clone(),
                constraint: c.name.clone(),
                risk: Risk::Safe,
            }),
            None => {}
        }

        ops.push(Operation::AddCheckConstraint {
            table: exp.table.clone(),
            columns: exp.columns.clone(),
            constraint: exp.constraint.clone(),
            expression: exp.expression.clone(),
            comment: managed_check_comment(
                &exp.table,
                &exp.columns.iter().map(String::as_str).collect::<Vec<_>>(),
                &exp.expression,
            ),
            // Adding a bound to a table that already holds rows fails if any row breaches it. That
            // is a refusal to apply, not data loss, so it is `Cautious` rather than `Destructive`:
            // the migration stops and every row stays exactly as it was.
            risk: Risk::Cautious,
        });
    }

    // A bound removed from the schema must be removed from the database, or it goes on rejecting
    // writes the schema now permits.
    for constraint in db_managed_checks(db) {
        if !schema_tables.contains(constraint.table.as_str()) {
            continue;
        }
        if expected_names.contains(&(constraint.table.as_str(), constraint.name.as_str())) {
            continue;
        }
        ops.push(Operation::DropCheckConstraint {
            table: constraint.table.clone(),
            constraint: constraint.name.clone(),
            risk: Risk::Safe,
        });
    }

    Ok(())
}

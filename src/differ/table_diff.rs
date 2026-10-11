use super::{column_diff, renames};
use super::{Operation, Risk};
use crate::introspector::constraints::DbConstraintType;
use crate::parser::ast::SchemaAst;
use crate::state::database_state::DatabaseState;
use anyhow::Result;

const EXTENSION_MANAGED_TABLES: &[&str] = &["spatial_ref_sys"];

fn is_extension_managed_table(name: &str) -> bool {
    EXTENSION_MANAGED_TABLES.contains(&name)
}

/// **Ownership gate.** Destructive operations here are conditional on a table being Supatype's, as
/// `DatabaseState::owns_table` decides: its ledger row (Phase 4.11), or for a table no push has
/// recorded yet, the `COMMENT ON TABLE` marker an older engine wrote.
///
/// Indexes, constraints and RLS policies have been gated this way for a long time; `doctor` even
/// reports an unmanaged index as "push will not drop; manual decision required". Tables were never
/// wired into the same mechanism, so **any** table in the managed schema absent from
/// `schema/index.ts` was dropped. On a database Supatype did not create, that is someone else's
/// data.
///
/// Additive operations are deliberately not gated: a table you do not own may gain a column, which
/// is intrusive but recoverable. It may not lose one.
pub fn diff(
    ast: &SchemaAst,
    db: &DatabaseState,
    previous: Option<&SchemaAst>,
    ops: &mut Vec<Operation>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let db_table_names: std::collections::HashSet<&str> =
        db.tables.iter().map(|t| t.name.as_str()).collect();
    // Junction tables are first-class schema objects, so they are included: otherwise the
    // "removed table" pass does not drop live M2M tables as orphans (and then
    // skip recreate because they still appear in the initial db snapshot).
    //
    // Snapshot tables likewise, and there the stakes are higher: they are Supatype's by the ledger, so
    // the ownership gate below is no protection at all, and dropping one takes every version of
    // every record with it. A model that *stops* declaring `versions` does fall out of this set, so
    // its history is dropped, destructively, which needs `--force`, the right ceremony for
    // deliberately discarding history.
    let versions_tables = crate::generator::sql::versions::versions_tables(ast);
    let schema_table_names: std::collections::HashSet<&str> = ast
        .models
        .iter()
        .map(|m| m.table_name())
        .chain(ast.junction_tables.iter().map(|j| j.name.as_str()))
        .chain(versions_tables.iter().map(String::as_str))
        .collect();

    // Renames are declared, never guessed (D1): a model's `renamedFrom` names its old table, which
    // is renamed only when it exists, is Supatype's and is not declared again (`renames`).
    let mut renamed_from: std::collections::HashSet<String> = std::collections::HashSet::new();
    for model in &ast.models {
        if let Some(from) = renames::check_table_rename(model, db, &schema_table_names)? {
            ops.push(Operation::RenameTable {
                from: from.to_string(),
                to: model.table_name().to_string(),
                risk: Risk::Safe,
            });
            renamed_from.insert(from.to_string());
        }
    }

    for model in &ast.models {
        if !db_table_names.contains(model.table_name()) {
            let source = model
                .annotations
                .db
                .renamed_from
                .as_deref()
                .filter(|from| renamed_from.contains(*from))
                .and_then(|from| db.tables.iter().find(|t| t.name == from));
            if let Some(db_table) = source {
                // The target of a declared rename: its columns are diffed against the old table,
                // and the last push's model is the one under the old name.
                let prev_model = previous_model(previous, &db_table.name);
                column_diff::diff(
                    model,
                    db_table,
                    db,
                    ops,
                    warnings,
                    ast.effective_default_locale(),
                    prev_model,
                )?;
            } else {
                // Genuinely new table. Its foreign keys are the reconcile's (Phase 4.1).
                ops.push(Operation::CreateTable {
                    table: model.table_name().to_string(),
                    model: Box::new(model.clone()),
                    risk: Risk::Safe,
                });
            }
        } else {
            // Existing table: diff its columns
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
        }
    }

    let mut to_drop: Vec<&str> = Vec::new();
    for db_table in &db.tables {
        if !schema_table_names.contains(db_table.name.as_str())
            && !is_extension_managed_table(db_table.name.as_str())
            && !renamed_from.contains(db_table.name.as_str())
        {
            // Never destroy a table Supatype did not create.
            //
            // Reported, not skipped in silence: a drop that quietly does nothing is how an operator
            // concludes push is broken. The message names the table and the way out.
            if !db.owns_table(db_table) {
                warnings.push(format!(
                    "Table \"{}\" is not managed by Supatype and is not in \
                     your schema, so it is left alone. Run `supatype adopt` to bring it under \
                     management, or remove it by hand.",
                    db_table.name
                ));
                continue;
            }
            to_drop.push(db_table.name.as_str());
        }
    }
    // Genuinely removed tables. A table's own constraints go with it; a foreign key from another
    // surviving table into it is the reconcile's to drop first, which the migration runs before
    // this (plan 3.3: nothing cascades). Between the dropped tables themselves, the one holding
    // the foreign key goes before the one it points at (a junction before its models, a history
    // table before its model), or Postgres refuses the parent's drop.
    for table in drop_order(to_drop, db) {
        ops.push(Operation::DropTable {
            table: table.to_string(),
            risk: Risk::Destructive,
        });
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

    // One snapshot table per versioned model, created when absent.
    //
    // `record_id` follows the model's own primary key rather than assuming `UUID`: a model keyed by
    // a `Serial` would otherwise get a foreign key Postgres refuses to create, and the push would
    // fail on a type mismatch that names neither the model nor the reason.
    for model in crate::generator::sql::versions::versioned_models(ast) {
        let table = model.table_name();
        let versions_table = crate::parser::accessors::versions_table_name(table);
        if db_table_names.contains(versions_table.as_str()) {
            continue;
        }
        let (primary_key, record_id_type) = versions_record_id(model);
        ops.push(Operation::CreateVersionsTable {
            table: table.to_string(),
            versions_table,
            record_id_type,
            primary_key,
            risk: Risk::Safe,
        });
    }

    Ok(())
}

/// The column and type `record_id` has to match, from the model's declared primary key.
///
/// Falls back to `id UUID`, which is what every scaffolded model has, rather than failing: a model
/// with no primary key at all cannot be versioned meaningfully and will have failed earlier for
/// reasons that name the real problem.
pub(crate) fn versions_record_id(model: &crate::parser::ast::ModelAst) -> (String, String) {
    model
        .fields
        .iter()
        .find(|(_, field)| column_diff::field_is_primary_key(field))
        .map(|(name, field)| (name.clone(), column_diff::field_pg_type(field)))
        .unwrap_or_else(|| ("id".to_string(), "UUID".to_string()))
}

fn previous_model<'a>(
    previous: Option<&'a SchemaAst>,
    table_name: &str,
) -> Option<&'a crate::parser::ast::ModelAst> {
    previous?
        .models
        .iter()
        .find(|m| m.table_name() == table_name)
}

/// `tables` ordered so that no table is dropped while another in the list still references it:
/// each round takes the tables nothing remaining points at. A cycle (two tables referencing each
/// other) falls back to the given order, and Postgres names the problem.
fn drop_order<'a>(mut tables: Vec<&'a str>, db: &DatabaseState) -> Vec<&'a str> {
    let mut ordered = Vec::with_capacity(tables.len());
    while !tables.is_empty() {
        let referenced: std::collections::HashSet<&str> = db
            .constraints
            .iter()
            .filter(|c| c.constraint_type == DbConstraintType::ForeignKey)
            .filter(|c| tables.contains(&c.table.as_str()))
            .filter_map(|c| c.foreign_table.as_deref())
            .filter(|parent| tables.contains(parent))
            .collect();
        let (ready, waiting): (Vec<&str>, Vec<&str>) =
            tables.iter().partition(|t| !referenced.contains(*t));
        if ready.is_empty() {
            ordered.extend(waiting);
            break;
        }
        ordered.extend(ready);
        tables = waiting;
    }
    ordered
}

#[cfg(test)]
mod tests {
    use super::{drop_order, is_extension_managed_table};
    use crate::introspector::constraints::{DbConstraint, DbConstraintType};
    use crate::state::database_state::DatabaseState;

    fn fk(table: &str, parent: &str) -> DbConstraint {
        DbConstraint {
            table: table.into(),
            name: format!("{table}_{parent}_fkey"),
            constraint_type: DbConstraintType::ForeignKey,
            columns: vec!["x".into()],
            foreign_table: Some(parent.into()),
            foreign_schema: None,
            foreign_columns: Some(vec!["id".into()]),
            check_expression: None,
            on_delete: None,
            definition: None,
            comment: None,
            foreign_key_options: Some(Default::default()),
        }
    }

    #[test]
    fn a_table_is_dropped_before_the_one_it_references() {
        let db = DatabaseState {
            constraints: vec![fk("enrolments", "courses"), fk("enrolments", "students")],
            ..DatabaseState::default()
        };
        assert_eq!(
            drop_order(vec!["courses", "enrolments", "students"], &db),
            ["enrolments", "courses", "students"]
        );
        // A cycle falls back to the given order rather than looping.
        let cycle = DatabaseState {
            constraints: vec![fk("a", "b"), fk("b", "a")],
            ..DatabaseState::default()
        };
        assert_eq!(drop_order(vec!["a", "b"], &cycle), ["a", "b"]);
    }

    #[test]
    fn ignores_known_extension_managed_tables() {
        assert!(is_extension_managed_table("spatial_ref_sys"));
        assert!(!is_extension_managed_table("post"));
    }
}

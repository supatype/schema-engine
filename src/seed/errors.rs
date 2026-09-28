//! Postgres failures, said in the schema's own terms.
//!
//! The engine generated the SQL and holds the schema, so it is the only layer that can map
//! a database error back to the model and field the author wrote. Without that, a unique
//! violation reads as
//! `duplicate key value violates unique constraint "event_slug_key"` with no indication of
//! which call, which row, or which file, and every piece of that context existed at the
//! moment the statement was built.
//!
//! Constraint names are looked up rather than parsed. Deriving `Event.slug` from
//! `event_slug_key` works until someone names a constraint explicitly, and then it
//! mis-reports the field with no sign that it has.

use crate::parser::accessors::db_foreign_key;
use crate::parser::ast::{FieldAst, SchemaAst};
use std::collections::HashMap;

/// What kind of rule the database refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintKind {
    Unique,
    ForeignKey,
    NotNull,
    Check,
}

impl ConstraintKind {
    fn describe(self, model: &str, fields: &str) -> String {
        match self {
            ConstraintKind::Unique => {
                format!("`{model}.{fields}` is already taken by another row")
            }
            ConstraintKind::ForeignKey => {
                format!("`{model}.{fields}` points at a row that does not exist")
            }
            ConstraintKind::NotNull => {
                format!("`{model}.{fields}` is required and was not supplied")
            }
            ConstraintKind::Check => format!("`{model}.{fields}` failed a check constraint"),
        }
    }
}

/// Why a run stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedFailure {
    /// A rule the schema declares, named in the schema's terms.
    Constraint {
        kind: ConstraintKind,
        model: String,
        fields: Vec<String>,
        sqlstate: String,
    },
    /// The database does not have the schema the seed was built for.
    SchemaDrift { missing: String, remedy: String },
    /// A value the column cannot hold, such as a string that is not a member of an enum.
    InvalidValue { detail: String },
    /// Anything else the database said.
    Database { sqlstate: String, message: String },
    /// The connection, the transaction, or something else outside a statement.
    Other { message: String },
}

impl std::fmt::Display for SeedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeedFailure::Constraint {
                kind,
                model,
                fields,
                ..
            } => write!(f, "{}", kind.describe(model, &fields.join(", "))),
            SeedFailure::SchemaDrift { missing, remedy } => {
                write!(f, "{missing}\n  {remedy}")
            }
            SeedFailure::InvalidValue { detail } => write!(f, "{detail}"),
            SeedFailure::Database { sqlstate, message } => {
                write!(f, "the database refused this ({sqlstate}): {message}")
            }
            SeedFailure::Other { message } => write!(f, "{message}"),
        }
    }
}

/// A failure, with where in the document it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedError {
    pub failure: SeedFailure,
    /// The dotted position in the IR, so a nested write says where it was.
    pub path: String,
    /// The author's own label, when they gave one.
    pub op_id: Option<String>,
    /// Attached when the rollback *also* failed.
    ///
    /// Attached rather than substituted: a failed rollback usually means a dropped
    /// connection, and the original error is still the one that explains the run.
    pub rollback_error: Option<String>,
}

impl std::fmt::Display for SeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.failure)?;
        if let Some(id) = &self.op_id {
            write!(f, " (operation `{id}`)")?;
        }
        if let Some(rollback) = &self.rollback_error {
            write!(f, "\n  the rollback also failed: {rollback}")?;
        }
        Ok(())
    }
}

impl std::error::Error for SeedError {}

/// Constraint name to the model and fields it belongs to.
///
/// Built by the caller from the schema, because only the schema knows which constraint
/// name came from which declaration.
#[derive(Debug, Clone, Default)]
pub struct ConstraintIndex {
    entries: HashMap<String, (String, Vec<String>)>,
    /// Table name to model name, for the errors that name a table rather than a constraint.
    tables: HashMap<String, String>,
}

impl ConstraintIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        constraint: impl Into<String>,
        model: impl Into<String>,
        fields: Vec<String>,
    ) {
        self.entries
            .insert(constraint.into(), (model.into(), fields));
    }

    pub fn insert_table(&mut self, table: impl Into<String>, model: impl Into<String>) {
        self.tables.insert(table.into(), model.into());
    }

    fn lookup(&self, constraint: &str) -> Option<(String, Vec<String>)> {
        self.entries.get(constraint).cloned()
    }

    fn model_for_table(&self, table: &str) -> String {
        self.tables
            .get(table)
            .cloned()
            .unwrap_or_else(|| table.to_string())
    }
}

/// Build the constraint lookup from the schema.
///
/// This is what makes an error say `Event.slug` instead of `event_slug_key`. The names are
/// **constructed from the same rules the migration generator uses**, not parsed back out of
/// a message: `{table}_{column}_key`, `{table}_{fk}_fkey`, `{table}_pkey`,
/// `{table}_{column}_bounds`, and an index's declared name or its derived one.
///
/// Reconstructing them here rather than recording them at migration time is a deliberate
/// trade. It means a constraint whose name the author set by hand is not in the map, and
/// the error falls back to naming the constraint as a constraint rather than guessing a
/// field. That is the right failure: a guess would be confidently wrong about the one thing
/// the author needs to be right.
pub fn constraint_index_for(ast: &SchemaAst) -> ConstraintIndex {
    let mut index = ConstraintIndex::new();

    for model in &ast.models {
        let table = &model.annotations.db.table_name;
        index.insert_table(table.clone(), model.name.clone());

        for (name, field) in &model.fields {
            let json = serde_json::to_value(field).unwrap_or(serde_json::Value::Null);
            let flag = |key: &str| {
                json.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
                    || json
                        .get("annotations")
                        .and_then(|a| a.get("db"))
                        .and_then(|db| db.get(key))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
            };

            if let FieldAst::Relation(_) = field {
                if let Some(fk) = db_foreign_key(field, name) {
                    index.insert(
                        format!("{table}_{fk}_fkey"),
                        model.name.clone(),
                        vec![name.clone()],
                    );
                }
                continue;
            }

            if flag("primaryKey") {
                index.insert(
                    format!("{table}_pkey"),
                    model.name.clone(),
                    vec![name.clone()],
                );
            }
            if flag("unique") {
                index.insert(
                    format!("{table}_{name}_key"),
                    model.name.clone(),
                    vec![name.clone()],
                );
            }

            // Bounds are named by Supatype rather than by Postgres, so an inline CHECK
            // written elsewhere cannot be mistaken for one the schema manages.
            index.insert(
                crate::managed::expected_check_constraint_name(table, name),
                model.name.clone(),
                vec![name.clone()],
            );
        }

        for declared in &model.annotations.db.indexes {
            let derived = format!("{table}_{}_idx", declared.fields.join("_"));
            let name = declared.name.clone().unwrap_or(derived);
            index.insert(name, model.name.clone(), declared.fields.clone());
        }
    }

    index
}

/// What the database reported, in the fields Postgres gives.
#[derive(Debug, Clone, Default)]
pub struct DatabaseFailure {
    pub sqlstate: String,
    pub message: String,
    pub constraint: Option<String>,
    pub table: Option<String>,
    pub column: Option<String>,
}

/// Map a database failure to the schema's own terms.
///
/// The two schema-drift codes matter more than they look. Editing the schema and forgetting
/// to push is the most common seed failure there is, and Postgres reports it as
/// `relation "event" does not exist`, which reads like a bug in the seed rather than a
/// stale build.
pub fn map_failure(failure: &DatabaseFailure, index: &ConstraintIndex) -> SeedFailure {
    let kind = match failure.sqlstate.as_str() {
        "23505" => Some(ConstraintKind::Unique),
        "23503" => Some(ConstraintKind::ForeignKey),
        "23502" => Some(ConstraintKind::NotNull),
        "23514" => Some(ConstraintKind::Check),
        "22P02" => {
            return SeedFailure::InvalidValue {
                detail: format!(
                    "a value is not valid for its column: {}",
                    failure.message.trim()
                ),
            }
        }
        "42P01" => {
            return SeedFailure::SchemaDrift {
                missing: format!(
                    "the database does not have a table this seed writes to: {}",
                    failure.message.trim()
                ),
                remedy: "Run `supatype push` to apply the schema before seeding.".to_string(),
            }
        }
        "42703" => {
            return SeedFailure::SchemaDrift {
                missing: format!(
                    "the database does not have a column this seed writes: {}",
                    failure.message.trim()
                ),
                remedy: "Run `supatype generate` to rebuild the seed builder, or `supatype push` \
                         if the database is the stale one."
                    .to_string(),
            }
        }
        _ => None,
    };

    let Some(kind) = kind else {
        return SeedFailure::Database {
            sqlstate: failure.sqlstate.clone(),
            message: failure.message.trim().to_string(),
        };
    };

    // A not-null violation names a column rather than a constraint, so it is resolved
    // through the table instead.
    let resolved = failure
        .constraint
        .as_deref()
        .and_then(|name| index.lookup(name))
        .or_else(|| {
            let model = failure
                .table
                .as_deref()
                .map(|table| index.model_for_table(table))?;
            let column = failure.column.clone()?;
            Some((model, vec![column]))
        });

    let Some((model, fields)) = resolved else {
        // Neither the constraint nor a column resolved to a field.
        //
        // The constraint name is deliberately **not** used as a field here. An explicitly
        // named constraint has no derivable shape, so presenting `some_hand_named_index`
        // where a field belongs would be a confident guess at the one thing the author
        // needs to be right. Naming the constraint as a constraint is less specific and
        // true.
        let model = failure
            .table
            .as_deref()
            .map(|table| index.model_for_table(table))
            .unwrap_or_else(|| "a table".to_string());
        return SeedFailure::Database {
            sqlstate: failure.sqlstate.clone(),
            message: format!(
                "`{model}` refused this write: constraint `{}` was violated. {}",
                failure.constraint.as_deref().unwrap_or("(unnamed)"),
                failure.message.trim()
            ),
        };
    };

    SeedFailure::Constraint {
        kind,
        model,
        fields: fields.into_iter().filter(|f| !f.is_empty()).collect(),
        sqlstate: failure.sqlstate.clone(),
    }
}

/// Read the parts of a `sqlx` error this needs.
#[cfg(not(target_arch = "wasm32"))]
pub fn database_failure_from(error: &sqlx::Error) -> Option<DatabaseFailure> {
    let sqlx::Error::Database(db) = error else {
        return None;
    };
    // A not-null violation names a *column* rather than a constraint, so the column is read
    // too. Without it, 23502 has neither and falls through to the generic branch, where the
    // author is told a constraint was violated without being told which column.
    let column = db
        .try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
        .and_then(|pg| pg.column().map(str::to_string));
    Some(DatabaseFailure {
        sqlstate: db.code().map(|c| c.into_owned()).unwrap_or_default(),
        message: db.message().to_string(),
        constraint: db.constraint().map(str::to_string),
        table: db.table().map(str::to_string),
        column,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index() -> ConstraintIndex {
        let mut index = ConstraintIndex::new();
        index.insert("event_slug_key", "Event", vec!["slug".to_string()]);
        index.insert(
            "booking_event_id_fkey",
            "Booking",
            vec!["event".to_string()],
        );
        index.insert_table("event", "Event");
        index
    }

    fn failure(sqlstate: &str, constraint: Option<&str>) -> DatabaseFailure {
        DatabaseFailure {
            sqlstate: sqlstate.to_string(),
            message: "something the database said".to_string(),
            constraint: constraint.map(str::to_string),
            table: Some("event".to_string()),
            column: None,
        }
    }

    #[test]
    fn a_unique_violation_names_the_model_and_field() {
        let mapped = map_failure(&failure("23505", Some("event_slug_key")), &index());
        assert_eq!(
            mapped.to_string(),
            "`Event.slug` is already taken by another row"
        );
    }

    #[test]
    fn a_foreign_key_violation_names_the_relation() {
        let mapped = map_failure(&failure("23503", Some("booking_event_id_fkey")), &index());
        assert!(mapped.to_string().contains("`Booking.event`"), "{mapped}");
    }

    /// The name is looked up, not parsed. An explicitly named constraint has no derivable
    /// shape, and guessing one would mis-report the field with no sign that it had.
    #[test]
    fn an_unknown_constraint_falls_back_to_the_table_not_a_guess() {
        let mapped = map_failure(&failure("23505", Some("some_hand_named_index")), &index());
        let rendered = mapped.to_string();
        assert!(
            rendered.contains("Event"),
            "resolved through the table: {rendered}"
        );
        assert!(
            !rendered.contains("Event.some_hand_named"),
            "the constraint name must not be presented as a field: {rendered}"
        );
        assert!(
            rendered.contains("constraint `some_hand_named_index`"),
            "but it should still be named, as a constraint: {rendered}"
        );
    }

    // The most common seed failure there is, and the one Postgres words worst.
    #[test]
    fn a_missing_table_says_push_rather_than_naming_a_relation() {
        let mapped = map_failure(&failure("42P01", None), &index());
        match &mapped {
            SeedFailure::SchemaDrift { remedy, .. } => {
                assert!(remedy.contains("supatype push"), "{remedy}")
            }
            other => panic!("expected drift, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_column_says_generate() {
        let mapped = map_failure(&failure("42703", None), &index());
        match &mapped {
            SeedFailure::SchemaDrift { remedy, .. } => {
                assert!(remedy.contains("supatype generate"), "{remedy}")
            }
            other => panic!("expected drift, got {other:?}"),
        }
    }

    #[test]
    fn an_invalid_enum_value_is_reported_as_a_value_problem() {
        let mapped = map_failure(&failure("22P02", None), &index());
        assert!(
            matches!(mapped, SeedFailure::InvalidValue { .. }),
            "{mapped:?}"
        );
    }

    /// Anything unrecognised still carries its SQLSTATE, so an unmapped code is
    /// diagnosable rather than swallowed.
    #[test]
    fn an_unmapped_code_keeps_its_sqlstate() {
        let mapped = map_failure(&failure("40001", None), &index());
        assert!(mapped.to_string().contains("40001"), "{mapped}");
    }

    /// A failed rollback is attached, never substituted: it usually means a dropped
    /// connection, and the original error is still the one that explains the run.
    #[test]
    fn a_failed_rollback_is_attached_to_the_original() {
        let error = SeedError {
            failure: map_failure(&failure("23505", Some("event_slug_key")), &index()),
            path: "operations[0]".to_string(),
            op_id: Some("conference".to_string()),
            rollback_error: Some("connection closed".to_string()),
        };
        let rendered = error.to_string();
        assert!(rendered.contains("already taken"), "{rendered}");
        assert!(rendered.contains("conference"), "{rendered}");
        assert!(rendered.contains("rollback also failed"), "{rendered}");
    }
}

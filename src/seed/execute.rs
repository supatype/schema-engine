//! Run a plan against Postgres, in one transaction.
//!
//! The statement shapes are the point. A batch becomes one
//! `INSERT ... SELECT ... FROM UNNEST(...)`, with one placeholder per *column* rather than
//! per cell, so a thousand-row `createMany` is one statement and does not approach the
//! 65535 parameter ceiling. The naive shape, one `VALUES` tuple per row, hits that ceiling
//! at a few thousand rows of a wide table and issues a statement whose text grows with the
//! data.

use super::errors::{database_failure_from, map_failure, ConstraintIndex, SeedError, SeedFailure};
use super::plan::{Batch, Plan, PlannedStep, PlannedWrite, WriteKind};
use super::{Condition, Value};
use crate::generator::sql::rls::{access_rule_to_expr, operand_to_expr};
use crate::parser::ast::{ModelAst, Operand, SchemaAst};
use indexmap::IndexMap;
use sqlx::{Executor, PgPool, Postgres, Row, Transaction};
use std::collections::HashMap;

/// What a run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Rows written per model.
    pub written: IndexMap<String, usize>,
    /// Groups whose condition was false.
    ///
    /// Reported rather than omitted: a seed that quietly did nothing should not look like
    /// one that did everything.
    pub skipped: Vec<String>,
}

/// How a column's value reaches the statement.
enum Rendered {
    /// A bound parameter, as text, cast to the column's type by Postgres.
    Bound(Option<String>),
    /// SQL written inline, because `now()` and `DEFAULT` are not values a placeholder can
    /// carry.
    Inline(String),
}

/// Render one value.
///
/// Non-literal operands go through the existing `operand_to_expr`, the same function that
/// compiles an access rule into a policy predicate, so a seed and a policy cannot disagree
/// about what `fromNow` means.
fn render(value: &Value) -> Rendered {
    match value {
        Value::Scalar(serde_json::Value::Null) => Rendered::Bound(None),
        Value::Scalar(serde_json::Value::String(text)) => Rendered::Bound(Some(text.clone())),
        Value::Scalar(other) => Rendered::Bound(Some(other.to_string())),
        Value::Numeric { numeric } => Rendered::Bound(Some(numeric.clone())),
        Value::Default { .. } => Rendered::Inline("DEFAULT".to_string()),
        Value::Operand(Operand::Literal { value }) => match serde_json::to_value(value) {
            Ok(serde_json::Value::String(text)) => Rendered::Bound(Some(text)),
            Ok(serde_json::Value::Null) => Rendered::Bound(None),
            Ok(other) => Rendered::Bound(Some(other.to_string())),
            Err(_) => Rendered::Bound(None),
        },
        Value::Operand(operand) => Rendered::Inline(operand_to_expr(operand)),
        // Resolved before rendering; a reference that reaches here is a planner bug.
        Value::Ref { .. } => Rendered::Bound(None),
        Value::Connect { .. } | Value::NestedCreate { .. } | Value::NestedCreateMany { .. } => {
            Rendered::Bound(None)
        }
    }
}

/// Quote an identifier for SQL.
fn quote(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

/// Build the statement for one batch.
///
/// Columns whose value is inline rather than bound are lifted out of the `UNNEST` array
/// set and into the `SELECT` list, because every row in a batch shares the same expression
/// by construction: a batch is only formed from rows with the same column set.
///
/// **Every bound column is cast to its real type.** Values travel as `text[]` so one
/// parameter carries a whole column whatever it holds, but Postgres does not implicitly
/// cast text to `uuid` or `integer` in an `INSERT ... SELECT`: it refuses with 42804,
/// `column "organiser_id" is of type uuid but expression is of type text`. Without the
/// cast this shape only ever worked for text columns.
fn batch_sql(
    batch: &Batch,
    table: &str,
    column_types: &HashMap<String, String>,
) -> (String, Vec<Option<String>>) {
    let mut bound_columns: Vec<&str> = Vec::new();
    let mut inline: Vec<(&str, String)> = Vec::new();

    let first = &batch.rows[0];
    for column in &batch.columns {
        match first.data.get(column).map(render) {
            Some(Rendered::Inline(expression)) => inline.push((column, expression)),
            _ => bound_columns.push(column),
        }
    }

    let mut parameters: Vec<Option<String>> = Vec::new();
    let mut unnest_args: Vec<String> = Vec::new();
    for (position, column) in bound_columns.iter().enumerate() {
        unnest_args.push(format!("${}::text[]", position + 1));
        let values: Vec<Option<String>> = batch
            .rows
            .iter()
            .map(|row| match row.data.get(*column).map(render) {
                Some(Rendered::Bound(v)) => v,
                _ => None,
            })
            .collect();
        // One parameter per column, holding every row's value for it.
        parameters.push(Some(encode_text_array(&values)));
    }

    let all_columns: Vec<String> = bound_columns
        .iter()
        .map(|c| quote(c))
        .chain(inline.iter().map(|(c, _)| quote(c)))
        .collect();

    let select_list: Vec<String> = bound_columns
        .iter()
        .map(|c| {
            let target = column_types.get(*c).map(String::as_str).unwrap_or("text");
            format!("src.{}::{}", quote(c), target)
        })
        .chain(inline.iter().map(|(_, expression)| expression.clone()))
        .collect();

    let source = if unnest_args.is_empty() {
        // Every column is an expression, so there is nothing to unnest. One row per
        // planned row, produced by generate_series.
        format!("generate_series(1, {})", batch.rows.len())
    } else {
        format!(
            "UNNEST({}) AS src({})",
            unnest_args.join(", "),
            bound_columns
                .iter()
                .map(|c| quote(c))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };

    let mut sql = format!(
        "INSERT INTO {} ({}) SELECT {} FROM {}",
        quote(table),
        all_columns.join(", "),
        select_list.join(", "),
        source
    );

    if batch.kind == WriteKind::Upsert && !batch.conflict.is_empty() {
        let conflict: Vec<String> = batch.conflict.iter().map(|c| quote(c)).collect();
        let updates: Vec<String> = batch
            .columns
            .iter()
            .filter(|column| !batch.conflict.contains(*column))
            .map(|column| format!("{c} = EXCLUDED.{c}", c = quote(column)))
            .collect();
        if updates.is_empty() {
            sql.push_str(&format!(
                " ON CONFLICT ({}) DO NOTHING",
                conflict.join(", ")
            ));
        } else {
            sql.push_str(&format!(
                " ON CONFLICT ({}) DO UPDATE SET {}",
                conflict.join(", "),
                updates.join(", ")
            ));
        }
    }

    (sql, parameters)
}

/// Postgres array literal for a column of text values.
fn encode_text_array(values: &[Option<String>]) -> String {
    let items: Vec<String> = values
        .iter()
        .map(|value| match value {
            None => "NULL".to_string(),
            Some(text) => format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\"")),
        })
        .collect();
    format!("{{{}}}", items.join(","))
}

/// Each column's Postgres type, so a bound text value can be cast back to it.
///
/// Read from the serialised field for the same reason the fingerprint does: `FieldAst` has
/// thirty-odd variants, and a match would omit whatever is added next.
fn column_types_for(ast: &SchemaAst, model: &str) -> HashMap<String, String> {
    let mut types = HashMap::new();
    let Some(model_ast) = ast.models.iter().find(|m| m.name == model) else {
        return types;
    };
    for (name, field) in &model_ast.fields {
        let json = serde_json::to_value(field).unwrap_or(serde_json::Value::Null);
        let pg_type = json
            .get("pgType")
            .and_then(|v| v.as_str())
            .filter(|t| !t.is_empty())
            .unwrap_or("text")
            .to_string();
        types.insert(name.clone(), pg_type.clone());
        // A relation's foreign key is writable under its own name too, and carries the
        // referenced key's type rather than the relation's.
        if let crate::parser::ast::FieldAst::Relation(_) = field {
            if let Some(fk) = crate::parser::accessors::db_foreign_key(field, name) {
                types.insert(fk, "uuid".to_string());
            }
        }
    }
    types
}

/// Which models a batch's rows belong to, for the report.
fn count_written(report: &mut Report, model: &str, rows: usize) {
    *report.written.entry(model.to_string()).or_insert(0) += rows;
}

/// Resolve `$ref` values against what earlier statements returned.
fn resolve_refs(write: &mut PlannedWrite, resolved: &HashMap<String, HashMap<String, String>>) {
    for value in write.data.values_mut() {
        let Value::Ref { reference } = value else {
            continue;
        };
        let Some((op_id, field)) = reference.split_once('.') else {
            continue;
        };
        if let Some(actual) = resolved.get(op_id).and_then(|fields| fields.get(field)) {
            *value = Value::Scalar(serde_json::Value::String(actual.clone()));
        }
    }
}

/// Compile a condition into the `SELECT EXISTS (...)` that answers it.
///
/// The filter is compiled by `access_rule_to_expr`, the same function that turns an access
/// rule into a policy predicate. One compiler, so a condition and a policy written with the
/// same rule mean the same thing.
fn condition_sql(
    condition: &Condition,
    ast: &SchemaAst,
    model: &ModelAst,
    table: &str,
    schema: &str,
) -> Option<String> {
    match condition {
        Condition::Exists { filter, .. } | Condition::NotExists { filter, .. } => {
            let predicate = filter
                .as_ref()
                .map(|rule| access_rule_to_expr(ast, model, rule, schema))
                .unwrap_or_else(|| "TRUE".to_string());
            Some(format!(
                "SELECT EXISTS (SELECT 1 FROM {} WHERE {})",
                quote(table),
                predicate
            ))
        }
        Condition::Environment { .. } => None,
    }
}

/// Run a plan.
///
/// One transaction: it commits or it rolls back. A seed that dies halfway leaving rows
/// behind is worse than one that fails, because seeds are re-run and that partial state is
/// what the next run collides with.
pub async fn execute(
    plan: &Plan,
    pool: &PgPool,
    ast: &SchemaAst,
    constraints: &ConstraintIndex,
    schema: &str,
    environment: Option<&str>,
) -> Result<Report, SeedError> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await.map_err(|e| SeedError {
        failure: SeedFailure::Other {
            message: format!("could not start a transaction: {e}"),
        },
        path: String::new(),
        op_id: None,
        rollback_error: None,
    })?;

    let outcome = run_steps(plan, &mut tx, ast, constraints, schema, environment).await;

    match outcome {
        Ok(report) => {
            tx.commit().await.map_err(|e| SeedError {
                failure: SeedFailure::Other {
                    message: format!("the seed could not be committed: {e}"),
                },
                path: String::new(),
                op_id: None,
                rollback_error: None,
            })?;
            Ok(report)
        }
        Err(mut error) => {
            // Attached, never substituted: a failed rollback usually means a dropped
            // connection, and the original error still explains the run.
            if let Err(rollback) = tx.rollback().await {
                error.rollback_error = Some(rollback.to_string());
            }
            Err(error)
        }
    }
}

async fn run_steps(
    plan: &Plan,
    tx: &mut Transaction<'_, Postgres>,
    ast: &SchemaAst,
    constraints: &ConstraintIndex,
    schema: &str,
    environment: Option<&str>,
) -> Result<Report, SeedError> {
    let tables: HashMap<String, String> = ast
        .models
        .iter()
        .map(|m| (m.name.clone(), m.annotations.db.table_name.clone()))
        .collect();
    let mut report = Report::default();
    let mut resolved: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut skipped_guards: Vec<usize> = Vec::new();

    for step in &plan.steps {
        // A step inside a group whose condition was false does not run.
        if step
            .guards()
            .iter()
            .any(|guard| skipped_guards.contains(guard))
        {
            continue;
        }

        match step {
            PlannedStep::Condition {
                guard,
                condition,
                path,
                ..
            } => {
                let holds =
                    evaluate(condition, tx, ast, &tables, schema, environment, path).await?;
                let wanted = matches!(condition, Condition::NotExists { .. });
                let run = if wanted { !holds } else { holds };
                if !run {
                    skipped_guards.push(*guard);
                    report.skipped.push(path.clone());
                }
            }

            PlannedStep::Sql { text, path, .. } => {
                tx.execute(sqlx::query(text))
                    .await
                    .map_err(|e| to_seed_error(&e, constraints, path, None))?;
            }

            PlannedStep::Write(_) => {}
        }
    }

    // Writes run as batches, in plan order.
    for batch in &plan.batches {
        if batch
            .guards
            .iter()
            .any(|guard| skipped_guards.contains(guard))
        {
            continue;
        }

        let table = tables
            .get(&batch.model)
            .cloned()
            .unwrap_or_else(|| batch.model.clone());

        let mut prepared = batch.clone();
        for row in &mut prepared.rows {
            resolve_refs(row, &resolved);
        }

        let column_types = column_types_for(ast, &batch.model);
        let (sql, parameters) = batch_sql(&prepared, &table, &column_types);
        let needs_ids: Vec<(usize, String)> = prepared
            .rows
            .iter()
            .enumerate()
            .filter_map(|(position, row)| row.op_id.clone().map(|id| (position, id)))
            .collect();

        let statement = if needs_ids.is_empty() {
            sql
        } else {
            format!("{sql} RETURNING \"id\"::text AS id")
        };

        let mut query = sqlx::query(&statement);
        for parameter in &parameters {
            query = query.bind(parameter.clone());
        }

        let path = prepared
            .rows
            .first()
            .map(|row| row.path.clone())
            .unwrap_or_default();
        let op_id = prepared.rows.first().and_then(|row| row.op_id.clone());

        if needs_ids.is_empty() {
            query
                .execute(&mut **tx)
                .await
                .map_err(|e| to_seed_error(&e, constraints, &path, op_id.clone()))?;
        } else {
            let rows = query
                .fetch_all(&mut **tx)
                .await
                .map_err(|e| to_seed_error(&e, constraints, &path, op_id.clone()))?;
            for (position, id) in needs_ids {
                if let Some(row) = rows.get(position) {
                    // Cast to text in the statement, so this reads one type whatever the
                    // key's column type is, and the engine needs no uuid dependency.
                    if let Ok(value) = row.try_get::<String, _>("id") {
                        resolved
                            .entry(id)
                            .or_default()
                            .insert("id".to_string(), value);
                    }
                }
            }
        }

        count_written(&mut report, &batch.model, prepared.rows.len());
    }

    Ok(report)
}

#[allow(clippy::too_many_arguments)]
async fn evaluate(
    condition: &Condition,
    tx: &mut Transaction<'_, Postgres>,
    ast: &SchemaAst,
    tables: &HashMap<String, String>,
    schema: &str,
    environment: Option<&str>,
    path: &str,
) -> Result<bool, SeedError> {
    if let Condition::Environment { name } = condition {
        return Ok(environment == Some(name.as_str()));
    }

    let model = match condition {
        Condition::Exists { model, .. } | Condition::NotExists { model, .. } => model,
        Condition::Environment { .. } => unreachable!("handled above"),
    };
    let table = tables.get(model).cloned().unwrap_or_else(|| model.clone());

    let Some(model_ast) = ast.models.iter().find(|m| &m.name == model) else {
        return Ok(true);
    };
    let Some(sql) = condition_sql(condition, ast, model_ast, &table, schema) else {
        return Ok(true);
    };

    let row = sqlx::query(&sql)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| SeedError {
            failure: SeedFailure::Other {
                message: format!("the condition could not be evaluated: {e}"),
            },
            path: path.to_string(),
            op_id: None,
            rollback_error: None,
        })?;

    Ok(row.try_get::<bool, _>(0).unwrap_or(false))
}

fn to_seed_error(
    error: &sqlx::Error,
    constraints: &ConstraintIndex,
    path: &str,
    op_id: Option<String>,
) -> SeedError {
    let failure = database_failure_from(error)
        .map(|db| map_failure(&db, constraints))
        .unwrap_or_else(|| SeedFailure::Other {
            message: error.to_string(),
        });
    SeedError {
        failure,
        path: path.to_string(),
        op_id,
        rollback_error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::plan::plan as build_plan;
    use crate::seed::SeedIr;

    fn ir(operations: &str) -> SeedIr {
        let document = format!(
            r#"{{"irVersion":1,"schemaFingerprint":"sha256:x","operations":{operations}}}"#
        );
        serde_json::from_str(&document).expect("the IR fixture parses")
    }

    fn sql_for(operations: &str) -> String {
        let planned = build_plan(&ir(operations)).expect("plans");
        let (sql, _) = batch_sql(&planned.batches[0], "venue", &HashMap::new());
        sql
    }

    /// One placeholder per column, not per cell. This is what keeps a large batch under
    /// the 65535 parameter ceiling and its statement text a constant size.
    #[test]
    fn a_batch_binds_one_parameter_per_column() {
        let rows: Vec<String> = (0..500).map(|n| format!(r#"{{"name":"v{n}"}}"#)).collect();
        let planned = build_plan(&ir(&format!(
            r#"[{{"op":"createMany","model":"Venue","rows":[{}]}}]"#,
            rows.join(",")
        )))
        .expect("plans");

        let (sql, parameters) = batch_sql(&planned.batches[0], "venue", &HashMap::new());
        assert_eq!(parameters.len(), 1, "one column, so one parameter");
        assert!(sql.contains("UNNEST($1::text[])"), "{sql}");
        assert!(
            !sql.contains("$2"),
            "the text must not grow with the rows: {sql}"
        );
    }

    #[test]
    fn an_insert_uses_unnest() {
        let sql =
            sql_for(r#"[{"op":"createMany","model":"Venue","rows":[{"name":"A","city":"B"}]}]"#);
        assert!(sql.starts_with("INSERT INTO \"venue\""), "{sql}");
        assert!(sql.contains("FROM UNNEST("), "{sql}");
    }

    #[test]
    fn an_upsert_adds_a_conflict_clause_that_excludes_the_key() {
        let sql = sql_for(
            r#"[{"op":"upsert","model":"Venue","where":{"name":"A"},"data":{"city":"Bristol"}}]"#,
        );
        assert!(
            sql.contains(r#"ON CONFLICT ("name") DO UPDATE SET"#),
            "{sql}"
        );
        assert!(sql.contains(r#""city" = EXCLUDED."city""#), "{sql}");
        assert!(
            !sql.contains(r#""name" = EXCLUDED."name""#),
            "the conflict key is not updated to itself: {sql}"
        );
    }

    /// An upsert with nothing but its key has nothing to update.
    #[test]
    fn an_upsert_with_only_a_key_does_nothing_on_conflict() {
        let sql = sql_for(r#"[{"op":"upsert","model":"Venue","where":{"name":"A"},"data":{}}]"#);
        assert!(sql.contains("DO NOTHING"), "{sql}");
    }

    /// `now()` and `DEFAULT` are not values a placeholder can carry, so they are written
    /// inline and lifted out of the array set.
    #[test]
    fn an_expression_column_moves_into_the_select_list() {
        let planned = build_plan(&ir(r#"[{"op":"createMany","model":"Event","rows":[
                {"title":"A","created_at":{"kind":"now"}},
                {"title":"B","created_at":{"kind":"now"}}
            ]}]"#))
        .expect("plans");

        let (sql, parameters) = batch_sql(&planned.batches[0], "event", &HashMap::new());
        assert_eq!(parameters.len(), 1, "only `title` is bound");
        assert!(sql.contains("SELECT now()"), "{sql}");
        assert!(
            !sql.contains("$2"),
            "the expression is not a parameter: {sql}"
        );
    }

    /// Rendering goes through the same function that compiles a policy predicate, so a
    /// seed and an access rule cannot disagree about what an operand means.
    #[test]
    fn operands_render_through_the_policy_renderer() {
        let planned = build_plan(&ir(r#"[{"op":"create","model":"Event","data":{"starts_at":
                {"kind":"after","base":{"kind":"startOf","unit":"day"},
                 "interval":{"days":30,"hours":9}}}}]"#))
        .expect("plans");
        let (sql, _) = batch_sql(&planned.batches[0], "event", &HashMap::new());
        assert!(
            sql.contains("date_trunc('day', now()) + INTERVAL '30 days 9 hours'"),
            "{sql}"
        );
    }

    #[test]
    fn identifiers_are_quoted() {
        let sql = sql_for(r#"[{"op":"createMany","model":"Venue","rows":[{"name":"A"}]}]"#);
        assert!(sql.contains(r#""venue""#), "{sql}");
        assert!(sql.contains(r#""name""#), "{sql}");
    }

    #[test]
    fn a_text_array_escapes_quotes_and_nulls() {
        let encoded = encode_text_array(&[
            Some("plain".to_string()),
            None,
            Some(r#"has "quotes""#.to_string()),
        ]);
        assert_eq!(encoded, r#"{"plain",NULL,"has \"quotes\""}"#);
    }
}

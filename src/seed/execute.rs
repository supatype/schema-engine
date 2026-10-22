//! Run a plan against Postgres, in one transaction.
//!
//! The statement shapes are the point. A batch becomes one
//! `INSERT ... SELECT ... FROM UNNEST(...)`, with one placeholder per *column* rather than
//! per cell, so a thousand-row `createMany` is one statement and does not approach the
//! 65535 parameter ceiling. The naive shape, one `VALUES` tuple per row, hits that ceiling
//! at a few thousand rows of a wide table and issues a statement whose text grows with the
//! data.
//!
//! The exception is a row nested under an `upsert`, which is written only when no row
//! already holds its values. That is one statement per row, so each row's match sees the
//! rows written before it; such rows are few, because they are what a fixture spells out.

use super::errors::{database_failure_from, map_failure, ConstraintIndex, SeedError, SeedFailure};
use super::plan::{Batch, ConnectLookup, Plan, PlannedStep, PlannedWrite, WriteKind};
use super::{Condition, Value};
use crate::generator::sql::column_conversion::lexical_normalise_expr;
use crate::generator::sql::rls::{access_rule_to_expr, operand_to_expr};
use crate::parser::ast::{ModelAst, Operand, SchemaAst};
use crate::sql_quote::quote_ident;
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
        // Lowered by the planner: a `connect` becomes its foreign-key column and a nested
        // write becomes a write of its own. Reaching here means the document was planned
        // without being validated, and validation is what refuses the shapes that cannot
        // be lowered.
        Value::Connect { .. } | Value::NestedCreate { .. } | Value::NestedCreateMany { .. } => {
            Rendered::Bound(None)
        }
    }
}

/// One column of an insert: its name, and the SQL its value comes from.
struct Column {
    name: String,
    expression: String,
    /// The value travels as a parameter, rather than as SQL written inline.
    bound: bool,
}

/// The pieces every statement for a batch is built from.
struct Parts {
    /// Bound columns first, then inline ones, in the batch's column order within each.
    columns: Vec<Column>,
    /// What the `SELECT` reads its rows from.
    source: String,
    /// One per bound column, holding every row's value for it.
    parameters: Vec<Option<String>>,
}

/// Split a batch's columns into bound and inline, and render the expression for each.
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
fn statement_parts(
    batch: &Batch,
    column_types: &HashMap<String, String>,
    lookups: &HashMap<String, String>,
) -> Parts {
    let (bound, inline) = split_columns(batch);
    let bound_columns = bound.iter().map(|column| Column {
        name: (*column).clone(),
        expression: bound_expression(column, column_types, lookups),
        bound: true,
    });
    Parts {
        parameters: bound.iter().map(|c| Some(column_array(batch, c))).collect(),
        source: source_sql(&bound, batch.rows.len()),
        columns: bound_columns.chain(inline).collect(),
    }
}

/// A batch's columns, as the names of those bound as parameters and the inline ones.
fn split_columns(batch: &Batch) -> (Vec<&String>, Vec<Column>) {
    let first = &batch.rows[0];
    let mut bound: Vec<&String> = Vec::new();
    let mut inline: Vec<Column> = Vec::new();
    for column in &batch.columns {
        match first.data.get(column) {
            // `DEFAULT` is not allowed in a `SELECT` list, so the column is left out of the
            // insert, which writes its default. The update half of an upsert still names it,
            // and `EXCLUDED` holds that default, so an update resets it as `$default` means.
            Some(Value::Default { .. }) => {}
            Some(value) => match render(value) {
                Rendered::Inline(expression) => inline.push(Column {
                    name: column.clone(),
                    expression,
                    bound: false,
                }),
                Rendered::Bound(_) => bound.push(column),
            },
            None => bound.push(column),
        }
    }
    (bound, inline)
}

/// Every row's value for one bound column, as one Postgres array literal.
fn column_array(batch: &Batch, column: &str) -> String {
    let values: Vec<Option<String>> = batch
        .rows
        .iter()
        .map(|row| match row.data.get(column).map(render) {
            Some(Rendered::Bound(v)) => v,
            _ => None,
        })
        .collect();
    encode_text_array(&values)
}

/// The value a bound column is written with: its parameter cast to the column's type, or
/// the lookup a `connect` by natural key became.
fn bound_expression(
    column: &str,
    column_types: &HashMap<String, String>,
    lookups: &HashMap<String, String>,
) -> String {
    match lookups.get(column) {
        // The bound value is a unique key, not the id, so the column is the id that key
        // names. Still one statement: the subquery reads `src`, so it is evaluated once per
        // row of the same `UNNEST` rather than once per round trip.
        Some(expression) => expression.clone(),
        None => {
            let target = column_types
                .get(column)
                .map(String::as_str)
                .unwrap_or("text");
            format!("src.{}::{}", quote_ident(column), target)
        }
    }
}

/// The rows a batch's `SELECT` reads: its bound columns unnested, or a row count when
/// every column is an expression and there is nothing to unnest.
fn source_sql(bound: &[&String], rows: usize) -> String {
    if bound.is_empty() {
        return format!("generate_series(1, {rows})");
    }
    let arguments: Vec<String> = (1..=bound.len()).map(|n| format!("${n}::text[]")).collect();
    let names: Vec<String> = bound.iter().map(|c| quote_ident(c)).collect();
    format!(
        "UNNEST({}) AS src({})",
        arguments.join(", "),
        names.join(", ")
    )
}

/// `INSERT INTO table (columns) SELECT expressions FROM source`.
///
/// With no columns at all, the column list is left out rather than written empty, which
/// Postgres refuses: a `SELECT` of no columns then fills every column with its default.
fn insert_sql(table: &str, parts: &Parts) -> String {
    let names: Vec<String> = parts.columns.iter().map(|c| quote_ident(&c.name)).collect();
    let expressions: Vec<&str> = parts
        .columns
        .iter()
        .map(|c| c.expression.as_str())
        .collect();
    let target = if names.is_empty() {
        quote_ident(table)
    } else {
        format!("{} ({})", quote_ident(table), names.join(", "))
    };
    format!(
        "INSERT INTO {target} SELECT {} FROM {}",
        expressions.join(", "),
        parts.source
    )
}

/// Build the statement for one batch.
fn batch_sql(
    batch: &Batch,
    table: &str,
    column_types: &HashMap<String, String>,
    lookups: &HashMap<String, String>,
) -> (String, Vec<Option<String>>) {
    let parts = statement_parts(batch, column_types, lookups);
    let mut sql = insert_sql(table, &parts);
    if batch.kind == WriteKind::Upsert && !batch.conflict.is_empty() {
        sql.push_str(&conflict_clause(batch));
    }
    (sql, parts.parameters)
}

/// `ON CONFLICT (key) DO UPDATE SET ...`, or `DO NOTHING` when there is nothing to update.
fn conflict_clause(batch: &Batch) -> String {
    let conflict: Vec<String> = batch.conflict.iter().map(|c| quote_ident(c)).collect();
    let updates: Vec<String> = batch
        .columns
        .iter()
        .filter(|column| !batch.conflict.contains(*column))
        .map(|column| format!("{c} = EXCLUDED.{c}", c = quote_ident(column)))
        .collect();
    if updates.is_empty() {
        format!(" ON CONFLICT ({}) DO NOTHING", conflict.join(", "))
    } else {
        format!(
            " ON CONFLICT ({}) DO UPDATE SET {}",
            conflict.join(", "),
            updates.join(", ")
        )
    }
}

/// How a model's columns are typed, for writing a row and for matching one.
struct Typing {
    types: HashMap<String, String>,
    /// Rich text columns, and whether each holds one document per locale.
    rich_text: HashMap<String, bool>,
}

/// The alias an existing row is read under when a planned row is matched against it.
const EXISTING: &str = "__existing";

/// Whether an existing row already holds the value one column of a planned row would write.
///
/// `IS NOT DISTINCT FROM`, so a NULL the seed gives matches a NULL column. The planned value
/// is the expression the insert would write, cast the same way, so the two sides are the
/// same type. Rich text is compared after the normalising expression its trigger applies,
/// so prose matches the document the trigger stored it as; `json` has no equality operator
/// and is compared as `jsonb`, by value.
fn column_matches(column: &Column, typing: &Typing) -> String {
    let existing = format!("{}.{}", quote_ident(EXISTING), quote_ident(&column.name));
    let planned = format!("({})", column.expression);
    if let Some(localised) = typing.rich_text.get(&column.name) {
        let normalised = lexical_normalise_expr(&planned, *localised);
        return format!("{existing} IS NOT DISTINCT FROM ({normalised})");
    }
    let pg_type = typing
        .types
        .get(&column.name)
        .map(String::as_str)
        .unwrap_or("text");
    match pg_type.to_ascii_lowercase().as_str() {
        "json" => format!("{existing}::jsonb IS NOT DISTINCT FROM {planned}::jsonb"),
        "xml" => format!("{existing}::text IS NOT DISTINCT FROM {planned}::text"),
        _ => format!("{existing} IS NOT DISTINCT FROM {planned}"),
    }
}

/// The predicate an existing row meets when it is the row a planned one would write.
///
/// Only bound columns are compared. An inline value is a time the database computes, such
/// as `now()`, which is a different value on every run: compared, it would make a child
/// carrying one look new every time, which is the duplication this match exists to stop.
/// Columns the seed leaves out, or sets to `$default`, are not compared either, so a column
/// filled by its default, or edited since, does not make the row look new.
fn match_predicate(parts: &Parts, typing: &Typing) -> String {
    let conditions: Vec<String> = parts
        .columns
        .iter()
        .filter(|column| column.bound)
        .map(|column| column_matches(column, typing))
        .collect();
    if conditions.is_empty() {
        "TRUE".to_string()
    } else {
        conditions.join(" AND ")
    }
}

/// The statement for one row that is written only when no matching row exists.
///
/// With `returning_id`, the row's id comes back whether it was written or matched, with a
/// flag saying which, so a child of a matched row is linked to the row that was already
/// there. The two CTEs read one snapshot, so `found` does not see `made`.
fn matched_sql(table: &str, parts: &Parts, typing: &Typing, returning_id: bool) -> String {
    let id = quote_ident("id");
    let selected = if returning_id {
        format!("{}.{id}", quote_ident(EXISTING))
    } else {
        "1".to_string()
    };
    let found = format!(
        "SELECT {selected} FROM {} AS {}, {} WHERE {} LIMIT 1",
        quote_ident(table),
        quote_ident(EXISTING),
        parts.source,
        match_predicate(parts, typing)
    );
    let insert = insert_sql(table, parts);
    if !returning_id {
        return format!("{insert} WHERE NOT EXISTS ({found})");
    }
    format!(
        "WITH found AS ({found}), made AS ({insert} WHERE NOT EXISTS (SELECT 1 FROM found) \
         RETURNING {id}) SELECT {id}::text AS id, TRUE AS inserted FROM made \
         UNION ALL SELECT {id}::text, FALSE FROM found"
    )
}

/// The scalar subquery a `connect` by natural key becomes, per column.
///
/// `{ connect: { slug: "northern" } }` names a row the planner cannot resolve, because
/// only the database knows which id that slug has. Rather than a round trip per row, the
/// key travels as the column's bound value and is joined here, inside the one statement
/// the batch already is.
///
/// The key is cast to the **target** column's type, not the foreign key's: comparing a
/// `uuid` column to text is an error, and the two columns differ whenever the key is a
/// natural one.
fn lookup_expressions(
    lookups: &IndexMap<String, ConnectLookup>,
    ast: &SchemaAst,
    tables: &HashMap<String, String>,
) -> HashMap<String, String> {
    lookups
        .iter()
        .map(|(column, lookup)| {
            let table = tables
                .get(&lookup.model)
                .cloned()
                .unwrap_or_else(|| lookup.model.clone());
            let key_type = column_types_for(ast, &lookup.model)
                .get(&lookup.key_column)
                .cloned()
                .unwrap_or_else(|| "text".to_string());
            let expression = format!(
                "(SELECT {alias}.{referenced} FROM {table} AS {alias} WHERE {alias}.{key} = src.{column}::{key_type})",
                alias = quote_ident("__connect"),
                referenced = quote_ident(&lookup.referenced_column),
                table = quote_ident(&table),
                key = quote_ident(&lookup.key_column),
                column = quote_ident(column),
            );
            (column.clone(), expression)
        })
        .collect()
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

/// The rich text columns of `model`, and whether each holds a map of locales rather than
/// one document.
fn rich_text_columns(ast: &SchemaAst, model: &str) -> HashMap<String, bool> {
    let Some(model_ast) = ast.models.iter().find(|m| m.name == model) else {
        return HashMap::new();
    };
    model_ast
        .fields
        .iter()
        .filter_map(|(name, field)| match field {
            crate::parser::ast::FieldAst::RichText(r) => Some((name.clone(), r.localized)),
            _ => None,
        })
        .collect()
}

/// Prose for a rich text column, bound as the JSON string it is.
///
/// A bound value is cast to the column's type, and prose is not JSON: `'Hello'::jsonb` fails
/// where `'"Hello"'::jsonb` is a JSON string, which the column's normalising trigger wraps into a
/// document. A document is an object and already travels as JSON text, so it is left alone, and
/// so is a localized column, which holds a map of locales rather than one document.
fn encode_prose(write: &mut PlannedWrite, rich_text: &HashMap<String, bool>) {
    for (column, localised) in rich_text {
        if *localised {
            continue;
        }
        if let Some(Value::Scalar(serde_json::Value::String(text))) = write.data.get_mut(column) {
            *text = serde_json::Value::String(text.clone()).to_string();
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
                quote_ident(table),
                predicate
            ))
        }
        Condition::Environment { .. } => None,
    }
}

/// Everything a run needs besides the plan itself.
///
/// Grouped rather than passed as five arguments, because the caller that owns the
/// transaction has to hand the same set to every document it runs in that transaction.
#[derive(Clone, Copy)]
pub struct Context<'a> {
    pub ast: &'a SchemaAst,
    pub constraints: &'a ConstraintIndex,
    /// The Postgres schema the tables live in.
    pub schema: &'a str,
    /// The environment this run targets, for an `environment` condition to match.
    pub environment: Option<&'a str>,
}

/// Anything that went wrong outside a statement, in the shape the rest of this module uses.
fn outside_a_statement(message: String) -> SeedError {
    SeedError::at("", SeedFailure::Other { message })
}

/// Run a plan inside a transaction the caller owns.
///
/// Separate from [`execute`] so a caller can do more in the same transaction than run one
/// document: write the ledger row beside the writes it describes, which is what makes the
/// ledger trustworthy, and run several documents together under `--atomic`. Neither is
/// possible if the only entry point commits before returning.
pub async fn execute_in(
    tx: &mut Transaction<'_, Postgres>,
    plan: &Plan,
    cx: Context<'_>,
) -> Result<Report, SeedError> {
    run_steps(plan, tx, cx).await
}

/// Run a plan in a transaction of its own.
///
/// One transaction: it commits or it rolls back. A seed that dies halfway leaving rows
/// behind is worse than one that fails, because seeds are re-run and that partial state is
/// what the next run collides with.
pub async fn execute(pool: &PgPool, plan: &Plan, cx: Context<'_>) -> Result<Report, SeedError> {
    let mut tx: Transaction<'_, Postgres> = pool
        .begin()
        .await
        .map_err(|e| outside_a_statement(format!("could not start a transaction: {e}")))?;

    match execute_in(&mut tx, plan, cx).await {
        Ok(report) => {
            tx.commit().await.map_err(|e| {
                outside_a_statement(format!("the seed could not be committed: {e}"))
            })?;
            Ok(report)
        }
        Err(error) => Err(rolling_back(tx, error).await),
    }
}

/// Roll back, and say so if that failed too.
///
/// Attached, never substituted: a failed rollback usually means a dropped connection, and
/// the original error still explains the run.
pub async fn rolling_back(tx: Transaction<'_, Postgres>, mut error: SeedError) -> SeedError {
    if let Err(rollback) = tx.rollback().await {
        error.rollback_error = Some(rollback.to_string());
    }
    error
}

async fn run_steps(
    plan: &Plan,
    tx: &mut Transaction<'_, Postgres>,
    cx: Context<'_>,
) -> Result<Report, SeedError> {
    let Context {
        ast,
        constraints,
        schema,
        environment,
    } = cx;
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
    let env = RunEnv {
        ast,
        constraints,
        tables: &tables,
    };
    for batch in &plan.batches {
        if batch
            .guards
            .iter()
            .any(|guard| skipped_guards.contains(guard))
        {
            continue;
        }
        let written = run_batch(tx, batch, &env, &mut resolved).await?;
        count_written(&mut report, &batch.model, written);
    }

    Ok(report)
}

/// Ids earlier statements returned, by the label of the write that returned them.
type Resolved = HashMap<String, HashMap<String, String>>;

/// What every batch in a run reads, beside the batch itself.
struct RunEnv<'a> {
    ast: &'a SchemaAst,
    constraints: &'a ConstraintIndex,
    tables: &'a HashMap<String, String>,
}

/// One batch, ready to render: its table, how its columns are typed, and its lookups.
struct Target {
    table: String,
    typing: Typing,
    lookups: HashMap<String, String>,
}

impl Target {
    fn of(batch: &Batch, env: &RunEnv<'_>) -> Self {
        Target {
            table: env
                .tables
                .get(&batch.model)
                .cloned()
                .unwrap_or_else(|| batch.model.clone()),
            typing: Typing {
                types: column_types_for(env.ast, &batch.model),
                rich_text: rich_text_columns(env.ast, &batch.model),
            },
            lookups: lookup_expressions(&batch.lookups, env.ast, env.tables),
        }
    }

    /// A row's `$ref`s resolved and its prose encoded, as the statement binds it.
    fn prepare(&self, row: &PlannedWrite, resolved: &Resolved) -> PlannedWrite {
        let mut row = row.clone();
        resolve_refs(&mut row, resolved);
        encode_prose(&mut row, &self.typing.rich_text);
        row
    }

    /// A batch with every row prepared, and the one statement that writes all of them.
    fn insert(&self, batch: &Batch, resolved: &Resolved) -> (Batch, String, Vec<Option<String>>) {
        let mut prepared = batch.clone();
        prepared.rows = batch
            .rows
            .iter()
            .map(|row| self.prepare(row, resolved))
            .collect();
        let (sql, parameters) =
            batch_sql(&prepared, &self.table, &self.typing.types, &self.lookups);
        (prepared, sql, parameters)
    }
}

/// Bind every parameter, in order.
fn bound_query<'q>(
    sql: &'q str,
    parameters: &'q [Option<String>],
) -> sqlx::query::Query<'q, Postgres, sqlx::postgres::PgArguments> {
    parameters
        .iter()
        .fold(sqlx::query(sql), |query, parameter| {
            query.bind(parameter.clone())
        })
}

/// Run one batch, returning how many rows it wrote.
async fn run_batch(
    tx: &mut Transaction<'_, Postgres>,
    batch: &Batch,
    env: &RunEnv<'_>,
    resolved: &mut Resolved,
) -> Result<usize, SeedError> {
    let target = Target::of(batch, env);
    if !batch.match_existing {
        return run_insert(tx, batch, &target, env, resolved).await;
    }
    // One statement per row, so each row's match sees the rows written before it in the
    // same seed: two identical children collapse to one, on the first run as on every run.
    let mut written = 0;
    for row in &batch.rows {
        written += run_matched(tx, batch, row, &target, env, resolved).await?;
    }
    Ok(written)
}

/// Run a batch as one `INSERT`, or one upsert, for all its rows.
async fn run_insert(
    tx: &mut Transaction<'_, Postgres>,
    batch: &Batch,
    target: &Target,
    env: &RunEnv<'_>,
    resolved: &mut Resolved,
) -> Result<usize, SeedError> {
    let (prepared, mut sql, parameters) = target.insert(batch, resolved);
    let labels = labels_of(&prepared.rows);
    if !labels.is_empty() {
        // Cast to text in the statement, so this reads one type whatever the key's column
        // type is, and the engine needs no uuid dependency.
        sql.push_str(" RETURNING \"id\"::text AS id");
    }
    let rows = bound_query(&sql, &parameters)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| failure_at(&e, env.constraints, prepared.rows.first()))?;
    for (position, label) in labels {
        if let Some(id) = rows.get(position).and_then(|r| r.try_get("id").ok()) {
            remember(resolved, label, id);
        }
    }
    Ok(prepared.rows.len())
}

/// The position and label of every row a later `$ref` may point at.
fn labels_of(rows: &[PlannedWrite]) -> Vec<(usize, String)> {
    rows.iter()
        .enumerate()
        .filter_map(|(position, row)| row.op_id.clone().map(|id| (position, id)))
        .collect()
}

/// Write one row only when no row already holds every value it gives, returning 1 when it
/// was written and 0 when it was matched.
async fn run_matched(
    tx: &mut Transaction<'_, Postgres>,
    batch: &Batch,
    row: &PlannedWrite,
    target: &Target,
    env: &RunEnv<'_>,
    resolved: &mut Resolved,
) -> Result<usize, SeedError> {
    let single = Batch {
        rows: vec![target.prepare(row, resolved)],
        ..batch.clone()
    };
    let parts = statement_parts(&single, &target.typing.types, &target.lookups);
    let sql = matched_sql(&target.table, &parts, &target.typing, row.op_id.is_some());
    let query = bound_query(&sql, &parts.parameters);
    let fail = |e: sqlx::Error| failure_at(&e, env.constraints, Some(row));

    let Some(label) = row.op_id.clone() else {
        let done = query.execute(&mut **tx).await.map_err(fail)?;
        return Ok(done.rows_affected() as usize);
    };
    let found = query.fetch_one(&mut **tx).await.map_err(fail)?;
    if let Ok(id) = found.try_get::<String, _>("id") {
        remember(resolved, label, id);
    }
    Ok(usize::from(
        found.try_get::<bool, _>("inserted").unwrap_or(false),
    ))
}

/// Record the id a labelled write produced or matched, for a later `$ref`.
fn remember(resolved: &mut Resolved, label: String, id: String) {
    resolved
        .entry(label)
        .or_default()
        .insert("id".to_string(), id);
}

/// A failed statement, named by the row it was writing.
fn failure_at(
    error: &sqlx::Error,
    constraints: &ConstraintIndex,
    row: Option<&PlannedWrite>,
) -> SeedError {
    let path = row.map(|r| r.path.clone()).unwrap_or_default();
    to_seed_error(error, constraints, &path, row.and_then(|r| r.op_id.clone()))
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

    let row = sqlx::query(&sql).fetch_one(&mut **tx).await.map_err(|e| {
        SeedError::at(
            path,
            SeedFailure::Other {
                message: format!("the condition could not be evaluated: {e}"),
            },
        )
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
        op_id,
        ..SeedError::at(path, failure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::plan::plan as build_plan;
    use crate::seed::SeedIr;

    /// The models these statements are built for.
    ///
    /// Planning reads the schema now, because a nested write names a relation and only the
    /// schema says which model that is.
    const SCHEMA: &str = r#"{
        "astVersion": 2,
        "models": [
            {"name": "Venue",
             "fields": {"id": {"kind": "uuid", "required": true, "primaryKey": true},
                        "name": {"kind": "text", "required": false},
                        "capacity": {"kind": "integer", "required": false}},
             "annotations": {"db": {"tableName": "venue"}}},
            {"name": "Event",
             "fields": {"id": {"kind": "uuid", "required": true, "primaryKey": true},
                        "title": {"kind": "text", "required": false},
                        "created_at": {"kind": "datetime", "required": false}},
             "annotations": {"db": {"tableName": "event"}}}
        ]
    }"#;

    fn schema() -> SchemaAst {
        serde_json::from_str(SCHEMA).expect("the schema fixture parses")
    }

    fn ir(operations: &str) -> SeedIr {
        let document = format!(
            r#"{{"irVersion":1,"schemaFingerprint":"sha256:x","operations":{operations}}}"#
        );
        serde_json::from_str(&document).expect("the IR fixture parses")
    }

    fn sql_for(operations: &str) -> String {
        let planned = build_plan(&ir(operations), &schema()).expect("plans");
        let (sql, _) = batch_sql(
            &planned.batches[0],
            "venue",
            &HashMap::new(),
            &HashMap::new(),
        );
        sql
    }

    /// One placeholder per column, not per cell. This is what keeps a large batch under
    /// the 65535 parameter ceiling and its statement text a constant size.
    #[test]
    fn a_batch_binds_one_parameter_per_column() {
        let rows: Vec<String> = (0..500).map(|n| format!(r#"{{"name":"v{n}"}}"#)).collect();
        let planned = build_plan(
            &ir(&format!(
                r#"[{{"op":"createMany","model":"Venue","rows":[{}]}}]"#,
                rows.join(",")
            )),
            &schema(),
        )
        .expect("plans");

        let (sql, parameters) = batch_sql(
            &planned.batches[0],
            "venue",
            &HashMap::new(),
            &HashMap::new(),
        );
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
        let planned = build_plan(
            &ir(r#"[{"op":"createMany","model":"Event","rows":[
                {"title":"A","created_at":{"kind":"now"}},
                {"title":"B","created_at":{"kind":"now"}}
            ]}]"#),
            &schema(),
        )
        .expect("plans");

        let (sql, parameters) = batch_sql(
            &planned.batches[0],
            "event",
            &HashMap::new(),
            &HashMap::new(),
        );
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
        let planned = build_plan(
            &ir(r#"[{"op":"create","model":"Event","data":{"starts_at":
                {"kind":"after","base":{"kind":"startOf","unit":"day"},
                 "interval":{"days":30,"hours":9}}}}]"#),
            &schema(),
        )
        .expect("plans");
        let (sql, _) = batch_sql(
            &planned.batches[0],
            "event",
            &HashMap::new(),
            &HashMap::new(),
        );
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

//! Validate a seed IR against the schema, before any statement runs.
//!
//! Two audiences, and the second is why this is a phase of its own rather than a side
//! effect of executing. A TypeScript author has a generated builder and a compiler, so
//! most mistakes never reach here. An author using a dynamically typed SDK has neither,
//! and this is where theirs are caught. Both are better served by failing before the first
//! write than by a half-applied seed and a Postgres error naming a column.
//!
//! What is deliberately **not** checked: value bounds, enum membership, string lengths.
//! Those are check constraints in the database, and duplicating them here would put two
//! validators in the product that can disagree after a partial push.

use super::{Condition, DataMap, Operation, SeedIr, Value, IR_VERSION};
use crate::parser::accessors::db_foreign_key;
use crate::parser::ast::{AccessRule, FieldAst, ModelAst, Operand, SchemaAst};
use std::collections::{BTreeSet, HashMap, HashSet};

/// How deep a group may nest.
///
/// A limit rather than unbounded recursion: an IR arrives as JSON from outside, and a
/// deeply nested document would otherwise be a stack overflow rather than an error.
const MAX_GROUP_DEPTH: usize = 16;

/// Column kinds a time operand may be written to.
const TIME_KINDS: [&str; 4] = ["datetime", "timestamp", "date", "dateOnly"];

/// What went wrong, and where.
///
/// `path` is the dotted position in the document, so a failure inside a nested write reads
/// as `operations[1].data.events[0].ticket_types[1]` rather than "insert failed". `op_id`
/// is the author's own label when they gave one, which is what lets them find the call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedValidationError {
    pub path: String,
    pub op_id: Option<String>,
    pub message: String,
    /// The remedy, when there is a specific one worth naming.
    pub remedy: Option<String>,
}

impl std::fmt::Display for SeedValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.message)?;
        if let Some(id) = &self.op_id {
            write!(f, " (operation `{id}`)")?;
        }
        if let Some(remedy) = &self.remedy {
            write!(f, "\n  {remedy}")?;
        }
        Ok(())
    }
}

impl std::error::Error for SeedValidationError {}

type Result<T> = std::result::Result<T, SeedValidationError>;

fn err(path: &str, message: impl Into<String>) -> SeedValidationError {
    SeedValidationError {
        path: path.to_string(),
        op_id: None,
        message: message.into(),
        remedy: None,
    }
}

fn with_remedy(mut error: SeedValidationError, remedy: impl Into<String>) -> SeedValidationError {
    error.remedy = Some(remedy.into());
    error
}

/// What a seed may write to one model, precomputed.
///
/// Built once per model rather than rederived per value: a `createMany` of a thousand rows
/// would otherwise rescan the model's fields a thousand times.
struct ModelIndex {
    /// Field names, plus the foreign-key column each relation generates. Both are writable
    /// and an author may reasonably use either.
    writable: HashSet<String>,
    /// Single columns that can be an `ON CONFLICT` target.
    unique_columns: HashSet<String>,
    /// Unique composites, as sets, so a multi-column `where` matches whole.
    unique_composites: Vec<BTreeSet<String>>,
    /// Fields an insert must supply: required, no default, not server-generated.
    required_without_default: BTreeSet<String>,
    /// Columns that have a default, so `$default` can be refused on those that do not.
    has_default: HashSet<String>,
    /// Relation field name, and its FK column, to the model it targets.
    relation_targets: HashMap<String, String>,
    /// Columns a time operand may be written to.
    time_columns: HashSet<String>,
}

/// Read a field's serialised shape.
///
/// Same reasoning as the fingerprint: [`FieldAst`] has thirty-odd variants over several
/// wrapper structs, and a match would need an arm each, or a catch-all that silently omits
/// whatever is added next.
fn field_json(field: &FieldAst) -> serde_json::Value {
    serde_json::to_value(field).unwrap_or(serde_json::Value::Null)
}

fn json_flag(value: &serde_json::Value, key: &str) -> bool {
    value.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

/// A flag that may live at the top level or under `annotations.db`.
///
/// `unique` is written by the CLI into `annotations.db.unique`, while `required` and
/// `primaryKey` are top-level. Both places are read rather than one, because a validator
/// that looked only at the top level silently treated every unique column as not unique,
/// and the failure was an upsert refused for naming a key that is in fact unique.
fn json_flag_either(value: &serde_json::Value, key: &str) -> bool {
    if json_flag(value, key) {
        return true;
    }
    value
        .get("annotations")
        .and_then(|a| a.get("db"))
        .map(|db| json_flag(db, key))
        .unwrap_or(false)
}

fn json_text(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

impl ModelIndex {
    fn build(model: &ModelAst) -> Self {
        let mut index = ModelIndex {
            writable: HashSet::new(),
            unique_columns: HashSet::new(),
            unique_composites: Vec::new(),
            required_without_default: BTreeSet::new(),
            has_default: HashSet::new(),
            relation_targets: HashMap::new(),
            time_columns: HashSet::new(),
        };

        for (name, field) in &model.fields {
            let json = field_json(field);
            let kind = json_text(&json, "kind");

            index.writable.insert(name.clone());

            if let FieldAst::Relation(relation) = field {
                if let Some(fk) = db_foreign_key(field, name) {
                    index.writable.insert(fk.clone());
                    index
                        .relation_targets
                        .insert(fk.clone(), relation.target.clone());
                    if relation.unique_fk {
                        index.unique_columns.insert(fk);
                    }
                }
                index
                    .relation_targets
                    .insert(name.clone(), relation.target.clone());
                // A relation is satisfied by `connect` or by writing its FK column, so it
                // is never counted as a missing required field in its own right.
                continue;
            }

            if json_flag_either(&json, "unique") || json_flag_either(&json, "primaryKey") {
                index.unique_columns.insert(name.clone());
            }

            let has_default = json.get("default").is_some_and(|d| !d.is_null());
            let server_generated =
                json_flag_either(&json, "serverGenerated") || json_flag_either(&json, "readOnly");
            if has_default || server_generated {
                index.has_default.insert(name.clone());
            } else if json_flag(&json, "required") {
                index.required_without_default.insert(name.clone());
            }

            if TIME_KINDS.contains(&kind.as_str()) {
                index.time_columns.insert(name.clone());
            }
        }

        for declared in &model.annotations.db.indexes {
            if !declared.unique {
                continue;
            }
            if declared.fields.len() == 1 {
                index.unique_columns.insert(declared.fields[0].clone());
            } else {
                index
                    .unique_composites
                    .push(declared.fields.iter().cloned().collect());
            }
        }

        index
    }

    /// True when `columns` is a usable `ON CONFLICT` target.
    fn is_conflict_target(&self, columns: &BTreeSet<String>) -> bool {
        if columns.len() == 1 {
            if let Some(only) = columns.iter().next() {
                if self.unique_columns.contains(only) {
                    return true;
                }
            }
        }
        self.unique_composites.iter().any(|set| set == columns)
    }

    fn sorted(set: &HashSet<String>) -> Vec<&str> {
        let mut names: Vec<&str> = set.iter().map(String::as_str).collect();
        names.sort_unstable();
        names
    }
}

/// The schema, indexed by model name.
struct SchemaIndex {
    models: HashMap<String, ModelIndex>,
}

impl SchemaIndex {
    fn build(ast: &SchemaAst) -> Self {
        SchemaIndex {
            models: ast
                .models
                .iter()
                .map(|model| (model.name.clone(), ModelIndex::build(model)))
                .collect(),
        }
    }

    fn get(&self, model: &str, path: &str) -> Result<&ModelIndex> {
        self.models.get(model).ok_or_else(|| {
            let mut names: Vec<&str> = self.models.keys().map(String::as_str).collect();
            names.sort_unstable();
            err(
                path,
                format!(
                    "`{model}` is not a model in this schema. Known models: {}.",
                    names.join(", ")
                ),
            )
        })
    }
}

/// Labels defined by earlier operations, and the model each produced.
type RefScope = HashMap<String, String>;

/// Validate `ir` against `ast`.
pub fn validate(ir: &SeedIr, ast: &SchemaAst, expected_fingerprint: &str) -> Result<()> {
    if ir.ir_version != IR_VERSION {
        return Err(with_remedy(
            err(
                "irVersion",
                format!(
                    "this engine reads seed IR version {IR_VERSION}, and the document says {}.",
                    ir.ir_version
                ),
            ),
            "Update the CLI and the engine together: they ship as a pair.",
        ));
    }

    if ir.schema_fingerprint != expected_fingerprint {
        return Err(with_remedy(
            err(
                "schemaFingerprint",
                "this seed was built against a different schema than the one in use.",
            ),
            "Run `supatype generate` to rebuild the seed builder, or `supatype push` if the \
             database is the stale one.",
        ));
    }

    let index = SchemaIndex::build(ast);
    let mut scope: RefScope = HashMap::new();
    validate_operations(&ir.operations, &index, &mut scope, "operations", 0)
}

fn validate_operations(
    operations: &[Operation],
    index: &SchemaIndex,
    scope: &mut RefScope,
    path: &str,
    depth: usize,
) -> Result<()> {
    if depth > MAX_GROUP_DEPTH {
        return Err(err(
            path,
            format!("groups are nested more than {MAX_GROUP_DEPTH} deep."),
        ));
    }
    for (position, operation) in operations.iter().enumerate() {
        validate_operation(
            operation,
            index,
            scope,
            &format!("{path}[{position}]"),
            depth,
        )?;
    }
    Ok(())
}

fn validate_operation(
    operation: &Operation,
    index: &SchemaIndex,
    scope: &mut RefScope,
    path: &str,
    depth: usize,
) -> Result<()> {
    match operation {
        Operation::Create { model, id, data } => {
            let model_index = index.get(model, path)?;
            validate_data(data, model_index, index, scope, &format!("{path}.data"))
                .map_err(|e| with_op_id(e, id))?;
            remember(scope, id, model);
        }

        Operation::CreateMany { model, rows } => {
            let model_index = index.get(model, path)?;
            if rows.is_empty() {
                return Err(err(path, "`createMany` was given no rows."));
            }
            for (position, row) in rows.iter().enumerate() {
                validate_data(
                    row,
                    model_index,
                    index,
                    scope,
                    &format!("{path}.rows[{position}]"),
                )?;
            }
        }

        Operation::Upsert {
            model,
            id,
            where_,
            data,
        } => {
            let model_index = index.get(model, path)?;
            validate_conflict_target(where_, model_index, model, path)
                .map_err(|e| with_op_id(e, id))?;

            // `where` and `data` are supplied together, so a required column named in
            // `where` is not missing from the insert half.
            let mut combined = data.clone();
            for (key, value) in where_ {
                combined.entry(key.clone()).or_insert_with(|| value.clone());
            }
            validate_data(
                &combined,
                model_index,
                index,
                scope,
                &format!("{path}.data"),
            )
            .map_err(|e| with_op_id(e, id))?;
            remember(scope, id, model);
        }

        Operation::Sql { text, params } => {
            if text.trim().is_empty() {
                return Err(err(path, "`sql` was given an empty statement."));
            }
            for (position, value) in params.iter().enumerate() {
                validate_value(
                    value,
                    None,
                    index,
                    scope,
                    &format!("{path}.params[{position}]"),
                )?;
            }
        }

        Operation::Group { if_, operations } => {
            if let Some(condition) = if_ {
                validate_condition(condition, index, &format!("{path}.if"))?;
            }
            validate_operations(
                operations,
                index,
                scope,
                &format!("{path}.operations"),
                depth + 1,
            )?;
        }
    }
    Ok(())
}

fn with_op_id(mut error: SeedValidationError, id: &Option<String>) -> SeedValidationError {
    if error.op_id.is_none() {
        error.op_id = id.clone();
    }
    error
}

fn remember(scope: &mut RefScope, id: &Option<String>, model: &str) {
    if let Some(id) = id {
        scope.insert(id.clone(), model.to_string());
    }
}

/// A `where` must name something Postgres can use as an `ON CONFLICT` target.
///
/// Anything else compiles to a statement that cannot do what the author asked, and the
/// database's error for it names a constraint rather than the rule that is wrong.
fn validate_conflict_target(
    where_: &DataMap,
    model_index: &ModelIndex,
    model: &str,
    path: &str,
) -> Result<()> {
    let at = format!("{path}.where");
    if where_.is_empty() {
        return Err(err(
            &at,
            "`upsert` needs a `where` naming the columns that decide a conflict.",
        ));
    }

    let columns: BTreeSet<String> = where_.keys().cloned().collect();
    for column in &columns {
        if !model_index.writable.contains(column) {
            return Err(err(&at, format!("`{column}` is not a field of `{model}`.")));
        }
    }

    if !model_index.is_conflict_target(&columns) {
        let unique = ModelIndex::sorted(&model_index.unique_columns);
        return Err(with_remedy(
            err(
                &at,
                format!(
                    "`{}` is not unique on `{model}`, so it cannot decide a conflict.",
                    columns.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
            ),
            format!(
                "Use a primary key, a `Unique<>` column, or a unique composite index. Unique on \
                 this model: {}.",
                if unique.is_empty() {
                    "none".to_string()
                } else {
                    unique.join(", ")
                }
            ),
        ));
    }
    Ok(())
}

fn validate_data(
    data: &DataMap,
    model_index: &ModelIndex,
    index: &SchemaIndex,
    scope: &mut RefScope,
    path: &str,
) -> Result<()> {
    for (key, value) in data {
        let at = format!("{path}.{key}");
        if !model_index.writable.contains(key) {
            let known = ModelIndex::sorted(&model_index.writable);
            return Err(err(
                &at,
                format!(
                    "`{key}` is not a field, relation or foreign key. Known: {}.",
                    known.join(", ")
                ),
            ));
        }
        validate_value(value, Some((key, model_index)), index, scope, &at)?;
    }

    let supplied: HashSet<&String> = data.keys().collect();
    let missing: Vec<&str> = model_index
        .required_without_default
        .iter()
        .filter(|field| !supplied.contains(field))
        .map(String::as_str)
        .collect();
    if !missing.is_empty() {
        return Err(err(
            path,
            format!(
                "{} required and has no default, so an insert must supply {}: {}.",
                if missing.len() == 1 { "is" } else { "are" },
                if missing.len() == 1 { "it" } else { "them" },
                missing.join(", ")
            ),
        ));
    }
    Ok(())
}

fn validate_value(
    value: &Value,
    column: Option<(&String, &ModelIndex)>,
    index: &SchemaIndex,
    scope: &mut RefScope,
    path: &str,
) -> Result<()> {
    match value {
        Value::Scalar(_) => Ok(()),

        Value::Numeric { numeric } => {
            if numeric.trim().is_empty() || numeric.trim().parse::<f64>().is_err() {
                return Err(err(path, format!("`{numeric}` is not a decimal number.")));
            }
            Ok(())
        }

        Value::Default { .. } => {
            let Some((name, model_index)) = column else {
                return Err(err(path, "`$default` has no meaning here."));
            };
            if !model_index.has_default.contains(name) {
                return Err(err(
                    path,
                    format!("`{name}` has no default, so it cannot be reset to one."),
                ));
            }
            Ok(())
        }

        Value::Ref { reference } => validate_ref(reference, index, scope, path),

        Value::Connect { connect } => {
            let (name, model_index) =
                column.ok_or_else(|| err(path, "`connect` has no meaning outside a relation."))?;
            let target = model_index.relation_targets.get(name).ok_or_else(|| {
                err(
                    path,
                    format!("`{name}` is not a relation, so it cannot be connected."),
                )
            })?;
            let target_index = index.get(target, path)?;
            let columns: BTreeSet<String> = connect.keys().cloned().collect();
            if columns.is_empty() {
                return Err(err(path, "`connect` names no columns."));
            }
            if !target_index.is_conflict_target(&columns) {
                return Err(err(
                    path,
                    format!(
                        "`connect` must name a unique key on `{target}`, and `{}` is not one.",
                        columns.iter().cloned().collect::<Vec<_>>().join(", ")
                    ),
                ));
            }
            for (key, inner) in connect {
                validate_value(inner, None, index, scope, &format!("{path}.{key}"))?;
            }
            Ok(())
        }

        Value::NestedCreate { create } => {
            validate_nested(create, column, index, scope, path, "create")
        }

        Value::NestedCreateMany { create_many } => {
            validate_nested(create_many, column, index, scope, path, "createMany")
        }

        Value::Operand(operand) => validate_operand(operand, column, path),
    }
}

fn validate_nested(
    rows: &[DataMap],
    column: Option<(&String, &ModelIndex)>,
    index: &SchemaIndex,
    scope: &mut RefScope,
    path: &str,
    what: &str,
) -> Result<()> {
    let (name, model_index) =
        column.ok_or_else(|| err(path, format!("`{what}` has no meaning outside a relation.")))?;
    let target = model_index
        .relation_targets
        .get(name)
        .cloned()
        .ok_or_else(|| {
            err(
                path,
                format!("`{name}` is not a relation, so it cannot nest a {what}."),
            )
        })?;
    let target_index = index.get(&target, path)?;
    for (position, row) in rows.iter().enumerate() {
        validate_data(
            row,
            target_index,
            index,
            scope,
            &format!("{path}[{position}]"),
        )?;
    }
    Ok(())
}

/// A reference points backwards, at a label an earlier operation defined.
fn validate_ref(reference: &str, index: &SchemaIndex, scope: &RefScope, path: &str) -> Result<()> {
    let Some((op_id, field)) = reference.split_once('.') else {
        return Err(err(
            path,
            format!("`{reference}` is not a reference. Write it as `<operation id>.<field>`."),
        ));
    };
    if field.is_empty() {
        return Err(err(path, format!("`{reference}` names no field.")));
    }

    let Some(target_model) = scope.get(op_id) else {
        return Err(with_remedy(
            err(
                path,
                format!("`{op_id}` is not an operation defined earlier in this seed."),
            ),
            "A reference can only point backwards: the value has to exist before it is used.",
        ));
    };

    let produced = index.get(target_model, path)?;
    if !produced.writable.contains(field) {
        return Err(err(
            path,
            format!("`{target_model}` has no field `{field}` to reference."),
        ));
    }
    Ok(())
}

/// A seed has no caller, so the operands describing one are refused outright.
///
/// `authUid` and its siblings would compile to SQL evaluating to null in a seed. Null is a
/// value, so nothing would fail: a row would simply be written with the wrong contents, or
/// a condition would quietly not match. An error is better than either.
fn validate_operand(
    operand: &Operand,
    column: Option<(&String, &ModelIndex)>,
    path: &str,
) -> Result<()> {
    match operand {
        Operand::AuthUid | Operand::AuthRole | Operand::Claim { .. } => Err(with_remedy(
            err(
                path,
                "a seed has no caller, so `authUid`, `authRole` and `claim` cannot be used.",
            ),
            "Write the value the seed means. These describe whoever is making a request, and a \
             seed is not a request.",
        )),

        Operand::Now
        | Operand::StartOf { .. }
        | Operand::Ago { .. }
        | Operand::FromNow { .. }
        | Operand::After { .. }
        | Operand::Before { .. } => {
            if let Some((name, model_index)) = column {
                if !model_index.time_columns.contains(name) {
                    return Err(err(
                        path,
                        format!(
                            "`{name}` is not a date or timestamp, so a time operand cannot be \
                             written to it."
                        ),
                    ));
                }
            }
            Ok(())
        }

        Operand::Literal { .. } => Ok(()),

        other => Err(err(
            path,
            format!("`{other:?}` describes a query, not a value a seed can write."),
        )),
    }
}

fn validate_condition(condition: &Condition, index: &SchemaIndex, path: &str) -> Result<()> {
    let (model, filter) = match condition {
        Condition::Exists { model, filter } | Condition::NotExists { model, filter } => {
            (model, filter)
        }
        Condition::Environment { name } => {
            if name.trim().is_empty() {
                return Err(err(path, "an environment condition names no environment."));
            }
            return Ok(());
        }
    };

    let model_index = index.get(model, path)?;
    if let Some(rule) = filter {
        validate_filter(rule, model_index, model, &format!("{path}.where"))?;
    }
    Ok(())
}

/// A condition's filter is an access rule, so its columns are checked the same way.
///
/// Unlike an upsert's `where` it need not be unique: it is a filter, not a conflict target.
fn validate_filter(
    rule: &AccessRule,
    model_index: &ModelIndex,
    model: &str,
    path: &str,
) -> Result<()> {
    match rule {
        AccessRule::Compare { left, right, .. } => {
            validate_filter_operand(left, model_index, model, path)?;
            validate_filter_operand(right, model_index, model, path)
        }
        AccessRule::NullCheck { operand, .. } => {
            validate_filter_operand(operand, model_index, model, path)
        }
        AccessRule::Any { rules } | AccessRule::All { rules } => rules
            .iter()
            .try_for_each(|inner| validate_filter(inner, model_index, model, path)),
        AccessRule::Not { rule } => validate_filter(rule, model_index, model, path),
        AccessRule::In { column, .. } => {
            if !model_index.writable.contains(column) {
                return Err(err(
                    path,
                    format!("`{column}` is not a field of `{model}`."),
                ));
            }
            // A membership source's own filter is evaluated against the other table, so its
            // columns are not this model's and are left to Postgres.
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_filter_operand(
    operand: &Operand,
    model_index: &ModelIndex,
    model: &str,
    path: &str,
) -> Result<()> {
    match operand {
        Operand::Column { name } => {
            if !model_index.writable.contains(name) {
                return Err(err(path, format!("`{name}` is not a field of `{model}`.")));
            }
            Ok(())
        }
        Operand::AuthUid | Operand::AuthRole | Operand::Claim { .. } => Err(err(
            path,
            "a seed has no caller, so `authUid`, `authRole` and `claim` cannot be used in a \
             condition.",
        )),
        _ => Ok(()),
    }
}

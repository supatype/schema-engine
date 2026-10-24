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

use super::placeholders::placeholder_count;
use super::{Condition, DataMap, Operation, SeedIr, Value, IR_VERSION};
use crate::generator::seed_model::{describe, RelationKind, SeedRelation, SeedSchema};
use crate::managed::clip_identifier;
use crate::parser::accessors::{column_names_for, db_foreign_key};
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
    /// The model this describes, so a check that needs the far side of a relation can ask
    /// the schema for it.
    name: String,
    /// Field names, plus the foreign-key column each relation generates. Both are writable
    /// and an author may reasonably use either.
    writable: HashSet<String>,
    /// The table's columns, as Postgres keeps their names: what a `$ref` may read back.
    ///
    /// Not `writable`, which also holds relation names. A `hasMany` relation is no column of
    /// this row, so a reference to it had nothing to read and resolved to NULL.
    columns: HashSet<String>,
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
            name: model.name.clone(),
            writable: HashSet::new(),
            columns: HashSet::new(),
            unique_columns: HashSet::new(),
            unique_composites: Vec::new(),
            required_without_default: BTreeSet::new(),
            has_default: HashSet::new(),
            relation_targets: HashMap::new(),
            time_columns: HashSet::new(),
        };
        for (name, field) in &model.fields {
            index.add_field(name, field);
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

    /// One field: its name, the columns it occupies, and what a write to it must respect.
    fn add_field(&mut self, name: &str, field: &FieldAst) {
        self.writable.insert(name.to_string());
        self.columns.extend(
            column_names_for(name, field)
                .iter()
                .map(|column| clip_identifier(column)),
        );
        if let FieldAst::Relation(relation) = field {
            // A relation is satisfied by `connect` or by writing its FK column, so it is
            // never counted as a missing required field in its own right.
            self.add_relation(name, field, &relation.target, relation.unique_fk);
            return;
        }
        let json = field_json(field);
        if json_flag_either(&json, "unique") || json_flag_either(&json, "primaryKey") {
            self.unique_columns.insert(name.to_string());
        }
        let has_default = json.get("default").is_some_and(|d| !d.is_null());
        let server_generated =
            json_flag_either(&json, "serverGenerated") || json_flag_either(&json, "readOnly");
        if has_default || server_generated {
            self.has_default.insert(name.to_string());
        } else if json_flag(&json, "required") {
            self.required_without_default.insert(name.to_string());
        }
        if TIME_KINDS.contains(&json_text(&json, "kind").as_str()) {
            self.time_columns.insert(name.to_string());
        }
    }

    /// A relation, writable by its own name and by its foreign-key column.
    fn add_relation(&mut self, name: &str, field: &FieldAst, target: &str, unique_fk: bool) {
        if let Some(fk) = db_foreign_key(field, name) {
            self.writable.insert(fk.clone());
            self.relation_targets.insert(fk.clone(), target.to_string());
            if unique_fk {
                self.unique_columns.insert(fk);
            }
        }
        self.relation_targets
            .insert(name.to_string(), target.to_string());
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
    /// The same schema as a generator sees it.
    ///
    /// Carried rather than rederived because the checks below are about the *shape* of a
    /// relation, which is what a builder is generated from: whether a nested write can be
    /// lowered into a foreign key at all. Answering that from a second reading of the AST
    /// would be a second set of rules, and the planner would eventually disagree with it.
    shapes: SeedSchema,
}

impl SchemaIndex {
    fn build(ast: &SchemaAst) -> Self {
        SchemaIndex {
            models: ast
                .models
                .iter()
                .map(|model| (model.name.clone(), ModelIndex::build(model)))
                .collect(),
            shapes: describe(ast),
        }
    }

    /// One relation, from the model that declares it.
    fn relation(&self, model: &str, field: &str) -> Option<&SeedRelation> {
        self.shapes
            .models
            .iter()
            .find(|m| m.name == model)?
            .relations
            .iter()
            .find(|r| r.field == field)
    }

    /// The column a relation's foreign key points at, `id` unless it named another.
    fn referenced_column(&self, model: &str, key: &str) -> String {
        self.shapes
            .models
            .iter()
            .find(|m| m.name == model)
            .and_then(|m| m.column(key))
            .and_then(|c| c.references_column.clone())
            .unwrap_or_else(|| "id".to_string())
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

        Operation::Sql { text, params } => validate_sql(text, params, index, scope, path)?,

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

/// Operand kinds, so a value that nearly is one can be told apart from a JSON column value.
const OPERAND_KINDS: [&str; 8] = [
    "literal", "column", "now", "startOf", "ago", "fromNow", "after", "before",
];

/// Catch a value that was meant to be an operand and did not parse as one.
///
/// `Value` is untagged: anything that fails to deserialise as an `Operand` falls through to
/// `Scalar` without a word. A negative interval component does that, because the components
/// are unsigned, and the operand then reached the database as a JSON string in a timestamp
/// column. Postgres refused it with `invalid input syntax`, naming neither the field nor the
/// real mistake.
///
/// A JSON column may legitimately hold an object with a `kind` in it, so only the kinds this
/// engine would have recognised are refused.
fn reject_malformed_operand(scalar: &serde_json::Value, path: &str) -> Result<()> {
    let Some(kind) = scalar.get("kind").and_then(|k| k.as_str()) else {
        return Ok(());
    };
    if !OPERAND_KINDS.contains(&kind) {
        return Ok(());
    }
    Err(with_remedy(
        err(
            path,
            format!(
                "this looks like a `{kind}` expression that could not be read, so it would be \
                 written as text rather than evaluated."
            ),
        ),
        "An interval's components are whole and not negative: the direction is in the \
         operand's name, so use `before`/`ago` rather than a negative amount."
            .to_string(),
    ))
}

fn validate_value(
    value: &Value,
    column: Option<(&String, &ModelIndex)>,
    index: &SchemaIndex,
    scope: &mut RefScope,
    path: &str,
) -> Result<()> {
    match value {
        Value::Scalar(scalar) => reject_malformed_operand(scalar, path),

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
            check_connectable(index, &model_index.name, name, columns.len(), path)?;
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

/// A raw statement: some text, one param for each placeholder it uses, and only values a
/// placeholder can carry.
fn validate_sql(
    text: &str,
    params: &[Value],
    index: &SchemaIndex,
    scope: &mut RefScope,
    path: &str,
) -> Result<()> {
    if text.trim().is_empty() {
        return Err(err(path, "`sql` was given an empty statement."));
    }
    check_param_count(text, params.len(), path)?;
    for (position, value) in params.iter().enumerate() {
        let at = format!("{path}.params[{position}]");
        validate_value(value, None, index, scope, &at)?;
        check_bindable(value, &at)?;
    }
    Ok(())
}

/// Exactly one param for each placeholder the statement uses.
fn check_param_count(text: &str, given: usize, path: &str) -> Result<()> {
    let used = placeholder_count(text);
    if used == given {
        return Ok(());
    }
    let message = format!(
        "`sql` takes {} but was given {given}: {}",
        parameters(used),
        excerpt(text)
    );
    Err(with_remedy(
        err(path, message),
        "Pass one value in `params` for each of `$1` to `$n` in the statement, in order.",
    ))
}

fn parameters(count: usize) -> String {
    match count {
        0 => "no parameters".to_string(),
        1 => "1 parameter".to_string(),
        n => format!("{n} parameters"),
    }
}

/// The start of a statement, on one line, so an error can name it without quoting a page.
fn excerpt(text: &str) -> String {
    const LIMIT: usize = 60;
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    match line.char_indices().nth(LIMIT) {
        Some((cut, _)) => format!("`{}...`", &line[..cut]),
        None => format!("`{line}`"),
    }
}

/// A placeholder carries a value, and a time operand is SQL rather than a value.
fn check_bindable(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Operand(
            Operand::Now
            | Operand::StartOf { .. }
            | Operand::Ago { .. }
            | Operand::FromNow { .. }
            | Operand::After { .. }
            | Operand::Before { .. },
        ) => Err(with_remedy(
            err(
                path,
                "a `sql` parameter must be a value, and this is an expression.",
            ),
            "Write the expression in the statement instead, such as `now()`.",
        )),
        _ => Ok(()),
    }
}

/// Whether a `connect` on this relation can be lowered into a foreign key.
///
/// The planner writes the key column, and only the `belongsTo` side has one. Connecting
/// the other way round would mean updating a row on the far side, which is a different
/// operation from the one the author wrote.
fn check_connectable(
    index: &SchemaIndex,
    model: &str,
    field: &str,
    named_columns: usize,
    path: &str,
) -> Result<()> {
    let Some(relation) = index.relation(model, field) else {
        return Ok(());
    };

    if relation.kind != RelationKind::BelongsTo {
        return Err(with_remedy(
            err(
                path,
                format!(
                    "`{field}` is a {} relation, and the foreign key for it is on `{}`, not here.",
                    relation.kind.as_str(),
                    relation.target
                ),
            ),
            format!(
                "Connect from the other side, or nest a `create` under `{field}` to write                  the `{}` rows this one owns.",
                relation.target
            ),
        ));
    }

    if relation.foreign_key.is_none() {
        return Err(err(
            path,
            format!("`{field}` has no foreign-key column, so there is nothing to connect."),
        ));
    }

    // One bound column per key part and a join on all of them: buildable, but nothing
    // asks for it yet, and guessing which part to use would connect the wrong row.
    if named_columns != 1 {
        return Err(with_remedy(
            err(
                path,
                format!(
                    "`connect` on `{field}` names {named_columns} columns, and a composite key                      cannot be resolved to one id."
                ),
            ),
            "Name a single-column unique key, or write the foreign key directly.".to_string(),
        ));
    }

    Ok(())
}

/// Whether a nested write on this relation can be lowered into rows of its own.
///
/// A nested write becomes an insert into the target's table, with the foreign key set to a
/// reference to the parent's id. Three shapes have no such key, and each of them used to
/// be planned as a write against a model named after the relation, which failed as
/// `relation "events" does not exist` rather than as anything an author could act on.
fn check_nestable(
    index: &SchemaIndex,
    model: &str,
    field: &str,
    what: &str,
    path: &str,
) -> Result<()> {
    let Some(relation) = index.relation(model, field) else {
        return Ok(());
    };

    match relation.kind {
        // The key is on this table, so the target row must exist before this one does.
        // That is what `connect` is, and writing it as a nested create would need the two
        // inserts in the other order.
        RelationKind::BelongsTo => {
            return Err(with_remedy(
                err(
                    path,
                    format!(
                        "`{field}` holds the foreign key, so a nested `{what}` cannot fill it."
                    ),
                ),
                format!(
                    "Use `{{ connect: {{ ... }} }}` to point at an existing `{}`, or create \
                     that row first and reference it.",
                    relation.target
                ),
            ));
        }
        // Rows of a junction table, which the IR has no operation for.
        RelationKind::ManyToMany => {
            return Err(with_remedy(
                err(
                    path,
                    format!(
                        "`{field}` is a many-to-many relation, and its rows live in a junction \
                         table a nested `{what}` cannot write."
                    ),
                ),
                "Write the junction rows as their own operation.".to_string(),
            ));
        }
        RelationKind::HasOne | RelationKind::HasMany => {}
    }

    let Some(key) = &relation.foreign_key else {
        return Err(with_remedy(
            err(
                path,
                format!(
                    "`{}` declares more than one relation back to `{model}`, so a nested `{what}` \
                     under `{field}` cannot tell which foreign key it fills.",
                    relation.target
                ),
            ),
            "Write the rows as their own operation and set the foreign key yourself.".to_string(),
        ));
    };

    // The parent's id is what the child gets, because that is the only column the
    // executor reads back from an insert.
    let referenced = index.referenced_column(&relation.target, key);
    if referenced != "id" {
        return Err(with_remedy(
            err(
                path,
                format!(
                    "`{field}` points at `{}.{referenced}` rather than its id, and a nested \
                     `{what}` can only carry the parent's id.",
                    relation.target
                ),
            ),
            "Write the rows as their own operation and set the foreign key yourself.".to_string(),
        ));
    }

    Ok(())
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
    check_nestable(index, &model_index.name, name, what, path)?;
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

    check_referable(index.get(target_model, path)?, field, path)
}

/// A reference reads back a column of the row, so it must name one the table has.
fn check_referable(produced: &ModelIndex, field: &str, path: &str) -> Result<()> {
    if produced.columns.contains(&clip_identifier(field)) {
        return Ok(());
    }
    let model = &produced.name;
    Err(with_remedy(
        err(
            path,
            format!("`{model}` has no field `{field}` to reference."),
        ),
        format!(
            "A reference reads a column of the row that was written. Columns of `{model}`: {}.",
            ModelIndex::sorted(&produced.columns).join(", ")
        ),
    ))
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

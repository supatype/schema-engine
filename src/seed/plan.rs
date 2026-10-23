//! Turn a validated IR into an ordered, batched plan.
//!
//! Three transformations, kept separate because they answer different questions and get
//! confused when they are one pass: flattening decides *what* is written, ordering decides
//! *when*, and grouping decides *how many statements*.
//!
//! The planner never changes what a seed means. It may reorder writes that do not depend
//! on each other and merge writes that share a shape, and nothing else. In particular a
//! conditional group's membership is fixed: an operation inside one may not run at all, so
//! moving anything across that boundary would change the outcome rather than the schedule.

use super::{Condition, DataMap, Operation, SeedIr, Value};
use crate::generator::seed_model::{describe, RelationKind, SeedModel, SeedRelation, SeedSchema};
use crate::parser::ast::SchemaAst;
use indexmap::IndexMap;
use std::collections::{BTreeSet, HashMap, HashSet};

/// The kind of statement a write becomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteKind {
    Insert,
    Upsert,
}

/// Where a `connect` has to look to find the id it names.
///
/// Present only when the author connected by a unique key that is not the referenced
/// column. The value bound for the column is then that key, and the executor wraps it in a
/// scalar subquery against the target table, one subquery in the statement rather than one
/// round trip per row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectLookup {
    /// The model holding the row, resolved to a table by the executor.
    pub model: String,
    /// The unique column the author named.
    pub key_column: String,
    /// The column the foreign key points at, almost always `id`.
    pub referenced_column: String,
}

/// One row to write, lifted out of whatever nesting it arrived in.
#[derive(Debug, Clone)]
pub struct PlannedWrite {
    pub model: String,
    pub kind: WriteKind,
    /// The author's label, when they gave one. What a later `$ref` points at.
    pub op_id: Option<String>,
    /// Where this row came from in the document, for an error to name.
    pub path: String,
    pub data: DataMap,
    /// Conflict columns, for an upsert.
    pub conflict: BTreeSet<String>,
    /// Write this row only when no row of the model already holds every value it gives.
    ///
    /// Set on a row nested under an `upsert`, and on every row nested under one of those.
    /// The upsert's own row is idempotent through its conflict key, but its children have
    /// none, so without this every run added them again. Under a plain `create` the parent
    /// is new, so nothing can already hang off it and no match is looked for.
    pub match_existing: bool,
    /// Columns whose bound value is a unique key to look up, not the value itself.
    ///
    /// Keyed by the foreign-key column. Empty for almost every write.
    pub lookups: IndexMap<String, ConnectLookup>,
    /// Which conditional groups enclose this write, outermost first.
    ///
    /// Two writes batch together only when these match: one statement cannot run for some
    /// of its rows and not others.
    pub guards: Vec<usize>,
    /// Position in the document, preserved so a stable sort keeps author order among
    /// writes that do not depend on each other.
    pub sequence: usize,
}

/// Something that is not a row: a raw statement, or a group's condition.
#[derive(Debug, Clone)]
pub enum PlannedStep {
    Write(PlannedWrite),
    /// Evaluate a condition and skip its members when false.
    Condition {
        guard: usize,
        condition: Condition,
        path: String,
        sequence: usize,
        guards: Vec<usize>,
    },
    Sql {
        text: String,
        params: Vec<Value>,
        path: String,
        sequence: usize,
        guards: Vec<usize>,
    },
}

impl PlannedStep {
    pub fn sequence(&self) -> usize {
        match self {
            PlannedStep::Write(w) => w.sequence,
            PlannedStep::Condition { sequence, .. } | PlannedStep::Sql { sequence, .. } => {
                *sequence
            }
        }
    }

    pub fn guards(&self) -> &[usize] {
        match self {
            PlannedStep::Write(w) => &w.guards,
            PlannedStep::Condition { guards, .. } | PlannedStep::Sql { guards, .. } => guards,
        }
    }

    /// The model this step writes, if it writes one.
    fn writes_model(&self) -> Option<&str> {
        match self {
            PlannedStep::Write(w) => Some(&w.model),
            _ => None,
        }
    }
}

/// A cycle in the dependency graph, named by the models involved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CycleError {
    pub models: Vec<String>,
}

impl std::fmt::Display for CycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "these writes depend on each other in a cycle, so no order satisfies them: {}",
            self.models.join(" -> ")
        )
    }
}

impl std::error::Error for CycleError {}

/// A read-after-write the author's own ordering created.
///
/// Legal, occasionally intended, and far more often a mistake, so it is reported rather
/// than refused. The planner itself cannot cause one: a condition is a read edge, so the
/// sort will not move a group across a write to the model it reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadAfterWrite {
    pub model: String,
    pub condition_path: String,
    pub write_path: String,
}

impl std::fmt::Display for ReadAfterWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the condition at {} reads `{}`, which {} writes earlier in the same seed, so it sees \
             that write",
            self.condition_path, self.model, self.write_path
        )
    }
}

/// One statement's worth of writes.
#[derive(Debug, Clone)]
pub struct Batch {
    pub model: String,
    pub kind: WriteKind,
    pub columns: Vec<String>,
    pub conflict: BTreeSet<String>,
    /// Every row is written only when no matching row exists. See [`PlannedWrite`].
    pub match_existing: bool,
    /// Shared by every row in the batch, because one statement renders one expression per
    /// column. Two writes that look up different columns cannot be one statement.
    pub lookups: IndexMap<String, ConnectLookup>,
    pub rows: Vec<PlannedWrite>,
    pub guards: Vec<usize>,
}

/// The finished plan.
#[derive(Debug, Clone)]
pub struct Plan {
    pub steps: Vec<PlannedStep>,
    pub batches: Vec<Batch>,
    /// Conditions that read a model written earlier in the same document.
    pub warnings: Vec<ReadAfterWrite>,
}

/// Lift every write out of its nesting, numbering them in document order.
pub fn flatten(ir: &SeedIr, schema: &SeedSchema) -> Vec<PlannedStep> {
    let mut flattener = Flattener::new(schema);
    flattener.operations(&ir.operations, &[], "operations");
    flattener.steps
}

/// One row on its way into the plan, before its nesting has been taken apart.
struct Pending {
    model: String,
    kind: WriteKind,
    op_id: Option<String>,
    data: DataMap,
    conflict: BTreeSet<String>,
    match_existing: bool,
}

impl Pending {
    /// A row that is not nested in anything.
    fn top_level(model: &str, kind: WriteKind, op_id: Option<String>, data: DataMap) -> Self {
        Pending {
            model: model.to_string(),
            kind,
            op_id,
            data,
            conflict: BTreeSet::new(),
            match_existing: false,
        }
    }

    /// Whether the rows nested in this one look for a match before they are written.
    ///
    /// An upsert's parent row may already exist with its children, so they are matched; a
    /// child of a matched row may be one that already existed, so its children are too.
    fn children_match(&self) -> bool {
        self.kind == WriteKind::Upsert || self.match_existing
    }
}

/// The parent a nested relation's rows are written under.
struct Parent<'p> {
    model: Option<&'p SeedModel>,
    /// The label the children's foreign key points at.
    label: &'p str,
    match_existing: bool,
}

/// A row's data, split into what is written to its own table and what is nested in it.
struct Split {
    own: DataMap,
    nested: Vec<(String, Vec<DataMap>)>,
    lookups: IndexMap<String, ConnectLookup>,
}

/// What flattening needs, rather than threaded through eight arguments.
///
/// The schema is the part that matters. A nested write names a **relation**, and only the
/// schema says which model that relation targets and which column links the two. Without
/// it the planner emitted a write against a model called `events` and the executor used
/// that as a table name, so a nested fixture failed with `relation "events" does not
/// exist` rather than being written.
struct Flattener<'a> {
    schema: &'a SeedSchema,
    steps: Vec<PlannedStep>,
    sequence: usize,
    next_guard: usize,
    /// How many labels have been invented, for naming the next one.
    synthesised: usize,
}

impl<'a> Flattener<'a> {
    fn new(schema: &'a SeedSchema) -> Self {
        Flattener {
            schema,
            steps: Vec::new(),
            sequence: 0,
            next_guard: 0,
            synthesised: 0,
        }
    }

    fn model(&self, name: &str) -> Option<&'a SeedModel> {
        self.schema.models.iter().find(|model| model.name == name)
    }

    /// A label for a parent whose children need something to point at.
    ///
    /// Invented during flattening rather than written into the IR, so it happens after
    /// validation and cannot collide with a label an author gave: `$` is not a character
    /// any builder puts in one.
    fn synthesise_label(&mut self) -> String {
        self.synthesised += 1;
        format!("$nested:{}", self.synthesised)
    }

    fn operations(&mut self, operations: &[Operation], guards: &[usize], path: &str) {
        for (position, operation) in operations.iter().enumerate() {
            self.operation(operation, guards, &format!("{path}[{position}]"));
        }
    }

    fn operation(&mut self, operation: &Operation, guards: &[usize], path: &str) {
        match operation {
            Operation::Create { model, id, data } => self.write(
                Pending::top_level(model, WriteKind::Insert, id.clone(), data.clone()),
                guards,
                path,
            ),

            Operation::CreateMany { model, rows } => {
                for (position, row) in rows.iter().enumerate() {
                    self.write(
                        Pending::top_level(model, WriteKind::Insert, None, row.clone()),
                        guards,
                        &format!("{path}.rows[{position}]"),
                    );
                }
            }

            Operation::Upsert {
                model,
                id,
                where_,
                data,
            } => {
                let mut combined = data.clone();
                for (key, value) in where_ {
                    combined.entry(key.clone()).or_insert_with(|| value.clone());
                }
                self.write(
                    Pending {
                        conflict: where_.keys().cloned().collect(),
                        ..Pending::top_level(model, WriteKind::Upsert, id.clone(), combined)
                    },
                    guards,
                    path,
                );
            }

            Operation::Sql { text, params } => {
                self.steps.push(PlannedStep::Sql {
                    text: text.clone(),
                    params: params.clone(),
                    path: path.to_string(),
                    sequence: self.sequence,
                    guards: guards.to_vec(),
                });
                self.sequence += 1;
            }

            Operation::Group { if_, operations } => {
                let mut inner = guards.to_vec();
                if let Some(condition) = if_ {
                    let guard = self.next_guard;
                    self.next_guard += 1;
                    self.steps.push(PlannedStep::Condition {
                        guard,
                        condition: condition.clone(),
                        path: format!("{path}.if"),
                        sequence: self.sequence,
                        guards: guards.to_vec(),
                    });
                    self.sequence += 1;
                    inner.push(guard);
                }
                self.operations(operations, &inner, &format!("{path}.operations"));
            }
        }
    }

    /// Push one write, then the rows nested inside it.
    ///
    /// Nested rows are emitted **after** their parent, which is what makes the parent's
    /// generated id available to them. The ordering pass may move them further apart but
    /// never in front, because the reference is a dependency edge.
    fn write(&mut self, pending: Pending, guards: &[usize], path: &str) {
        let model = self.model(&pending.model);
        let children_match = pending.children_match();
        let split = split_data(model, pending.data);
        let op_id = self.label_for(pending.op_id, !split.nested.is_empty());

        self.steps.push(PlannedStep::Write(PlannedWrite {
            model: pending.model,
            kind: pending.kind,
            op_id: op_id.clone(),
            path: path.to_string(),
            data: split.own,
            conflict: pending.conflict,
            match_existing: pending.match_existing,
            lookups: split.lookups,
            guards: guards.to_vec(),
            sequence: self.sequence,
        }));
        self.sequence += 1;

        let label = op_id.unwrap_or_default();
        let parent = Parent {
            model,
            label: &label,
            match_existing: children_match,
        };
        for (field, rows) in split.nested {
            self.nested(&parent, &field, rows, guards, path);
        }
    }

    /// The label a write is known by.
    ///
    /// A child's foreign key is a reference to its parent's id, so a parent with children
    /// needs a label for them to point at. Most writes have none: an author labels an
    /// operation only when they mean to refer to it themselves.
    fn label_for(&mut self, given: Option<String>, has_children: bool) -> Option<String> {
        match (given, has_children) {
            (Some(given), _) => Some(given),
            (None, true) => Some(self.synthesise_label()),
            (None, false) => None,
        }
    }

    /// The rows of one nested relation, resolved to the model they actually write.
    fn nested(
        &mut self,
        parent: &Parent<'_>,
        field: &str,
        rows: Vec<DataMap>,
        guards: &[usize],
        path: &str,
    ) {
        let relation = parent
            .model
            .and_then(|model| model.relations.iter().find(|r| r.field == field));

        for (position, row) in rows.into_iter().enumerate() {
            let (model, row) = child_row(relation, field, row, parent.label);
            self.write(
                Pending {
                    match_existing: parent.match_existing,
                    ..Pending::top_level(&model, WriteKind::Insert, None, row)
                },
                guards,
                &format!("{path}.{field}[{position}]"),
            );
        }
    }
}

/// A nested row as a row of the model its relation targets, linked to the parent `label`.
fn child_row(
    relation: Option<&SeedRelation>,
    field: &str,
    mut row: DataMap,
    label: &str,
) -> (String, DataMap) {
    // Validation names every relation a nested write may use, so an unresolved one is a
    // document that skipped it. The field name is carried through unchanged so the failure
    // still names what the author wrote.
    let Some(relation) = relation else {
        return (field.to_string(), row);
    };
    // `or_insert_with`, not `insert`: an author who wrote the foreign key by hand meant that
    // value, and overwriting it would silently move the row.
    if let Some(key) = relation.foreign_key.clone() {
        row.entry(key).or_insert_with(|| Value::Ref {
            reference: format!("{label}.id"),
        });
    }
    (relation.target.clone(), row)
}

/// Split a row's data into its own columns, its nested rows and its `connect` lookups.
fn split_data(model: Option<&SeedModel>, data: DataMap) -> Split {
    let mut split = Split {
        own: DataMap::new(),
        nested: Vec::new(),
        lookups: IndexMap::new(),
    };
    for (key, value) in data {
        match value {
            Value::NestedCreate { create } => split.nested.push((key, create)),
            Value::NestedCreateMany { create_many } => split.nested.push((key, create_many)),
            Value::Connect { connect } => split_connect(&mut split, model, key, connect),
            other => {
                // A later value for a column replaces an earlier one, and the lookup that
                // came with the earlier one has to go with it. An upsert keyed on a
                // foreign key does exactly this: `where` names the id and `data` connects
                // by slug, and a lookup left behind searched for a row whose slug was a
                // uuid, found none, and wrote NULL into a column that refuses it.
                split.lookups.shift_remove(&key);
                split.own.insert(key, other);
            }
        }
    }
    split
}

/// Lower one `connect` into the column it fills, and the lookup that goes with it.
fn split_connect(
    split: &mut Split,
    model: Option<&SeedModel>,
    key: String,
    connect: IndexMap<String, Value>,
) {
    match model.and_then(|m| lower_connect(m, &key, &connect)) {
        Some(lowered) => {
            if let Some(lookup) = lowered.lookup {
                split.lookups.insert(lowered.column.clone(), lookup);
            }
            split.own.insert(lowered.column, lowered.value);
        }
        // Validation refuses every shape this cannot lower, so arriving here means the
        // document was planned without being validated. The value is kept as it was, so
        // the failure names the field the author wrote rather than disappearing.
        None => {
            split.own.insert(key, Value::Connect { connect });
        }
    }
}

/// A `connect` lowered to the column it fills.
struct LoweredConnect {
    column: String,
    value: Value,
    lookup: Option<ConnectLookup>,
}

/// Turn `{ connect: { ... } }` into the foreign-key column it means.
///
/// Two shapes come out of it. Naming the referenced column, `{ connect: { id: alex.id } }`,
/// gives a value the planner already holds, so the column takes it directly. Naming another
/// unique key, `{ connect: { slug: "northern" } }`, gives a value only the database holds,
/// so the column takes the key and a [`ConnectLookup`] saying where the id is found.
///
/// Neither shape reaches the executor as a `connect`, which is the point: it used to be
/// written out as a column named after the relation, so `connect` failed with
/// `column "organiser" of relation "event" does not exist`.
fn lower_connect(
    model: &SeedModel,
    field: &str,
    connect: &IndexMap<String, Value>,
) -> Option<LoweredConnect> {
    let relation = model.relations.iter().find(|r| r.field == field)?;
    if relation.kind != RelationKind::BelongsTo {
        return None;
    }
    let column = relation.foreign_key.clone()?;
    let referenced = model
        .column(&column)
        .and_then(|c| c.references_column.clone())
        .unwrap_or_else(|| "id".to_string());

    // One key only. A composite unique key would need one bound column per part and a
    // lookup joining on all of them; validation refuses it by name rather than letting a
    // guess pick the first part.
    if connect.len() != 1 {
        return None;
    }
    let (named, value) = connect.iter().next()?;

    let lookup = (named != &referenced).then(|| ConnectLookup {
        model: relation.target.clone(),
        key_column: named.clone(),
        referenced_column: referenced,
    });

    Some(LoweredConnect {
        column,
        value: value.clone(),
        lookup,
    })
}

/// Every `$ref` label a step points at: a write's data, or a raw statement's params.
fn referenced_labels(step: &PlannedStep) -> HashSet<String> {
    let mut labels = HashSet::new();
    match step {
        PlannedStep::Write(write) => collect_labels(write.data.values(), &mut labels),
        PlannedStep::Sql { params, .. } => collect_labels(params, &mut labels),
        PlannedStep::Condition { .. } => {}
    }
    labels
}

fn collect_labels<'a>(values: impl IntoIterator<Item = &'a Value>, labels: &mut HashSet<String>) {
    for value in values {
        match value {
            Value::Ref { reference } => {
                if let Some((op_id, _)) = reference.split_once('.') {
                    labels.insert(op_id.to_string());
                }
            }
            Value::Connect { connect } => collect_labels(connect.values(), labels),
            _ => {}
        }
    }
}

/// Order the steps so every dependency is satisfied.
///
/// Three kinds of edge, and the third is the one that is easy to leave out:
///
/// 1. A `$ref` edge: a write or raw statement using a label must follow the write that
///    defines it.
/// 2. A guard edge: a step inside a conditional group must follow its condition.
/// 3. **A read edge**: a condition reads a model, so it must not be moved across a write
///    to that model. Without it the sort is free to float a group past such a write and
///    silently change the condition's answer, which no test of the author's IR would
///    catch, because their IR is correct and the planner is what broke it.
///
/// Stable in the absence of edges: steps that do not depend on each other keep document
/// order, so a plan does not change shape between runs.
pub fn order(
    steps: Vec<PlannedStep>,
) -> Result<(Vec<PlannedStep>, Vec<ReadAfterWrite>), CycleError> {
    let count = steps.len();
    let mut edges: Vec<HashSet<usize>> = vec![HashSet::new(); count];
    let mut indegree = vec![0usize; count];

    // Where each label is defined.
    let mut defined_at: HashMap<String, usize> = HashMap::new();
    for (position, step) in steps.iter().enumerate() {
        if let PlannedStep::Write(write) = step {
            if let Some(id) = &write.op_id {
                defined_at.insert(id.clone(), position);
            }
        }
    }

    let add_edge =
        |from: usize, to: usize, edges: &mut Vec<HashSet<usize>>, indegree: &mut Vec<usize>| {
            if from != to && edges[from].insert(to) {
                indegree[to] += 1;
            }
        };

    for (position, step) in steps.iter().enumerate() {
        // 1. references
        for label in referenced_labels(step) {
            if let Some(&source) = defined_at.get(&label) {
                add_edge(source, position, &mut edges, &mut indegree);
            }
        }

        // 2. guards
        for guard in step.guards() {
            if let Some(condition_position) = steps.iter().position(
                |other| matches!(other, PlannedStep::Condition { guard: g, .. } if g == guard),
            ) {
                add_edge(condition_position, position, &mut edges, &mut indegree);
            }
        }
    }

    // 3. read edges, and the report that falls out of them
    let mut warnings = Vec::new();
    for (position, step) in steps.iter().enumerate() {
        let PlannedStep::Condition {
            condition, path, ..
        } = step
        else {
            continue;
        };
        let Some(read_model) = condition_model(condition) else {
            continue;
        };

        for (other_position, other) in steps.iter().enumerate() {
            if other.writes_model() != Some(read_model) {
                continue;
            }
            if other_position < position {
                // The author put a write first. Legal, and it means the condition sees it.
                add_edge(other_position, position, &mut edges, &mut indegree);
                if let PlannedStep::Write(write) = other {
                    warnings.push(ReadAfterWrite {
                        model: read_model.to_string(),
                        condition_path: path.clone(),
                        write_path: write.path.clone(),
                    });
                }
            } else {
                // The condition comes first, so it must stay in front of that write.
                //
                // Belt and braces: the sort already preserves document order wherever no
                // edge forces otherwise, because it takes the lowest-numbered ready step,
                // so this edge changes no output today. It is here because that guarantee
                // is a property of the tie-break rather than of the graph, and a later
                // change to how the ready set is drained (preferring same-model steps to
                // batch better, say) would silently let a condition float past a write it
                // reads. An edge cannot be optimised away by accident; a tie-break can.
                add_edge(position, other_position, &mut edges, &mut indegree);
            }
        }
    }

    // Kahn's algorithm, taking the lowest-numbered ready step each time so the result is
    // stable and stays close to document order.
    let mut ready: BTreeSet<usize> = (0..count).filter(|i| indegree[*i] == 0).collect();
    let mut ordered = Vec::with_capacity(count);
    let mut taken = vec![false; count];

    while let Some(&next) = ready.iter().next() {
        ready.remove(&next);
        taken[next] = true;
        ordered.push(next);
        let mut targets: Vec<usize> = edges[next].iter().copied().collect();
        targets.sort_unstable();
        for target in targets {
            indegree[target] -= 1;
            if indegree[target] == 0 {
                ready.insert(target);
            }
        }
    }

    if ordered.len() != count {
        let mut models: Vec<String> = steps
            .iter()
            .enumerate()
            .filter(|(i, _)| !taken[*i])
            .filter_map(|(_, step)| step.writes_model().map(str::to_string))
            .collect();
        models.dedup();
        return Err(CycleError { models });
    }

    let mut by_position: Vec<Option<PlannedStep>> = steps.into_iter().map(Some).collect();
    let result = ordered
        .into_iter()
        .map(|position| by_position[position].take().expect("each step taken once"))
        .collect();
    Ok((result, warnings))
}

/// The model a condition reads, when it reads one.
fn condition_model(condition: &Condition) -> Option<&str> {
    match condition {
        Condition::Exists { model, .. } | Condition::NotExists { model, .. } => Some(model),
        Condition::Environment { .. } => None,
    }
}

/// Collapse adjacent writes that share a shape into one statement.
///
/// Adjacency comes from the ordering, so grouping can never reorder across a dependency:
/// it only ever merges neighbours. Three things must match, and the third is the one that
/// is easy to miss: the enclosing guards, because one statement cannot run for some of its
/// rows and not others.
pub fn group(steps: &[PlannedStep]) -> Vec<Batch> {
    let mut batches: Vec<Batch> = Vec::new();

    for step in steps {
        let PlannedStep::Write(write) = step else {
            // A condition or a raw statement ends any run: what follows it may or may not
            // run, or may depend on what it did.
            batches.push(Batch {
                model: String::new(),
                kind: WriteKind::Insert,
                columns: Vec::new(),
                conflict: BTreeSet::new(),
                match_existing: false,
                lookups: IndexMap::new(),
                rows: Vec::new(),
                guards: step.guards().to_vec(),
            });
            continue;
        };

        let columns: Vec<String> = write.data.keys().cloned().collect();
        let extends = batches.last().is_some_and(|last| {
            !last.rows.is_empty()
                && last.model == write.model
                && last.kind == write.kind
                && last.columns == columns
                && last.conflict == write.conflict
                && last.match_existing == write.match_existing
                && last.lookups == write.lookups
                && last.guards == write.guards
        });

        if extends {
            batches
                .last_mut()
                .expect("checked above")
                .rows
                .push(write.clone());
        } else {
            batches.push(Batch {
                model: write.model.clone(),
                kind: write.kind,
                columns,
                conflict: write.conflict.clone(),
                match_existing: write.match_existing,
                lookups: write.lookups.clone(),
                rows: vec![write.clone()],
                guards: write.guards.clone(),
            });
        }
    }

    batches.retain(|batch| !batch.rows.is_empty());
    batches
}

/// Flatten, order and group in one call.
pub fn plan(ir: &SeedIr, ast: &SchemaAst) -> Result<Plan, CycleError> {
    let schema = describe(ast);
    let flattened = flatten(ir, &schema);
    let (ordered, warnings) = order(flattened)?;
    let batches = group(&ordered);
    Ok(Plan {
        steps: ordered,
        batches,
        warnings,
    })
}

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
use std::collections::{BTreeSet, HashMap, HashSet};

/// The kind of statement a write becomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteKind {
    Insert,
    Upsert,
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
pub fn flatten(ir: &SeedIr) -> Vec<PlannedStep> {
    let mut steps = Vec::new();
    let mut sequence = 0usize;
    let mut next_guard = 0usize;
    flatten_operations(
        &ir.operations,
        &mut steps,
        &mut sequence,
        &mut next_guard,
        &[],
        "operations",
    );
    steps
}

fn flatten_operations(
    operations: &[Operation],
    steps: &mut Vec<PlannedStep>,
    sequence: &mut usize,
    next_guard: &mut usize,
    guards: &[usize],
    path: &str,
) {
    for (position, operation) in operations.iter().enumerate() {
        let at = format!("{path}[{position}]");
        flatten_operation(operation, steps, sequence, next_guard, guards, &at);
    }
}

fn flatten_operation(
    operation: &Operation,
    steps: &mut Vec<PlannedStep>,
    sequence: &mut usize,
    next_guard: &mut usize,
    guards: &[usize],
    path: &str,
) {
    match operation {
        Operation::Create { model, id, data } => {
            push_write(
                steps,
                sequence,
                model,
                WriteKind::Insert,
                id.clone(),
                data.clone(),
                BTreeSet::new(),
                guards,
                path,
            );
        }

        Operation::CreateMany { model, rows } => {
            for (position, row) in rows.iter().enumerate() {
                push_write(
                    steps,
                    sequence,
                    model,
                    WriteKind::Insert,
                    None,
                    row.clone(),
                    BTreeSet::new(),
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
            push_write(
                steps,
                sequence,
                model,
                WriteKind::Upsert,
                id.clone(),
                combined,
                where_.keys().cloned().collect(),
                guards,
                path,
            );
        }

        Operation::Sql { text, params } => {
            steps.push(PlannedStep::Sql {
                text: text.clone(),
                params: params.clone(),
                path: path.to_string(),
                sequence: *sequence,
                guards: guards.to_vec(),
            });
            *sequence += 1;
        }

        Operation::Group { if_, operations } => {
            let mut inner_guards = guards.to_vec();
            if let Some(condition) = if_ {
                let guard = *next_guard;
                *next_guard += 1;
                steps.push(PlannedStep::Condition {
                    guard,
                    condition: condition.clone(),
                    path: format!("{path}.if"),
                    sequence: *sequence,
                    guards: guards.to_vec(),
                });
                *sequence += 1;
                inner_guards.push(guard);
            }
            flatten_operations(
                operations,
                steps,
                sequence,
                next_guard,
                &inner_guards,
                &format!("{path}.operations"),
            );
        }
    }
}

/// Push one write, then the rows nested inside it.
///
/// Nested rows are emitted **after** their parent, which is what makes the parent's
/// generated id available to them. The ordering pass may move them further apart but never
/// in front, because the dependency edge says so.
#[allow(clippy::too_many_arguments)]
fn push_write(
    steps: &mut Vec<PlannedStep>,
    sequence: &mut usize,
    model: &str,
    kind: WriteKind,
    op_id: Option<String>,
    data: DataMap,
    conflict: BTreeSet<String>,
    guards: &[usize],
    path: &str,
) {
    let mut own = DataMap::new();
    let mut nested: Vec<(String, Vec<DataMap>)> = Vec::new();

    for (key, value) in data {
        match value {
            Value::NestedCreate { create } => nested.push((key, create)),
            Value::NestedCreateMany { create_many } => nested.push((key, create_many)),
            other => {
                own.insert(key, other);
            }
        }
    }

    steps.push(PlannedStep::Write(PlannedWrite {
        model: model.to_string(),
        kind,
        op_id: op_id.clone(),
        path: path.to_string(),
        data: own,
        conflict,
        guards: guards.to_vec(),
        sequence: *sequence,
    }));
    *sequence += 1;

    for (relation, rows) in nested {
        for (position, row) in rows.into_iter().enumerate() {
            // The nested model is not named in the IR: it is the relation's target, which
            // validation has already resolved. Carried as the relation name here and
            // resolved by the caller against the schema.
            push_write(
                steps,
                sequence,
                &relation,
                WriteKind::Insert,
                None,
                row,
                BTreeSet::new(),
                guards,
                &format!("{path}.{relation}[{position}]"),
            );
        }
    }
}

/// Every `$ref` label a write's data points at.
fn referenced_labels(data: &DataMap) -> HashSet<String> {
    let mut labels = HashSet::new();
    collect_labels(data, &mut labels);
    labels
}

fn collect_labels(data: &DataMap, labels: &mut HashSet<String>) {
    for value in data.values() {
        match value {
            Value::Ref { reference } => {
                if let Some((op_id, _)) = reference.split_once('.') {
                    labels.insert(op_id.to_string());
                }
            }
            Value::Connect { connect } => {
                for inner in connect.values() {
                    if let Value::Ref { reference } = inner {
                        if let Some((op_id, _)) = reference.split_once('.') {
                            labels.insert(op_id.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Order the steps so every dependency is satisfied.
///
/// Three kinds of edge, and the third is the one that is easy to leave out:
///
/// 1. A `$ref` edge: a write using a label must follow the write that defines it.
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
        if let PlannedStep::Write(write) = step {
            for label in referenced_labels(&write.data) {
                if let Some(&source) = defined_at.get(&label) {
                    add_edge(source, position, &mut edges, &mut indegree);
                }
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
                rows: vec![write.clone()],
                guards: write.guards.clone(),
            });
        }
    }

    batches.retain(|batch| !batch.rows.is_empty());
    batches
}

/// Flatten, order and group in one call.
pub fn plan(ir: &SeedIr) -> Result<Plan, CycleError> {
    let flattened = flatten(ir);
    let (ordered, warnings) = order(flattened)?;
    let batches = group(&ordered);
    Ok(Plan {
        steps: ordered,
        batches,
        warnings,
    })
}

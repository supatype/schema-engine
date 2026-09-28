//! The planner: flattening, ordering, and batching.
//!
//! Two of these tests guard against the planner introducing a bug rather than against a
//! bad document. A conditional group that batches with its neighbours, or a sort that
//! floats a group past a write its condition reads, is wrong even though the author's IR
//! is correct, and no test of their seed would find it.

use supatype_engine::seed::plan::{flatten, group, order, plan, PlannedStep, WriteKind};
use supatype_engine::seed::SeedIr;

fn ir(operations: &str) -> SeedIr {
    let document =
        format!(r#"{{"irVersion":1,"schemaFingerprint":"sha256:x","operations":{operations}}}"#);
    serde_json::from_str(&document)
        .unwrap_or_else(|e| panic!("the IR fixture does not parse: {e}\n{document}"))
}

fn write_paths(steps: &[PlannedStep]) -> Vec<String> {
    steps
        .iter()
        .filter_map(|step| match step {
            PlannedStep::Write(w) => Some(w.path.clone()),
            _ => None,
        })
        .collect()
}

fn write_models(steps: &[PlannedStep]) -> Vec<String> {
    steps
        .iter()
        .filter_map(|step| match step {
            PlannedStep::Write(w) => Some(w.model.clone()),
            _ => None,
        })
        .collect()
}

// --- Flattening ---

/// A three-level graph: organiser, its events, their ticket types.
///
/// Nesting is how an author writes a fixture, and one row per level is what the database
/// needs. The parent must come out before its children, because the child's foreign key is
/// the parent's generated id.
#[test]
fn it_lifts_a_three_level_graph_parents_first() {
    let document = ir(r#"[
        {"op":"create","model":"Organiser","id":"northern","data":{
            "name":"Northern",
            "events":{"create":[
                {"title":"Conf","ticket_types":{"createMany":[{"name":"Early"},{"name":"Std"}]}}
            ]}
        }}
    ]"#);

    let steps = flatten(&document);
    let models = write_models(&steps);
    assert_eq!(
        models,
        vec!["Organiser", "events", "ticket_types", "ticket_types"]
    );

    // And the path says where each came from, for an error to name later.
    let paths = write_paths(&steps);
    assert_eq!(paths[0], "operations[0]");
    assert_eq!(paths[1], "operations[0].events[0]");
    assert_eq!(paths[2], "operations[0].events[0].ticket_types[0]");
}

#[test]
fn a_create_many_becomes_one_write_per_row() {
    let document =
        ir(r#"[{"op":"createMany","model":"Venue","rows":[{"name":"A"},{"name":"B"}]}]"#);
    assert_eq!(write_models(&flatten(&document)).len(), 2);
}

// --- Ordering ---

/// A reference is a dependency: the value must exist before it is used.
#[test]
fn it_orders_a_reference_after_its_definition() {
    let document = ir(r#"[
        {"op":"create","model":"Event","data":{"organiser_id":{"$ref":"northern.id"}}},
        {"op":"create","model":"Organiser","id":"northern","data":{"name":"N"}}
    ]"#);

    let (ordered, _) = order(flatten(&document)).expect("orderable");
    let models = write_models(&ordered);
    assert_eq!(
        models,
        vec!["Organiser", "Event"],
        "the definition must be planned before the use, whatever order it was written in"
    );
}

/// A dependency crossing a group boundary still holds.
///
/// This is why a group is not sorted in isolation: the parent is outside it and the child
/// is inside.
#[test]
fn a_dependency_crossing_a_group_boundary_still_orders() {
    let document = ir(r#"[
        {"op":"group","if":{"kind":"notExists","model":"Event"},"operations":[
            {"op":"create","model":"Event","data":{"organiser_id":{"$ref":"northern.id"}}}
        ]},
        {"op":"create","model":"Organiser","id":"northern","data":{"name":"N"}}
    ]"#);

    let (ordered, _) = order(flatten(&document)).expect("orderable");
    let models = write_models(&ordered);
    let organiser = models
        .iter()
        .position(|m| m == "Organiser")
        .expect("present");
    let event = models.iter().position(|m| m == "Event").expect("present");
    assert!(
        organiser < event,
        "the parent outside the group must still precede the child inside it: {models:?}"
    );
}

/// Steps that do not depend on each other keep document order, so a plan does not change
/// shape between runs.
#[test]
fn independent_writes_keep_document_order() {
    let document = ir(r#"[
        {"op":"create","model":"A","data":{"n":1}},
        {"op":"create","model":"B","data":{"n":2}},
        {"op":"create","model":"C","data":{"n":3}}
    ]"#);
    let (ordered, _) = order(flatten(&document)).expect("orderable");
    assert_eq!(write_models(&ordered), vec!["A", "B", "C"]);
}

/// A cycle has no valid order, so it is an error naming the models rather than a hang or a
/// stack overflow.
#[test]
fn it_reports_a_cycle_rather_than_looping() {
    let document = ir(r#"[
        {"op":"create","model":"A","id":"a","data":{"b_id":{"$ref":"b.id"}}},
        {"op":"create","model":"B","id":"b","data":{"a_id":{"$ref":"a.id"}}}
    ]"#);

    let error = order(flatten(&document)).expect_err("a cycle has no order");
    let rendered = error.to_string();
    assert!(rendered.contains("cycle"), "{rendered}");
    assert!(
        rendered.contains('A') && rendered.contains('B'),
        "the error must name the models involved: {rendered}"
    );
}

// --- The condition as a read edge ---

/// The planner must not float a group past a write to the model its condition reads.
///
/// The author's IR is correct here; it is the planner that would be wrong, which is why
/// this is pinned rather than left to a seed-level test.
///
/// Worth knowing what currently provides the guarantee: the sort drains its ready set
/// lowest-index-first, so document order survives wherever no edge forces otherwise, and
/// removing the read edge does **not** make this test fail today. The edge is kept because
/// the guarantee would then rest on the tie-break rather than on the graph, and a later
/// change to how the ready set is drained could remove it silently. The companion test
/// below pins the tie-break for that reason.
#[test]
fn a_condition_is_not_moved_across_a_write_it_reads() {
    let document = ir(r#"[
        {"op":"group","if":{"kind":"notExists","model":"Organiser"},"operations":[
            {"op":"create","model":"Log","data":{"note":"was empty"}}
        ]},
        {"op":"create","model":"Organiser","data":{"name":"N"}}
    ]"#);

    let (ordered, warnings) = order(flatten(&document)).expect("orderable");

    let condition_at = ordered
        .iter()
        .position(|step| matches!(step, PlannedStep::Condition { .. }))
        .expect("the condition is planned");
    let organiser_at = ordered
        .iter()
        .position(|step| matches!(step, PlannedStep::Write(w) if w.model == "Organiser"))
        .expect("the write is planned");

    assert!(
        condition_at < organiser_at,
        "the condition was written first, so it must stay in front of the write it reads"
    );
    assert!(
        warnings.is_empty(),
        "nothing is out of order here, so there is nothing to report: {warnings:?}"
    );
}

/// The ordering is stable, and that is load-bearing.
///
/// `a_condition_is_not_moved_across_a_write_it_reads` currently holds because of this, not
/// because of the read edge. If the ready set is ever drained in another order, this fails
/// first and says why, rather than a condition quietly answering a different question.
#[test]
fn ordering_is_stable_where_no_dependency_forces_otherwise() {
    let document = ir(r#"[
        {"op":"create","model":"Z","data":{"n":1}},
        {"op":"create","model":"Y","data":{"n":2}},
        {"op":"create","model":"X","data":{"n":3}},
        {"op":"create","model":"W","data":{"n":4}}
    ]"#);

    let (ordered, _) = order(flatten(&document)).expect("orderable");
    assert_eq!(
        write_models(&ordered),
        vec!["Z", "Y", "X", "W"],
        "independent steps must come out in the order they were written"
    );
}

/// And when the author's own ordering puts the write first, that is reported.
///
/// Legal, occasionally intended, far more often a mistake.
#[test]
fn a_read_after_write_in_the_authors_order_is_reported() {
    let document = ir(r#"[
        {"op":"create","model":"Organiser","data":{"name":"N"}},
        {"op":"group","if":{"kind":"notExists","model":"Organiser"},"operations":[
            {"op":"create","model":"Log","data":{"note":"was empty"}}
        ]}
    ]"#);

    let (_, warnings) = order(flatten(&document)).expect("orderable");
    assert_eq!(warnings.len(), 1, "one read-after-write: {warnings:?}");
    let reported = warnings[0].to_string();
    assert!(reported.contains("Organiser"), "{reported}");
    assert!(
        reported.contains("operations[0]") && reported.contains("operations[1]"),
        "the report must name both positions: {reported}"
    );
}

// --- Batching ---

#[test]
fn adjacent_writes_of_the_same_shape_become_one_batch() {
    let document = ir(r#"[{"op":"createMany","model":"Venue","rows":[
        {"name":"A","city":"Bristol"},
        {"name":"B","city":"London"}
    ]}]"#);

    let planned = plan(&document).expect("plans");
    assert_eq!(planned.batches.len(), 1);
    assert_eq!(planned.batches[0].rows.len(), 2);
    assert_eq!(planned.batches[0].columns, vec!["name", "city"]);
}

/// A thousand rows must be one statement, not a thousand.
#[test]
fn a_large_create_many_is_still_one_batch() {
    let rows: Vec<String> = (0..1000)
        .map(|n| format!(r#"{{"name":"venue {n}"}}"#))
        .collect();
    let document = ir(&format!(
        r#"[{{"op":"createMany","model":"Venue","rows":[{}]}}]"#,
        rows.join(",")
    ));

    let planned = plan(&document).expect("plans");
    assert_eq!(planned.batches.len(), 1, "one statement, not a thousand");
    assert_eq!(planned.batches[0].rows.len(), 1000);
}

#[test]
fn writes_with_different_columns_do_not_batch_together() {
    let document = ir(r#"[{"op":"createMany","model":"Venue","rows":[
        {"name":"A","city":"Bristol"},
        {"name":"B"}
    ]}]"#);
    assert_eq!(plan(&document).expect("plans").batches.len(), 2);
}

/// The constraint that is easiest to get silently wrong.
///
/// One statement cannot run for some of its rows and not others, so a write inside a
/// conditional group must never share a statement with one outside it. An optimiser that
/// only compared model and columns would merge these and write rows that should have been
/// skipped.
#[test]
fn a_conditional_group_does_not_batch_with_its_neighbours() {
    let document = ir(r#"[
        {"op":"create","model":"Venue","data":{"name":"A"}},
        {"op":"group","if":{"kind":"notExists","model":"Log"},"operations":[
            {"op":"create","model":"Venue","data":{"name":"B"}}
        ]},
        {"op":"create","model":"Venue","data":{"name":"C"}}
    ]"#);

    let planned = plan(&document).expect("plans");
    for batch in &planned.batches {
        let guards: Vec<&Vec<usize>> = batch.rows.iter().map(|row| &row.guards).collect();
        assert!(
            guards.windows(2).all(|pair| pair[0] == pair[1]),
            "a batch mixed guarded and unguarded rows: {guards:?}"
        );
    }

    let guarded: usize = planned
        .batches
        .iter()
        .filter(|b| !b.guards.is_empty())
        .map(|b| b.rows.len())
        .sum();
    assert_eq!(guarded, 1, "exactly one row is inside the group");
}

/// A raw statement ends a run: what follows may depend on what it did.
#[test]
fn a_raw_statement_breaks_a_batch() {
    let document = ir(r#"[
        {"op":"create","model":"Venue","data":{"name":"A"}},
        {"op":"sql","text":"ANALYZE venue","params":[]},
        {"op":"create","model":"Venue","data":{"name":"B"}}
    ]"#);
    assert_eq!(plan(&document).expect("plans").batches.len(), 2);
}

#[test]
fn an_upsert_carries_its_conflict_columns() {
    let document =
        ir(r#"[{"op":"upsert","model":"Organiser","where":{"slug":"n"},"data":{"name":"N"}}]"#);
    let planned = plan(&document).expect("plans");
    assert_eq!(planned.batches[0].kind, WriteKind::Upsert);
    assert!(planned.batches[0].conflict.contains("slug"));
}

/// An upsert and an insert of the same model are different statements.
#[test]
fn an_upsert_does_not_batch_with_an_insert() {
    let document = ir(r#"[
        {"op":"create","model":"Organiser","data":{"name":"A"}},
        {"op":"upsert","model":"Organiser","where":{"name":"B"},"data":{"name":"B"}}
    ]"#);
    assert_eq!(plan(&document).expect("plans").batches.len(), 2);
}

/// Grouping only ever merges neighbours, so it cannot reorder across a dependency.
#[test]
fn grouping_never_reorders() {
    let document = ir(r#"[
        {"op":"create","model":"Organiser","id":"n","data":{"name":"N"}},
        {"op":"create","model":"Event","data":{"organiser_id":{"$ref":"n.id"}}},
        {"op":"create","model":"Organiser","data":{"name":"M"}}
    ]"#);

    let (ordered, _) = order(flatten(&document)).expect("orderable");
    let before: Vec<String> = write_models(&ordered);
    let batched: Vec<String> = group(&ordered)
        .iter()
        .flat_map(|batch| batch.rows.iter().map(|row| row.model.clone()))
        .collect();
    assert_eq!(before, batched, "grouping changed the order of the writes");
}

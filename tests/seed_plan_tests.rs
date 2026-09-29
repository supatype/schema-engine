//! The planner: flattening, ordering, and batching.
//!
//! Two of these tests guard against the planner introducing a bug rather than against a
//! bad document. A conditional group that batches with its neighbours, or a sort that
//! floats a group past a write its condition reads, is wrong even though the author's IR
//! is correct, and no test of their seed would find it.

use supatype_engine::generator::seed_model::describe;
use supatype_engine::parser::ast::SchemaAst;
use supatype_engine::seed::plan::{flatten, group, order, plan, Plan, PlannedStep, WriteKind};
use supatype_engine::seed::{DataMap, SeedIr, Value};

fn ir(operations: &str) -> SeedIr {
    let document =
        format!(r#"{{"irVersion":1,"schemaFingerprint":"sha256:x","operations":{operations}}}"#);
    serde_json::from_str(&document)
        .unwrap_or_else(|e| panic!("the IR fixture does not parse: {e}\n{document}"))
}

/// The models the fixtures name.
///
/// Flattening resolves a nested write against the schema, so the planner needs one: the
/// relation `events` is not a model, and only the schema says it means `Event` and links
/// through `organiser_id`. Only the models that nest carry relations; the rest are an id.
const SCHEMA: &str = r#"{
    "astVersion": 2,
    "models": [
        {
            "name": "Organiser",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true},
                "slug": {"kind": "text", "required": false, "annotations": {"db": {"unique": true}}},
                "name": {"kind": "text", "required": false},
                "events": {"kind": "relation", "cardinality": "hasMany", "target": "Event"}
            },
            "annotations": {"db": {"tableName": "organiser"}}
        },
        {
            "name": "Event",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true},
                "title": {"kind": "text", "required": false},
                "organiser": {
                    "kind": "relation", "cardinality": "belongsTo", "target": "Organiser",
                    "annotations": {"db": {"foreignKey": "organiser_id"}}
                },
                "ticket_types": {"kind": "relation", "cardinality": "hasMany", "target": "TicketType"}
            },
            "annotations": {"db": {"tableName": "event"}}
        },
        {
            "name": "TicketType",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true},
                "name": {"kind": "text", "required": false},
                "event": {
                    "kind": "relation", "cardinality": "belongsTo", "target": "Event",
                    "annotations": {"db": {"foreignKey": "event_id"}}
                }
            },
            "annotations": {"db": {"tableName": "ticket_type"}}
        },
        {"name": "Venue", "fields": {"id": {"kind": "uuid", "required": true, "primaryKey": true}},
         "annotations": {"db": {"tableName": "venue"}}},
        {"name": "Log", "fields": {"id": {"kind": "uuid", "required": true, "primaryKey": true}},
         "annotations": {"db": {"tableName": "log"}}},
        {"name": "A", "fields": {"id": {"kind": "uuid", "required": true, "primaryKey": true}},
         "annotations": {"db": {"tableName": "a"}}},
        {"name": "B", "fields": {"id": {"kind": "uuid", "required": true, "primaryKey": true}},
         "annotations": {"db": {"tableName": "b"}}},
        {"name": "C", "fields": {"id": {"kind": "uuid", "required": true, "primaryKey": true}},
         "annotations": {"db": {"tableName": "c"}}},
        {"name": "W", "fields": {"id": {"kind": "uuid", "required": true, "primaryKey": true}},
         "annotations": {"db": {"tableName": "w"}}},
        {"name": "X", "fields": {"id": {"kind": "uuid", "required": true, "primaryKey": true}},
         "annotations": {"db": {"tableName": "x"}}},
        {"name": "Y", "fields": {"id": {"kind": "uuid", "required": true, "primaryKey": true}},
         "annotations": {"db": {"tableName": "y"}}},
        {"name": "Z", "fields": {"id": {"kind": "uuid", "required": true, "primaryKey": true}},
         "annotations": {"db": {"tableName": "z"}}}
    ]
}"#;

fn schema() -> SchemaAst {
    serde_json::from_str(SCHEMA).expect("the schema fixture parses")
}

fn flat(document: &SeedIr) -> Vec<PlannedStep> {
    flatten(document, &describe(&schema()))
}

fn planned(document: &SeedIr) -> Plan {
    plan(document, &schema()).expect("plans")
}

/// The data of the nth write, for asserting what a lowering produced.
fn write_data(steps: &[PlannedStep], position: usize) -> DataMap {
    steps
        .iter()
        .filter_map(|step| match step {
            PlannedStep::Write(w) => Some(w.data.clone()),
            _ => None,
        })
        .nth(position)
        .unwrap_or_else(|| panic!("no write at {position}"))
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

    let steps = flat(&document);
    let models = write_models(&steps);
    assert_eq!(
        models,
        vec!["Organiser", "Event", "TicketType", "TicketType"],
        "a nested write is a write of the model its relation targets"
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
    assert_eq!(write_models(&flat(&document)).len(), 2);
}

// --- Ordering ---

/// A reference is a dependency: the value must exist before it is used.
#[test]
fn it_orders_a_reference_after_its_definition() {
    let document = ir(r#"[
        {"op":"create","model":"Event","data":{"organiser_id":{"$ref":"northern.id"}}},
        {"op":"create","model":"Organiser","id":"northern","data":{"name":"N"}}
    ]"#);

    let (ordered, _) = order(flat(&document)).expect("orderable");
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

    let (ordered, _) = order(flat(&document)).expect("orderable");
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
    let (ordered, _) = order(flat(&document)).expect("orderable");
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

    let error = order(flat(&document)).expect_err("a cycle has no order");
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

    let (ordered, warnings) = order(flat(&document)).expect("orderable");

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

    let (ordered, _) = order(flat(&document)).expect("orderable");
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

    let (_, warnings) = order(flat(&document)).expect("orderable");
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

    let planned = planned(&document);
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

    let planned = planned(&document);
    assert_eq!(planned.batches.len(), 1, "one statement, not a thousand");
    assert_eq!(planned.batches[0].rows.len(), 1000);
}

#[test]
fn writes_with_different_columns_do_not_batch_together() {
    let document = ir(r#"[{"op":"createMany","model":"Venue","rows":[
        {"name":"A","city":"Bristol"},
        {"name":"B"}
    ]}]"#);
    assert_eq!(planned(&document).batches.len(), 2);
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

    let planned = planned(&document);
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
    assert_eq!(planned(&document).batches.len(), 2);
}

#[test]
fn an_upsert_carries_its_conflict_columns() {
    let document =
        ir(r#"[{"op":"upsert","model":"Organiser","where":{"slug":"n"},"data":{"name":"N"}}]"#);
    let planned = planned(&document);
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
    assert_eq!(planned(&document).batches.len(), 2);
}

/// Grouping only ever merges neighbours, so it cannot reorder across a dependency.
#[test]
fn grouping_never_reorders() {
    let document = ir(r#"[
        {"op":"create","model":"Organiser","id":"n","data":{"name":"N"}},
        {"op":"create","model":"Event","data":{"organiser_id":{"$ref":"n.id"}}},
        {"op":"create","model":"Organiser","data":{"name":"M"}}
    ]"#);

    let (ordered, _) = order(flat(&document)).expect("orderable");
    let before: Vec<String> = write_models(&ordered);
    let batched: Vec<String> = group(&ordered)
        .iter()
        .flat_map(|batch| batch.rows.iter().map(|row| row.model.clone()))
        .collect();
    assert_eq!(before, batched, "grouping changed the order of the writes");
}

// --- Nested writes and `connect` ---

/// A nested write names a relation, and a relation is not a table.
///
/// This used to be planned as a write against a model called `events`, which the executor
/// used as a table name: a nested fixture failed with `relation "events" does not exist`
/// rather than being written.
#[test]
fn a_nested_write_resolves_to_the_model_the_relation_targets() {
    let document = ir(r#"[
        {"op":"create","model":"Organiser","id":"northern","data":{
            "name":"Northern",
            "events":{"create":[{"title":"Conf"}]}
        }}
    ]"#);

    let steps = flat(&document);
    assert_eq!(write_models(&steps), vec!["Organiser", "Event"]);
}

/// And the child has to point at the parent, or the two rows are unrelated.
#[test]
fn a_nested_write_carries_a_reference_to_its_parent() {
    let document = ir(r#"[
        {"op":"create","model":"Organiser","id":"northern","data":{
            "name":"Northern",
            "events":{"create":[{"title":"Conf"}]}
        }}
    ]"#);

    let child = write_data(&flat(&document), 1);
    assert_eq!(
        child.get("organiser_id"),
        Some(&Value::Ref {
            reference: "northern.id".to_string()
        }),
        "the child's foreign key is the parent's id: {child:?}"
    );
}

/// A parent nobody labelled still needs something for its children to point at, and the
/// label the planner invents must not be one an author could have written.
#[test]
fn an_unlabelled_parent_is_given_a_label_its_children_can_use() {
    let document = ir(r#"[
        {"op":"create","model":"Organiser","data":{
            "name":"Northern",
            "events":{"create":[{"title":"Conf"}]}
        }}
    ]"#);

    let steps = flat(&document);
    let parent_label = match &steps[0] {
        PlannedStep::Write(w) => w.op_id.clone().expect("the parent was given a label"),
        other => panic!("expected a write, got {other:?}"),
    };
    assert!(
        parent_label.starts_with("$nested:"),
        "an invented label is marked as one: {parent_label}"
    );
    assert_eq!(
        write_data(&steps, 1).get("organiser_id"),
        Some(&Value::Ref {
            reference: format!("{parent_label}.id")
        })
    );
}

/// An author who wrote the foreign key meant that value. Overwriting it would move the row
/// somewhere they did not ask for, and say nothing.
#[test]
fn a_nested_write_does_not_overwrite_a_foreign_key_the_author_set() {
    let document = ir(r#"[
        {"op":"create","model":"Organiser","id":"northern","data":{
            "name":"Northern",
            "events":{"create":[{"title":"Conf","organiser_id":"11111111-1111-4111-8111-111111111111"}]}
        }}
    ]"#);

    assert_eq!(
        write_data(&flat(&document), 1).get("organiser_id"),
        Some(&Value::Scalar(serde_json::json!(
            "11111111-1111-4111-8111-111111111111"
        )))
    );
}

/// `connect` is a relation field in the document and a foreign-key column in the database.
/// It used to reach the executor unchanged, which wrote a column named after the relation:
/// `column "organiser" of relation "event" does not exist`.
#[test]
fn a_connect_by_id_becomes_the_foreign_key_column() {
    let document = ir(r#"[
        {"op":"create","model":"Event","data":{
            "title":"Conf",
            "organiser":{"connect":{"id":"11111111-1111-4111-8111-111111111111"}}
        }}
    ]"#);

    let steps = flat(&document);
    let data = write_data(&steps, 0);
    assert!(
        data.get("organiser").is_none(),
        "the relation field is not a column: {data:?}"
    );
    assert_eq!(
        data.get("organiser_id"),
        Some(&Value::Scalar(serde_json::json!(
            "11111111-1111-4111-8111-111111111111"
        )))
    );

    match &steps[0] {
        PlannedStep::Write(w) => assert!(
            w.lookups.is_empty(),
            "connecting by the referenced column needs no lookup"
        ),
        other => panic!("expected a write, got {other:?}"),
    }
}

/// Connecting by a natural key names a row whose id only the database knows, so the column
/// carries the key and the plan says where to resolve it.
#[test]
fn a_connect_by_natural_key_carries_a_lookup() {
    let document = ir(r#"[
        {"op":"create","model":"Event","data":{
            "title":"Conf",
            "organiser":{"connect":{"slug":"northern"}}
        }}
    ]"#);

    let steps = flat(&document);
    assert_eq!(
        write_data(&steps, 0).get("organiser_id"),
        Some(&Value::Scalar(serde_json::json!("northern")))
    );

    match &steps[0] {
        PlannedStep::Write(w) => {
            let lookup = w
                .lookups
                .get("organiser_id")
                .expect("the column says where to look");
            assert_eq!(lookup.model, "Organiser");
            assert_eq!(lookup.key_column, "slug");
            assert_eq!(lookup.referenced_column, "id");
        }
        other => panic!("expected a write, got {other:?}"),
    }
}

/// One statement renders one expression per column, so two rows resolving the same column
/// differently cannot share a statement.
#[test]
fn writes_that_resolve_a_column_differently_do_not_batch_together() {
    let document = ir(r#"[
        {"op":"create","model":"Event","data":{
            "title":"A","organiser":{"connect":{"slug":"northern"}}
        }},
        {"op":"create","model":"Event","data":{
            "title":"B","organiser":{"connect":{"id":"11111111-1111-4111-8111-111111111111"}}
        }}
    ]"#);

    assert_eq!(
        planned(&document).batches.len(),
        2,
        "a looked-up column and a direct one are different statements"
    );
}

/// And two rows resolving it the same way still do.
#[test]
fn writes_that_resolve_a_column_the_same_way_still_batch() {
    let document = ir(r#"[
        {"op":"create","model":"Event","data":{
            "title":"A","organiser":{"connect":{"slug":"northern"}}
        }},
        {"op":"create","model":"Event","data":{
            "title":"B","organiser":{"connect":{"slug":"southern"}}
        }}
    ]"#);

    assert_eq!(planned(&document).batches.len(), 1);
}

/// An upsert keyed on a foreign key names that column twice: once in `where`, as the id, and
/// once in `data`, as a `connect` by another key. The planner merges `where` into the row, so
/// one value replaces the other, and the lookup that came with the replaced one has to go too.
///
/// It did not. The executor was left resolving "the row whose slug equals this uuid", found
/// none, and wrote NULL into a column that refuses it: the seed failed with
/// `TicketType.event_id is required and was not supplied`, naming a column the author had
/// supplied twice.
#[test]
fn a_replaced_column_does_not_keep_the_lookup_it_arrived_with() {
    let document = ir(r#"[
        {"op":"upsert","model":"Event",
         "where":{"organiser_id":"11111111-1111-4111-8111-111111111111","title":"Conf"},
         "data":{"organiser":{"connect":{"slug":"northern"}}}}
    ]"#);

    let steps = flat(&document);
    match &steps[0] {
        PlannedStep::Write(w) => {
            assert_eq!(
                w.data.get("organiser_id"),
                Some(&Value::Scalar(serde_json::json!(
                    "11111111-1111-4111-8111-111111111111"
                ))),
                "the id in `where` is the value that survives"
            );
            assert!(
                w.lookups.is_empty(),
                "and the connect's lookup went with the value it replaced: {:?}",
                w.lookups
            );
        }
        other => panic!("expected a write, got {other:?}"),
    }
}

/// The other order, so the rule is "whatever the column ends up holding decides", not "drop
/// every lookup".
#[test]
fn a_connect_that_wins_keeps_its_lookup() {
    let document = ir(r#"[
        {"op":"create","model":"Event","data":{
            "title":"Conf","organiser":{"connect":{"slug":"northern"}}
        }}
    ]"#);

    match &flat(&document)[0] {
        PlannedStep::Write(w) => {
            assert!(w.lookups.contains_key("organiser_id"), "{:?}", w.lookups)
        }
        other => panic!("expected a write, got {other:?}"),
    }
}

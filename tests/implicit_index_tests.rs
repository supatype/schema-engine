//! Indexes the generator creates on its own, and the differ must therefore expect.
//!
//! `expected_index_names` walked only the indexes a schema *declares*, while the generator also
//! creates three kinds nobody declares: a btree for an `Indexed` field, a btree on `deleted_at`
//! for a soft-deleting model, and a GIN for an indexed `Blocks` column. Each is written with a
//! managed comment, so the differ saw a managed index it could not account for and proposed
//! dropping it. Every push then dropped it and the next push proposed dropping it again.
//!
//! Found by the field conformance harness, on the assertion that a second push is a no-op. It had
//! never run before: `dev --no-watch` tore the stack down ahead of the first API call.

use supatype_engine::differ::{self, Operation};
use supatype_engine::introspector::indexes::DbIndex;
use supatype_engine::introspector::tables::{DbColumn, DbTable};
use supatype_engine::parser;
use supatype_engine::state::database_state::DatabaseState;

fn col(name: &str, data_type: &str) -> DbColumn {
    DbColumn {
        name: name.into(),
        data_type: data_type.into(),
        udt_name: data_type.into(),
        nullable: true,
        default: None,
        ordinal_position: 1,
        ..Default::default()
    }
}

fn schema() -> &'static str {
    r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "probe",
      "annotations": { "db": { "tableName": "probe" } },
      "fields": {
        "id": { "kind": "uuid", "required": true },
        "probeBlocks": { "kind": "blocks", "required": false, "index": true, "blocks": [] }
      }
    }
  ]
}"#
}

fn live_db(indexes: Vec<DbIndex>) -> DatabaseState {
    DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "probe".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("probeBlocks", "jsonb")],
        }],
        indexes,
        ..Default::default()
    }
}

fn managed_gin() -> DbIndex {
    DbIndex {
        table: "probe".into(),
        name: "probe_probeBlocks_gin_idx".into(),
        columns: vec!["probeBlocks".into()],
        unique: false,
        method: "gin".into(),
        is_primary: false,
        comment: Some("supatype:managed;kind=index".into()),
    }
}

#[test]
fn the_gin_index_a_blocks_field_creates_is_not_proposed_for_dropping() {
    let ast = parser::parse(schema()).expect("schema parses");
    let ops = differ::diff(&ast, &live_db(vec![managed_gin()])).expect("diff runs").operations;

    let drops: Vec<&Operation> = ops
        .iter()
        .filter(|op| matches!(op, Operation::DropIndex { .. }))
        .collect();

    assert!(
        drops.is_empty(),
        "a second push must propose nothing, got {drops:?}"
    );
}

#[test]
fn a_managed_index_nothing_declares_is_still_dropped() {
    // The control. Making the differ expect everything would silence the assertion above and
    // leave orphaned indexes behind forever.
    let orphan = DbIndex {
        table: "probe".into(),
        name: "probe_gone_idx".into(),
        columns: vec!["gone".into()],
        unique: false,
        method: "btree".into(),
        is_primary: false,
        comment: Some("supatype:managed;kind=index".into()),
    };
    let ast = parser::parse(schema()).expect("schema parses");
    let ops = differ::diff(&ast, &live_db(vec![managed_gin(), orphan])).expect("diff runs").operations;

    let dropped: Vec<String> = ops
        .iter()
        .filter_map(|op| match op {
            Operation::DropIndex { index_name, .. } => Some(index_name.clone()),
            _ => None,
        })
        .collect();

    assert_eq!(dropped, vec!["probe_gone_idx".to_string()]);
}

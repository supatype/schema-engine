//! The foreign keys between tables, and the junction tables a many-to-many creates, as the
//! generated TypeScript describes them.
//!
//! `@supatype/client` reads `Relationships` to type an embedded select:
//! `select("*, author:authors(*)")` is resolved by finding the key between the two tables and which
//! side holds it. Every table used to say `Relationships: []`, so the client could only type the
//! base row and every project that embedded a relation declared the joined shape by hand. The
//! junction tables were missing altogether, although PostgREST serves them like any other table
//! and an embed such as `tags:post_tags(tag:tags(*))` goes through one.
//!
//! The columns are the ones the SQL generator creates: a `belongsTo` puts its key on its own table
//! referencing the target's `references` column (`id` by default), and a junction holds one key
//! per side referencing that side's primary key.

use super::types::{emit_one, ts_type_of, Mode};
use crate::parser::ast::{
    FieldAst, JunctionTableAst, ModelAst, RelationCardinality, RelationFieldAst, SchemaAst,
};
use crate::parser::resolver::to_snake_case;

/// One foreign key, described on the table that holds it.
pub(crate) struct Relationship {
    column: String,
    one_to_one: bool,
    referenced_table: String,
    referenced_column: String,
}

/// The table a relation's target (a model name) lives in.
fn table_of(ast: &SchemaAst, model_name: &str) -> String {
    ast.models
        .iter()
        .find(|m| m.name == model_name)
        .map(|m| m.table_name().to_string())
        .unwrap_or_else(|| to_snake_case(model_name))
}

/// The column a `belongsTo` field occupies on its own table.
pub(crate) fn foreign_key_column(name: &str, rel: &RelationFieldAst) -> String {
    rel.foreign_key
        .clone()
        .unwrap_or_else(|| format!("{}_id", to_snake_case(name)))
}

/// Every foreign key `model` holds, one per `belongsTo` field, in declaration order.
pub(crate) fn of_model(ast: &SchemaAst, model: &ModelAst) -> Vec<Relationship> {
    model
        .fields
        .iter()
        .filter_map(|(name, field)| match field {
            FieldAst::Relation(rel)
                if matches!(rel.cardinality, RelationCardinality::BelongsTo) =>
            {
                Some(Relationship {
                    column: foreign_key_column(name, rel),
                    one_to_one: rel.unique_fk,
                    referenced_table: table_of(ast, &rel.target),
                    referenced_column: rel.references.clone().unwrap_or_else(|| "id".into()),
                })
            }
            _ => None,
        })
        .collect()
}

/// The primary key column of the model named `name`, and the TypeScript type of a key to it.
fn primary_key_of(ast: &SchemaAst, name: &str) -> (String, String) {
    ast.models
        .iter()
        .find(|m| m.name == name)
        .and_then(|m| {
            m.fields
                .iter()
                .find(|(_, f)| crate::parser::accessors::is_primary_key(f))
        })
        .map(|(column, field)| (column.clone(), ts_type_of(field).0))
        .unwrap_or_else(|| ("id".into(), "string".into()))
}

/// A junction's two key columns, as `(column, ts type, referenced table, referenced column)`.
fn junction_sides(ast: &SchemaAst, j: &JunctionTableAst) -> [(String, String, String, String); 2] {
    [(&j.fk_a, &j.model_a), (&j.fk_b, &j.model_b)].map(|(column, model)| {
        let (pk_column, pk_ts) = primary_key_of(ast, model);
        (column.clone(), pk_ts, table_of(ast, model), pk_column)
    })
}

/// One junction table's entry: its two keys as Row, Insert and Update, and the keys' targets.
pub(crate) fn emit_junction(ast: &SchemaAst, j: &JunctionTableAst, out: &mut String, ind: &str) {
    let sides = junction_sides(ast, j);
    out.push_str(&format!("{ind}{}: {{\n", quote_key(&j.name)));
    let body = format!("{ind}  ");
    let fields = format!("{ind}    ");
    for (label, mode) in [
        ("Row", Mode::Row),
        ("Insert", Mode::Insert),
        ("Update", Mode::Update),
    ] {
        out.push_str(&format!("{body}{label}: {{\n"));
        for (column, ts, _, _) in &sides {
            emit_one(column, ts, false, false, mode, out, &fields);
        }
        out.push_str(&format!("{body}}}\n"));
    }
    let relationships: Vec<Relationship> = sides
        .into_iter()
        .map(
            |(column, _, referenced_table, referenced_column)| Relationship {
                column,
                one_to_one: false,
                referenced_table,
                referenced_column,
            },
        )
        .collect();
    emit(&relationships, out, &body);
    out.push_str(&format!("{ind}}}\n"));
}

/// `Relationships: [...]` at indent `ind`, as a tuple type the client can index.
pub(crate) fn emit(relationships: &[Relationship], out: &mut String, ind: &str) {
    if relationships.is_empty() {
        out.push_str(&format!("{ind}Relationships: []\n"));
        return;
    }
    out.push_str(&format!("{ind}Relationships: [\n"));
    for r in relationships {
        out.push_str(&format!("{ind}  {{\n"));
        out.push_str(&format!("{ind}    columns: [{}]\n", quote(&r.column)));
        out.push_str(&format!("{ind}    isOneToOne: {}\n", r.one_to_one));
        out.push_str(&format!(
            "{ind}    referencedRelation: {}\n",
            quote(&r.referenced_table)
        ));
        out.push_str(&format!(
            "{ind}    referencedColumns: [{}]\n",
            quote(&r.referenced_column)
        ));
        out.push_str(&format!("{ind}  }},\n"));
    }
    out.push_str(&format!("{ind}]\n"));
}

fn quote(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| format!("\"{value}\""))
}

/// An object key, quoted only where it has to be.
pub(crate) fn quote_key(key: &str) -> String {
    let valid = key
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$');
    if valid {
        key.to_string()
    } else {
        quote(key)
    }
}

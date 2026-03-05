use anyhow::Result;
use strsim::jaro_winkler;
use crate::parser::ast::{FieldAst, IndexAst, IndexMethod, ModelAst, RelationCardinality};
use crate::introspector::tables::DbTable;
use super::{Operation, Risk};

const RENAME_THRESHOLD: f64 = 0.7;

/// Returns the effective column name(s) produced by a field.
/// Relations produce a FK column name; composites produce multiple.
fn column_names_for(field_name: &str, field: &FieldAst) -> Vec<String> {
    match field {
        FieldAst::Relation(rel) => match rel.cardinality {
            RelationCardinality::BelongsTo => {
                vec![rel.foreign_key.clone().unwrap_or_else(|| format!("{field_name}_id"))]
            }
            _ => vec![],
        },
        FieldAst::Timestamps => vec!["created_at".into(), "updated_at".into()],
        FieldAst::Publishable => vec!["status".into(), "published_at".into(), "scheduled_at".into()],
        FieldAst::SoftDelete => vec!["deleted_at".into()],
        _ => vec![field_name.to_string()],
    }
}

/// Returns true if the field has `index: true` set.
fn has_index_flag(field: &FieldAst) -> bool {
    match field {
        FieldAst::Text(f) | FieldAst::Email(f) | FieldAst::Uuid(f)
        | FieldAst::Integer(f) | FieldAst::Float(f) | FieldAst::Boolean(f)
        | FieldAst::Datetime(f) | FieldAst::BigInt(f) | FieldAst::Bytes(f)
        | FieldAst::SmallInt(f) | FieldAst::Date(f) | FieldAst::Timestamp(f)
        | FieldAst::Serial(f) | FieldAst::BigSerial(f) | FieldAst::Money(f)
        | FieldAst::Url(f) | FieldAst::Ip(f) | FieldAst::Cidr(f)
        | FieldAst::Macaddr(f) | FieldAst::Interval(f) | FieldAst::TsQuery(f)
        | FieldAst::TsVector(f) | FieldAst::Xml(f) | FieldAst::RichText(f) => f.index,
        _ => false,
    }
}

pub fn diff(
    model: &ModelAst,
    db_table: &DbTable,
    ops: &mut Vec<Operation>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let db_col_names: std::collections::HashSet<String> =
        db_table.columns.iter().map(|c| c.name.clone()).collect();

    // Expand schema fields to the actual DB columns they produce
    let schema_columns: std::collections::HashMap<String, (&str, &FieldAst)> = model
        .fields
        .iter()
        .flat_map(|(name, field)| {
            column_names_for(name, field)
                .into_iter()
                .map(move |col| (col, (name.as_str(), field)))
        })
        .collect();

    // Columns added by model options (not explicit fields) must not be treated as dropped.
    let mut options_cols: std::collections::HashSet<String> = std::collections::HashSet::new();
    if model.options.timestamps && !model.fields.contains_key("timestamps") {
        options_cols.insert("created_at".into());
        options_cols.insert("updated_at".into());
    }
    if model.options.soft_delete && !model.fields.contains_key("softDelete") {
        options_cols.insert("deleted_at".into());
    }

    let schema_col_names: std::collections::HashSet<&str> =
        schema_columns.keys().map(|s| s.as_str()).collect();

    let added: Vec<&str> = schema_columns
        .keys()
        .filter(|n| !db_col_names.contains(*n))
        .map(|s| s.as_str())
        .collect();

    let dropped: Vec<&str> = db_table
        .columns
        .iter()
        .filter(|c| !schema_col_names.contains(c.name.as_str()) && !options_cols.contains(&c.name))
        .map(|c| c.name.as_str())
        .collect();

    // Rename detection
    let mut renamed_dropped = std::collections::HashSet::new();
    let mut renamed_added = std::collections::HashSet::new();

    for &drop in &dropped {
        if let Some(&add) = added
            .iter()
            .filter(|&&a| !renamed_added.contains(a))
            .max_by(|&&a, &&b| {
                jaro_winkler(drop, a)
                    .partial_cmp(&jaro_winkler(drop, b))
                    .unwrap()
            })
        {
            if jaro_winkler(drop, add) >= RENAME_THRESHOLD {
                ops.push(Operation::RenameColumn {
                    table: model.table_name.clone(),
                    from: drop.to_string(),
                    to: add.to_string(),
                    risk: Risk::Safe,
                });
                warnings.push(format!(
                    "Column '{drop}' removed and '{add}' added on table '{}'. Treating as rename. \
                     Specify in platform.renames.json to suppress this warning.",
                    model.table_name
                ));
                renamed_dropped.insert(drop);
                renamed_added.insert(add);
            }
        }
    }

    for col in &added {
        if !renamed_added.contains(*col) {
            if let Some((_, field)) = schema_columns.get(*col) {
                ops.push(Operation::AddColumn {
                    table: model.table_name.clone(),
                    column: col.to_string(),
                    field: Box::new((*field).clone()),
                    risk: Risk::Safe,
                });

                // If the field has `index: true` and it's a new column, also emit AddIndex.
                if has_index_flag(field) {
                    ops.push(Operation::AddIndex {
                        table: model.table_name.clone(),
                        index: Box::new(IndexAst {
                            name: None,
                            fields: vec![col.to_string()],
                            unique: false,
                            using: IndexMethod::Btree,
                        }),
                        risk: Risk::Safe,
                    });
                }
            }
        }
    }

    for col in &dropped {
        if !renamed_dropped.contains(*col) {
            ops.push(Operation::DropColumn {
                table: model.table_name.clone(),
                column: col.to_string(),
                risk: Risk::Destructive,
            });
        }
    }

    Ok(())
}

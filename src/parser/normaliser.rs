use super::accessors::db_table_name_mut;
use super::annotations::FieldAnnotations;
use super::ast::{DefaultValueAst, FieldAst, ScalarFieldAst, SchemaAst};
use super::resolver::to_snake_case;
#[allow(unused_imports)]
use indexmap::IndexMap;

/// Apply naming conventions and fill in defaults.
pub fn normalise(mut ast: SchemaAst) -> SchemaAst {
    for model in &mut ast.models {
        let model_name = model.name.clone();
        let table_name = db_table_name_mut(model);
        if table_name.is_empty() {
            *table_name = to_snake_case(&model_name);
        }

        let has_explicit_pk = model.fields.values().any(|f| match f {
            FieldAst::Text(s)
            | FieldAst::Uuid(s)
            | FieldAst::Integer(s)
            | FieldAst::BigInt(s)
            | FieldAst::Serial(s)
            | FieldAst::BigSerial(s) => s.primary_key,
            _ => false,
        });

        if !has_explicit_pk && !model.fields.contains_key("id") {
            model.fields.insert(
                "id".to_string(),
                FieldAst::Uuid(ScalarFieldAst {
                    pg_type: "UUID".to_string(),
                    required: true,
                    unique: false,
                    primary_key: true,
                    index: false,
                    default: Some(DefaultValueAst::GenRandomUuid),
                    check: None,
                    validation: None,
                    localized: false,
                    read_only: false,
                    sources: vec![],
                    template: None,
                    identity: None,
                    generated: None,
                    annotations: FieldAnnotations {
                        db: super::annotations::DbFieldAnnotations {
                            pg_type: "UUID".to_string(),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                }),
            );
        }
    }
    ast
}

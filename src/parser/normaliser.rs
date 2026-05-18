use super::ast::{DefaultValueAst, FieldAst, ScalarFieldAst, SchemaAst};
use super::resolver::to_snake_case;
#[allow(unused_imports)]
use indexmap::IndexMap;

/// Apply naming conventions and fill in defaults.
pub fn normalise(mut ast: SchemaAst) -> SchemaAst {
    for model in &mut ast.models {
        // Ensure table_name follows snake_case convention
        if model.table_name.is_empty() {
            model.table_name = to_snake_case(&model.name);
        }

        // Inject a synthetic `id UUID PRIMARY KEY DEFAULT gen_random_uuid()` as the
        // first field whenever the model doesn't declare its own primary key.
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
                    localized: false,
                    read_only: false,
                    sources: vec![],
                    template: None,
                }),
            );
        }
    }
    ast
}

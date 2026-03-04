use anyhow::Result;
use crate::parser::ast::{FieldAst, SchemaAst};

pub fn generate(ast: &SchemaAst) -> Result<String> {
    let mut out = String::new();

    // updated_at trigger function (shared, created once)
    out.push_str(UPDATED_AT_FUNCTION);

    for model in &ast.models {
        let needs_updated_at = model.options.timestamps
            || model.fields.contains_key("updatedAt")
            || model.fields.contains_key("updated_at");

        if needs_updated_at {
            out.push_str(&updated_at_trigger(&model.table_name));
        }

        for (field_name, field) in &model.fields {
            if let FieldAst::Slug(slug) = field {
                out.push_str(&slug_trigger(&model.table_name, field_name, &slug.from));
            }
        }
    }

    Ok(out)
}

const UPDATED_AT_FUNCTION: &str = r#"
CREATE OR REPLACE FUNCTION _platform.set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

"#;

fn updated_at_trigger(table: &str) -> String {
    format!(
        "CREATE TRIGGER \"{table}_updated_at_trigger\"\n\
         BEFORE UPDATE ON \"public\".\"{table}\"\n\
         FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();\n\n"
    )
}

fn slug_trigger(table: &str, slug_field: &str, source_field: &str) -> String {
    format!(
        "-- Slug trigger for {table}.{slug_field} from {source_field}\n\
         -- TODO: Phase 1 — full slug generation trigger\n\n"
    )
}

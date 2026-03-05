use anyhow::Result;
use crate::parser::ast::{FieldAst, SchemaAst};

pub fn generate(ast: &SchemaAst) -> Result<String> {
    let mut out = String::new();

    // updated_at trigger function (shared, created once per schema push)
    out.push_str(UPDATED_AT_FUNCTION);
    // slugify helper function (shared, created once)
    out.push_str(SLUGIFY_FUNCTION);

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

/// A portable slugify function that handles Unicode via unaccent + regexp_replace.
const SLUGIFY_FUNCTION: &str = r#"
CREATE EXTENSION IF NOT EXISTS "unaccent";

CREATE OR REPLACE FUNCTION _platform.slugify(val TEXT)
RETURNS TEXT AS $$
BEGIN
  RETURN lower(
    regexp_replace(
      regexp_replace(
        unaccent(trim(val)),
        '[^a-zA-Z0-9\s-]', '', 'g'
      ),
      '[\s-]+', '-', 'g'
    )
  );
END;
$$ LANGUAGE plpgsql IMMUTABLE;

"#;

fn updated_at_trigger(table: &str) -> String {
    format!(
        "CREATE OR REPLACE TRIGGER \"{table}_updated_at_trigger\"\n\
         BEFORE UPDATE ON \"public\".\"{table}\"\n\
         FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();\n\n"
    )
}

fn slug_trigger(table: &str, slug_field: &str, source_field: &str) -> String {
    let fn_name = format!("_platform.set_{table}_{slug_field}");
    format!(
        r#"CREATE OR REPLACE FUNCTION {fn_name}()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' OR NEW."{source_field}" IS DISTINCT FROM OLD."{source_field}" THEN
    NEW."{slug_field}" = _platform.slugify(NEW."{source_field}"::TEXT);
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER "{table}_{slug_field}_trigger"
BEFORE INSERT OR UPDATE ON "public"."{table}"
FOR EACH ROW EXECUTE FUNCTION {fn_name}();

"#
    )
}

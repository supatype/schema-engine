use crate::parser::ast::{FieldAst, SchemaAst};
use anyhow::Result;

/// `schema` is the schema Supatype manages. The trigger targets used to be a literal
/// `"public"."{table}"`, so a project pointed at its own schema attached its `updated_at` and slug
/// triggers to whatever sat in `public` under the same name — someone else's table, on a database
/// Supatype did not create.
pub fn generate(ast: &SchemaAst, schema: &str) -> Result<String> {
    let mut out = String::new();

    // Trigger functions live in the _platform schema — ensure it exists and is
    // usable by the app roles, since BEFORE INSERT/UPDATE triggers execute these
    // functions as the invoking role (e.g. `authenticated`).
    out.push_str("CREATE SCHEMA IF NOT EXISTS _platform;\n");
    out.push_str("GRANT USAGE ON SCHEMA _platform TO PUBLIC;\n\n");
    // updated_at trigger function (shared, created once per schema push)
    out.push_str(UPDATED_AT_FUNCTION);
    // slugify helper function (shared, created once)
    out.push_str(SLUGIFY_FUNCTION);

    for model in &ast.models {
        let needs_updated_at = model.options.timestamps
            || model.fields.contains_key("updatedAt")
            || model.fields.contains_key("updated_at");

        if needs_updated_at {
            out.push_str(&updated_at_trigger(schema, model.table_name()));
        }

        for (field_name, field) in &model.fields {
            if let FieldAst::Slug(slug) = field {
                out.push_str(&slug_trigger(
                    schema,
                    model.table_name(),
                    field_name,
                    &slug.from,
                ));
            }
        }

        // Carries the localized flag, not just the name: a localized column holds one document
        // per locale, and normalising the map as though it were the document loses every locale.
        let rich_text: Vec<(&str, bool)> = model
            .fields
            .iter()
            .filter(|(_, field)| matches!(field, FieldAst::RichText(_)))
            .map(|(name, field)| (name.as_str(), super::column_conversion::is_localised(field)))
            .collect();
        if !rich_text.is_empty() {
            out.push_str(&rich_text_trigger(schema, model.table_name(), &rich_text));
        }
    }

    // Trigger functions must be executable by whichever role performs the
    // insert/update that fires them.
    out.push_str("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA _platform TO PUBLIC;\n");

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

fn updated_at_trigger(schema: &str, table: &str) -> String {
    format!(
        "CREATE OR REPLACE TRIGGER \"{table}_updated_at_trigger\"\n\
         BEFORE UPDATE ON \"{schema}\".\"{table}\"\n\
         FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();\n\n"
    )
}

/// Generate a LISTEN/NOTIFY trigger function and trigger for realtime subscriptions.
///
/// The Postgres function fires after any INSERT, UPDATE, or DELETE on `table_name`
/// and sends a JSON payload on the `supatype_{table_name}` channel via pg_notify.
/// The payload is `{"table": "...", "event": "INSERT|UPDATE|DELETE", "id": <row id>}`.
///
/// This is called for every table unconditionally (all tables are subscription-enabled
/// until a per-model subscription flag is added to the AST).
pub fn generate_realtime_triggers(schema: &str, table_name: &str) -> String {
    format!(
        r#"CREATE OR REPLACE FUNCTION _platform.notify_{table_name}_changes() RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify('supatype_{table_name}',
    json_build_object('table', '{table_name}', 'event', TG_OP, 'id',
      CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END)::text);
  RETURN NEW;
END; $$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER {table_name}_changes_trigger
AFTER INSERT OR UPDATE OR DELETE ON "{schema}"."{table_name}"
FOR EACH ROW EXECUTE FUNCTION _platform.notify_{table_name}_changes();

"#
    )
}

/// Generate DROP statements to remove the realtime trigger and function for `table_name`.
///
/// Drops the pre-schema-isolation name too: the create was unqualified, so it landed in whatever
/// `public` the connection's search path resolved to, and a qualified drop alone would leave it.
pub fn generate_realtime_trigger_drop(schema: &str, table_name: &str) -> String {
    format!(
        "DROP TRIGGER IF EXISTS {table_name}_changes_trigger ON \"{schema}\".\"{table_name}\";\n\
         DROP FUNCTION IF EXISTS _platform.notify_{table_name}_changes();\n\
         DROP FUNCTION IF EXISTS public.notify_{table_name}_changes();\n\n"
    )
}

/// Keep a rich text column holding a Lexical document, whoever writes to it.
///
/// The column is JSONB with no check constraint, so `'"hello"'::jsonb` is accepted, while
/// `types/database.ts` types the column as a document and has never said otherwise. That made
/// the type a claim the database did not keep: a seed, a hook or a person with psql could put a
/// bare string in one, and the next read returned something the generated types say is
/// impossible.
///
/// **A trigger rather than the writers.** Wrapping in the seed executor fixes seeds and wrapping
/// in the API fixes API writes; neither makes the *read* type true, which is the thing being
/// claimed. This is the only place that holds for every writer.
///
/// The expression is `jsonb_to_lexical_migrate_expr`, the same one the migration uses when a
/// text column becomes a rich text one. It already returns NULL unchanged and a document
/// unchanged, and wraps a string, an array or any other JSON value, so there is no guard here
/// and no second implementation of the wrapping to drift from the first.
///
/// One trigger per table rather than one per column, so a model with five rich text fields
/// fires one function instead of five.
fn rich_text_trigger(schema: &str, table: &str, fields: &[(&str, bool)]) -> String {
    let fn_name = format!("_platform.normalise_{table}_rich_text");
    let assignments: String = fields
        .iter()
        .map(|(field, localised)| {
            format!(
                "  NEW.\"{field}\" := {expr};\n",
                field = field,
                expr = super::column_conversion::lexical_normalise_expr(
                    &format!("NEW.\"{field}\""),
                    *localised
                ),
            )
        })
        .collect();

    format!(
        r#"CREATE OR REPLACE FUNCTION {fn_name}()
RETURNS TRIGGER AS $$
BEGIN
{assignments}  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER "{table}_rich_text_trigger"
BEFORE INSERT OR UPDATE ON "{schema}"."{table}"
FOR EACH ROW EXECUTE FUNCTION {fn_name}();

"#
    )
}

fn slug_trigger(schema: &str, table: &str, slug_field: &str, source_field: &str) -> String {
    let fn_name = format!("_platform.set_{table}_{slug_field}");
    format!(
        r#"CREATE OR REPLACE FUNCTION {fn_name}()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW."{slug_field}" IS NULL OR BTRIM(NEW."{slug_field}"::TEXT) = '' THEN
      NEW."{slug_field}" = _platform.slugify(NEW."{source_field}"::TEXT);
    END IF;
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW."{source_field}" IS DISTINCT FROM OLD."{source_field}" THEN
      IF OLD."{slug_field}" IS NOT DISTINCT FROM _platform.slugify(OLD."{source_field}"::TEXT) THEN
        NEW."{slug_field}" = _platform.slugify(NEW."{source_field}"::TEXT);
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER "{table}_{slug_field}_trigger"
BEFORE INSERT OR UPDATE ON "{schema}"."{table}"
FOR EACH ROW EXECUTE FUNCTION {fn_name}();

"#
    )
}

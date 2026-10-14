//! The trigger layer: the `_platform` functions and the triggers on model tables that keep
//! `updated_at`, slugs and rich text documents right, whoever writes the row.
//!
//! Rendered per object since Phase 4.2, because each function and trigger is a ledger object the
//! reconcile creates, replaces and drops on its own: [`shared_functions`], [`model_functions`] and
//! [`model_triggers`] are what the desired set builds from. [`generate`] joins the same pieces
//! into the whole layer, for the `triggers` command and the tests that read it as one script.
//!
//! `schema` is the schema Supatype manages. The trigger targets used to be a literal
//! `"public"."{table}"`, so a project pointed at its own schema attached its `updated_at` and slug
//! triggers to whatever sat in `public` under the same name: someone else's table, on a database
//! Supatype did not create.

use crate::desired::identity::{function_key, quote_if_needed};
use crate::managed::ObjectNames;
use crate::parser::ast::{FieldAst, ModelAst, SchemaAst};
use crate::sql_quote::{quote_ident, quote_qualified};
use anyhow::Result;

/// The schema the trigger functions live in.
pub const PLATFORM_SCHEMA: &str = "_platform";

/// The schema itself and what every role needs on it: `BEFORE INSERT`/`UPDATE` triggers run their
/// function as the invoking role (`authenticated`, say), which must be able to reach the schema
/// and execute what it finds there. `EXECUTE` is `PUBLIC`'s by default on a new function; the
/// default-privileges line keeps that so on a database whose defaults were changed, and the grant
/// on all functions covers the ones already there.
pub fn platform_schema_sql() -> String {
    format!(
        "CREATE SCHEMA IF NOT EXISTS {PLATFORM_SCHEMA};\n\
         GRANT USAGE ON SCHEMA {PLATFORM_SCHEMA} TO PUBLIC;\n\
         ALTER DEFAULT PRIVILEGES IN SCHEMA {PLATFORM_SCHEMA} GRANT EXECUTE ON FUNCTIONS TO PUBLIC;\n\
         GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {PLATFORM_SCHEMA} TO PUBLIC;\n"
    )
}

/// One `_platform` function, held as the parts the catalog reports (`DbFunction`) so the desired
/// set predicts a live function's structure exactly, and rendered from them.
#[derive(Debug, Clone)]
pub struct TriggerFunction {
    pub name: String,
    /// The declared argument list, as written in the `CREATE`.
    pub args: &'static str,
    /// The return type as `pg_get_function_result` spells it.
    pub returns: &'static str,
    /// `pg_proc.provolatile`: `i`, `s` or `v`.
    pub volatility: char,
    /// The body between the dollar quotes, verbatim.
    pub body: String,
    /// The path the body runs under, for one that calls an extension's function: resolved when
    /// it runs, so the writer's own path would otherwise decide whether it is found.
    pub search_path: Option<&'static str>,
}

impl TriggerFunction {
    /// `name(types)`, the ledger's name for a function (`crate::desired::identity`).
    pub fn key_name(&self) -> String {
        function_key(&self.name, self.args)
    }

    /// `_platform.name`, as a trigger's `EXECUTE FUNCTION` names it and the catalog reports it:
    /// quoted only when Postgres would quote it, so a name made from a table holding a quote is
    /// still one identifier.
    pub fn qualified(&self) -> String {
        qualified_function(&self.name)
    }

    pub fn create_sql(&self) -> String {
        let volatility = match self.volatility {
            'i' => " IMMUTABLE",
            's' => " STABLE",
            _ => "",
        };
        let path = self
            .search_path
            .map(|p| format!(" SET search_path = {p}"))
            .unwrap_or_default();
        format!(
            "CREATE OR REPLACE FUNCTION {}({})\nRETURNS {} AS $${}$$ LANGUAGE plpgsql{volatility}{path};\n",
            self.qualified(),
            self.args,
            self.returns.to_ascii_uppercase(),
            self.body
        )
    }
}

/// One `BEFORE ... FOR EACH ROW` trigger on a model table.
#[derive(Debug, Clone)]
pub struct ModelTrigger {
    pub table: String,
    pub name: String,
    /// `INSERT`, `UPDATE`, in the order `pg_trigger` reports them.
    pub events: &'static [&'static str],
    /// The function it runs, one of this module's, by bare name.
    pub function: String,
}

impl ModelTrigger {
    /// `_platform.name`, as the catalog reports the function a trigger runs.
    pub fn qualified_function(&self) -> String {
        qualified_function(&self.function)
    }

    pub fn create_sql(&self, schema: &str) -> String {
        format!(
            "CREATE OR REPLACE TRIGGER {}\nBEFORE {} ON {}\nFOR EACH ROW EXECUTE FUNCTION {}();\n",
            quote_ident(&self.name),
            self.events.join(" OR "),
            quote_qualified(schema, &self.table),
            self.qualified_function()
        )
    }
}

/// `_platform.<name>` for one of this module's functions, the name spelled as the catalog spells it.
fn qualified_function(name: &str) -> String {
    format!("{PLATFORM_SCHEMA}.{}", quote_if_needed(name))
}

/// The functions every push has, whatever the schema declares: shared by every model's
/// `updated_at` trigger and every slug function.
pub fn shared_functions() -> Vec<TriggerFunction> {
    vec![
        TriggerFunction {
            name: "set_updated_at".into(),
            args: "",
            returns: "trigger",
            volatility: 'v',
            body: "\nBEGIN\n  NEW.updated_at = NOW();\n  RETURN NEW;\nEND;\n".into(),
            search_path: None,
        },
        // Portable: Unicode via unaccent, then the regexps. `unaccent` is found through the
        // function's own path, in `extensions` or where an older engine left it, whatever path the
        // row's writer has.
        TriggerFunction {
            name: "slugify".into(),
            args: "val TEXT",
            returns: "text",
            volatility: 'i',
            body: "\nBEGIN\n  RETURN lower(\n    regexp_replace(\n      regexp_replace(\n        unaccent(trim(val)),\n        '[^a-zA-Z0-9\\s-]', '', 'g'\n      ),\n      '[\\s-]+', '-', 'g'\n    )\n  );\nEND;\n".into(),
            search_path: Some(super::extensions::OBJECT_SEARCH_PATH),
        },
    ]
}

fn needs_updated_at(model: &ModelAst) -> bool {
    model.options.timestamps
        || model.fields.contains_key("updatedAt")
        || model.fields.contains_key("updated_at")
}

pub(crate) fn slug_fields(model: &ModelAst) -> impl Iterator<Item = (&String, &str)> {
    model.fields.iter().filter_map(|(name, field)| match field {
        FieldAst::Slug(slug) => Some((name, slug.from.as_str())),
        _ => None,
    })
}

/// The rich text columns, with the localized flag: a localized column holds one document per
/// locale, and normalising the map as though it were the document loses every locale.
fn rich_text_fields(model: &ModelAst) -> Vec<(&str, bool)> {
    model
        .fields
        .iter()
        .filter(|(_, field)| matches!(field, FieldAst::RichText(_)))
        .map(|(name, field)| (name.as_str(), super::column_conversion::is_localised(field)))
        .collect()
}

/// The functions a model's own triggers run: one per slug field, one for all its rich text.
///
/// Their names (`set_{table}_{slug}`, `normalise_{table}_rich_text`) are [`ObjectNames`]'s,
/// fitted to 63 bytes and folded to lower case because [`TriggerFunction::create_sql`] writes the
/// name unquoted, so Postgres stores it folded: a `probeSlug` field kept as written was keyed
/// `set_probe_all_probeSlug` against the catalog's `set_probe_all_probeslug`, and the push could
/// not find the function it had just created.
pub fn model_functions(model: &ModelAst, names: &ObjectNames) -> Vec<TriggerFunction> {
    let table = model.table_name();
    let mut out: Vec<TriggerFunction> = slug_fields(model)
        .map(|(slug_field, source_field)| TriggerFunction {
            name: names.slug_function(table, slug_field),
            args: "",
            returns: "trigger",
            volatility: 'v',
            body: format!(
                "\nBEGIN\n  IF TG_OP = 'INSERT' THEN\n    IF NEW.{slug} IS NULL OR BTRIM(NEW.{slug}::TEXT) = '' THEN\n      NEW.{slug} = {PLATFORM_SCHEMA}.slugify(NEW.{source}::TEXT);\n    END IF;\n  ELSIF TG_OP = 'UPDATE' THEN\n    IF NEW.{source} IS DISTINCT FROM OLD.{source} THEN\n      IF OLD.{slug} IS NOT DISTINCT FROM {PLATFORM_SCHEMA}.slugify(OLD.{source}::TEXT) THEN\n        NEW.{slug} = {PLATFORM_SCHEMA}.slugify(NEW.{source}::TEXT);\n      END IF;\n    END IF;\n  END IF;\n  RETURN NEW;\nEND;\n",
                slug = quote_ident(slug_field),
                source = quote_ident(source_field),
            ),
            search_path: None,
        })
        .collect();

    // Keep a rich text column holding a Lexical document, whoever writes to it. The column is
    // JSONB with no check, so `'"hello"'::jsonb` is accepted while the generated types say the
    // column is a document; wrapping in the seed executor or the API fixes those writers and not
    // the *read* type, which is the claim. A trigger holds for every writer. The expression is
    // `lexical_normalise_expr`, the one the `text -> richText` migration uses, so there is no
    // second wrapping to drift from the first. One trigger per table, not per column.
    let rich_text = rich_text_fields(model);
    if !rich_text.is_empty() {
        let assignments: String = rich_text
            .iter()
            .map(|(field, localised)| {
                let column = format!("NEW.{}", quote_ident(field));
                format!(
                    "  {column} := {};\n",
                    super::column_conversion::lexical_normalise_expr(&column, *localised)
                )
            })
            .collect();
        out.push(TriggerFunction {
            name: names.rich_text_function(table),
            args: "",
            returns: "trigger",
            volatility: 'v',
            body: format!("\nBEGIN\n{assignments}  RETURN NEW;\nEND;\n"),
            search_path: None,
        });
    }
    out
}

/// The triggers on a model's table.
pub fn model_triggers(model: &ModelAst, names: &ObjectNames) -> Vec<ModelTrigger> {
    let table = model.table_name();
    let mut out = Vec::new();
    if needs_updated_at(model) {
        out.push(ModelTrigger {
            table: table.to_string(),
            name: names.updated_at_trigger(table),
            events: &["UPDATE"],
            function: "set_updated_at".into(),
        });
    }
    for (slug_field, _) in slug_fields(model) {
        out.push(ModelTrigger {
            table: table.to_string(),
            name: names.slug_trigger(table, slug_field),
            events: &["INSERT", "UPDATE"],
            function: names.slug_function(table, slug_field),
        });
    }
    if !rich_text_fields(model).is_empty() {
        out.push(ModelTrigger {
            table: table.to_string(),
            name: names.rich_text_trigger(table),
            events: &["INSERT", "UPDATE"],
            function: names.rich_text_function(table),
        });
    }
    out
}

/// The whole layer as one script: the schema, every function, then every trigger. What a push
/// applies piece by piece through the reconcile.
pub fn generate(ast: &SchemaAst, schema: &str) -> Result<String> {
    let mut out = platform_schema_sql();
    out.push_str(&format!(
        "\n{}\n{}\n\n",
        super::extensions::schema_sql(),
        super::extensions::create_sql("unaccent")
    ));
    let names = ObjectNames::for_schema(ast);
    let functions = shared_functions()
        .into_iter()
        .chain(ast.models.iter().flat_map(|m| model_functions(m, &names)));
    for function in functions {
        out.push_str(&function.create_sql());
        out.push('\n');
    }
    for trigger in ast.models.iter().flat_map(|m| model_triggers(m, &names)) {
        out.push_str(&trigger.create_sql(schema));
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The name a model's function is keyed and called by is the one Postgres stores for the
    /// unquoted `CREATE`, so a camelCase field or table cannot split the two apart.
    #[test]
    fn a_model_function_is_named_as_postgres_folds_it() {
        let names = ObjectNames::default();
        assert_eq!(
            names.slug_function("probe_all", "probeSlug"),
            "set_probe_all_probeslug"
        );
        assert_eq!(
            names.rich_text_function("BlogPosts"),
            "normalise_blogposts_rich_text"
        );
    }
}

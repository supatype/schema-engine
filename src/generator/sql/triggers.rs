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

use crate::desired::identity::function_key;
use crate::parser::ast::{FieldAst, ModelAst, SchemaAst};
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
}

impl TriggerFunction {
    /// `name(types)`, the ledger's name for a function (`crate::desired::identity`).
    pub fn key_name(&self) -> String {
        function_key(&self.name, self.args)
    }

    /// `_platform.name`, as a trigger's `EXECUTE FUNCTION` names it and the catalog reports it.
    pub fn qualified(&self) -> String {
        format!("{PLATFORM_SCHEMA}.{}", self.name)
    }

    pub fn create_sql(&self) -> String {
        let volatility = match self.volatility {
            'i' => " IMMUTABLE",
            's' => " STABLE",
            _ => "",
        };
        format!(
            "CREATE OR REPLACE FUNCTION {}({})\nRETURNS {} AS $${}$$ LANGUAGE plpgsql{volatility};\n",
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
        format!("{PLATFORM_SCHEMA}.{}", self.function)
    }

    pub fn create_sql(&self, schema: &str) -> String {
        format!(
            "CREATE OR REPLACE TRIGGER \"{}\"\nBEFORE {} ON \"{schema}\".\"{}\"\nFOR EACH ROW EXECUTE FUNCTION {}();\n",
            self.name,
            self.events.join(" OR "),
            self.table,
            self.qualified_function()
        )
    }
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
        },
        // Portable: Unicode via unaccent, then the regexps.
        TriggerFunction {
            name: "slugify".into(),
            args: "val TEXT",
            returns: "text",
            volatility: 'i',
            body: "\nBEGIN\n  RETURN lower(\n    regexp_replace(\n      regexp_replace(\n        unaccent(trim(val)),\n        '[^a-zA-Z0-9\\s-]', '', 'g'\n      ),\n      '[\\s-]+', '-', 'g'\n    )\n  );\nEND;\n".into(),
        },
    ]
}

fn needs_updated_at(model: &ModelAst) -> bool {
    model.options.timestamps
        || model.fields.contains_key("updatedAt")
        || model.fields.contains_key("updated_at")
}

fn slug_fields(model: &ModelAst) -> impl Iterator<Item = (&String, &str)> {
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
pub fn model_functions(model: &ModelAst) -> Vec<TriggerFunction> {
    let table = model.table_name();
    let mut out: Vec<TriggerFunction> = slug_fields(model)
        .map(|(slug_field, source_field)| TriggerFunction {
            name: format!("set_{table}_{slug_field}"),
            args: "",
            returns: "trigger",
            volatility: 'v',
            body: format!(
                "\nBEGIN\n  IF TG_OP = 'INSERT' THEN\n    IF NEW.\"{slug_field}\" IS NULL OR BTRIM(NEW.\"{slug_field}\"::TEXT) = '' THEN\n      NEW.\"{slug_field}\" = {PLATFORM_SCHEMA}.slugify(NEW.\"{source_field}\"::TEXT);\n    END IF;\n  ELSIF TG_OP = 'UPDATE' THEN\n    IF NEW.\"{source_field}\" IS DISTINCT FROM OLD.\"{source_field}\" THEN\n      IF OLD.\"{slug_field}\" IS NOT DISTINCT FROM {PLATFORM_SCHEMA}.slugify(OLD.\"{source_field}\"::TEXT) THEN\n        NEW.\"{slug_field}\" = {PLATFORM_SCHEMA}.slugify(NEW.\"{source_field}\"::TEXT);\n      END IF;\n    END IF;\n  END IF;\n  RETURN NEW;\nEND;\n"
            ),
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
                format!(
                    "  NEW.\"{field}\" := {};\n",
                    super::column_conversion::lexical_normalise_expr(
                        &format!("NEW.\"{field}\""),
                        *localised
                    )
                )
            })
            .collect();
        out.push(TriggerFunction {
            name: format!("normalise_{table}_rich_text"),
            args: "",
            returns: "trigger",
            volatility: 'v',
            body: format!("\nBEGIN\n{assignments}  RETURN NEW;\nEND;\n"),
        });
    }
    out
}

/// The triggers on a model's table.
pub fn model_triggers(model: &ModelAst) -> Vec<ModelTrigger> {
    let table = model.table_name();
    let mut out = Vec::new();
    if needs_updated_at(model) {
        out.push(ModelTrigger {
            table: table.to_string(),
            name: format!("{table}_updated_at_trigger"),
            events: &["UPDATE"],
            function: "set_updated_at".into(),
        });
    }
    for (slug_field, _) in slug_fields(model) {
        out.push(ModelTrigger {
            table: table.to_string(),
            name: format!("{table}_{slug_field}_trigger"),
            events: &["INSERT", "UPDATE"],
            function: format!("set_{table}_{slug_field}"),
        });
    }
    if !rich_text_fields(model).is_empty() {
        out.push(ModelTrigger {
            table: table.to_string(),
            name: format!("{table}_rich_text_trigger"),
            events: &["INSERT", "UPDATE"],
            function: format!("normalise_{table}_rich_text"),
        });
    }
    out
}

/// The whole layer as one script: the schema, every function, then every trigger. What a push
/// applies piece by piece through the reconcile.
pub fn generate(ast: &SchemaAst, schema: &str) -> Result<String> {
    let mut out = platform_schema_sql();
    out.push_str("\nCREATE EXTENSION IF NOT EXISTS \"unaccent\";\n\n");
    let functions = shared_functions()
        .into_iter()
        .chain(ast.models.iter().flat_map(model_functions));
    for function in functions {
        out.push_str(&function.create_sql());
        out.push('\n');
    }
    for trigger in ast.models.iter().flat_map(model_triggers) {
        out.push_str(&trigger.create_sql(schema));
        out.push('\n');
    }
    Ok(out)
}

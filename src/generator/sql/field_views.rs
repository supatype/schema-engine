//! Tier 2 field masking: generated `api`-schema views, for a database that cannot load
//! `supatype_mask`.
//!
//! Tier 1 rewrites references to the base table in the planner, which needs an extension in
//! `shared_preload_libraries` — a server-level setting and a restart, so not something a managed
//! provider will do. Tier 2 puts the same masking expression in a view definition instead, and
//! PostgREST is pointed at the `api` schema rather than the managed one.
//!
//! The behaviour both tiers must present is written once, in
//! `tests/field_access_contract_tests.rs`, and run per tier. Five of its six requirements are met
//! exactly here. The sixth cannot be, and the design below is shaped by measuring rather than
//! assuming:
//!
//! * **A non-reader gets NULL, not an error** (so `SELECT *` keeps working), yet **an aggregate over
//!   a masked column must not quietly undercount**. One view expression cannot behave differently in
//!   a projection than inside `sum()`. Tier 1 raises `column … is masked for this role and cannot be
//!   aggregated`; tier 2 returns the sum of what the caller may see. **Decided (2026-08-12):** accept
//!   it. PostgREST ships `db-aggregates-enabled = false` and Supatype never sets it, so no API caller
//!   can reach the divergence — only direct SQL against these views. The contract test asserts the
//!   difference per tier so it cannot drift silently.
//!
//! * **No whole-row references.** The `can_*` affordance functions take the row as a composite, and
//!   with `supatype_mask` loaded a whole-row reference to a masked table is rejected outright
//!   (`whole-row reference to "t" is not supported because the table has masked columns`). So the
//!   predicate is inlined over individual columns — which also lets both tiers coexist in one
//!   database, as the contract test requires.
//!
//! * **`security_invoker`.** Without it a view executes as its owner, and row-level security on the
//!   base table would not apply to the caller at all — masking a column while exposing every row.
//!   PG15+; Supatype's baseline is PG17.
//!
//! * **`IS NOT TRUE`, never `NOT`.** A write predicate returning NULL — an unset `current_setting`,
//!   a null column — makes `NOT predicate` NULL, and `IF NULL THEN RAISE` does not raise. Measured on
//!   a prototype: an unauthorised write succeeded silently.

use crate::parser::accessors::{db_table_name, platform_access};
use crate::parser::ast::{ModelAst, SchemaAst};
use crate::state::database_state::DatabaseState;

/// Schema the views live in. PostgREST is pointed here instead of the managed schema.
pub const VIEW_SCHEMA: &str = "api";

/// Roles the API switches between; the views need the same reach as the tables behind them.
const API_ROLES: &str = "anon, authenticated, service_role";

/// True when this schema needs tier 2 at all — that is, when any model masks a column.
pub fn has_field_rules(ast: &SchemaAst) -> bool {
    ast.models
        .iter()
        .any(|m| !platform_access(m).fields.is_empty())
}

/// `CREATE SCHEMA` and grants for the view schema.
fn preamble() -> String {
    format!(
        "CREATE SCHEMA IF NOT EXISTS \"{VIEW_SCHEMA}\";\n\
         GRANT USAGE ON SCHEMA \"{VIEW_SCHEMA}\" TO {API_ROLES};\n\n"
    )
}

/// The read predicate for a column, as SQL over the base table's own columns.
///
/// `None` when the column has no read rule: it is then as readable as the table itself, and wrapping
/// it in `CASE WHEN TRUE` would only make the view harder to read.
fn read_predicate(ast: &SchemaAst, model: &ModelAst, schema: &str, column: &str) -> Option<String> {
    let rules = platform_access(model).fields.get(column)?;
    let rule = rules.read.as_ref()?;
    Some(crate::generator::sql::rls::access_rule_to_expr(
        ast, model, rule, schema,
    ))
}

/// The write predicate, conjoined with the read predicate.
///
/// Writing a column you cannot read is not a right the schema can express, and allowing it would let
/// a caller discover the old value by trial: attempt a write, observe whether it was refused.
fn write_predicate(ast: &SchemaAst, model: &ModelAst, schema: &str, column: &str) -> Option<String> {
    let rules = platform_access(model).fields.get(column)?;
    let write = rules.write.as_ref()?;
    let write_expr = crate::generator::sql::rls::access_rule_to_expr(ast, model, write, schema);
    Some(match read_predicate(ast, model, schema, column) {
        Some(read) => format!("({write_expr}) AND ({read})"),
        None => write_expr,
    })
}

fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// The primary-key columns of a table, in order.
///
/// Row identity for the write trigger. `ctid` was the first attempt and it silently does not work: a
/// view row has no `ctid`, so `WHERE {key_match}` matched nothing, the stored row came back all
/// NULLs, and every masked write was permitted and written as NULL. Nothing failed loudly — the
/// contract's requirement 5 kept passing for an unrelated reason.
fn primary_key_columns(db: &DatabaseState, table: &str) -> Vec<String> {
    // From the backing index, not from `db.constraints`: the constraint reader only emits foreign
    // keys, so `DbConstraintType::PrimaryKey` is a variant nothing ever produces. Reading it there
    // returned "no key" for every table, which skipped the trigger and left the view read-only —
    // failing with `cannot update column "salary" of view` rather than anything about keys.
    db.indexes
        .iter()
        .find(|i| i.table == table && i.is_primary)
        .map(|i| i.columns.clone())
        .unwrap_or_default()
}

/// SQL for every `api` view the schema needs, plus the triggers that carry the write contract.
///
/// Driven by the **database's** columns rather than the AST's, so a table carrying columns the schema
/// does not declare — an adopted table, say — keeps serving them instead of losing them from the API
/// the moment tier 2 is switched on.
pub fn generate_field_views(ast: &SchemaAst, db: &DatabaseState, schema: &str) -> String {
    if !has_field_rules(ast) {
        return String::new();
    }

    let mut out = preamble();

    for model in &ast.models {
        let table = db_table_name(model);
        let Some(db_table) = db.tables.iter().find(|t| t.name == table) else {
            // Nothing to build a view over yet. The next push, after the table exists, emits it.
            continue;
        };

        let masked: Vec<&String> = platform_access(model).fields.keys().collect();
        let mut projections: Vec<String> = Vec::new();
        for column in &db_table.columns {
            let qualified = format!("{}.{}", quoted(table), quoted(&column.name));
            match read_predicate(ast, model, schema, &column.name) {
                Some(predicate) => projections.push(format!(
                    // NULL rather than an error, so `SELECT *` — what PostgREST sends by default —
                    // keeps working for a caller who may not read one column.
                    "    CASE WHEN {predicate} THEN {qualified} ELSE NULL END AS {}",
                    quoted(&column.name)
                )),
                None => projections.push(format!("    {qualified}")),
            }
        }

        out.push_str(&format!(
            "CREATE OR REPLACE VIEW {}.{} WITH (security_invoker = true) AS\n\
             SELECT\n{}\n  FROM {}.{};\n",
            quoted(VIEW_SCHEMA),
            quoted(table),
            projections.join(",\n"),
            quoted(schema),
            quoted(table),
        ));
        out.push_str(&format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON {}.{} TO {API_ROLES};\n\n",
            quoted(VIEW_SCHEMA),
            quoted(table),
        ));

        if !masked.is_empty() {
            let key = primary_key_columns(db, table);
            if key.is_empty() {
                // Without a key there is no way to say *which* row an INSTEAD OF trigger should
                // write, so the view is left read-only rather than given a trigger that guesses.
                // PostgREST cannot update a keyless relation either, so nothing is lost that worked.
                out.push_str(&format!(
                    "-- No primary key on {}.{}: its masked view is read-only, because an INSTEAD OF\n                     -- trigger has no way to identify the row being written.\n\n",
                    schema, table
                ));
                continue;
            }
            out.push_str(&render_write_trigger(ast, model, db, schema, table, &key));
        }
    }

    out
}

/// The `INSTEAD OF` triggers that make a masked view writable, and enforce the write rules.
///
/// A view containing a `CASE` expression is not auto-updatable, so without these the API would lose
/// every write verb on any table that masks a column — a far worse regression than the masking is an
/// improvement.
fn render_write_trigger(
    ast: &SchemaAst,
    model: &ModelAst,
    db: &DatabaseState,
    schema: &str,
    table: &str,
    key: &[String],
) -> String {
    let db_table = db
        .tables
        .iter()
        .find(|t| t.name == table)
        .expect("caller checked the table exists");
    let columns: Vec<&str> = db_table.columns.iter().map(|c| c.name.as_str()).collect();
    let fn_name = format!("{table}__write");
    let access = platform_access(model);

    let mut guards = String::new();
    for column in access.fields.keys() {
        if !columns.contains(&column.as_str()) {
            continue;
        }
        let col = quoted(column);

        // A predicate from the rule compiler names columns **unqualified** — `"author_id" = …` —
        // because a policy is evaluated with its table already in scope. Inside a trigger nothing is
        // in scope, so each predicate is evaluated against a one-row relation aliased to the table's
        // name, which is the same device `can_*` functions use (`FROM (SELECT ($1).*) AS "t"`).
        // Rewriting the SQL string instead was the first attempt and it silently did nothing.
        let row = format!("(SELECT stored.*) AS {}", quoted(table));

        let readable = match read_predicate(ast, model, schema, column) {
            Some(predicate) => format!("(SELECT ({predicate}) FROM {row})"),
            None => "TRUE".into(),
        };
        let write = match write_predicate(ast, model, schema, column) {
            Some(predicate) => format!("(SELECT ({predicate}) FROM {row})"),
            // No write rule means the column is as writable as the table.
            None => "TRUE".into(),
        };

        guards.push_str(&format!(
            "    -- {column}
                 -- Three cases, in the order tier 1 handles them — measured against the
                 -- extension, not inferred from its documentation:
                 --
                 -- 1. The caller cannot read the column. Their write is silently discarded rather
                 --    than refused: the extension reports the UPDATE as applied and leaves the
                 --    stored value alone. It is also what keeps a whole-object PATCH working for a
                 --    client that never saw the value.
                 -- 2. The caller can read it and sent back what is stored: nothing to do.
                 -- 3. A real edit, so the write rule decides. `IS NOT TRUE` is load-bearing here:
                 --    a predicate comparing a column to an absent claim is NULL, and `NOT NULL`
                 --    would let the write through.
                 IF {readable} IS NOT TRUE THEN
                   NEW.{col} := stored.{col};
                 ELSIF NEW.{col} IS NOT DISTINCT FROM stored.{col} THEN
                   NEW.{col} := stored.{col};
                 ELSIF {write} IS NOT TRUE THEN
                   RAISE EXCEPTION 'permission denied for column {column} of relation {table}'
                     USING ERRCODE = '42501';
                 END IF;

"
        ));
    }

    let assignments = columns
        .iter()
        .map(|c| format!("{} = NEW.{}", quoted(c), quoted(c)))
        .collect::<Vec<_>>()
        .join(",\n           ");
    let insert_cols = columns.iter().map(|c| quoted(c)).collect::<Vec<_>>().join(", ");
    let insert_vals = columns
        .iter()
        .map(|c| format!("NEW.{}", quoted(c)))
        .collect::<Vec<_>>()
        .join(", ");

    // Row identity for the UPDATE/DELETE branch, from the primary key.
    format!(
        "CREATE OR REPLACE FUNCTION {view_schema}.{fn_quoted}() RETURNS trigger\n\
         LANGUAGE plpgsql SECURITY INVOKER AS $trg$\n\
         DECLARE\n\
         \x20 stored {schema_quoted}.{table_quoted};\n\
         BEGIN\n\
         \x20 IF TG_OP = 'DELETE' THEN\n\
         \x20   DELETE FROM {schema_quoted}.{table_quoted} WHERE {key_match};\n\
         \x20   RETURN OLD;\n\
         \x20 END IF;\n\
         \n\
         \x20 IF TG_OP = 'INSERT' THEN\n\
         \x20   -- Masked columns on a new row are governed by the write rule alone; there is no\n\
         \x20   -- stored value to round-trip against.\n\
         \x20   INSERT INTO {schema_quoted}.{table_quoted} ({insert_cols}) VALUES ({insert_vals});\n\
         \x20   RETURN NEW;\n\
         \x20 END IF;\n\
         \n\
         \x20 SELECT * INTO stored FROM {schema_quoted}.{table_quoted} WHERE {key_match};\n\
         \n\
         {guards}\
         \x20 UPDATE {schema_quoted}.{table_quoted}\n\
         \x20    SET {assignments}\n\
         \x20  WHERE {key_match};\n\
         \x20 RETURN NEW;\n\
         END $trg$;\n\
         \n\
         CREATE OR REPLACE TRIGGER {trigger_name}\n\
         \x20 INSTEAD OF INSERT OR UPDATE OR DELETE ON {view_schema}.{table_quoted}\n\
         \x20 FOR EACH ROW EXECUTE FUNCTION {view_schema}.{fn_quoted}();\n\n",
        view_schema = quoted(VIEW_SCHEMA),
        fn_quoted = quoted(&fn_name),
        schema_quoted = quoted(schema),
        table_quoted = quoted(table),
        trigger_name = quoted(&format!("{table}_write")),
        key_match = key
            .iter()
            .map(|c| format!("{q} = OLD.{q}", q = quoted(c)))
            .collect::<Vec<_>>()
            .join(" AND "),
    )
}

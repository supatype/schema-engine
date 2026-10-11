//! Tier 2 field masking: generated `api`-schema views, for a database that cannot load
//! `supatype_mask`.
//!
//! Tier 1 rewrites references to the base table in the planner, which needs an extension in
//! `shared_preload_libraries`: a server-level setting and a restart, so not something a managed
//! provider will do. Tier 2 puts the same masking expression in a view definition instead, and
//! PostgREST is pointed at the `api` schema rather than the managed one.
//!
//! The behaviour both tiers must present is written once, in
//! `tests/field_access_contract_tests.rs`, and run per tier; `tests/tier_two_api_tests.rs` runs
//! every API caller through what a push makes. The design below is shaped by measuring rather than
//! assuming:
//!
//! * **Owner rights, not invoker rights (Option C, plan D5).** The API roles hold nothing on a base
//!   table under tier 2, or `Accept-Profile` and GraphQL would walk straight round the mask. So the
//!   views cannot run as their caller: they run as [`API_OWNER`], a `NOLOGIN NOBYPASSRLS` role that
//!   holds the base tables' rows and nothing else, with `security_barrier` on so a caller's filter
//!   cannot be pushed beneath the mask. Row-level security still filters per caller: the policies
//!   apply to the owner (they are `TO PUBLIC`) and read the caller's JWT, which the owner's rights
//!   do not change. The write triggers are `SECURITY DEFINER` under the same role, with a pinned
//!   `search_path`, and no API role may call them directly.
//!
//! * **A hand-written policy restricted to an API role no longer applies through the views.** The
//!   policy's role is compared with the view's owner, not the caller, so a permissive one `TO
//!   authenticated` stops granting (fail closed) and a restrictive one stops restricting. `doctor`
//!   warns about either on a tier 2 table.
//!
//! * **`service_role` is exempt, as in tier 1.** The extension exempts it by its database role;
//!   here the views and the triggers exempt the JWT role `service_role`, and one permissive policy
//!   per table admits it, since it loses its `BYPASSRLS` behind an owner-rights view.
//!
//! * **A non-reader gets NULL, not an error** (so `SELECT *` keeps working), yet **an aggregate over
//!   a masked column must not quietly undercount**. One view expression cannot behave differently in
//!   a projection than inside `sum()`. Tier 1 raises `column … is masked for this role and cannot be
//!   aggregated`; tier 2 returns the sum of what the caller may see. **Decided (2026-08-12):** accept
//!   it. PostgREST ships `db-aggregates-enabled = false` and Supatype never sets it, so no API caller
//!   can reach the divergence; only direct SQL against these views. The contract test asserts the
//!   difference per tier so it cannot drift silently.
//!
//! * **No whole-row references.** The `can_*` affordance functions take the row as a composite, and
//!   with `supatype_mask` loaded a whole-row reference to a masked table is rejected outright
//!   (`whole-row reference to "t" is not supported because the table has masked columns`). So the
//!   predicate is inlined over individual columns, which also lets both tiers coexist in one
//!   database, as the contract test requires.
//!
//! * **`IS NOT TRUE`, never `NOT`.** A write predicate returning NULL (an unset `current_setting`,
//!   a null column) makes `NOT predicate` NULL, and `IF NULL THEN RAISE` does not raise. Measured on
//!   a prototype: an unauthorised write succeeded silently.

use crate::generator::sql::auth_functions::CLAIMS_SCHEMA;
use crate::generator::sql::rls::AUTH_ROLE;
use crate::parser::accessors::{db_table_name, platform_access};
use crate::parser::ast::{ModelAst, SchemaAst};
use crate::sql_quote::{comment_text, quote_ident, quote_literal, quote_qualified, raise_message};
use crate::state::database_state::DatabaseState;

/// Schema the views live in. PostgREST is pointed here instead of the managed schema.
pub const VIEW_SCHEMA: &str = "api";

/// The role that owns the views and their write triggers, and the only one holding rows of the
/// base tables under tier 2. `NOLOGIN NOBYPASSRLS`: nobody connects as it, and every policy
/// applies to it.
pub const API_OWNER: &str = "supatype_api_owner";

/// The dollar tag of the block that makes [`API_OWNER`] and gives it what the views need.
/// Statement attribution recognises the block by it.
pub const OWNER_TAG: &str = "api_owner";

/// The dollar tag of the block giving [`API_OWNER`] the functions the API roles may call, which a
/// policy evaluated as the owner may call too.
pub const OWNER_REACH_TAG: &str = "api_owner_reach";

/// The dollar tag of the block that copies a base table's defaults onto its view.
pub const VIEW_SETUP_TAG: &str = "view_setup";

/// True when this schema needs tier 2 at all, that is, when any model masks a column.
pub fn has_field_rules(ast: &SchemaAst) -> bool {
    ast.models
        .iter()
        .any(|m| !platform_access(m).fields.is_empty())
}

/// The caller is `service_role`, which tier 1 exempts from every mask and write check.
fn service_role_exempt() -> String {
    format!("{AUTH_ROLE} = 'service_role'")
}

/// `CREATE SCHEMA`, the API roles' usage, and the owner role with what it needs.
fn preamble(schema: &str) -> String {
    let api = quote_ident(VIEW_SCHEMA);
    format!(
        "CREATE SCHEMA IF NOT EXISTS {api};\n\
         GRANT USAGE ON SCHEMA {api} TO anon, authenticated, service_role;\n\n\
         {}\n\n",
        owner_block(schema)
    )
}

/// Makes [`API_OWNER`] where it does not exist, refuses one that could log in or bypass row-level
/// security, lets the pushing role own objects as it, and grants it the schemas the views read and
/// the claim readers the write triggers call as it. Idempotent, and safe against another database
/// of the same cluster making the role at the same moment.
fn owner_block(schema: &str) -> String {
    let owner = quote_ident(API_OWNER);
    let owner_lit = quote_literal(API_OWNER);
    let claims = quote_ident(CLAIMS_SCHEMA);
    let readers = crate::generator::sql::auth_functions::CLAIM_READERS
        .iter()
        .map(|r| format!("{claims}.{r}"))
        .collect::<Vec<_>>()
        .join(", ");
    let refused = raise_message(&format!(
        "role {API_OWNER} can log in or bypass row-level security"
    ));
    let hint = quote_literal(&format!(
        "The api views and their write triggers run as this role. As a superuser: ALTER ROLE \
         {API_OWNER} NOLOGIN NOBYPASSRLS NOSUPERUSER;"
    ));
    format!(
        "DO ${OWNER_TAG}$\nBEGIN\n\
         \x20 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {owner_lit}) THEN\n\
         \x20   BEGIN\n\
         \x20     CREATE ROLE {owner} NOLOGIN NOBYPASSRLS NOINHERIT;\n\
         \x20   EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;\n\
         \x20   END;\n\
         \x20 END IF;\n\
         \x20 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {owner_lit}\n\
         \x20            AND (rolcanlogin OR rolbypassrls OR rolsuper)) THEN\n\
         \x20   RAISE EXCEPTION {refused} USING ERRCODE = '42501', HINT = {hint};\n\
         \x20 END IF;\n\
         \x20 -- Owning an object as a role takes membership in it; a superuser has that already.\n\
         \x20 IF NOT pg_has_role(current_user, {owner_lit}, 'MEMBER') THEN\n\
         \x20   EXECUTE format('GRANT %I TO %I', {owner_lit}, current_user);\n\
         \x20 END IF;\n\
         \x20 GRANT USAGE, CREATE ON SCHEMA {api} TO {owner};\n\
         \x20 GRANT USAGE ON SCHEMA {project} TO {owner};\n\
         \x20 GRANT USAGE ON SCHEMA {claims} TO {owner};\n\
         \x20 GRANT EXECUTE ON FUNCTION {readers} TO {owner};\n\
         \x20 IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'auth') THEN\n\
         \x20   GRANT USAGE ON SCHEMA \"auth\" TO {owner};\n\
         \x20 END IF;\n\
         END\n${OWNER_TAG}$;",
        api = quote_ident(VIEW_SCHEMA),
        project = quote_ident(schema),
    )
}

/// Gives [`API_OWNER`] every function in the claims and project schemas that an API role may call
/// and it may not.
///
/// A function a view or its table's policies call is checked against the caller, who holds these
/// already. The write trigger is different: it runs as the owner, so every policy its statements
/// meet calls its functions with the owner's rights, and one calling a function the API roles were
/// granted by name (an affordance function since H2, the drafts layer's visibility check) would
/// fail every write. Run after the drafts layer, which makes some of them. The owner gains nothing a
/// caller could use: nobody connects as it, and it only runs the triggers' own statements.
pub fn owner_reach_sql(schema: &str) -> String {
    let owner_lit = quote_literal(API_OWNER);
    format!(
        "DO ${OWNER_REACH_TAG}$\nDECLARE\n  f regprocedure;\nBEGIN\n\
         \x20 FOR f IN\n\
         \x20   SELECT p.oid::regprocedure FROM pg_proc p\n\
         \x20    WHERE p.pronamespace IN ({claims}::regnamespace, {project}::regnamespace)\n\
         \x20      AND p.prokind = 'f'\n\
         \x20      AND EXISTS (SELECT 1 FROM pg_roles r\n\
         \x20                   WHERE r.rolname IN ('anon', 'authenticated')\n\
         \x20                     AND has_function_privilege(r.oid, p.oid, 'EXECUTE'))\n\
         \x20      AND NOT has_function_privilege({owner_lit}, p.oid, 'EXECUTE')\n\
         \x20 LOOP\n\
         \x20   EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I', f, {owner_lit});\n\
         \x20 END LOOP;\n\
         END\n${OWNER_REACH_TAG}$;\n",
        claims = quote_literal(&quote_ident(CLAIMS_SCHEMA)),
        project = quote_literal(&quote_ident(schema)),
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
fn write_predicate(
    ast: &SchemaAst,
    model: &ModelAst,
    schema: &str,
    column: &str,
) -> Option<String> {
    let rules = platform_access(model).fields.get(column)?;
    let write = rules.write.as_ref()?;
    let write_expr = crate::generator::sql::rls::access_rule_to_expr(ast, model, write, schema);
    Some(match read_predicate(ast, model, schema, column) {
        Some(read) => format!("({write_expr}) AND ({read})"),
        None => write_expr,
    })
}

/// The primary key a model declares, for a table that does not exist yet.
///
/// Read from the serialised field rather than through an accessor: `primaryKey` lives on the payload
/// of some thirty `FieldAst` variants and there is no `is_primary_key` helper, so matching on all of
/// them here would be a lot of code to say one thing. Generation-time only.
fn ast_primary_key(model: &ModelAst) -> Vec<String> {
    model
        .fields
        .iter()
        .filter(|(_, field)| {
            serde_json::to_value(field)
                .ok()
                .and_then(|v| v.get("primaryKey").and_then(|p| p.as_bool()))
                .unwrap_or(false)
        })
        .flat_map(|(name, field)| crate::parser::accessors::column_names_for(name, field))
        .collect()
}

/// The primary-key columns of a table, in order.
///
/// Row identity for the write trigger. `ctid` was the first attempt and it silently does not work: a
/// view row has no `ctid`, so `WHERE {key_match}` matched nothing, the stored row came back all
/// NULLs, and every masked write was permitted and written as NULL. Nothing failed loudly: the
/// contract's requirement 5 kept passing for an unrelated reason.
fn primary_key_columns(db: &DatabaseState, table: &str) -> Vec<String> {
    // From the backing index. When this was written the constraint reader emitted only foreign
    // keys, so reading `db.constraints` returned "no key" for every table, which skipped the
    // trigger and left the view read-only, failing with `cannot update column "salary" of view`
    // rather than anything about keys. The reader reports primary keys now; the index is kept as
    // the source because it is what identifies the row, and is read the same way either way.
    db.indexes
        .iter()
        .find(|i| i.table == table && i.is_primary)
        .map(|i| i.columns.clone())
        .unwrap_or_default()
}

/// The columns a model declares, in declaration order.
///
/// Used for a table that does not exist *yet*: on a first push the diff is computed against an empty
/// database, so there are no introspected columns, but the `CREATE TABLE` runs earlier in the same
/// migration, so by the time the view is created the table is there. Without this the first push
/// emitted an empty view layer and then granted on `api.<table>`, failing with `relation
/// "api.tier_employee" does not exist`.
fn ast_columns(model: &ModelAst) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (field_name, field) in &model.fields {
        for column in crate::parser::accessors::column_names_for(field_name, field) {
            if !column.is_empty() && !out.contains(&column) {
                out.push(column);
            }
        }
    }
    // Option-driven columns, mirroring `column_diff`: a model can ask for these without declaring a
    // field for them.
    if model.options.timestamps && !model.fields.contains_key("timestamps") {
        for column in ["created_at", "updated_at"] {
            if !out.iter().any(|c| c == column) {
                out.push(column.to_string());
            }
        }
    }
    if model.options.soft_delete
        && !model.fields.contains_key("softDelete")
        && !out.iter().any(|c| c == "deleted_at")
    {
        out.push("deleted_at".to_string());
    }
    out
}

/// One table's shape, as the view generator needs it.
///
/// Carried in the diff so the renderer can build the SQL with the schema *it* was given. Generating
/// the SQL in the differ instead meant reaching for `db.schema`, which is empty on a
/// `DatabaseState::default()`, and every view came out as `FROM ""."users"`, a zero-length
/// identifier that Postgres rejects. Data here, SQL in the renderer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldViewTable {
    pub table: String,
    pub columns: Vec<String>,
    /// Primary key, for the write trigger's row identity. Empty means the view is read-only.
    pub key: Vec<String>,
}

/// What the `api` layer needs to cover, read from the database (and from the schema for tables this
/// migration is about to create).
pub fn field_view_plan(ast: &SchemaAst, db: &DatabaseState) -> Vec<FieldViewTable> {
    let mut plan = Vec::new();
    for model in &ast.models {
        let table = db_table_name(model);
        let db_table = db.tables.iter().find(|t| t.name == table);

        // The database's columns when the table exists, so a table carrying columns the schema does
        // not declare keeps serving them, and the schema's own when it is being created by this very
        // migration.
        let columns: Vec<String> = match db_table {
            Some(t) => t.columns.iter().map(|c| c.name.clone()).collect(),
            None => ast_columns(model),
        };
        if columns.is_empty() {
            continue;
        }

        let key = match primary_key_columns(db, table) {
            k if !k.is_empty() => k,
            // Not introspectable on a first push, for the same reason as the columns.
            _ => ast_primary_key(model),
        };

        plan.push(FieldViewTable {
            table: table.to_string(),
            columns,
            key,
        });
    }
    plan
}

/// SQL for the whole `api` view layer, plus the triggers that carry the write contract.
///
/// **Every** model gets a view, not only the ones that mask a column. Under tier 2 the managed schema
/// is not exposed to PostgREST at all. It cannot be, because a client picks its schema per request
/// with `Accept-Profile`, so leaving `public` on the list lets any caller read the unmasked table and
/// makes the mask opt-out. With only `api` exposed, a model without a view simply disappears from the
/// API, so the unmasked ones are passed through verbatim.
///
/// Driven by the **database's** columns rather than the AST's, so a table carrying columns the schema
/// does not declare (an adopted table, say) keeps serving them instead of losing them from the API
/// the moment tier 2 is switched on.
pub fn render_field_views(ast: &SchemaAst, plan: &[FieldViewTable], schema: &str) -> String {
    if plan.is_empty() {
        return String::new();
    }
    let mut out = preamble(schema);
    let names = crate::managed::ObjectNames::for_schema(ast);

    for entry in plan {
        let Some(model) = ast.models.iter().find(|m| db_table_name(m) == entry.table) else {
            continue;
        };
        out.push_str(&render_view(ast, model, entry, schema));
        if platform_access(model).fields.is_empty() {
            // Nothing masked: the view is a plain projection, which Postgres updates by itself.
            continue;
        }
        if entry.key.is_empty() {
            // Without a key there is no way to say *which* row an INSTEAD OF trigger should
            // write, so the view is left read-only rather than given a trigger that guesses.
            // PostgREST cannot update a keyless relation either, so nothing is lost that worked.
            out.push_str(&format!(
                "-- No primary key on {}.{}: its masked view is read-only, because an INSTEAD OF\n\
                 -- trigger has no way to identify the row being written.\n\n",
                comment_text(schema),
                comment_text(&entry.table)
            ));
            continue;
        }
        let trigger = WriteTrigger {
            names: &names,
            ast,
            model,
            schema,
            entry,
        };
        out.push_str(&trigger.render());
    }
    for grant in crate::generator::sql::grants::api_owner_junction_grants(ast) {
        out.push_str(&grant.create_sql(schema));
        out.push_str("\n\n");
    }

    out
}

/// One table's view: the masked projection, owned by [`API_OWNER`], with the base table's
/// defaults, its GraphQL identity, and its privileges.
fn render_view(ast: &SchemaAst, model: &ModelAst, entry: &FieldViewTable, schema: &str) -> String {
    let view = quote_qualified(VIEW_SCHEMA, &entry.table);
    let projections: Vec<String> = entry
        .columns
        .iter()
        .map(|column| projection(ast, model, schema, &entry.table, column))
        .collect();
    // Dropped and recreated, not `CREATE OR REPLACE`: replace refuses anything but appending
    // columns at the end, so a renamed or removed column would break every later push. The `api`
    // schema is generated in full by Supatype, so there is nothing of the operator's to lose, and
    // the trigger, which belongs to the view, is recreated with it.
    let mut out = format!(
        "DROP VIEW IF EXISTS {view};\n\
         CREATE VIEW {view} WITH (security_barrier = true) AS\n\
         SELECT\n{}\n  FROM {};\n\
         ALTER VIEW {view} OWNER TO {};\n",
        projections.join(",\n"),
        quote_qualified(schema, &entry.table),
        quote_ident(API_OWNER),
    );
    out.push_str(&view_setup(schema, &entry.table));
    if let Some(comment) = graphql_comment(&entry.key) {
        out.push_str(&format!("COMMENT ON VIEW {view} IS {comment};\n"));
    }
    out.push_str(&crate::generator::sql::grants::view_grants(
        model,
        VIEW_SCHEMA,
    ));
    out.push_str(&crate::generator::sql::grants::api_owner_grant(model).create_sql(schema));
    out.push_str("\n\n");
    out
}

/// One column of the view: the base column, or NULL for a caller its read rule refuses.
/// `service_role` reads everything, as tier 1 lets it.
fn projection(
    ast: &SchemaAst,
    model: &ModelAst,
    schema: &str,
    table: &str,
    column: &str,
) -> String {
    let qualified = format!("{}.{}", quote_ident(table), quote_ident(column));
    match read_predicate(ast, model, schema, column) {
        // NULL rather than an error, so `SELECT *` (what PostgREST sends by default) keeps working
        // for a caller who may not read one column.
        Some(predicate) => format!(
            "    CASE WHEN {} OR ({predicate}) THEN {qualified} ELSE NULL END AS {}",
            service_role_exempt(),
            quote_ident(column)
        ),
        None => format!("    {qualified}"),
    }
}

/// Copies each base column's default onto the view, so an insert through the view that leaves a
/// column out gets what the table would have given it (T2-N4), and lets the owner draw from the
/// table's sequences, which the write trigger fills a key from.
///
/// Read from the catalog when the migration runs rather than from the schema: on a first push the
/// table is created a few statements earlier, and a column the schema does not declare keeps its
/// default too. A sequence default (`nextval`) is left to the trigger, which draws it as the owner:
/// a caller holds no privilege on the table's sequences.
fn view_setup(schema: &str, table: &str) -> String {
    let base = quote_literal(&quote_qualified(schema, table));
    let view = quote_literal(&quote_qualified(VIEW_SCHEMA, table));
    format!(
        "DO ${VIEW_SETUP_TAG}$\nDECLARE\n  d record;\nBEGIN\n\
         \x20 FOR d IN\n\
         \x20   SELECT a.attname, pg_get_expr(ad.adbin, ad.adrelid) AS expr\n\
         \x20     FROM pg_attrdef ad\n\
         \x20     JOIN pg_attribute a ON a.attrelid = ad.adrelid AND a.attnum = ad.adnum\n\
         \x20    WHERE ad.adrelid = {base}::regclass AND a.attgenerated = ''\n\
         \x20      AND pg_get_expr(ad.adbin, ad.adrelid) NOT LIKE 'nextval(%'\n\
         \x20      AND EXISTS (SELECT 1 FROM pg_attribute v\n\
         \x20                   WHERE v.attrelid = {view}::regclass AND v.attname = a.attname)\n\
         \x20 LOOP\n\
         \x20   EXECUTE format('ALTER VIEW %s ALTER COLUMN %I SET DEFAULT %s', {view}, d.attname, d.expr);\n\
         \x20 END LOOP;\n\
         \x20 FOR d IN\n\
         \x20   SELECT s.objid::regclass AS seq FROM pg_depend s\n\
         \x20     JOIN pg_class c ON c.oid = s.objid AND c.relkind = 'S'\n\
         \x20    WHERE s.refobjid = {base}::regclass AND s.classid = 'pg_class'::regclass\n\
         \x20      AND s.deptype IN ('a', 'i')\n\
         \x20 LOOP\n\
         \x20   EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE %s TO %I', d.seq, {owner});\n\
         \x20 END LOOP;\n\
         END\n${VIEW_SETUP_TAG}$;\n",
        owner = quote_literal(API_OWNER),
    )
}

/// The comment pg_graphql reads a view's primary key from: a view has none of its own, and without
/// one pg_graphql does not reflect it at all. `None` for a keyless view, which it then leaves out.
fn graphql_comment(key: &[String]) -> Option<String> {
    if key.is_empty() {
        return None;
    }
    let spec = serde_json::json!({ "primary_key_columns": key });
    Some(quote_literal(&format!("@graphql({spec})")))
}

/// The `INSTEAD OF` trigger that makes a masked view writable, and enforces the write rules.
///
/// A view containing a `CASE` expression is not auto-updatable, so without it the API would lose
/// every write verb on any table that masks a column, a far worse regression than the masking is an
/// improvement.
///
/// What it returns is what the caller may see: the row read back through the view, masked as their
/// own `SELECT` would be (T2-N1), or nothing when the base statement touched no row because a policy
/// refused it (T2-N2), so a refused write reports no row rather than echoing one.
struct WriteTrigger<'a> {
    names: &'a crate::managed::ObjectNames,
    ast: &'a SchemaAst,
    model: &'a ModelAst,
    schema: &'a str,
    entry: &'a FieldViewTable,
}

impl WriteTrigger<'_> {
    fn base(&self) -> String {
        quote_qualified(self.schema, &self.entry.table)
    }

    fn view(&self) -> String {
        quote_qualified(VIEW_SCHEMA, &self.entry.table)
    }

    /// `"k1" = <row>."k1" AND ...` over the primary key.
    fn key_match(&self, row: &str) -> String {
        self.entry
            .key
            .iter()
            .map(|c| format!("{q} = {row}.{q}", q = quote_ident(c)))
            .collect::<Vec<_>>()
            .join(" AND ")
    }

    /// The masked columns this table has, in the rules' order.
    fn masked_columns(&self) -> Vec<&String> {
        platform_access(self.model)
            .fields
            .keys()
            .filter(|c| self.entry.columns.contains(c))
            .collect()
    }

    /// Columns no write may name: a generated one, which Postgres refuses to write.
    fn generated(&self) -> Vec<String> {
        self.model
            .fields
            .iter()
            .filter(|(_, f)| {
                crate::parser::ast::scalar_of(f).is_some_and(|s| s.generated.is_some())
            })
            .flat_map(|(n, f)| crate::parser::accessors::column_names_for(n, f))
            .collect()
    }

    /// `GENERATED ALWAYS` identity columns, which an insert may not give a value.
    fn always_identity(&self) -> Vec<String> {
        self.model
            .fields
            .iter()
            .filter(|(_, f)| {
                crate::parser::accessors::never_written(f)
                    && crate::parser::ast::scalar_of(f).is_some_and(|s| s.generated.is_none())
            })
            .flat_map(|(n, f)| crate::parser::accessors::column_names_for(n, f))
            .collect()
    }

    /// The columns an insert writes: every column but a generated one.
    fn inserted(&self) -> Vec<&String> {
        let generated = self.generated();
        self.entry
            .columns
            .iter()
            .filter(|c| !generated.contains(c))
            .collect()
    }

    /// The columns an update writes: neither a generated one nor an identity Postgres keeps.
    fn updated(&self) -> Vec<&String> {
        let always = self.always_identity();
        self.inserted()
            .into_iter()
            .filter(|c| !always.contains(c))
            .collect()
    }

    /// `rule` evaluated against `row`, aliased to the table's name so the rule's unqualified columns
    /// resolve, which is the same device the `can_*` functions use.
    fn against(&self, predicate: &str, row: &str) -> String {
        format!(
            "(SELECT ({predicate}) FROM (SELECT {row}.*) AS {})",
            quote_ident(&self.entry.table)
        )
    }

    fn render(&self) -> String {
        let function = quote_qualified(VIEW_SCHEMA, &self.names.write_function(&self.entry.table));
        let owner = quote_ident(API_OWNER);
        format!(
            "CREATE OR REPLACE FUNCTION {function}() RETURNS trigger\n\
             LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $trg$\n\
             DECLARE\n\
             \x20 stored {base};\n\
             \x20 touched bigint;\n\
             \x20 written text[];\n\
             \x20 filled record;\n\
             \x20 exempt boolean := {exempt};\n\
             BEGIN\n\
             {delete}{insert}{update}END $trg$;\n\
             ALTER FUNCTION {function}() OWNER TO {owner};\n\
             REVOKE ALL ON FUNCTION {function}() FROM PUBLIC;\n\
             \n\
             CREATE TRIGGER {trigger}\n\
             \x20 INSTEAD OF INSERT OR UPDATE OR DELETE ON {view}\n\
             \x20 FOR EACH ROW EXECUTE FUNCTION {function}();\n\n",
            base = self.base(),
            exempt = service_role_exempt(),
            delete = self.delete_branch(),
            insert = self.insert_branch(),
            update = self.update_branch(),
            trigger = quote_ident(&self.names.write_trigger(&self.entry.table)),
            view = self.view(),
        )
    }

    /// A delete reports the row the caller saw (`OLD` is read through the view, so it is already
    /// masked), or nothing when a policy kept the base row.
    fn delete_branch(&self) -> String {
        format!(
            "\x20 IF TG_OP = 'DELETE' THEN\n\
             \x20   DELETE FROM {base} WHERE {key};\n\
             \x20   GET DIAGNOSTICS touched = ROW_COUNT;\n\
             \x20   IF touched = 0 THEN\n\
             \x20     RETURN NULL;\n\
             \x20   END IF;\n\
             \x20   RETURN OLD;\n\
             \x20 END IF;\n\n",
            base = self.base(),
            key = self.key_match("OLD"),
        )
    }

    /// The row as the caller may see it, read back through the view by its key, or nothing when
    /// they may not see it at all. `indent` is the enclosing block's.
    fn reread(&self, indent: &str) -> String {
        format!(
            "{indent}SELECT v.* INTO NEW FROM {view} AS v WHERE {key};\n\
             {indent}IF NOT FOUND THEN\n\
             {indent}  RETURN NULL;\n\
             {indent}END IF;\n\
             {indent}RETURN NEW;\n",
            view = self.view(),
            key = self
                .entry
                .key
                .iter()
                .map(|c| format!("v.{q} = NEW.{q}", q = quote_ident(c)))
                .collect::<Vec<_>>()
                .join(" AND "),
        )
    }

    /// An insert, as tier 1 makes one (T2-N3): a value the caller may not write is not written, and
    /// the column gets its default instead, silently, so a client POSTing a whole object still
    /// works. The rule is evaluated against a row of NULLs, as the extension does, since there is
    /// no stored row: a rule that reads the row then answers NULL and the column falls back. The
    /// statement names only the columns that remain, which is what makes the table's own default
    /// apply. A key left empty is drawn from its sequence first, as the owner, so the row can be
    /// read back without `RETURNING`, which would refuse a row the caller may write but not read.
    fn insert_branch(&self) -> String {
        let columns = self
            .inserted()
            .iter()
            .map(|c| quote_literal(c))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "\x20 IF TG_OP = 'INSERT' THEN\n\
             {refused}{fill}\
             \x20   written := ARRAY[{columns}]::text[];\n\
             \x20   IF NOT exempt THEN\n\
             {coerced}\
             \x20   END IF;\n\
             \x20   EXECUTE {insert_into}\n\
             \x20     || coalesce('(' || (SELECT string_agg(quote_ident(c), ', ') FROM unnest(written) AS c)\n\
             \x20       || ') OVERRIDING SYSTEM VALUE SELECT '\n\
             \x20       || (SELECT string_agg('n.' || quote_ident(c), ', ') FROM unnest(written) AS c)\n\
             \x20       || ' FROM (SELECT ($1).*) AS n', 'DEFAULT VALUES')\n\
             \x20     USING NEW;\n\
             {reread}\
             \x20 END IF;\n\n",
            refused = self.always_identity_refusal(),
            fill = self.fill_from_sequences(),
            coerced = self.insert_coercions(),
            insert_into = quote_literal(&format!("INSERT INTO {} ", self.base())),
            reread = self.reread("    "),
        )
    }

    /// Postgres refuses a value for a `GENERATED ALWAYS` identity; so does the view, the insert
    /// below giving it one of its own from the sequence.
    fn always_identity_refusal(&self) -> String {
        self.always_identity()
            .iter()
            .map(|c| {
                format!(
                    "\x20   IF NEW.{q} IS NOT NULL THEN\n\
                     \x20     RAISE EXCEPTION {message} USING ERRCODE = '428C9';\n\
                     \x20   END IF;\n",
                    q = quote_ident(c),
                    message = raise_message(&format!(
                        "cannot insert a non-DEFAULT value into column {c}"
                    )),
                )
            })
            .collect()
    }

    /// Each column backed by a sequence (a serial, an identity) that the caller left empty, filled
    /// from it as the owner.
    fn fill_from_sequences(&self) -> String {
        let base = quote_literal(&self.base());
        format!(
            "\x20   FOR filled IN\n\
             \x20     SELECT a.attname::text AS col, pg_get_serial_sequence({base}, a.attname) AS seq\n\
             \x20       FROM pg_attribute a\n\
             \x20      WHERE a.attrelid = {base}::regclass AND a.attnum > 0 AND NOT a.attisdropped\n\
             \x20        AND pg_get_serial_sequence({base}, a.attname) IS NOT NULL\n\
             \x20   LOOP\n\
             \x20     IF to_jsonb(NEW) ->> filled.col IS NULL THEN\n\
             \x20       NEW := jsonb_populate_record(NEW, jsonb_build_object(filled.col, nextval(filled.seq)));\n\
             \x20     END IF;\n\
             \x20   END LOOP;\n"
        )
    }

    /// Takes each masked column the caller may not write out of the insert.
    fn insert_coercions(&self) -> String {
        let null_row = format!("(NULL::{})", self.base());
        self.masked_columns()
            .into_iter()
            .filter_map(|column| {
                let test = write_predicate(self.ast, self.model, self.schema, column)
                    .or_else(|| read_predicate(self.ast, self.model, self.schema, column))?;
                Some(format!(
                    "\x20     IF {} IS NOT TRUE THEN\n\
                     \x20       written := array_remove(written, {});\n\
                     \x20     END IF;\n",
                    self.against(&test, &null_row),
                    quote_literal(column),
                ))
            })
            .collect()
    }

    /// An update: each masked column decided as tier 1 decides it, the base row written, and the
    /// row read back through the view, or nothing when a policy refused the write.
    fn update_branch(&self) -> String {
        let assignments = self
            .updated()
            .iter()
            .map(|c| format!("{q} = NEW.{q}", q = quote_ident(c)))
            .collect::<Vec<_>>()
            .join(",\n           ");
        format!(
            "\x20 SELECT * INTO stored FROM {base} WHERE {key};\n\
             \x20 IF NOT exempt THEN\n\
             {guards}\
             \x20 END IF;\n\
             \x20 UPDATE {base}\n\
             \x20    SET {assignments}\n\
             \x20  WHERE {key};\n\
             \x20 GET DIAGNOSTICS touched = ROW_COUNT;\n\
             \x20 IF touched = 0 THEN\n\
             \x20   RETURN NULL;\n\
             \x20 END IF;\n\
             {reread}",
            base = self.base(),
            key = self.key_match("OLD"),
            guards = self.update_guards(),
            reread = self.reread("  "),
        )
    }

    /// One guard per masked column. Three cases, in the order tier 1 handles them, measured against
    /// the extension rather than inferred from its documentation:
    ///
    /// 1. The caller cannot read the column. Their write is silently discarded rather than refused:
    ///    the extension reports the UPDATE as applied and leaves the stored value alone. It is also
    ///    what keeps a whole-object PATCH working for a client that never saw the value.
    /// 2. The caller can read it and sent back what is stored: nothing to do.
    /// 3. A real edit, so the write rule decides. `IS NOT TRUE` is load-bearing here: a predicate
    ///    comparing a column to an absent claim is NULL, and `NOT NULL` would let the write through.
    fn update_guards(&self) -> String {
        self.masked_columns()
            .into_iter()
            .map(|column| {
                let readable = read_predicate(self.ast, self.model, self.schema, column)
                    .map_or("TRUE".to_string(), |p| self.against(&p, "stored"));
                let writable = write_predicate(self.ast, self.model, self.schema, column)
                    .map_or("TRUE".to_string(), |p| self.against(&p, "stored"));
                let col = quote_ident(column);
                format!(
                    "\x20   -- {label}\n\
                     \x20   IF {readable} IS NOT TRUE THEN\n\
                     \x20     NEW.{col} := stored.{col};\n\
                     \x20   ELSIF NEW.{col} IS NOT DISTINCT FROM stored.{col} THEN\n\
                     \x20     NEW.{col} := stored.{col};\n\
                     \x20   ELSIF {writable} IS NOT TRUE THEN\n\
                     \x20     RAISE EXCEPTION {denied} USING ERRCODE = '42501';\n\
                     \x20   END IF;\n",
                    label = comment_text(column),
                    denied = raise_message(&format!(
                        "permission denied for column {column} of relation {}",
                        self.entry.table
                    )),
                )
            })
            .collect()
    }
}

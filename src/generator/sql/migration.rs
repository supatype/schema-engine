use crate::differ::column_diff::field_pg_type;
use crate::differ::{ColumnDependencySnapshot, DiffOutput, Operation, Risk};
use crate::generator::sql::column_conversion::{
    add_column_backfill_default, kind_migrate_pre_update, rich_text_default_sql,
    using_expr_for_alter, ConversionStrategy, ConversionStrategyKind,
};
use crate::managed::{
    comment_on_constraint_sql, comment_on_index_sql, expected_check_constraint_name,
    expected_model_constraint_name, expected_unique_constraint_name, foreign_key_name,
    managed_check_comment, managed_comment, primary_key_name, type_check_name,
};
use crate::parser::accessors::{column_names_for, db_unique};
use crate::parser::ast::{
    scalar_of, AccessRule, DefaultValueAst, FieldAst, IndexAst, IndexMethod, ModelAst,
    RelationCardinality, RelationFieldAst, ScalarFieldAst, SchemaAst, ValidationAst,
};
use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};

/// A push refused because the schema declares tables Supatype does not manage.
///
/// A type rather than only a message so a caller can act on it: the CLI offers to adopt exactly
/// these tables, which it used to find out by matching the wording below.
#[derive(Debug)]
pub struct UnmanagedModelTables {
    pub tables: Vec<String>,
}

/// The stable name a caller matches on, in the engine's JSON output and the server's response.
pub const UNMANAGED_MODEL_TABLES: &str = "unmanaged_model_tables";

impl std::fmt::Display for UnmanagedModelTables {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tables = self.tables.join(", ");
        write!(
            f,
            "Your schema declares model(s) for table(s) Supatype does not manage: {tables}.\n\n\
             Nothing was applied. These tables already exist without Supatype's ownership marker, so \
             a push may neither alter them nor attach access rules to them, and leaving them in the \
             API without those rules would serve them under whatever privileges they already \
             have.\n\n\
             What to do:\n\
             • Run `supatype adopt` to bring them under management (it shows the SQL first)\n\
             • Or point the model at a different table with `tableName`\n\n\
             If these tables were created by an older Supatype that did not stamp tables, `adopt` \
             is the right move: one run and pushes work as before."
        )
    }
}

impl std::error::Error for UnmanagedModelTables {}

/// Refuse a push whose schema declares a table Supatype does not manage.
///
/// Public because the check has to happen at the *entry* to a push, not only where SQL is rendered:
/// an unchanged schema produces an empty diff, skips the renderer, and would otherwise report
/// "schema pushed" while a declared table sat in the API with none of its rules applied.
pub fn assert_no_unmanaged_model_tables(diff: &DiffOutput) -> Result<()> {
    if diff.unmanaged_model_tables.is_empty() {
        return Ok(());
    }
    Err(UnmanagedModelTables {
        tables: diff.unmanaged_model_tables.clone(),
    }
    .into())
}

fn assert_forward_allowed(diff: &DiffOutput, force: bool) -> Result<()> {
    // Defence in depth for library callers that render SQL without going through a push entry point.
    assert_no_unmanaged_model_tables(diff)?;

    if diff.summary.is_destructive && !force {
        bail!(
            "{} destructive operation(s) detected. Use --force to proceed.",
            diff.summary.destructive
        );
    }
    Ok(())
}

/// Returns only the forward (apply) SQL, suitable for execution against a live DB.
///
/// Layout: preamble (header + optional `CREATE EXTENSION`), then `BEGIN`, model DDL, `COMMIT`.
/// Extension lines are emitted **before** the explicit `BEGIN` (legacy layout; still one
/// `sqlx::raw_sql` batch).
pub fn forward_sql(
    diff: &DiffOutput,
    force: bool,
    schema: &str,
    ast: &SchemaAst,
) -> Result<String> {
    assert_forward_allowed(diff, force)?;
    render_forward_wrapped(diff, schema, ast)
}

/// Preamble + model DDL **without** surrounding `BEGIN`/`COMMIT`, for embedding inside a
/// larger transaction (e.g. `storage` materialization + model migration in one `BEGIN`…`COMMIT`).
pub fn forward_sql_outer_body(
    diff: &DiffOutput,
    force: bool,
    schema: &str,
    ast: &SchemaAst,
) -> Result<String> {
    assert_forward_allowed(diff, force)?;
    render_forward_outer_body(diff, schema, ast)
}

/// `storage` SQL followed by [`forward_sql_outer_body`], for execution inside an existing
/// `sqlx::Transaction` (no surrounding `BEGIN`/`COMMIT`; the transaction provides atomicity).
pub fn push_storage_and_model_apply_body(
    storage_sql: &str,
    diff: &DiffOutput,
    force: bool,
    schema: &str,
    ast: &SchemaAst,
) -> Result<String> {
    assert_forward_allowed(diff, force)?;
    let body = render_forward_outer_body(diff, schema, ast)?;
    // Slug / updated_at trigger functions are idempotent (CREATE OR REPLACE) and
    // must run in the same transaction as the DDL, otherwise NOT NULL columns
    // populated by triggers (e.g. `Slug<...>`) fail on insert. The per-operation
    // renderer only emits a placeholder comment for CreateTrigger, so apply the
    // generated trigger SQL here.
    let triggers = super::triggers::generate(ast, schema)?;
    Ok(format!(
        "{}\n{}\n{}",
        storage_sql.trim(),
        body.trim_end(),
        triggers.trim_end()
    ))
}

/// Single `BEGIN`…`COMMIT` script: `storage` SQL, then [`forward_sql_outer_body`].
pub fn push_storage_and_model_batch_sql(
    storage_sql: &str,
    diff: &DiffOutput,
    force: bool,
    schema: &str,
    ast: &SchemaAst,
) -> Result<String> {
    let inner = push_storage_and_model_apply_body(storage_sql, diff, force, schema, ast)?;
    Ok(batch_sql(&inner))
}

/// `body` as the single `BEGIN`…`COMMIT` script the migration history stores.
pub fn batch_sql(body: &str) -> String {
    format!(
        "-- supatype-engine: storage + model migration (single transaction)\nBEGIN;\n{}\nCOMMIT;",
        body.trim_end()
    )
}

/// Returns the full migration file (forward + rollback) for saving to disk.
pub fn generate(diff: &DiffOutput, force: bool, schema: &str, ast: &SchemaAst) -> Result<String> {
    if diff.summary.is_destructive && !force {
        bail!(
            "{} destructive operation(s) detected. Use --force to proceed.",
            diff.summary.destructive
        );
    }

    let forward = render_forward_wrapped(diff, schema, ast)?;
    let rollback = super::rollback::generate(diff, schema)?;
    let hash = migration_hash(&forward);

    Ok(format!(
        "-- Migration generated by supatype-engine v{ver}\n\
         -- Hash: {hash}\n\
         -- Risk: {risk}\n\n\
         {forward}\n\n\
         {rollback}",
        ver = env!("ENGINE_VERSION"),
        risk = if diff.summary.is_destructive {
            "destructive"
        } else if diff.summary.cautious > 0 {
            "cautious"
        } else {
            "safe"
        },
    ))
}

fn needs_pgcrypto(diff: &DiffOutput) -> bool {
    use crate::parser::ast::FieldAst;
    let uuid_default = |f: &FieldAst| {
        matches!(f,
            FieldAst::Uuid(s) if matches!(&s.default, Some(DefaultValueAst::GenRandomUuid))
        )
    };
    diff.operations.iter().any(|op| match op {
        Operation::CreateTable { model, .. } => model.fields.values().any(uuid_default),
        Operation::AddColumn { field, .. } => uuid_default(field),
        _ => false,
    })
}

fn needs_vector(diff: &DiffOutput) -> bool {
    use crate::parser::ast::FieldAst;
    let is_vector = |f: &FieldAst| matches!(f, FieldAst::Vector(_));
    diff.operations.iter().any(|op| match op {
        Operation::CreateTable { model, .. } => model.fields.values().any(is_vector),
        Operation::AddColumn { field, .. } => is_vector(field),
        _ => false,
    })
}

fn needs_postgis(diff: &DiffOutput) -> bool {
    use crate::parser::ast::FieldAst;
    let is_geo = |f: &FieldAst| matches!(f, FieldAst::Geo(_));
    diff.operations.iter().any(|op| match op {
        Operation::CreateTable { model, .. } => model.fields.values().any(is_geo),
        Operation::AddColumn { field, .. } => is_geo(field),
        _ => false,
    })
}

// Optional extensions before inner `BEGIN`: pgcrypto (uuid gen_random_uuid), vector (pgvector),
// postgis (GEOGRAPHY). `FieldAst::Custom` is not analysed here.
fn render_forward_preamble(diff: &DiffOutput) -> Vec<String> {
    let mut lines = vec![
        "-- ============================================================".into(),
        "-- FORWARD MIGRATION".into(),
        "-- ============================================================".into(),
        String::new(),
    ];

    if needs_pgcrypto(diff) {
        lines.push("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\";".into());
        lines.push(String::new());
    }

    if needs_vector(diff) {
        lines.push("CREATE EXTENSION IF NOT EXISTS \"vector\";".into());
        lines.push(String::new());
    }

    if needs_postgis(diff) {
        lines.push("CREATE EXTENSION IF NOT EXISTS \"postgis\";".into());
        lines.push(String::new());
    }

    // Unconditional, for the same reason the affordance functions below are: a definition that is
    // only re-emitted when the diff happens to carry an RLS operation drifts from the policies that
    // call it, and nothing notices until a policy evaluates against a stale helper.
    //
    // It was gated, which is why the `auth` schema grant had to be emitted a second time from the
    // field-masking block: a steady-state push checked a privilege that nothing in that push had
    // tried to establish. Every statement here is `IF NOT EXISTS` or `CREATE OR REPLACE`, so
    // re-emission costs a parse and settles the question for every push rather than some of them.
    lines.push(
        crate::generator::sql::rls::generate_auth_helpers()
            .trim()
            .into(),
    );
    lines.push(String::new());

    lines
}

/// `can_*` affordance functions, appended after the tables they read exist.
///
/// Emitted at the end rather than in the preamble: each takes its table's composite
/// type as a parameter, so the table has to exist first. `CREATE OR REPLACE` makes
/// re-emission free, and emitting them on every push is what keeps them in step
/// with the policies: a stale affordance function is a UI that lies.
fn render_can_function_lines(ast: &SchemaAst, schema: &str) -> Vec<String> {
    let sql = crate::generator::sql::rls::generate_can_functions(ast, schema);
    if sql.trim().is_empty() {
        return Vec::new();
    }
    vec![
        "-- Row-level affordance functions (PostgREST computed columns)".into(),
        sql.trim().into(),
        String::new(),
    ]
}

/// Table privileges derived from the access rules.
///
/// Emitted after the tables exist, for the same reason the affordance functions
/// are. Idempotent: a `REVOKE` of a privilege that is not held is a no-op, and the
/// matching `GRANT` is what restores access when a rule is relaxed, so running this
/// on every push is what keeps privileges tracking the schema.
fn render_grant_lines(
    ast: &SchemaAst,
    schema: &str,
    skip: &[String],
    serve_from: Option<&str>,
) -> Vec<String> {
    let sql = crate::generator::sql::grants::generate_table_grants(ast, schema, skip, serve_from);
    if sql.trim().is_empty() {
        return Vec::new();
    }
    vec![
        "-- Table privileges derived from access rules (defence in depth)".into(),
        sql.trim().into(),
        String::new(),
    ]
}

/// Security labels for the field rules, emitted after the affordance functions they
/// point at.
///
/// Includes the capability probe: a schema that declares a masked column, pushed to a
/// database without the masking extension, fails here rather than applying and leaving
/// the column readable.
fn render_security_label_lines(ast: &SchemaAst, schema: &str, skip: &[String]) -> Vec<String> {
    let sql = crate::generator::sql::rls::generate_security_labels(ast, schema, skip);
    if sql.trim().is_empty() {
        return Vec::new();
    }
    vec![
        "-- Field-level access: security labels read by supatype_mask".into(),
        sql.trim().into(),
        String::new(),
    ]
}

/// Everything re-asserted on every push rather than diffed.
///
/// These three are idempotent by construction (`CREATE OR REPLACE`, `GRANT`/`REVOKE`
/// pairs, and `SECURITY LABEL` upserts), so re-running them is what keeps them tracking
/// the schema instead of drifting from it.
///
/// Shared by both forward paths deliberately. They diverged before: the wrapped path
/// applied the derived privileges and the outer-body path did not, and the outer body is
/// what every real push actually runs (`push_storage_and_model_apply_body`), so the
/// privileges were generated and never applied. Anything in this list belongs on every
/// path that applies a migration.
fn render_reasserted_lines(
    diff: &DiffOutput,
    ast: &SchemaAst,
    schema: &str,
    skip: &[String],
) -> Vec<String> {
    let views = diff.field_masking == crate::differ::FieldMaskingTier::Views;

    // `can_*` functions are not skipped: they live in the managed schema and read the table, they do
    // not change it. A Studio affordance for a table the API cannot reach is useless but harmless.
    let mut lines = render_can_function_lines(ast, schema);

    // Tier 2's views come **before** the grants, which name `api.<table>` and would otherwise run
    // against a schema that does not exist yet.
    //
    // One tier or the other, never both. Labels *and* views would give every deployment the views'
    // weaker aggregate behaviour, and the extension rejects the whole-row references the write trigger
    // needs.
    if views {
        let sql = crate::generator::sql::field_views::render_field_views(
            ast,
            &diff.field_view_plan,
            schema,
        );
        if !sql.trim().is_empty() {
            lines.push(
                "-- Field-level access, tier 2: api views (this database cannot load supatype_mask)"
                    .into(),
            );
            lines.push(sql.trim_end().into());
            lines.push(String::new());
        }
    }

    // Under tier 2 the API reads the `api` views, so that is where the privileges belong, and the
    // base tables lose theirs, or `Accept-Profile: public` walks straight round the mask.
    let serve_from = views.then_some(crate::generator::sql::field_views::VIEW_SCHEMA);
    lines.extend(render_grant_lines(ast, schema, skip, serve_from));

    if views {
        // Column privileges are tier 1's second layer, for what a *database role* provably can never
        // write. Under tier 2 `anon` and `authenticated` hold no privilege on the base table at all,
        // so narrowing one would be describing access that does not exist.
    } else {
        // Strictly after the table grants: these narrow a table-level write privilege to a
        // column list, and the table grants would hand the whole table back if they ran after.
        lines.extend(render_column_grant_lines(ast, schema, skip));
        lines.extend(render_security_label_lines(ast, schema, skip));
    }

    lines
}

/// Column-level write privileges derived from the field rules: a second layer under the
/// masking extension, for what a database role provably can never write.
fn render_column_grant_lines(ast: &SchemaAst, schema: &str, skip: &[String]) -> Vec<String> {
    let sql = crate::generator::sql::grants::generate_column_grants(ast, schema, skip);
    if sql.trim().is_empty() {
        return Vec::new();
    }
    vec![
        "-- Column write privileges derived from field rules (defence in depth)".into(),
        sql.trim().into(),
        String::new(),
    ]
}

fn render_forward_operation_lines(
    diff: &DiffOutput,
    schema: &str,
    ast: &SchemaAst,
) -> Result<Vec<String>> {
    let mut lines = Vec::new();

    for op in &diff.operations {
        let risk_label = match op {
            Operation::CreateTable { risk, .. }
            | Operation::DropTable { risk, .. }
            | Operation::RenameTable { risk, .. }
            | Operation::AddColumn { risk, .. }
            | Operation::DropColumn { risk, .. }
            | Operation::RenameColumn { risk, .. }
            | Operation::AlterColumn { risk, .. }
            | Operation::RecreateColumn { risk, .. }
            | Operation::AddIndex { risk, .. }
            | Operation::DropIndex { risk, .. }
            | Operation::AddForeignKey { risk, .. }
            | Operation::DropForeignKey { risk, .. }
            | Operation::AddUniqueConstraint { risk, .. }
            | Operation::DropUniqueConstraint { risk, .. }
            | Operation::AddCheckConstraint { risk, .. }
            | Operation::DropCheckConstraint { risk, .. }
            | Operation::CreateEnum { risk, .. }
            | Operation::DropEnum { risk, .. }
            | Operation::AddEnumValue { risk, .. }
            | Operation::RemoveEnumValue { risk, .. }
            | Operation::RenameEnumValue { risk, .. }
            | Operation::ReorderEnumValues { risk, .. }
            | Operation::EnableRls { risk, .. }
            | Operation::CreateRlsPolicy { risk, .. }
            | Operation::DropRlsPolicy { risk, .. }
            | Operation::CreateTrigger { risk, .. }
            | Operation::DropTrigger { risk, .. }
            | Operation::CreateJunctionTable { risk, .. }
            | Operation::CreateVersionsTable { risk, .. }
            | Operation::EnableExtension { risk, .. } => match risk {
                Risk::Safe => "safe",
                Risk::Cautious => "cautious",
                Risk::Destructive => "destructive",
            },
        };

        let sql = render_operation(op, schema, ast)?;
        lines.push(format!(
            "-- [{risk_label}] {desc}",
            desc = op_description(op)
        ));
        lines.push(sql);
        lines.push(String::new());
    }

    Ok(lines)
}

/// Everything a forward migration does, between the preamble and the transaction boundary.
///
/// **One composition, because there were two and they drifted.** `render_forward_wrapped` builds the
/// migration file and `render_forward_outer_body` builds what a push applies, and they were separate
/// lists of the same steps: the drafts and publishing layer was added to the first and not the
/// second, so a push created the snapshot tables and none of the views, functions or policies that
/// make them mean anything. The push reported success. Only running it against a real database
/// showed it, because every test rendered the file.
fn render_forward_core(diff: &DiffOutput, schema: &str, ast: &SchemaAst) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    // A CHECK that calls a function is validated when the table is created, so the helper
    // functions have to exist before any operation line runs, not alongside the triggers.
    lines.push(super::constraint_helpers::generate());
    // Before the operations, because a draft view depends on every column it selects and would
    // otherwise refuse a column drop. Recreated by the versions layer at the end of this same
    // migration, so the window where they are missing is inside one transaction.
    let drop_drafts = crate::generator::sql::versions::drop_draft_views_sql(ast);
    if !drop_drafts.trim().is_empty() {
        lines.push(drop_drafts.trim_end().to_string());
        lines.push(String::new());
    }
    lines.extend(render_forward_operation_lines(diff, schema, ast)?);
    lines.extend(render_reasserted_lines(
        diff,
        ast,
        schema,
        &diff.unmanaged_model_tables,
    ));
    // Last, because it reads the snapshot tables the operations above create and the model tables
    // they reference. Errors rather than warns when the push failed to state who may see a draft.
    lines.extend(render_versions_lines(ast, schema)?);
    Ok(lines)
}

fn render_forward_outer_body(diff: &DiffOutput, schema: &str, ast: &SchemaAst) -> Result<String> {
    let mut lines = render_forward_preamble(diff);
    lines.extend(render_forward_core(diff, schema, ast)?);
    Ok(lines.join("\n"))
}

fn render_forward_wrapped(diff: &DiffOutput, schema: &str, ast: &SchemaAst) -> Result<String> {
    let mut lines = render_forward_preamble(diff);
    lines.push("BEGIN;".into());
    lines.push(String::new());
    lines.extend(render_forward_core(diff, schema, ast)?);
    lines.push("COMMIT;".into());
    Ok(lines.join("\n"))
}

/// The drafts and publishing layer, when this schema has a versioned model.
fn render_versions_lines(ast: &SchemaAst, schema: &str) -> Result<Vec<String>> {
    let sql = crate::generator::sql::versions::render_versions_layer(ast, schema)?;
    if sql.trim().is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![
        "-- Drafts, version history and publishing".into(),
        sql.trim_end().into(),
        String::new(),
    ])
}

fn op_description(op: &Operation) -> String {
    match op {
        Operation::CreateTable { table, .. } => format!("Create table: {table}"),
        Operation::DropTable { table, .. } => format!("Drop table: {table}"),
        Operation::RenameTable { from, to, .. } => format!("Rename table: {from} -> {to}"),
        Operation::AddColumn { table, column, .. } => format!("Add column: {table}.{column}"),
        Operation::DropColumn { table, column, .. } => format!("Drop column: {table}.{column}"),
        Operation::RenameColumn {
            table, from, to, ..
        } => format!("Rename column: {table}.{from} -> {to}"),
        Operation::AlterColumn { table, column, .. } => format!("Alter column: {table}.{column}"),
        Operation::RecreateColumn { table, column, .. } => {
            format!("Recreate column (data loss): {table}.{column}")
        }
        Operation::AddIndex { table, index, .. } => {
            format!("Add index on: {table}({})", index.fields.join(", "))
        }
        Operation::DropIndex { index_name, .. } => format!("Drop index: {index_name}"),
        Operation::AddForeignKey {
            table, relation, ..
        } => format!("Add FK: {table} -> {}", relation.target),
        Operation::DropForeignKey {
            table, constraint, ..
        } => format!("Drop FK: {table}.{constraint}"),
        Operation::AddUniqueConstraint { table, column, .. } => {
            format!("Add unique constraint: {table}.{column}")
        }
        Operation::DropUniqueConstraint {
            table, constraint, ..
        } => format!("Drop unique constraint: {table}.{constraint}"),
        Operation::AddCheckConstraint { table, columns, .. } => {
            format!("Set bounds: {table}.{}", columns.join(", "))
        }
        Operation::DropCheckConstraint {
            table, constraint, ..
        } => format!("Drop bounds: {table}.{constraint}"),
        Operation::CreateEnum { name, .. } => format!("Create enum: {name}"),
        Operation::DropEnum { name, .. } => format!("Drop enum: {name}"),
        Operation::AddEnumValue {
            enum_name, value, ..
        } => format!("Add enum value: {enum_name}.'{value}'"),
        Operation::RemoveEnumValue {
            enum_name, value, ..
        } => format!("Remove enum value: {enum_name}.'{value}'"),
        Operation::RenameEnumValue {
            enum_name,
            from,
            to,
            ..
        } => format!("Rename enum value: {enum_name}.'{from}' -> '{to}'"),
        Operation::ReorderEnumValues { enum_name, .. } => {
            format!("Reorder enum values: {enum_name}")
        }
        Operation::EnableRls { table, .. } => format!("Enable RLS: {table}"),
        Operation::CreateRlsPolicy { table, policy, .. } => {
            format!("Create RLS policy: {table}.{policy}")
        }
        Operation::DropRlsPolicy { table, policy, .. } => {
            format!("Drop RLS policy: {table}.{policy}")
        }
        Operation::CreateTrigger { table, trigger, .. } => {
            format!("Create trigger: {table}.{trigger}")
        }
        Operation::DropTrigger { table, trigger, .. } => format!("Drop trigger: {table}.{trigger}"),
        Operation::CreateJunctionTable { table, .. } => format!("Create junction table: {table}"),
        Operation::CreateVersionsTable { versions_table, .. } => {
            format!("Create versions table: {versions_table}")
        }
        Operation::EnableExtension { name, .. } => format!("Enable extension: {name}"),
    }
}

fn render_create_rls_policy_sql(
    table: &str,
    policy: &str,
    schema: &str,
    ast: &SchemaAst,
) -> Result<String> {
    let prefix = format!("{table}_");
    if !policy.starts_with(&prefix) {
        bail!("CreateRlsPolicy: policy name {policy} does not start with expected prefix {prefix}");
    }
    let suffix = &policy[prefix.len()..];
    if !matches!(suffix, "select" | "insert" | "update" | "delete") {
        bail!("CreateRlsPolicy: unknown policy suffix {suffix}");
    }

    if let Some(model) = ast.models.iter().find(|m| m.table_name() == table) {
        let rule = match suffix {
            "select" => model.access().read.as_ref(),
            "insert" => model.access().create.as_ref(),
            "update" => model.access().update.as_ref(),
            _ => model.access().delete.as_ref(),
        };
        let rule = rule.ok_or_else(|| {
            anyhow!("CreateRlsPolicy: table {table} has no access rule for {suffix}")
        })?;
        return Ok(crate::generator::sql::rls::render_policy_migration_sql(
            schema, table, suffix, ast, model, rule,
        ));
    }

    // Junction tables have no model of their own, so their policies are derived
    // from the intersection of both parents' rules (see differ::rls_diff).
    let junction = ast
        .junction_tables
        .iter()
        .find(|j| j.name == table)
        .ok_or_else(|| anyhow!("CreateRlsPolicy: unknown table {table}"))?;
    let parent_a = ast
        .models
        .iter()
        .find(|m| m.name == junction.model_a)
        .ok_or_else(|| {
            anyhow!(
                "CreateRlsPolicy: junction {table} parent {} not found",
                junction.model_a
            )
        })?;
    let parent_b = ast
        .models
        .iter()
        .find(|m| m.name == junction.model_b)
        .ok_or_else(|| {
            anyhow!(
                "CreateRlsPolicy: junction {table} parent {} not found",
                junction.model_b
            )
        })?;

    let derived = crate::differ::rls_diff::intersect_access(parent_a.access(), parent_b.access());
    let rule = match suffix {
        "select" => derived.read,
        "insert" => derived.create,
        "update" => derived.update,
        _ => derived.delete,
    }
    .ok_or_else(|| {
        anyhow!("CreateRlsPolicy: junction {table} has no derivable access rule for {suffix}")
    })?;

    // The differ only derives row-independent rules for junctions, because the
    // junction table has none of the parents' columns for a row-dependent
    // expression to reference. Assert that here rather than emit invalid SQL.
    if matches!(rule, AccessRule::Owner { .. } | AccessRule::Any { .. }) {
        bail!(
            "CreateRlsPolicy: junction {table} derived a row-dependent rule for {suffix}; \
             it cannot reference parent columns"
        );
    }

    Ok(crate::generator::sql::rls::render_policy_migration_sql(
        schema, table, suffix, ast, parent_a, &rule,
    ))
}

pub(crate) fn render_operation(op: &Operation, schema: &str, ast: &SchemaAst) -> Result<String> {
    match op {
        Operation::CreateTable { model, .. } => create_table_sql(model, schema, ast),
        Operation::DropTable { table, .. } => Ok(format!(
            "DROP TABLE IF EXISTS \"{schema}\".\"{table}\" CASCADE;"
        )),
        Operation::RenameTable { from, to, .. } => Ok(format!(
            "ALTER TABLE \"{schema}\".\"{from}\" RENAME TO \"{to}\";"
        )),
        Operation::AddColumn {
            table,
            column,
            field,
            ..
        } => {
            // BelongsTo relations produce an FK column typed like the target PK;
            // the FK constraint is a separate AddForeignKey operation.
            if let FieldAst::Relation(rel) = field.as_ref() {
                if matches!(rel.cardinality, RelationCardinality::BelongsTo) {
                    let uniq = if rel.unique_fk {
                        format!(
                            " CONSTRAINT \"{}\" UNIQUE",
                            expected_unique_constraint_name(table, column)
                        )
                    } else {
                        String::new()
                    };
                    let req = if rel.required { " NOT NULL" } else { "" };
                    let pg_type = fk_pg_type_for_model(ast, &rel.target);
                    return Ok(format!(
                        "ALTER TABLE \"{schema}\".\"{table}\" ADD COLUMN \"{column}\" {pg_type}{uniq}{req};"
                    ));
                }
            }
            // Composite fields: the differ stores the parent composite FieldAst
            // against each expanded column name, so we emit the right DDL here.
            let composite_sql = match (field.as_ref(), column.as_str()) {
                (FieldAst::Timestamps, "created_at") => Some(format!(
                    "ALTER TABLE \"{schema}\".\"{table}\" ADD COLUMN IF NOT EXISTS \
                     \"created_at\" TIMESTAMPTZ NOT NULL DEFAULT NOW();"
                )),
                (FieldAst::Timestamps, "updated_at") => Some(format!(
                    "ALTER TABLE \"{schema}\".\"{table}\" ADD COLUMN IF NOT EXISTS \
                     \"updated_at\" TIMESTAMPTZ NOT NULL DEFAULT NOW();"
                )),
                (FieldAst::Publishable, "status") => Some(format!(
                    "ALTER TABLE \"{schema}\".\"{table}\" ADD COLUMN IF NOT EXISTS \
                     \"status\" TEXT NOT NULL DEFAULT 'draft' \
                     CONSTRAINT \"{}\" CHECK ({});",
                    type_check_name(table, "status"),
                    super::type_checks::publishable_status_check_expr()
                )),
                (FieldAst::Publishable, "published_at") => Some(format!(
                    "ALTER TABLE \"{schema}\".\"{table}\" ADD COLUMN IF NOT EXISTS \
                     \"published_at\" TIMESTAMPTZ;"
                )),
                (FieldAst::Publishable, "scheduled_at") => Some(format!(
                    "ALTER TABLE \"{schema}\".\"{table}\" ADD COLUMN IF NOT EXISTS \
                     \"scheduled_at\" TIMESTAMPTZ;"
                )),
                (FieldAst::SoftDelete, "deleted_at") => Some(format!(
                    "ALTER TABLE \"{schema}\".\"{table}\" ADD COLUMN IF NOT EXISTS \
                     \"deleted_at\" TIMESTAMPTZ;"
                )),
                _ => None,
            };
            if let Some(sql) = composite_sql {
                return Ok(sql);
            }
            let col_def = field_to_column_def(table, column, field)?;
            if let Some(backfill) = add_column_backfill_default(field) {
                return Ok(format!(
                    "ALTER TABLE \"{schema}\".\"{table}\" ADD COLUMN {col_def} DEFAULT {backfill};\n\
                     ALTER TABLE \"{schema}\".\"{table}\" ALTER COLUMN \"{column}\" DROP DEFAULT;"
                ));
            }
            Ok(format!(
                "ALTER TABLE \"{schema}\".\"{table}\" ADD COLUMN {col_def};"
            ))
        }
        Operation::DropColumn { table, column, .. } => Ok(format!(
            "ALTER TABLE \"{schema}\".\"{table}\" DROP COLUMN IF EXISTS \"{column}\";"
        )),
        Operation::RenameColumn {
            table, from, to, ..
        } => Ok(format!(
            "ALTER TABLE \"{schema}\".\"{table}\" RENAME COLUMN \"{from}\" TO \"{to}\";"
        )),
        Operation::AlterColumn {
            table,
            column,
            field,
            changes,
            ..
        } => alter_column_sql(table, column, field.as_ref(), changes, schema),
        Operation::RecreateColumn {
            table,
            column,
            field,
            dependencies,
            ..
        } => recreate_column_sql(table, column, field.as_ref(), dependencies, schema),
        Operation::AddIndex { table, index, .. } => create_index_sql(table, index, schema),
        Operation::DropIndex { index_name, .. } => {
            Ok(format!("DROP INDEX IF EXISTS \"{index_name}\";"))
        }
        Operation::AddForeignKey {
            table,
            field_name,
            relation,
            ref_table,
            ref_schema,
            ..
        } => add_fk_sql(
            table,
            field_name,
            relation,
            ref_table,
            schema,
            ref_schema.as_deref().unwrap_or(schema),
        ),
        Operation::DropForeignKey {
            table, constraint, ..
        } => Ok(format!(
            "ALTER TABLE \"{schema}\".\"{table}\" DROP CONSTRAINT IF EXISTS \"{constraint}\";"
        )),
        Operation::AddUniqueConstraint {
            table,
            column,
            constraint,
            ..
        } => add_unique_constraint_sql(table, column, constraint, schema),
        Operation::DropUniqueConstraint {
            table, constraint, ..
        } => Ok(format!(
            "ALTER TABLE \"{schema}\".\"{table}\" DROP CONSTRAINT IF EXISTS \"{constraint}\";"
        )),
        Operation::AddCheckConstraint {
            table,
            constraint,
            expression,
            comment,
            ..
        } => Ok(format!(
            // Dropped first so the operation means "this table carries exactly this bound" rather
            // than "this bound is new". The differ only emits an add when it believes the
            // constraint is absent, and it can believe that wrongly: it diffs against a cached
            // snapshot, and a snapshot written by an engine that recorded less than this one does
            // will not mention a constraint that is really there. Without the drop, that mismatch
            // is a duplicate-name error that fails this push and every push after it, with no way
            // out from inside the tool. The drop costs a revalidation of the table, but only on the
            // path that was otherwise going to fail: an unchanged bound produces no add at all.
            "ALTER TABLE \"{schema}\".\"{table}\" DROP CONSTRAINT IF EXISTS \"{constraint}\";
ALTER TABLE \"{schema}\".\"{table}\" ADD CONSTRAINT \"{constraint}\" CHECK ({expression});
{}",
            comment_on_constraint_sql(table, constraint, comment, schema)
        )),
        Operation::DropCheckConstraint {
            table, constraint, ..
        } => Ok(format!(
            "ALTER TABLE \"{schema}\".\"{table}\" DROP CONSTRAINT IF EXISTS \"{constraint}\";"
        )),
        Operation::CreateEnum { name, values, .. } => {
            let vals = values
                .iter()
                .map(|v| format!("'{v}'"))
                .collect::<Vec<_>>()
                .join(", ");
            Ok(format!("CREATE TYPE \"{name}\" AS ENUM ({vals});"))
        }
        Operation::DropEnum { name, .. } => Ok(format!("DROP TYPE IF EXISTS \"{name}\";")),
        // Task 67: Add enum value. Postgres 12+ supports this inside transactions.
        Operation::AddEnumValue {
            enum_name, value, ..
        } => Ok(format!("ALTER TYPE \"{enum_name}\" ADD VALUE '{value}';")),
        // Task 68: Remove enum value. Postgres has no ALTER TYPE ... REMOVE VALUE.
        // Strategy: rename old type → create new type without value → alter columns → drop old.
        Operation::RemoveEnumValue {
            enum_name,
            value,
            affected_columns,
            ..
        } => {
            let old_name = format!("{enum_name}_old");
            let mut stmts = Vec::new();

            // 1. Pre-flight check: warn/fail if rows use this value
            for (table, column) in affected_columns {
                stmts.push(format!(
                    "DO $$ BEGIN\n  \
                     IF EXISTS (SELECT 1 FROM \"{schema}\".\"{table}\" WHERE \"{column}\"::text = '{value}') THEN\n    \
                     RAISE WARNING 'Rows in {table}.{column} still use enum value ''{value}''. Update them before applying.';\n  \
                     END IF;\n\
                     END $$;"
                ));
            }

            // 2. Rename old type
            stmts.push(format!(
                "ALTER TYPE \"{enum_name}\" RENAME TO \"{old_name}\";"
            ));

            // 3. We need the new values: they are all old values minus the removed one.
            //    Since we don't carry the full old values list in RemoveEnumValue,
            //    we build the new type dynamically from pg_enum.
            stmts.push(format!(
                "DO $$ \n\
                 DECLARE\n  \
                   _vals text;\n\
                 BEGIN\n  \
                   SELECT string_agg(quote_literal(enumlabel), ', ' ORDER BY enumsortorder)\n  \
                     INTO _vals\n  \
                     FROM pg_enum\n  \
                     JOIN pg_type ON pg_type.oid = pg_enum.enumtypid\n  \
                    WHERE pg_type.typname = '{old_name}'\n  \
                      AND enumlabel != '{value}';\n  \
                   EXECUTE format('CREATE TYPE \"{enum_name}\" AS ENUM (%s)', _vals);\n\
                 END $$;"
            ));

            // 4. Alter columns to use the new type
            for (table, column) in affected_columns {
                stmts.push(format!(
                    "ALTER TABLE \"{schema}\".\"{table}\" ALTER COLUMN \"{column}\" \
                     TYPE \"{enum_name}\" USING \"{column}\"::text::\"{enum_name}\";"
                ));
            }

            // 5. Drop the old type
            stmts.push(format!("DROP TYPE \"{old_name}\";"));

            Ok(stmts.join("\n"))
        }
        // Task 69: Rename enum value. Postgres 10+ native support.
        Operation::RenameEnumValue {
            enum_name,
            from,
            to,
            ..
        } => Ok(format!(
            "ALTER TYPE \"{enum_name}\" RENAME VALUE '{from}' TO '{to}';"
        )),
        // Task 70: Reorder enum values. Must recreate the type since Postgres
        // enum ordering is determined by creation order.
        Operation::ReorderEnumValues {
            enum_name,
            new_values,
            affected_columns,
            ..
        } => {
            let old_name = format!("{enum_name}_old");
            let vals = new_values
                .iter()
                .map(|v| format!("'{v}'"))
                .collect::<Vec<_>>()
                .join(", ");

            let mut stmts = Vec::new();

            // 1. Rename old type
            stmts.push(format!(
                "ALTER TYPE \"{enum_name}\" RENAME TO \"{old_name}\";"
            ));

            // 2. Create new type with desired order
            stmts.push(format!("CREATE TYPE \"{enum_name}\" AS ENUM ({vals});"));

            // 3. Alter all columns to use the new type
            for (table, column) in affected_columns {
                stmts.push(format!(
                    "ALTER TABLE \"{schema}\".\"{table}\" ALTER COLUMN \"{column}\" \
                     TYPE \"{enum_name}\" USING \"{column}\"::text::\"{enum_name}\";"
                ));
            }

            // 4. Drop old type
            stmts.push(format!("DROP TYPE \"{old_name}\";"));

            Ok(stmts.join("\n"))
        }
        Operation::EnableRls { table, .. } => Ok(format!(
            "ALTER TABLE \"{schema}\".\"{table}\" ENABLE ROW LEVEL SECURITY;"
        )),
        Operation::CreateRlsPolicy { table, policy, .. } => {
            render_create_rls_policy_sql(table, policy, schema, ast)
        }
        Operation::DropRlsPolicy { table, policy, .. } => Ok(format!(
            "DROP POLICY IF EXISTS \"{policy}\" ON \"{schema}\".\"{table}\";"
        )),
        Operation::CreateTrigger { table, trigger, .. } => Ok(format!(
            "-- Trigger '{trigger}' on '{table}': run supatype-engine generate (triggers)"
        )),
        Operation::DropTrigger { table, trigger, .. } => Ok(format!(
            "DROP TRIGGER IF EXISTS \"{trigger}\" ON \"{schema}\".\"{table}\";"
        )),
        Operation::CreateJunctionTable {
            table,
            fk_a,
            table_a,
            fk_b,
            table_b,
            ..
        } => {
            let (ref_table_a, pk_a, type_a) = junction_ref_for_model(ast, table_a);
            let (ref_table_b, pk_b, type_b) = junction_ref_for_model(ast, table_b);
            // Stamped like any other table Supatype creates. A junction table is *entirely* ours
            // (it has no model of its own), so without the marker the ownership gate would refuse to
            // drop it ever, and a removed many-to-many would leave its junction behind for good.
            let marker = managed_comment("table", table, &[]);
            let fk_a_name = foreign_key_name(table, fk_a);
            let fk_b_name = foreign_key_name(table, fk_b);
            let pk_name = primary_key_name(table);
            Ok(format!(
                "CREATE TABLE IF NOT EXISTS \"{schema}\".\"{table}\" (\n    \
                 \"{fk_a}\" {type_a} NOT NULL CONSTRAINT \"{fk_a_name}\" REFERENCES \"{schema}\".\"{ref_table_a}\" (\"{pk_a}\") ON DELETE CASCADE,\n    \
                 \"{fk_b}\" {type_b} NOT NULL CONSTRAINT \"{fk_b_name}\" REFERENCES \"{schema}\".\"{ref_table_b}\" (\"{pk_b}\") ON DELETE CASCADE,\n    \
                 CONSTRAINT \"{pk_name}\" PRIMARY KEY (\"{fk_a}\", \"{fk_b}\")\n\
                 );\n\n\
                 COMMENT ON TABLE \"{schema}\".\"{table}\" IS '{marker}';"
            ))
        }
        Operation::CreateVersionsTable {
            table,
            versions_table,
            record_id_type,
            primary_key,
            ..
        } => Ok(crate::generator::sql::versions::create_versions_table_sql(
            schema,
            table,
            versions_table,
            record_id_type,
            primary_key,
        )),
        Operation::EnableExtension { name, .. } => {
            Ok(format!("CREATE EXTENSION IF NOT EXISTS \"{name}\";"))
        }
    }
}

// ─── CREATE TABLE ────────────────────────────────────────────────────────────

fn create_table_sql(model: &ModelAst, schema: &str, ast: &SchemaAst) -> Result<String> {
    let table = &model.table_name();
    let mut col_defs: Vec<String> = Vec::new();

    for (field_name, field) in &model.fields {
        match field {
            FieldAst::Relation(rel) => {
                if matches!(rel.cardinality, RelationCardinality::BelongsTo) {
                    let fk_col = rel
                        .foreign_key
                        .clone()
                        .unwrap_or_else(|| format!("{field_name}_id"));
                    // When the FK column is also declared explicitly as a scalar
                    // field (the documented `author: RelatedTo<…>` + `author_id`
                    // pattern), that scalar definition owns the column. Emitting it
                    // here too produces a duplicate `column "…" specified more than
                    // once` error, so defer to the explicit declaration.
                    let explicitly_declared = model
                        .fields
                        .get(fk_col.as_str())
                        .map(|f| !matches!(f, FieldAst::Relation(_)))
                        .unwrap_or(false);
                    if !explicitly_declared {
                        let uniq = if rel.unique_fk {
                            format!(
                                " CONSTRAINT \"{}\" UNIQUE",
                                expected_unique_constraint_name(table, &fk_col)
                            )
                        } else {
                            String::new()
                        };
                        let req = if rel.required { " NOT NULL" } else { "" };
                        let pg_type = fk_pg_type_for_model(ast, &rel.target);
                        col_defs.push(format!("    \"{fk_col}\" {pg_type}{uniq}{req}"));
                    }
                    // FK constraint is a separate AddForeignKey operation (emitted after all tables).
                }
                // hasMany / hasOne / manyToMany produce no column here
            }
            FieldAst::Timestamps => {
                col_defs.push("    \"created_at\" TIMESTAMPTZ NOT NULL DEFAULT NOW()".into());
                col_defs.push("    \"updated_at\" TIMESTAMPTZ NOT NULL DEFAULT NOW()".into());
            }
            FieldAst::Publishable => {
                col_defs.push(format!(
                    "    \"status\" TEXT NOT NULL DEFAULT 'draft' CONSTRAINT \"{}\" CHECK ({})",
                    type_check_name(table, "status"),
                    super::type_checks::publishable_status_check_expr()
                ));
                col_defs.push("    \"published_at\" TIMESTAMPTZ".into());
                col_defs.push("    \"scheduled_at\" TIMESTAMPTZ".into());
            }
            FieldAst::SoftDelete => {
                col_defs.push("    \"deleted_at\" TIMESTAMPTZ".into());
            }
            other => {
                col_defs.push(format!(
                    "    {}",
                    field_to_column_def(table, field_name, other)?
                ));
            }
        }
    }

    // Timestamps from options (if not already added as composite field)
    if model.options.timestamps && !model.fields.contains_key("timestamps") {
        let has_created =
            model.fields.contains_key("created_at") || model.fields.contains_key("createdAt");
        let has_updated =
            model.fields.contains_key("updated_at") || model.fields.contains_key("updatedAt");
        if !has_created {
            col_defs.push("    \"created_at\" TIMESTAMPTZ NOT NULL DEFAULT NOW()".into());
        }
        if !has_updated {
            col_defs.push("    \"updated_at\" TIMESTAMPTZ NOT NULL DEFAULT NOW()".into());
        }
    }

    let has_soft_delete_field = model.fields.contains_key("softDelete");
    if model.options.soft_delete
        && !has_soft_delete_field
        && !model.fields.contains_key("deleted_at")
    {
        col_defs.push("    \"deleted_at\" TIMESTAMPTZ".into());
    }

    let mut statements = vec![format!(
        "CREATE TABLE IF NOT EXISTS \"{schema}\".\"{table}\" (\n{}\n);",
        col_defs.join(",\n")
    )];

    // Stamp inline UNIQUE constraints created by CREATE TABLE.
    for (field_name, field) in &model.fields {
        if !db_unique(field) || matches!(field, FieldAst::Relation(_)) {
            continue;
        }
        for col in column_names_for(field_name, field) {
            if col.is_empty() {
                continue;
            }
            let constraint = expected_unique_constraint_name(table, &col);
            let comment = managed_comment("unique_constraint", table, &[col.as_str()]);
            statements.push(comment_on_constraint_sql(
                table,
                &constraint,
                &comment,
                schema,
            ));
        }
    }

    // Stamp the bounds constraints CREATE TABLE declared inline. The comment carries a fingerprint
    // of the expression, which is what lets the differ notice a *changed* bound later without
    // comparing SQL text that Postgres has already rewritten on read-back.
    for (field_name, field) in &model.fields {
        for col in column_names_for(field_name, field) {
            let Some(expr) = field_check_expression(field, &col) else {
                continue;
            };
            statements.push(comment_on_constraint_sql(
                table,
                &expected_check_constraint_name(table, &col),
                &managed_check_comment(table, &[col.as_str()], &expr),
                schema,
            ));
        }
    }

    // Model-level constraints, as named table constraints stamped like the column bounds. Named for
    // the same reason: the name is how the differ finds it again, and the fingerprinted comment is
    // how a *changed* constraint is noticed without comparing SQL Postgres has already rewritten.
    for (index, rule) in model.annotations.db.constraints.iter().enumerate() {
        let expr = crate::generator::sql::constraints::constraint_to_expr(rule)?;
        let constraint = expected_model_constraint_name(table, index);
        statements.push(format!(
            "ALTER TABLE \"{schema}\".\"{table}\" ADD CONSTRAINT \"{constraint}\" CHECK ({expr});"
        ));
        // The columns the rule actually reads, not the constraint's own name. `columns_in` exists
        // for this; passing the name put `fields=events_check_1` in ownership metadata, which reads
        // as a column that does not exist.
        let mut columns = Vec::new();
        crate::parser::ast::columns_in(rule, &mut columns);
        let column_refs: Vec<&str> = columns.iter().map(String::as_str).collect();
        statements.push(comment_on_constraint_sql(
            table,
            &constraint,
            &managed_check_comment(table, &column_refs, &expr),
            schema,
        ));
    }

    // Explicit model-level indexes
    for index in model.indexes() {
        statements.push(create_index_sql(table, index, schema)?);
    }

    // And the ones nobody declares. Shared with the differ rather than written twice: these
    // carry a managed comment, so an index the differ cannot account for is one it proposes
    // dropping, and every push then dropped it and proposed dropping it again.
    for index in implicit_model_indexes(model) {
        statements.push(create_index_sql(table, &index, schema)?);
    }

    // Singleton (global config): enforce exactly one row via a partial unique index.
    if model.options.singleton {
        let idx_name = format!("{table}_singleton_idx");
        statements.push(format!(
            "CREATE UNIQUE INDEX IF NOT EXISTS \"{idx_name}\" \
             ON \"{schema}\".\"{table}\" ((TRUE));"
        ));
        let comment = managed_comment("unique_index", table, &[]);
        statements.push(comment_on_index_sql(&idx_name, &comment, schema));
    }

    // Stamp ownership, exactly as indexes, constraints and RLS policies already do.
    //
    // This is what lets the differ destroy this table later and refuse to destroy one it merely
    // found. Without it, every table in the managed schema was a drop candidate, which on a
    // database Supatype did not create is someone else's data.
    let table_marker = managed_comment("table", table, &[]);
    statements.push(format!(
        "COMMENT ON TABLE \"{schema}\".\"{table}\" IS '{table_marker}';"
    ));

    Ok(statements.join("\n\n"))
}

/// Returns Some(true) if the field has an `index: true` flag, None otherwise.
/// The indexes a model gets without declaring any.
///
/// Three rules, all of which emit a managed comment: a btree for a field marked `index`, a btree
/// on `deleted_at` for a soft-deleting model, and a GIN for an indexed `Blocks` column.
///
/// Public to the crate because the differ needs the identical list. It previously expected only
/// the indexes a schema *declares*, so each of these read as a managed index nothing accounted
/// for, and the differ proposed dropping it. The push dropped it, recreated it from the rules
/// above, and the next diff proposed dropping it again: `supatype push` was never idempotent for
/// any model with an indexed Blocks column. One definition, read by both, is the only version of
/// this that stays true.
pub(crate) fn implicit_model_indexes(model: &ModelAst) -> Vec<IndexAst> {
    let table = model.table_name();
    let mut indexes = Vec::new();

    for (field_name, field) in &model.fields {
        if let Some(true) = field_index_flag(field) {
            indexes.push(IndexAst {
                name: None,
                fields: vec![field_name.clone()],
                unique: false,
                using: IndexMethod::Btree,
            });
        }
    }

    // Either spelling asks for the same index, and only one is emitted. The guard reads as a
    // plain `or` now that both branches live here; it was two blocks, and the second excluded the
    // first to avoid adding the index twice.
    if model.fields.contains_key("softDelete") || model.options.soft_delete {
        indexes.push(IndexAst {
            name: Some(format!("{table}_deleted_at_idx")),
            fields: vec!["deleted_at".into()],
            unique: false,
            using: IndexMethod::Btree,
        });
    }

    for (field_name, field) in &model.fields {
        if let FieldAst::Blocks(b) = field {
            if b.index {
                indexes.push(IndexAst {
                    name: Some(format!("{table}_{field_name}_gin_idx")),
                    fields: vec![field_name.clone()],
                    unique: false,
                    using: IndexMethod::Gin,
                });
            }
        }
    }

    indexes
}

pub(crate) fn field_index_flag(field: &FieldAst) -> Option<bool> {
    match field {
        FieldAst::Text(f)
        | FieldAst::Email(f)
        | FieldAst::Uuid(f)
        | FieldAst::Integer(f)
        | FieldAst::Float(f)
        | FieldAst::Boolean(f)
        | FieldAst::Datetime(f)
        | FieldAst::BigInt(f)
        | FieldAst::Bytes(f)
        | FieldAst::SmallInt(f)
        | FieldAst::Date(f)
        | FieldAst::Timestamp(f)
        | FieldAst::Serial(f)
        | FieldAst::BigSerial(f)
        | FieldAst::Money(f)
        | FieldAst::Url(f)
        | FieldAst::Ip(f)
        | FieldAst::Cidr(f)
        | FieldAst::Macaddr(f)
        | FieldAst::Interval(f)
        | FieldAst::TsQuery(f)
        | FieldAst::TsVector(f)
        | FieldAst::Xml(f)
        | FieldAst::RichText(f)
        | FieldAst::Color(f) => {
            if f.index {
                Some(true)
            } else {
                None
            }
        }
        _ => None,
    }
}

// ─── COLUMN DEFINITION ───────────────────────────────────────────────────────

fn field_to_column_def(table: &str, name: &str, field: &FieldAst) -> Result<String> {
    match field {
        FieldAst::Uuid(f) => Ok(scalar_col(table, name, "UUID", f, false)),
        FieldAst::Text(f) | FieldAst::RichText(f) | FieldAst::Bytes(f) | FieldAst::Color(f) => {
            let pg = if matches!(field, FieldAst::RichText(_)) {
                "JSONB"
            } else if matches!(field, FieldAst::Bytes(_)) {
                "BYTEA"
            } else {
                "TEXT"
            };
            let rich_text = matches!(field, FieldAst::RichText(_));
            Ok(scalar_col(table, name, pg, f, rich_text))
        }
        FieldAst::Email(f) => {
            let mut def = scalar_col(table, name, "TEXT", f, false);
            def.push_str(&format!(
                " CONSTRAINT \"{}\" CHECK ({})",
                type_check_name(table, name),
                super::type_checks::email_check_expr(name)
            ));
            Ok(def)
        }
        FieldAst::Integer(f) => Ok(scalar_col(table, name, "INTEGER", f, false)),
        FieldAst::Float(f) => Ok(scalar_col(table, name, "DOUBLE PRECISION", f, false)),
        FieldAst::Boolean(f) => Ok(scalar_col(table, name, "BOOLEAN", f, false)),
        FieldAst::Datetime(f) => Ok(scalar_col(table, name, "TIMESTAMPTZ", f, false)),
        FieldAst::BigInt(f) => Ok(scalar_col(table, name, "BIGINT", f, false)),
        FieldAst::SmallInt(f) => Ok(scalar_col(table, name, "SMALLINT", f, false)),
        FieldAst::Date(f) => Ok(scalar_col(table, name, "DATE", f, false)),
        FieldAst::Timestamp(f) => Ok(scalar_col(table, name, "TIMESTAMP", f, false)),
        FieldAst::Serial(f) => {
            // SERIAL is self-declaring: NOT NULL + sequence default are implicit.
            // primary_key / unique flags still apply.
            let pk = primary_key_clause(table, f.primary_key);
            let uniq = unique_clause(table, name, f.unique && !f.primary_key);
            Ok(format!("\"{name}\" SERIAL{pk}{uniq}"))
        }
        FieldAst::BigSerial(f) => {
            let pk = primary_key_clause(table, f.primary_key);
            let uniq = unique_clause(table, name, f.unique && !f.primary_key);
            Ok(format!("\"{name}\" BIGSERIAL{pk}{uniq}"))
        }
        FieldAst::Money(f) => Ok(scalar_col(table, name, "NUMERIC(19,4)", f, false)),
        FieldAst::Url(f) => {
            let mut def = scalar_col(table, name, "TEXT", f, false);
            def.push_str(&format!(
                " CONSTRAINT \"{}\" CHECK ({})",
                type_check_name(table, name),
                super::type_checks::url_check_expr(name)
            ));
            Ok(def)
        }
        FieldAst::Ip(f) => Ok(scalar_col(table, name, "INET", f, false)),
        FieldAst::Cidr(f) => Ok(scalar_col(table, name, "CIDR", f, false)),
        FieldAst::Macaddr(f) => Ok(scalar_col(table, name, "MACADDR", f, false)),
        FieldAst::Interval(f) => Ok(scalar_col(table, name, "INTERVAL", f, false)),
        FieldAst::TsQuery(f) => Ok(scalar_col(table, name, "TSQUERY", f, false)),
        FieldAst::TsVector(f) => {
            // tsvector is typically NOT NULL; index is GIN.
            let req = if f.required { " NOT NULL" } else { "" };
            Ok(format!("\"{name}\" TSVECTOR{req}"))
        }
        FieldAst::Xml(f) => Ok(scalar_col(table, name, "XML", f, false)),
        FieldAst::Array(f) => {
            let req = if f.required { " NOT NULL" } else { "" };
            let uniq = unique_clause(table, name, f.unique);
            let elem = f.element_type.to_uppercase();
            let check = render_check(table, name, field);
            Ok(format!("\"{name}\" {elem}[]{req}{uniq}{check}"))
        }
        FieldAst::Slug(f) => {
            let unique = unique_clause(table, name, f.unique);
            let req = if f.required { " NOT NULL" } else { "" };
            let check = render_check(table, name, field);
            Ok(format!("\"{name}\" TEXT{req}{unique}{check}"))
        }
        FieldAst::Enum(f) => {
            let req = if f.required { " NOT NULL" } else { "" };
            let uniq = unique_clause(table, name, f.unique);
            let default = f
                .default
                .as_ref()
                .map(|d| format!(" DEFAULT '{d}'"))
                .unwrap_or_default();
            let check_name = type_check_name(table, name);
            let check = super::type_checks::enum_check_expr(name, &f.values);
            Ok(format!(
                "\"{name}\" TEXT{req}{uniq} CONSTRAINT \"{check_name}\" CHECK ({check}){default}"
            ))
        }
        FieldAst::Json(f) => {
            let req = if f.required { " NOT NULL" } else { "" };
            let check = render_check(table, name, field);
            Ok(format!("\"{name}\" JSONB{req}{check}"))
        }
        FieldAst::Button(f) => {
            let req = if f.required { " NOT NULL" } else { "" };
            let check = render_check(table, name, field);
            Ok(format!("\"{name}\" JSONB{req}{check}"))
        }
        FieldAst::Decimal(f) => {
            let pg = match (f.precision, f.scale) {
                (Some(p), Some(s)) => format!("NUMERIC({p}, {s})"),
                (Some(p), None) => format!("NUMERIC({p})"),
                _ => "NUMERIC".into(),
            };
            let req = if f.required { " NOT NULL" } else { "" };
            let check = render_check(table, name, field);
            Ok(format!("\"{name}\" {pg}{req}{check}"))
        }
        FieldAst::Image(f) | FieldAst::File(f) => Ok(scalar_col(
            table,
            name,
            "JSONB",
            &ScalarFieldAst {
                pg_type: "JSONB".into(),
                required: f.required,
                localized: f.localized,
                ..Default::default()
            },
            false,
        )),
        FieldAst::Blocks(f) => Ok(scalar_col(
            table,
            name,
            "JSONB",
            &ScalarFieldAst {
                pg_type: "JSONB".into(),
                required: f.required,
                localized: f.localized,
                check: f.check.clone(),
                validation: f.validation.clone(),
                ..Default::default()
            },
            false,
        )),
        FieldAst::Geo(f) => {
            let geo_type = f.geo_type.to_uppercase();
            let srid = f.srid.unwrap_or(4326);
            let req = if f.required { " NOT NULL" } else { "" };
            Ok(format!("\"{name}\" GEOGRAPHY({geo_type}, {srid}){req}"))
        }
        FieldAst::Vector(f) => {
            let req = if f.required { " NOT NULL" } else { "" };
            Ok(format!("\"{name}\" vector({}){req}", f.dimensions))
        }
        // Plugin-defined custom field type: use the declared pg_type directly.
        FieldAst::Custom(f) => {
            let req = if f.required { " NOT NULL" } else { "" };
            let uniq = unique_clause(table, name, f.unique);
            let default = f
                .default
                .as_ref()
                .map(|d| format!(" DEFAULT {}", render_default(d)))
                .unwrap_or_default();
            Ok(format!(
                "\"{name}\" {pg}{req}{uniq}{default}",
                pg = f.pg_type.to_uppercase()
            ))
        }
        // Composites are expanded at the table level, never called here individually
        FieldAst::Timestamps | FieldAst::Publishable | FieldAst::SoftDelete => {
            anyhow::bail!("composite field '{name}' must be expanded at table level")
        }
        FieldAst::Relation(_) => {
            anyhow::bail!("relation field '{name}' must be handled at table level")
        } // Array is handled above; this arm satisfies exhaustiveness if a new variant slips through
    }
}

/// The `CHECK` expression a column carries, or `None`.
///
/// One function rather than a clause built inside each `field_to_column_def` arm, because the same
/// answer is needed twice: once to render the column, and once to stamp the constraint's comment
/// with a fingerprint of it. Two derivations of the same expression would drift, and a comment that
/// disagrees with its constraint is worse than no comment, since the differ trusts it.
/// The expression itself, from already-decomposed parts.
///
/// `scalar_col` is handed synthesized `ScalarFieldAst` values for image, file and blocks columns and
/// never sees the enum, so both entry points meet here rather than each deriving the expression.
fn check_expression_parts(
    check: Option<&str>,
    validation: Option<&ValidationAst>,
    name: &str,
    localized: bool,
    pg_type: &str,
    rich_text: bool,
) -> Option<String> {
    if localized {
        return localized_check(validation, name, pg_type, rich_text);
    }
    check.map(|c| c.replace("{name}", name))
}

pub fn field_check_expression(field: &FieldAst, name: &str) -> Option<String> {
    let (check, validation, localized, pg_type, rich_text) = match field {
        FieldAst::Slug(f) => (
            f.check.as_deref(),
            f.validation.as_ref(),
            f.localized,
            "TEXT".to_string(),
            false,
        ),
        // Stated here rather than left to `pg_type`, for both. This is the one place the field's
        // `pg_type` reaches generated SQL (a localized column's CHECK), so a Money field falling
        // through to the catch-all below would have bounded a numeric column with a text
        // expression. Decimal already named itself; Money was the one relying on the default.
        FieldAst::Decimal(f) => (
            f.check.as_deref(),
            f.validation.as_ref(),
            f.localized,
            "NUMERIC".to_string(),
            false,
        ),
        // Separate arm rather than joined to Decimal above: Money carries a ScalarFieldAst and
        // Decimal its own type, so one pattern cannot bind both.
        FieldAst::Money(f) => (
            f.check.as_deref(),
            f.validation.as_ref(),
            f.localized,
            "NUMERIC".to_string(),
            false,
        ),
        FieldAst::Json(f) | FieldAst::Button(f) => (
            f.check.as_deref(),
            f.validation.as_ref(),
            f.localized,
            "JSONB".to_string(),
            false,
        ),
        // An array column is never localized: translations of a list are a model change, not a
        // column one, so there is no locale map to iterate.
        FieldAst::Array(f) => (
            f.check.as_deref(),
            f.validation.as_ref(),
            false,
            f.element_type.to_uppercase(),
            false,
        ),
        FieldAst::Blocks(f) => (
            f.check.as_deref(),
            f.validation.as_ref(),
            f.localized,
            "JSONB".to_string(),
            false,
        ),
        FieldAst::RichText(f) => (
            f.check.as_deref(),
            f.validation.as_ref(),
            f.localized,
            "JSONB".to_string(),
            true,
        ),
        other => {
            let f = scalar_of(other)?;
            (
                f.check.as_deref(),
                f.validation.as_ref(),
                f.localized,
                f.pg_type.clone(),
                false,
            )
        }
    };

    check_expression_parts(check, validation, name, localized, &pg_type, rich_text)
}

/// A column's named `CONSTRAINT ... CHECK (...)` clause, or empty.
///
/// Named rather than left to Postgres's `{table}_{column}_check`: the name is how the differ finds
/// the constraint again on the next push, and the comment stamped alongside it is how a *changed*
/// bound is detected. Anonymous inline checks were only ever created, never reconciled, so
/// tightening a bound used to produce no migration at all.
fn render_check(table: &str, name: &str, field: &FieldAst) -> String {
    field_check_expression(field, name)
        .map(|expr| {
            format!(
                " CONSTRAINT \"{}\" CHECK ({expr})",
                expected_check_constraint_name(table, name)
            )
        })
        .unwrap_or_default()
}

/// Which `_supatype.localized_*` family bounds this column.
///
/// Read from the bounds themselves rather than from the field variant: the CLI has already decided
/// that a `JSON<T[]>` takes item counts and a `JSON<{...}>` takes none, and re-deriving that here
/// from `JSONB` alone would be a guess. Storage only settles the question the bounds cannot: whether
/// a range is numeric or temporal.
fn localized_measure(v: &ValidationAst, pg_type: &str, rich_text: bool) -> &'static str {
    if v.max_items.is_some() || v.min_items.is_some() {
        return "items";
    }
    if v.max_length.is_some() || v.min_length.is_some() {
        return if rich_text {
            "richtext_length"
        } else {
            "length"
        };
    }
    let upper = pg_type.to_uppercase();
    if upper.starts_with("DATE") || upper.starts_with("TIMESTAMP") || upper.starts_with("INTERVAL")
    {
        "temporal"
    } else {
        "number"
    }
}

fn localized_check(
    validation: Option<&ValidationAst>,
    name: &str,
    pg_type: &str,
    rich_text: bool,
) -> Option<String> {
    let v = validation?;
    if v.is_empty() {
        return None;
    }
    let measure = localized_measure(v, pg_type, rich_text);

    // One call per bound. A two-sided helper would be STRICT over a NULL argument and pass silently,
    // which is the failure this area is not allowed to have twice.
    let mut clauses: Vec<String> = Vec::new();
    let mut push = |direction: &str, arg: String| {
        clauses.push(format!(
            "{schema}.localized_{measure}_{direction}(\"{name}\", {arg})",
            schema = crate::generator::sql::constraint_helpers::HELPER_SCHEMA,
        ));
    };

    match measure {
        "items" => {
            if let Some(n) = v.max_items {
                push("max", n.to_string());
            }
            if let Some(n) = v.min_items {
                push("min", n.to_string());
            }
        }
        "length" | "richtext_length" => {
            if let Some(n) = v.max_length {
                push("max", n.to_string());
            }
            if let Some(n) = v.min_length {
                push("min", n.to_string());
            }
        }
        _ => {
            for (bound, direction) in [(v.max.as_ref(), "max"), (v.min.as_ref(), "min")] {
                let Some(bound) = bound else { continue };
                let arg = match bound {
                    serde_json::Value::String(s) => format!("'{}'", s.replace('\'', "''")),
                    other => other.to_string(),
                };
                push(direction, arg);
            }
        }
    }

    if clauses.is_empty() {
        return None;
    }
    Some(clauses.join(" AND "))
}

fn scalar_col(
    table: &str,
    name: &str,
    pg_type: &str,
    f: &ScalarFieldAst,
    rich_text: bool,
) -> String {
    // Localized fields are stored as JSONB regardless of their base type.
    let effective_type = if f.localized { "JSONB" } else { pg_type };
    let pk = primary_key_clause(table, f.primary_key);
    let req = if f.required && !f.primary_key {
        " NOT NULL"
    } else {
        ""
    };
    let uniq = unique_clause(table, name, f.unique && !f.primary_key);
    let default = f
        .default
        .as_ref()
        .map(|d| {
            let expr = if rich_text {
                rich_text_default_sql(d).unwrap_or_else(|| render_default(d))
            } else {
                render_default(d)
            };
            format!(" DEFAULT {expr}")
        })
        .unwrap_or_default();
    let check = check_expression_parts(
        f.check.as_deref(),
        f.validation.as_ref(),
        name,
        f.localized,
        pg_type,
        rich_text,
    )
    .map(|expr| {
        format!(
            " CONSTRAINT \"{}\" CHECK ({expr})",
            expected_check_constraint_name(table, name)
        )
    })
    .unwrap_or_default();
    format!("\"{name}\" {effective_type}{pk}{req}{uniq}{default}{check}")
}

/// ` CONSTRAINT "{table}_pkey" PRIMARY KEY`, or nothing.
///
/// Named explicitly, with the name Postgres would have chosen, so that no object a push creates is
/// named by anyone but us. Postgres names an unnamed constraint after the fact and disambiguates a
/// collision with a digit, and a name only it knows is a name the differ and the ledger cannot
/// look for.
fn primary_key_clause(table: &str, primary_key: bool) -> String {
    if primary_key {
        format!(" CONSTRAINT \"{}\" PRIMARY KEY", primary_key_name(table))
    } else {
        String::new()
    }
}

/// ` CONSTRAINT "{table}_{column}_key" UNIQUE`, or nothing. See [`primary_key_clause`].
fn unique_clause(table: &str, column: &str, unique: bool) -> String {
    if unique {
        format!(
            " CONSTRAINT \"{}\" UNIQUE",
            expected_unique_constraint_name(table, column)
        )
    } else {
        String::new()
    }
}

fn render_default(d: &DefaultValueAst) -> String {
    match d {
        DefaultValueAst::Value { value } => match value {
            serde_json::Value::String(s) => format!("'{s}'"),
            serde_json::Value::Bool(b) => b.to_string(),
            other => other.to_string(),
        },
        DefaultValueAst::Expression { expr } => expr.clone(),
        DefaultValueAst::Now => "NOW()".into(),
        DefaultValueAst::GenRandomUuid => "gen_random_uuid()".into(),
    }
}

// ─── ALTER COLUMN ─────────────────────────────────────────────────────────────

fn strategy_from_changes(changes: &serde_json::Value) -> ConversionStrategy {
    let conv = changes.get("conversion");
    let kind = conv
        .and_then(|c| c.get("strategy"))
        .and_then(|v| v.as_str())
        .unwrap_or("transform_cast");
    ConversionStrategy {
        kind: match kind {
            "safe_cast" => ConversionStrategyKind::SafeCast,
            "kind_migrate" => ConversionStrategyKind::KindMigrate,
            "recreate_column" => ConversionStrategyKind::RecreateColumn,
            "blocked" => ConversionStrategyKind::Blocked,
            _ => ConversionStrategyKind::TransformCast,
        },
        using_expr: conv
            .and_then(|c| c.get("usingExpr"))
            .and_then(|v| v.as_str())
            .map(String::from),
        pre_update: conv
            .and_then(|c| c.get("preUpdate"))
            .and_then(|v| v.as_str())
            .map(String::from),
        blocked_reason: changes
            .get("blocked")
            .and_then(|v| v.as_str())
            .map(String::from),
    }
}

fn alter_column_sql(
    table: &str,
    column: &str,
    field: &FieldAst,
    changes: &serde_json::Value,
    schema: &str,
) -> Result<String> {
    let mut stmts: Vec<String> = Vec::new();
    let strategy = strategy_from_changes(changes);

    if let Some(pre) = strategy.pre_update.as_ref() {
        stmts.push(pre.clone());
    }

    if let Some(kc) = changes.get("kind_change") {
        let from = kc.get("from").and_then(|v| v.as_str()).unwrap_or("");
        let to = kc.get("to").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(pre) = kind_migrate_pre_update(table, column, schema, from, to, field) {
            stmts.push(pre);
        }
    }

    if let Some(type_change) = changes.get("type") {
        let pg_type = type_change
            .get("to_pg")
            .and_then(|v| v.as_str())
            .unwrap_or("TEXT");
        let from_udt = type_change
            .get("from_udt")
            .and_then(|v| v.as_str())
            .unwrap_or("?");

        let using_expr = using_expr_for_alter(&strategy, column, pg_type);

        stmts.push(format!(
            "ALTER TABLE \"{schema}\".\"{table}\" ALTER COLUMN \"{column}\" \
             TYPE {pg_type} USING {using_expr}; \
             -- was: {from_udt}"
        ));
    }

    if let Some(null_change) = changes.get("nullability") {
        let to = null_change.get("to").and_then(|v| v.as_str()).unwrap_or("");
        if to == "not_null" {
            stmts.push(format!(
                "DO $$ BEGIN\n  \
                 IF EXISTS (SELECT 1 FROM \"{schema}\".\"{table}\" WHERE \"{column}\" IS NULL) THEN\n    \
                 RAISE EXCEPTION 'Cannot set NOT NULL on {table}.{column}: NULL values exist.';\n  \
                 END IF;\n\
                 END $$;"
            ));
            stmts.push(format!(
                "ALTER TABLE \"{schema}\".\"{table}\" ALTER COLUMN \"{column}\" SET NOT NULL;"
            ));
        } else {
            stmts.push(format!(
                "ALTER TABLE \"{schema}\".\"{table}\" ALTER COLUMN \"{column}\" DROP NOT NULL;"
            ));
        }
    }

    Ok(stmts.join("\n"))
}

fn recreate_column_sql(
    table: &str,
    column: &str,
    field: &FieldAst,
    dependencies: &[ColumnDependencySnapshot],
    schema: &str,
) -> Result<String> {
    let mut stmts: Vec<String> = Vec::new();

    for dep in dependencies {
        match dep.kind.as_str() {
            "foreign_key" => {
                stmts.push(format!(
                    "ALTER TABLE \"{schema}\".\"{}\" DROP CONSTRAINT IF EXISTS \"{}\";",
                    dep.table, dep.name
                ));
            }
            "index" => {
                stmts.push(format!("DROP INDEX IF EXISTS \"{}\";", dep.name));
            }
            _ => {}
        }
    }

    stmts.push(format!(
        "ALTER TABLE \"{schema}\".\"{table}\" DROP COLUMN IF EXISTS \"{column}\";"
    ));

    let col_def = field_to_column_def(table, column, field)?;
    stmts.push(format!(
        "ALTER TABLE \"{schema}\".\"{table}\" ADD COLUMN {col_def};"
    ));

    for dep in dependencies {
        if dep.kind != "foreign_key" {
            continue;
        }
        let cols = dep
            .columns
            .as_ref()
            .map(|c| {
                c.iter()
                    .map(|n| format!("\"{n}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| format!("\"{column}\""));
        let ref_table = dep.foreign_table.as_deref().unwrap_or("?");
        let ref_cols = dep
            .foreign_columns
            .as_ref()
            .map(|c| {
                c.iter()
                    .map(|n| format!("\"{n}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| "\"id\"".into());
        let on_delete = dep
            .on_delete
            .as_deref()
            .map(|a| format!(" ON DELETE {a}"))
            .unwrap_or_default();
        stmts.push(format!(
            "ALTER TABLE \"{schema}\".\"{}\" ADD CONSTRAINT \"{}\" \
             FOREIGN KEY ({cols}) REFERENCES \"{schema}\".\"{ref_table}\" ({ref_cols}){on_delete};",
            dep.table, dep.name
        ));
    }

    for dep in dependencies {
        if dep.kind != "index" {
            continue;
        }
        let cols = dep
            .columns
            .as_ref()
            .map(|c| {
                c.iter()
                    .map(|n| format!("\"{n}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| format!("\"{column}\""));
        let unique = if dep.unique { "UNIQUE " } else { "" };
        let method = dep.index_method.as_deref().unwrap_or("btree");
        stmts.push(format!(
            "CREATE {unique}INDEX IF NOT EXISTS \"{}\" ON \"{schema}\".\"{}\" USING {method} ({cols});",
            dep.name, dep.table
        ));
    }

    Ok(stmts.join("\n"))
}

// ─── INDEX ───────────────────────────────────────────────────────────────────

fn create_index_sql(table: &str, index: &IndexAst, schema: &str) -> Result<String> {
    let unique = if index.unique { "UNIQUE " } else { "" };
    let method = index.using.as_sql();
    let cols = index
        .fields
        .iter()
        .map(|f| format!("\"{f}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let idx_name = index.name.as_deref().unwrap_or_else(|| {
        Box::leak(format!("{table}_{}_idx", index.fields.join("_")).into_boxed_str())
    });

    let kind = if index.unique {
        "unique_index"
    } else {
        "index"
    };
    let field_refs: Vec<&str> = index.fields.iter().map(String::as_str).collect();
    let comment = managed_comment(kind, table, &field_refs);
    let comment_sql = comment_on_index_sql(idx_name, &comment, schema);

    // Dropped first so the operation means "this table carries exactly this index" rather than
    // "this index is new". The differ only emits an add when the live index does not match the
    // declared one, and `IF NOT EXISTS` on its own would keep the old one, so an index that changed
    // shape would silently stay as it was. Emitting a separate drop does not work either: adds are
    // applied before drops, so the pair would create nothing and then remove what was there.
    Ok(format!(
        "DROP INDEX IF EXISTS \"{schema}\".\"{idx_name}\";\nCREATE {unique}INDEX IF NOT EXISTS \"{idx_name}\" ON \"{schema}\".\"{table}\" USING {method} ({cols});\n{comment_sql}"
    ))
}

fn add_unique_constraint_sql(
    table: &str,
    column: &str,
    constraint: &str,
    schema: &str,
) -> Result<String> {
    let comment = managed_comment("unique_constraint", table, &[column]);
    let comment_sql = comment_on_constraint_sql(table, constraint, &comment, schema);
    Ok(format!(
        "ALTER TABLE \"{schema}\".\"{table}\" ADD CONSTRAINT \"{constraint}\" UNIQUE (\"{column}\");\n{comment_sql}"
    ))
}

// ─── FOREIGN KEY ─────────────────────────────────────────────────────────────

pub(crate) fn normalize_fk_action(action: &str) -> &'static str {
    match action.to_lowercase().replace([' ', '_', '-'], "").as_str() {
        "cascade" => "CASCADE",
        "setnull" => "SET NULL",
        "setdefault" => "SET DEFAULT",
        "restrict" => "RESTRICT",
        "noaction" => "NO ACTION",
        _ => "RESTRICT",
    }
}

fn add_fk_sql(
    table: &str,
    field_name: &str,
    rel: &RelationFieldAst,
    ref_table: &str,
    schema: &str,
    ref_schema: &str,
) -> Result<String> {
    // Derive FK column from field name when not explicitly set: "author" → "author_id".
    let derived;
    let fk_col = match rel.foreign_key.as_deref() {
        Some(fk) => fk,
        None => {
            derived = format!("{field_name}_id");
            &derived
        }
    };
    let ref_col = rel.references.as_deref().unwrap_or("id");
    let on_delete = normalize_fk_action(rel.on_delete.as_deref().unwrap_or("restrict"));
    let constraint = foreign_key_name(table, fk_col);

    Ok(format!(
        "ALTER TABLE \"{schema}\".\"{table}\" ADD CONSTRAINT \"{constraint}\" \
         FOREIGN KEY (\"{fk_col}\") REFERENCES \"{ref_schema}\".\"{ref_table}\" (\"{ref_col}\") \
         ON DELETE {on_delete} ON UPDATE CASCADE;"
    ))
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────

/// FK column SQL type for a target model PK (SERIAL → INTEGER, UUID → UUID, …).
fn fk_pg_type_for_model(ast: &SchemaAst, model_name: &str) -> String {
    match model_primary_key(ast, model_name) {
        Some((_, field)) => field_pg_type(field),
        None => "UUID".into(),
    }
}

/// `(table_name, pk_column, fk_pg_type)` for junction REFERENCES clauses.
fn junction_ref_for_model(ast: &SchemaAst, model_name: &str) -> (String, String, String) {
    let Some(model) = ast.models.iter().find(|m| m.name == model_name) else {
        return (to_snake_case(model_name), "id".into(), "UUID".into());
    };
    let (pk_col, pk_type) = match model_primary_key(ast, model_name) {
        Some((col, field)) => (col.to_string(), field_pg_type(field)),
        None => ("id".into(), "UUID".into()),
    };
    (model.table_name().to_string(), pk_col, pk_type)
}

fn model_primary_key<'a>(ast: &'a SchemaAst, model_name: &str) -> Option<(&'a str, &'a FieldAst)> {
    let model = ast.models.iter().find(|m| m.name == model_name)?;
    model
        .fields
        .iter()
        .find(|(_, f)| crate::differ::column_diff::field_is_primary_key(f))
        .map(|(name, field)| (name.as_str(), field))
}

fn to_snake_case(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(c.to_lowercase().next().unwrap());
    }
    out
}

/// `sha256:<hex>` over a migration file, the form `_supatype.migrations.hash` holds.
pub fn migration_hash(sql: &str) -> String {
    let mut h = Sha256::new();
    h.update(sql.as_bytes());
    format!("sha256:{}", hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    #[test]
    fn junction_fk_columns_match_serial_primary_keys() {
        let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Platform",
      "fields": {
        "id": {
          "kind": "serial",
          "primaryKey": true,
          "required": true,
          "annotations": { "db": { "pgType": "SERIAL", "unique": true } }
        },
        "games": {
          "kind": "relation",
          "cardinality": "manyToMany",
          "target": "Game"
        }
      },
      "options": { "timestamps": false, "softDelete": false },
      "annotations": {
        "db": { "tableName": "platform", "indexes": [] },
        "platform": { "access": {} }
      }
    },
    {
      "name": "Game",
      "fields": {
        "id": {
          "kind": "serial",
          "primaryKey": true,
          "required": true,
          "annotations": { "db": { "pgType": "SERIAL", "unique": true } }
        }
      },
      "options": { "timestamps": false, "softDelete": false },
      "annotations": {
        "db": { "tableName": "game", "indexes": [] },
        "platform": { "access": {} }
      }
    }
  ]
}"#;
        let ast = parser::parse(ast_json).unwrap();
        assert!(
            !ast.junction_tables.is_empty(),
            "expected junction tables, models={:?}",
            ast.models.iter().map(|m| &m.name).collect::<Vec<_>>()
        );
        let jt = &ast.junction_tables[0];
        let op = Operation::CreateJunctionTable {
            table: jt.name.clone(),
            fk_a: jt.fk_a.clone(),
            table_a: jt.model_a.clone(),
            fk_b: jt.fk_b.clone(),
            table_b: jt.model_b.clone(),
            risk: Risk::Safe,
        };
        let sql = render_operation(&op, "public", &ast).unwrap();
        assert!(
            sql.contains("INTEGER NOT NULL CONSTRAINT \"")
                && sql.contains("REFERENCES \"public\".\"game\""),
            "expected INTEGER FK to game, got:\n{sql}"
        );
        assert!(
            sql.contains("REFERENCES \"public\".\"platform\""),
            "expected INTEGER FK to platform, got:\n{sql}"
        );
        assert!(
            !sql.contains("UUID NOT NULL REFERENCES"),
            "must not hardcode UUID for serial PKs:\n{sql}"
        );
    }
}

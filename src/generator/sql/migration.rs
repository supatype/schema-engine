use crate::differ::column_diff::field_pg_type;
use crate::differ::{ColumnDependencySnapshot, DiffOutput, Operation, Risk};
use crate::generator::sql::column_conversion::{
    add_column_backfill_default, kind_migrate_pre_update, rich_text_default_sql,
    using_expr_for_alter, ConversionStrategy, ConversionStrategyKind,
};
use crate::ledger::reconcile;
use crate::managed::{
    comment_on_constraint_sql, expected_check_constraint_name, expected_model_constraint_name,
    expected_unique_constraint_name, foreign_key_name, managed_comment, primary_key_name,
    type_check_name,
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

/// The differ's operations alone, as the forward script of a migration file. For the tests and
/// tools that render a diff with no reconcile; a push goes through [`Migration`].
pub fn forward_sql(
    diff: &DiffOutput,
    force: bool,
    schema: &str,
    ast: &SchemaAst,
) -> Result<String> {
    Ok(Migration::render(diff, &[], force, schema, ast)?.up_script())
}

/// The differ's operations alone after the storage layer, as a push of a diff with no reconcile
/// would run them ([`Migration::apply_body`]).
pub fn push_storage_and_model_apply_body(
    storage_sql: &str,
    diff: &DiffOutput,
    force: bool,
    schema: &str,
    ast: &SchemaAst,
) -> Result<String> {
    let migration = Migration::render(diff, &[], force, schema, ast)?;
    Ok(migration.apply_body(storage_sql))
}

/// Single `BEGIN`…`COMMIT` script: [`push_storage_and_model_apply_body`] inside [`batch_sql`].
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

/// `body` as a single `BEGIN`…`COMMIT` script, for applying a push's body outside a push.
pub fn batch_sql(body: &str) -> String {
    format!(
        "-- supatype-engine: storage + model migration (single transaction)\nBEGIN;\n{}\nCOMMIT;",
        body.trim_end()
    )
}

/// The differ's operations alone as a migration file ([`Migration::file`]), for the tests that
/// render a diff with no reconcile.
pub fn generate(diff: &DiffOutput, force: bool, schema: &str, ast: &SchemaAst) -> Result<String> {
    Ok(Migration::render(diff, &[], force, schema, ast)?.file())
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

    // The trigger functions' schema and the extension `slugify` reads, before the reconcile
    // creates the functions (Phase 4.2). Unconditional: the shared functions always exist.
    lines.push("CREATE EXTENSION IF NOT EXISTS \"unaccent\";".into());
    lines.push(String::new());
    lines.push(super::triggers::platform_schema_sql().trim_end().into());
    lines.push(String::new());

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

/// The checks that field rules can be enforced here, emitted after the affordance functions the
/// labels point at. The labels themselves are ledger objects, set by the reconcile after these
/// have run: a schema that declares a masked column, pushed to a database without the masking
/// extension, fails here rather than applying and leaving the column readable.
fn render_mask_probe_lines(ast: &SchemaAst, schema: &str) -> Vec<String> {
    let sql = crate::generator::sql::rls::generate_mask_probes(ast, schema);
    if sql.trim().is_empty() {
        return Vec::new();
    }
    vec![
        "-- Field-level access: supatype_mask can enforce the labels".into(),
        sql.trim().into(),
        String::new(),
    ]
}

/// Everything re-asserted on every push rather than reconciled: the affordance functions, tier 2's
/// views with their privileges, and the masking probes. Idempotent by construction (`CREATE OR
/// REPLACE`, `GRANT`/`REVOKE` pairs, checks), so re-running them is what keeps them tracking the
/// schema. The model tables' privileges are ledger objects (Phase 4.7c), set by the reconcile.
///
/// Shared by both forward paths deliberately. They diverged before: the wrapped path applied the
/// derived privileges and the outer-body path did not, and the outer body is what every real push
/// actually runs, so the privileges were generated and never applied. Anything in this list
/// belongs on every path that applies a migration.
fn render_reasserted_lines(diff: &DiffOutput, ast: &SchemaAst, schema: &str) -> Vec<String> {
    // `can_*` functions live in the managed schema and read the table, they do not change it.
    let mut lines = render_can_function_lines(ast, schema);

    // One tier or the other, never both. Labels *and* views would give every deployment the views'
    // weaker aggregate behaviour, and the extension rejects the whole-row references the write
    // trigger needs.
    if diff.field_masking != crate::differ::FieldMaskingTier::Views {
        lines.extend(render_mask_probe_lines(ast, schema));
        return lines;
    }
    let views =
        crate::generator::sql::field_views::render_field_views(ast, &diff.field_view_plan, schema);
    if !views.trim().is_empty() {
        lines.push(
            "-- Field-level access, tier 2: api views (this database cannot load supatype_mask)"
                .into(),
        );
        lines.push(views.trim_end().into());
        lines.push(String::new());
    }
    // Under tier 2 the API reads the `api` views, so that is where the privileges belong. The views
    // are made again on every push, which takes their privileges with them, so these are made
    // again with them rather than recorded.
    let grants = crate::generator::sql::grants::generate_view_grants(
        ast,
        crate::generator::sql::field_views::VIEW_SCHEMA,
    );
    lines.push("-- Field-level access, tier 2: privileges on the api views".into());
    lines.push(grants.trim().into());
    lines.push(String::new());
    lines
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
            | Operation::AddForeignKey { risk, .. }
            | Operation::AddUniqueConstraint { risk, .. }
            | Operation::DropUniqueConstraint { risk, .. }
            | Operation::CreateRlsPolicy { risk, .. }
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
    lines.extend(render_reasserted_lines(diff, ast, schema));
    // Last, because it reads the snapshot tables the operations above create and the model tables
    // they reference. Errors rather than warns when the push failed to state who may see a draft.
    lines.extend(render_versions_lines(ast, schema)?);
    Ok(lines)
}

/// The reconcile's statements under their own heading, or nothing when it has none.
fn reconciled_section(statements: Vec<String>) -> Vec<String> {
    if statements.is_empty() {
        return Vec::new();
    }
    let mut lines = vec!["-- reconciled objects".to_string()];
    lines.extend(statements);
    lines.push(String::new());
    lines
}

/// One migration, rendered once: what `supatype migrate` prints, what a push applies and what the
/// history records. The differ's operations and the reconcile's actions in one body, so the three
/// can never show three different migrations (plan section 4; Phase 4.0).
pub struct Migration {
    /// The lines before the transaction: the forward header, `CREATE EXTENSION` lines and the
    /// auth helpers. Kept apart from `body` only so the file can print them before its `BEGIN`.
    preamble: Vec<String>,
    /// The forward statements, without `BEGIN`/`COMMIT`.
    body: Vec<String>,
    /// The statements that undo `body`, newest effect first, without `BEGIN`/`COMMIT`.
    down: Vec<String>,
    /// `sha256:` over [`Migration::up`], the form `_supatype.migrations.hash` holds.
    pub hash: String,
    /// How many of the forward statements the reconcile contributed.
    pub reconciled: usize,
    risk: &'static str,
}

impl Migration {
    /// Renders the diff's operations and then the reconcile's actions, refusing a destructive diff
    /// without `force` and a schema that declares an unmanaged table.
    pub fn render(
        diff: &DiffOutput,
        reconcile: &[reconcile::Action],
        force: bool,
        schema: &str,
        ast: &SchemaAst,
    ) -> Result<Migration> {
        assert_forward_allowed(diff, force)?;
        // The reconcile's removals first, so a drop the operations depend on has happened (a
        // foreign key into a table they drop, a function taking its row type; nothing ever
        // cascades), then the operations, then the reconcile's additions, which may need a table
        // or column the operations create. A function nothing of the operations depends on waits
        // for them instead: the trigger that depends on it may sit on a table they drop, and goes
        // with the table.
        let dropped_tables: Vec<String> = diff
            .operations
            .iter()
            .filter_map(|op| match op {
                Operation::DropTable { table, .. } => Some(table.clone()),
                _ => None,
            })
            .collect();
        let (late, early): (Vec<&reconcile::Action>, Vec<&reconcile::Action>) = reconcile
            .iter()
            .partition(|a| a.removal_is_late(&dropped_tables));
        let removals: Vec<String> = early.iter().filter_map(|a| a.removal_sql()).collect();
        let late_removals: Vec<String> = late.iter().filter_map(|a| a.removal_sql()).collect();
        let additions: Vec<String> = reconcile
            .iter()
            .flat_map(reconcile::Action::addition_sql)
            .collect();
        let mut body = reconciled_section(removals.clone());
        body.extend(render_forward_core(diff, schema, ast)?);
        body.extend(reconciled_section(late_removals.clone()));
        body.extend(reconciled_section(additions.clone()));

        // Undone in reverse: the additions, the late removals, the operations, then what the
        // early removals took.
        let mut down = reconciled_section(
            reconcile
                .iter()
                .rev()
                .filter_map(reconcile::Action::undo_addition)
                .chain(late.iter().rev().filter_map(|a| a.undo_removal()))
                .collect(),
        );
        down.extend(super::rollback::statements(diff, schema)?);
        down.extend(reconciled_section(
            early
                .iter()
                .rev()
                .filter_map(|a| a.undo_removal())
                .collect(),
        ));

        let mut migration = Migration {
            preamble: render_forward_preamble(diff),
            body,
            down,
            hash: String::new(),
            reconciled: removals.len() + late_removals.len() + additions.len(),
            risk: if diff.summary.is_destructive {
                "destructive"
            } else if diff.summary.cautious > 0 {
                "cautious"
            } else {
                "safe"
            },
        };
        migration.hash = migration_hash(&migration.up());
        Ok(migration)
    }

    /// The forward statements, preamble included, for running inside a transaction the caller
    /// owns. What the history stores as `sql_up`.
    pub fn up(&self) -> String {
        let mut lines = self.preamble.clone();
        lines.extend(self.body.iter().cloned());
        lines.join("\n")
    }

    /// The statements that undo [`Migration::up`], for running inside a transaction the caller
    /// owns. What the history stores as `sql_down`.
    pub fn down(&self) -> String {
        self.down.join("\n")
    }

    /// The forward statements as a script of their own: the preamble, then the body inside
    /// `BEGIN`/`COMMIT`. `CREATE EXTENSION` stays before the `BEGIN` (legacy layout; still one
    /// `sqlx::raw_sql` batch).
    pub fn up_script(&self) -> String {
        let mut lines = self.preamble.clone();
        lines.push("BEGIN;".into());
        lines.push(String::new());
        lines.extend(self.body.iter().cloned());
        lines.push("COMMIT;".into());
        lines.join("\n")
    }

    /// The migration file, forward then rollback, for saving to disk.
    pub fn file(&self) -> String {
        format!(
            "-- Migration generated by supatype-engine v{ver}\n\
             -- Hash: {hash}\n\
             -- Risk: {risk}\n\n\
             {forward}\n\n\
             {rollback}",
            ver = env!("ENGINE_VERSION"),
            hash = self.hash,
            risk = self.risk,
            forward = self.up_script(),
            rollback = super::rollback::script(&self.down),
        )
    }

    /// What a push runs inside its transaction: the storage layer, then this migration. The
    /// storage layer is re-asserted on every push until its kinds move onto the reconcile.
    pub fn apply_body(&self, storage_sql: &str) -> String {
        format!("{}\n{}", storage_sql.trim(), self.up().trim_end())
    }
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
        Operation::AddForeignKey {
            table, relation, ..
        } => format!("Add FK: {table} -> {}", relation.target),
        Operation::AddUniqueConstraint { table, column, .. } => {
            format!("Add unique constraint: {table}.{column}")
        }
        Operation::DropUniqueConstraint {
            table, constraint, ..
        } => format!("Drop unique constraint: {table}.{constraint}"),
        Operation::CreateRlsPolicy { table, policy, .. } => {
            format!("Create RLS policy: {table}.{policy}")
        }
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
        // Never `CASCADE` (plan 3.3): what depends on the table and is ours is dropped before it
        // (its draft and api views here, a foreign key from another table or an affordance
        // function by the reconcile); what depends on it and is not ours blocks the drop and is
        // named, rather than vanishing.
        Operation::DropTable { table, .. } => Ok(format!(
            "{}{}DROP TABLE IF EXISTS \"{schema}\".\"{table}\";",
            super::versions::drop_views_in_schema_sql("draft", &[table]),
            super::versions::drop_views_in_schema_sql(super::field_views::VIEW_SCHEMA, &[table]),
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
        Operation::CreateRlsPolicy { table, policy, .. } => {
            render_create_rls_policy_sql(table, policy, schema, ast)
        }
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

/// The columns a model's options add beside its fields: `timestamps` and `softDelete`, unless a
/// field of the same name already provides one. One list, so the `CREATE TABLE` that makes them and
/// the desired set that records them (Phase 4.9) cannot disagree.
pub fn option_columns(model: &ModelAst) -> Vec<(&'static str, &'static str)> {
    let has = |names: &[&str]| names.iter().any(|n| model.fields.contains_key(*n));
    let mut out = Vec::new();
    if model.options.timestamps && !has(&["timestamps"]) {
        if !has(&["created_at", "createdAt"]) {
            out.push(("created_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()"));
        }
        if !has(&["updated_at", "updatedAt"]) {
            out.push(("updated_at", "TIMESTAMPTZ NOT NULL DEFAULT NOW()"));
        }
    }
    if model.options.soft_delete && !has(&["softDelete", "deleted_at"]) {
        out.push(("deleted_at", "TIMESTAMPTZ"));
    }
    out
}

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

    for (column, definition) in option_columns(model) {
        col_defs.push(format!("    \"{column}\" {definition}"));
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

    // Model-level constraints, as named table constraints. Checks carry no stamp: the ledger
    // records them (plan 3.2) and their comments are the user's.
    for (index, rule) in model.annotations.db.constraints.iter().enumerate() {
        let expr = crate::generator::sql::constraints::constraint_to_expr(rule)?;
        let constraint = expected_model_constraint_name(table, index);
        statements.push(format!(
            "ALTER TABLE \"{schema}\".\"{table}\" ADD CONSTRAINT \"{constraint}\" CHECK ({expr});"
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

    // Singleton (global config): enforce exactly one row via a unique index on an expression.
    // Recorded by the ledger (Phase 4.3), so no stamp.
    if model.options.singleton {
        let idx_name = format!("{table}_singleton_idx");
        statements.push(format!(
            "CREATE UNIQUE INDEX IF NOT EXISTS \"{idx_name}\" \
             ON \"{schema}\".\"{table}\" ((TRUE));"
        ));
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
    let derived = format!("{table}_{}_idx", index.fields.join("_"));
    let idx_name = index.name.as_deref().unwrap_or(&derived);

    // The `CREATE` alone, no stamp (the ledger is the record, plan section 6) and no drop before
    // it: an index whose shape changed is the reconcile's `Replace`, which drops and recreates.
    Ok(format!(
        "CREATE {unique}INDEX IF NOT EXISTS \"{idx_name}\" ON \"{schema}\".\"{table}\" USING {method} ({cols});"
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

use crate::differ::column_diff::field_pg_type;
use crate::differ::{DiffOutput, Operation, Risk};
use crate::generator::sql::column_conversion::{
    add_column_backfill_default, kind_migrate_pre_update, rich_text_default_sql,
    using_expr_for_alter, ConversionStrategy, ConversionStrategyKind,
};
use crate::generator::sql::online::{self, AfterCommit, Online, OnlineTables};
use crate::generator::sql::recreate::{recreate_column_sql, Reconciled};
use crate::generator::sql::settled::Settled;
use crate::introspector::fingerprint::ObjectKind;
use crate::ledger::reconcile;
use crate::managed::ObjectNames;
use crate::parser::ast::{
    scalar_of, DefaultValueAst, FieldAst, IndexAst, ModelAst, RelationCardinality,
    RelationFieldAst, ScalarFieldAst, SchemaAst, ValidationAst,
};
use crate::sql_quote::{comment_text, quote_ident, quote_literal, quote_qualified, raise_message};
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
             Nothing was applied. These tables already exist and Supatype did not create them, so \
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
    assert_consent(diff, force)
}

/// Refuse, without `force`, a diff that drops data or rewrites a large table. Public because a push
/// asks it before it renders anything, to record the refusal with what it would have run.
pub fn assert_consent(diff: &DiffOutput, force: bool) -> Result<()> {
    if diff.summary.is_destructive && !force {
        bail!(
            "{} destructive operation(s) detected. Use --force to proceed.",
            diff.summary.destructive
        );
    }
    // IN-C 3: a rewrite that stops a large table's reads and writes needs the same consent.
    if let Some(refusal) = crate::differ::rewrites::refusal(&diff.rewrites).filter(|_| !force) {
        bail!(refusal);
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
    Ok(format!(
        "{}\n{}",
        storage_sql.trim(),
        migration.up().trim_end()
    ))
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

/// The extensions this diff needs, in the order they are created: pgcrypto (`gen_random_uuid()`
/// defaults), vector (pgvector) and postgis (`GEOGRAPHY`) when a column asks for one, and always
/// `unaccent`, which `slugify` reads and the shared functions always include. `FieldAst::Custom` is
/// not analysed here.
fn needed_extensions(diff: &DiffOutput) -> Vec<&'static str> {
    let wanted = [
        ("pgcrypto", needs_pgcrypto(diff)),
        ("vector", needs_vector(diff)),
        ("postgis", needs_postgis(diff)),
        ("unaccent", true),
    ];
    wanted
        .into_iter()
        .filter_map(|(name, needed)| needed.then_some(name))
        .collect()
}

// Extensions go before the inner `BEGIN`, in their own schema and never in `public`
// (`super::extensions`), which is created first.
fn render_forward_preamble(diff: &DiffOutput) -> Vec<String> {
    let mut lines = vec![
        "-- ============================================================".into(),
        "-- FORWARD MIGRATION".into(),
        "-- ============================================================".into(),
        String::new(),
        super::extensions::schema_sql(),
        String::new(),
    ];
    for name in needed_extensions(diff) {
        lines.push(super::extensions::create_sql(name));
        lines.push(String::new());
    }

    // The trigger functions' schema, before the reconcile creates the functions (Phase 4.2).
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

/// The schema's names for each end of a relation, in the `@graphql` directive pg_graphql reads
/// from the key's comment. Re-asserted on every push, after the reconcile's additions, which make
/// the keys; a key whose comment already holds its directive is not touched.
fn render_graphql_name_lines(ast: &SchemaAst, schema: &str) -> Vec<String> {
    let sql = super::graphql_names::graphql_names_sql(ast, schema);
    if sql.is_empty() {
        return Vec::new();
    }
    vec![
        "-- GraphQL relation names, as the schema declares them".into(),
        sql,
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
fn render_reasserted_lines(
    diff: &DiffOutput,
    ast: &SchemaAst,
    schema: &str,
    settled: &Settled,
) -> Vec<String> {
    // `can_*` functions live in the managed schema and read the table, they do not change it.
    let mut lines = render_can_function_lines(ast, schema);

    // One tier or the other, never both. Labels *and* views would give every deployment the views'
    // weaker aggregate behaviour, and the extension rejects the whole-row references the write
    // trigger needs.
    if diff.field_masking != crate::differ::FieldMaskingTier::Views {
        lines.extend(render_mask_probe_lines(ast, schema));
        return lines;
    }
    // Under tier 2 the API reads the `api` views, so that is where the privileges belong. A view is
    // made again when it changed, which takes its privileges with it, so each view's are made with
    // it, and recorded on the ledger as it is (F14). One in place as this push wants it is left
    // alone: making it again locks it against every API read (LK7).
    let views = settled.leave_out(
        &crate::generator::sql::field_views::render_field_views(ast, &diff.field_view_plan, schema),
        schema,
    );
    if !views.trim().is_empty() {
        lines.push(
            "-- Field-level access, tier 2: api views (this database cannot load supatype_mask)"
                .into(),
        );
        lines.push(views.trim_end().into());
        lines.push(String::new());
    }
    lines
}

/// Under tier 2, the functions a policy evaluated as the views' owner may call: after the drafts
/// layer, which makes some of them. Nothing for the other tiers.
fn render_owner_reach_lines(diff: &DiffOutput, schema: &str) -> Vec<String> {
    if diff.field_masking != crate::differ::FieldMaskingTier::Views
        || diff.field_view_plan.is_empty()
    {
        return Vec::new();
    }
    vec![
        "-- Field-level access, tier 2: what the views' owner may call".into(),
        crate::generator::sql::field_views::owner_reach_sql(
            schema,
            crate::generator::sql::field_views::plan_owner(&diff.field_view_plan),
        )
        .trim_end()
        .into(),
        String::new(),
    ]
}

/// What a migration's forward body is rendered from.
struct Forward<'a> {
    diff: &'a DiffOutput,
    schema: &'a str,
    ast: &'a SchemaAst,
    /// What is in place as the push wants it, left out of the re-asserted scripts (LK7).
    settled: Settled,
    /// The tables with rows, on which `SET NOT NULL` is proved after commit (LK7).
    tables: &'a OnlineTables,
    /// What the reconcile does with the engine's objects a recreated column's dependents may be.
    reconciled: Reconciled,
}

/// `sql` rendered for `op`, with a `SET NOT NULL` on a table with rows replaced by its helper
/// check, which `after` validates once the transaction has committed (LK7). Not with an identity
/// change in the same operation, which needs the column `NOT NULL` before it.
fn online_not_null(
    op: &Operation,
    sql: String,
    f: &Forward<'_>,
    after: &mut AfterCommit,
) -> String {
    let Operation::AlterColumn {
        table,
        column,
        changes,
        ..
    } = op
    else {
        return sql;
    };
    if !f.tables.with_rows.contains(table) || !crate::differ::rewrites::not_null_online(changes) {
        return sql;
    }
    let set = format!(
        "{} SET NOT NULL;",
        alter_column_prefix(f.schema, table, column)
    );
    if !sql.contains(&set) {
        return sql;
    }
    let not_null = online::NotNull::new(f.schema, table, column);
    let sql = sql.replacen(&set, &not_null.add_sql(), 1);
    after.not_null.push(not_null);
    sql
}

fn render_forward_operation_lines(f: &Forward<'_>, after: &mut AfterCommit) -> Result<Vec<String>> {
    let (diff, schema, ast) = (f.diff, f.schema, f.ast);
    let mut lines = Vec::new();
    let names = ObjectNames::for_schema(ast);

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
            | Operation::CreateRlsPolicy { risk, .. }
            | Operation::CreateJunctionTable { risk, .. }
            | Operation::CreateVersionsTable { risk, .. }
            | Operation::EnableExtension { risk, .. }
            | Operation::RelocateExtension { risk, .. } => match risk {
                Risk::Safe => "safe",
                Risk::Cautious => "cautious",
                Risk::Destructive => "destructive",
            },
        };

        let sql = online_not_null(
            op,
            render_operation_reconciled(op, schema, ast, &names, &f.reconciled)?,
            f,
            after,
        );
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
fn render_forward_core(f: &Forward<'_>, after: &mut AfterCommit) -> Result<Vec<String>> {
    let (diff, schema, ast, settled) = (f.diff, f.schema, f.ast, &f.settled);
    let mut lines = Vec::new();
    // A CHECK that calls a function is validated when the table is created, so the helper
    // functions have to exist before any operation line runs, not alongside the triggers.
    lines.push(super::constraint_helpers::generate());
    // Before the operations, because a draft view depends on every column it selects and would
    // otherwise refuse a column drop. Recreated by the versions layer at the end of this same
    // migration, so the window where they are missing is inside one transaction.
    let drop_drafts = crate::generator::sql::versions::drop_draft_views_sql(
        ast,
        &super::settled::changed_tables(&diff.operations),
    );
    if !drop_drafts.trim().is_empty() {
        lines.push(drop_drafts.trim_end().to_string());
        lines.push(String::new());
    }
    lines.extend(render_forward_operation_lines(f, after)?);
    lines.extend(render_reasserted_lines(diff, ast, schema, settled));
    // Last, because it reads the snapshot tables the operations above create and the model tables
    // they reference. Errors rather than warns when the push failed to state who may see a draft.
    lines.extend(render_versions_lines(ast, schema, settled)?);
    lines.extend(render_owner_reach_lines(diff, schema));
    Ok(lines)
}

/// The body's first statement: an extension's types resolve wherever it is installed, `extensions`
/// or, for a PostGIS an older engine left there, `public`. Inside the transaction, so it holds for
/// the statements a file runs after its `BEGIN` as it does for a push.
fn search_path_section() -> Vec<String> {
    vec![super::extensions::search_path_sql(), String::new()]
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
    /// The storage layer: the `storage` schema and tables, the bucket rows, and row-level security
    /// on `storage.objects`, which the reconcile's bucket policies in `body` are created on. Empty
    /// when the schema declares no bucket. Re-asserted whole on every push until its kinds move onto
    /// the reconcile, so it is not part of `hash`.
    storage: String,
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
    /// The project schema the migration applies to, which names what the file's rollback section
    /// refuses to undo.
    schema: String,
    /// What runs once the transaction has committed: the concurrent index builds and the
    /// validations (IN-C 2). Empty when every table the push changes is new or has no rows.
    pub after_commit: AfterCommit,
}

/// What a migration file writes beside the migration, so that applying it by hand is a push: the
/// engine's own tables, then the history row and the ledger rows the push would write. Empty for
/// a file that records nothing.
#[derive(Debug, Default)]
pub struct Recording {
    /// Statements, closed with a `;` or not.
    pub bootstrap: Vec<String>,
    /// Statements, closed with a `;` or not.
    pub ledger: Vec<String>,
    /// What the rollback section runs after undoing the migration: the ledger put back and the
    /// migration marked rolled back, as `supatype rollback` does (HI2). Statements, closed with a
    /// `;` or not.
    pub restore: Vec<String>,
}

const BOOTSTRAP_HEADER: &str =
    "-- Supatype's own tables and claim readers, created or repaired as a push does";
const LEDGER_HEADER: &str =
    "-- What a push records: the history row, and which objects are Supatype's";
const RESTORE_HEADER: &str =
    "-- What a rollback records: the ledger as it was before the push, and the migration rolled back";

/// `statements` under `header`, each closed with one `;`, or nothing when there are none.
fn push_section(lines: &mut Vec<String>, header: &str, statements: &[String]) {
    if statements.is_empty() {
        return;
    }
    lines.push(header.into());
    lines.extend(
        statements
            .iter()
            .map(|s| format!("{};", s.trim_end().trim_end_matches(';'))),
    );
    lines.push(String::new());
}

impl Migration {
    /// Renders the diff's operations and then the reconcile's actions, refusing a destructive diff
    /// without `force` and a schema that declares an unmanaged table. Every statement runs in the
    /// transaction: [`Migration::render_online`] is the form for a database whose tables hold rows.
    pub fn render(
        diff: &DiffOutput,
        reconcile: &[reconcile::Action],
        force: bool,
        schema: &str,
        ast: &SchemaAst,
    ) -> Result<Migration> {
        Migration::render_online(
            diff,
            reconcile,
            force,
            schema,
            ast,
            &OnlineTables::default(),
        )
    }

    /// [`Migration::render`], with each new index on a table in `tables.with_rows` built
    /// concurrently after commit, and each key or check added to one `NOT VALID` and validated
    /// after commit (IN-C 2).
    pub fn render_online(
        diff: &DiffOutput,
        reconcile: &[reconcile::Action],
        force: bool,
        schema: &str,
        ast: &SchemaAst,
        tables: &OnlineTables,
    ) -> Result<Migration> {
        assert_forward_allowed(diff, force)?;
        // The reconcile's removals first, so a drop the operations depend on has happened (a
        // foreign key into a table they drop, a function taking its row type; nothing ever
        // cascades), then the operations, then the reconcile's additions, which may need a table
        // or column the operations create. A function nothing of the operations depends on waits
        // for them instead: the trigger that depends on it may sit on a table they drop, and goes
        // with the table. A table they rename counts as one they drop: its old name, which an
        // affordance function's identity names (its row type), is gone once they have run, so the
        // function is dropped before them, and its rollback re-created after the table has its old
        // name back.
        let dropped_tables: Vec<String> = diff
            .operations
            .iter()
            .filter_map(|op| match op {
                Operation::DropTable { table, .. } => Some(table.clone()),
                Operation::RenameTable { from, .. } => Some(from.clone()),
                _ => None,
            })
            .collect();
        let (late, mut early): (Vec<&reconcile::Action>, Vec<&reconcile::Action>) = reconcile
            .iter()
            .partition(|a| a.removal_is_late(&dropped_tables));
        // Dependents first across every removal, not only among the drops: a foreign key a push
        // replaces or rebuilds goes before the key it references, which may itself be replaced.
        early.sort_by_key(|a| std::cmp::Reverse(reconcile::creation_rank(a.key().kind)));
        let (additions, mut after_commit) = split_online(reconcile, schema, tables);
        // An index rebuilt after commit keeps its old one until the new one is swapped in.
        let rebuilt = after_commit.rebuilt_keys();
        let removal = |a: &&reconcile::Action| {
            (!rebuilt.contains(a.key()))
                .then(|| a.removal_sql())
                .flatten()
        };
        let removals: Vec<String> = early.iter().filter_map(removal).collect();
        let late_removals: Vec<String> = late.iter().filter_map(removal).collect();
        let mut body = search_path_section();
        body.extend(reconciled_section(removals.clone()));
        let forward = Forward {
            diff,
            schema,
            ast,
            settled: Settled::of(reconcile, &diff.operations),
            tables,
            reconciled: Reconciled::of(reconcile),
        };
        body.extend(render_forward_core(&forward, &mut after_commit)?);
        body.extend(reconciled_section(late_removals.clone()));
        body.extend(reconciled_section(additions.clone()));
        body.extend(render_graphql_name_lines(ast, schema));

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
        down.extend(super::rollback::statements(diff, schema, ast)?);
        down.extend(reconciled_section(
            early
                .iter()
                .rev()
                .filter_map(|a| a.undo_removal())
                .collect(),
        ));

        let storage = if ast.storage_buckets.is_empty() {
            String::new()
        } else {
            super::storage::generate(ast)?
        };

        let mut migration = Migration {
            storage,
            preamble: render_forward_preamble(diff),
            body,
            down,
            after_commit: AfterCommit::default(),
            hash: String::new(),
            reconciled: removals.len()
                + late_removals.len()
                + additions.len()
                + after_commit.indexes.len(),
            risk: if diff.summary.is_destructive {
                "destructive"
            } else if diff.summary.cautious > 0 {
                "cautious"
            } else {
                "safe"
            },
            schema: schema.to_string(),
        };
        migration.after_commit = after_commit;
        migration.hash = migration_hash(&migration.hashed());
        Ok(migration)
    }

    /// This migration with `statements` last in its transaction: the data a push moves once
    /// every change to the tables has been made (block entries kept in the flat shape, say). The
    /// hash covers them, so the history records the migration that ran. Their effect on the rows
    /// is not undone by a rollback, which the rollback section says.
    pub fn with_data_section(mut self, header: &str, statements: Vec<String>) -> Migration {
        if statements.is_empty() {
            return self;
        }
        self.body.push(format!("-- {header}"));
        self.body.extend(statements);
        self.body.push(String::new());
        // Newest effect first, as the rest of `down` is ordered.
        self.down
            .insert(0, format!("-- Not undone, the rows keep it: {header}"));
        self.hash = migration_hash(&self.hashed());
        self
    }

    /// What [`Migration::hash`] is taken over: [`Migration::up`], then what runs after commit.
    fn hashed(&self) -> String {
        let after = self.after_commit.statements();
        if after.is_empty() {
            return self.up();
        }
        format!("{}\n{}", self.up(), after.join("\n"))
    }

    /// [`Migration::apply_body`] and then what runs after commit: what the history records as the
    /// migration's `sql_up`.
    pub fn recorded_up(&self) -> String {
        let section = online::file_section(&self.after_commit);
        if section.is_empty() {
            return self.apply_body();
        }
        format!("{}\n{section}", self.apply_body())
    }

    /// The forward statements, preamble included, for running inside a transaction the caller
    /// owns. What `hash` is taken over; the history stores [`Migration::apply_body`].
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

    /// The migration file, forward then rollback, for saving to disk. The forward section is what a
    /// push runs ([`Migration::apply_body`]): the storage layer first, inside the transaction, so
    /// the bucket policies have `storage.objects` to be created on.
    pub fn file(&self) -> String {
        self.file_recording(&Recording::default())
    }

    /// [`Migration::file`] with `recording` inside the forward transaction: the bootstrap after
    /// its `BEGIN`, the history and ledger writes before its `COMMIT`.
    pub fn file_recording(&self, recording: &Recording) -> String {
        format!(
            "-- Migration generated by supatype-engine v{ver}\n\
             -- Hash: {hash}\n\
             -- Risk: {risk}\n\n\
             {forward}\n\n\
             {rollback}",
            ver = env!("ENGINE_VERSION"),
            hash = self.hash,
            risk = self.risk,
            forward = self.applied_script(recording),
            rollback = super::rollback::script(&self.down_recording(recording), &self.schema),
        )
    }

    /// [`Migration::down`]'s statements, then what the rollback records.
    fn down_recording(&self, recording: &Recording) -> Vec<String> {
        let mut lines = self.down.clone();
        push_section(&mut lines, RESTORE_HEADER, &recording.restore);
        lines
    }

    /// [`Migration::up_script`] with the storage layer at the start of the transaction.
    fn applied_script(&self, recording: &Recording) -> String {
        let mut lines = self.preamble.clone();
        lines.push("BEGIN;".into());
        lines.push(String::new());
        push_section(&mut lines, BOOTSTRAP_HEADER, &recording.bootstrap);
        if !self.storage.trim().is_empty() {
            lines.push(self.storage.trim_end().to_string());
            lines.push(String::new());
        }
        lines.extend(self.body.iter().cloned());
        push_section(&mut lines, LEDGER_HEADER, &recording.ledger);
        lines.push("COMMIT;".into());
        let after = online::file_section(&self.after_commit);
        if !after.is_empty() {
            lines.push(String::new());
            lines.push(after);
        }
        lines.join("\n")
    }

    /// What a push runs inside its transaction, and what the history stores as `sql_up`: the
    /// storage layer, then this migration. The storage layer is re-asserted on every push until
    /// its kinds move onto the reconcile.
    pub fn apply_body(&self) -> String {
        if self.storage.trim().is_empty() {
            return self.up().trim_end().to_string();
        }
        format!("{}\n{}", self.storage.trim(), self.up().trim_end())
    }
}

/// The reconcile's additions that run in the transaction, and what runs after it commits: a new
/// index on a table with rows is built concurrently, and a key or check on one is added `NOT VALID`
/// and validated (IN-C 2). An index made again where an INVALID one of its name was left is
/// preceded by the drop of that one, which introspection does not see.
fn split_online(
    reconcile: &[reconcile::Action],
    schema: &str,
    tables: &OnlineTables,
) -> (Vec<String>, AfterCommit) {
    let mut additions = Vec::new();
    let mut after = AfterCommit::default();
    for action in reconcile {
        let key = action.key();
        let placed = action.addition_sql();
        match online::online(action, schema, tables) {
            Online::Concurrent(index) => after.indexes.push(index),
            Online::NotValid { create_sql } => {
                let original = action.create_sql().unwrap_or_default();
                additions.extend(placed.into_iter().map(|sql| {
                    if sql == original {
                        create_sql.clone()
                    } else {
                        sql
                    }
                }));
                after.validate(key.clone());
            }
            Online::No => {
                let left_invalid = key.kind == ObjectKind::Index
                    && key.schema == schema
                    && tables.invalid_indexes.contains(&key.name);
                if left_invalid && !placed.is_empty() {
                    additions.push(online::drop_invalid_sql(key));
                }
                additions.extend(placed);
            }
        }
    }
    for key in &tables.unvalidated {
        after.validate(key.clone());
    }
    (additions, after)
}

/// The drafts and publishing layer, when this schema has a versioned model.
fn render_versions_lines(ast: &SchemaAst, schema: &str, settled: &Settled) -> Result<Vec<String>> {
    let sql = settled.leave_out(
        &crate::generator::sql::versions::render_versions_layer(ast, schema)?,
        schema,
    );
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
        Operation::CreateRlsPolicy { table, policy, .. } => {
            format!("Create RLS policy: {table}.{policy}")
        }
        Operation::CreateJunctionTable { table, .. } => format!("Create junction table: {table}"),
        Operation::CreateVersionsTable { versions_table, .. } => {
            format!("Create versions table: {versions_table}")
        }
        Operation::EnableExtension { name, .. } => format!("Enable extension: {name}"),
        Operation::RelocateExtension { name, from, to, .. } => {
            format!("Move extension: {name} from {from} to {to}")
        }
    }
}

fn render_create_rls_policy_sql(
    table: &str,
    policy: &str,
    schema: &str,
    ast: &SchemaAst,
) -> Result<String> {
    // Read back through the one naming rule, since a long table's name is shortened in front of
    // the suffix and no longer starts with `{table}_`.
    let Some(suffix) = ["select", "insert", "update", "delete"]
        .into_iter()
        .find(|suffix| crate::managed::policy_name(table, suffix) == policy)
    else {
        bail!("CreateRlsPolicy: policy name {policy} is not one of the policies of {table}");
    };

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

    // A junction has no model of its own: its policies follow from its ends
    // (`junction_access`).
    let junction = ast
        .junction_tables
        .iter()
        .find(|j| j.name == table)
        .ok_or_else(|| anyhow!("CreateRlsPolicy: unknown table {table}"))?;
    crate::generator::sql::junction_access::policy_sql(schema, ast, junction, suffix)
}

pub(crate) fn render_operation(op: &Operation, schema: &str, ast: &SchemaAst) -> Result<String> {
    render_operation_named(op, schema, ast, &ObjectNames::for_schema(ast))
}

/// [`render_operation`] with the schema's names already chosen, for a caller rendering many
/// operations of one schema.
pub(crate) fn render_operation_named(
    op: &Operation,
    schema: &str,
    ast: &SchemaAst,
    names: &ObjectNames,
) -> Result<String> {
    render_operation_reconciled(op, schema, ast, names, &Reconciled::default())
}

/// [`render_operation_named`], knowing what the push's reconcile does with the engine's objects,
/// which decides what a recreated column's dependents need of the recreate.
fn render_operation_reconciled(
    op: &Operation,
    schema: &str,
    ast: &SchemaAst,
    names: &ObjectNames,
    reconciled: &Reconciled,
) -> Result<String> {
    match op {
        Operation::CreateTable { model, .. } => create_table_sql(model, schema, ast, names),
        // Never `CASCADE` (plan 3.3): what depends on the table and is ours is dropped before it
        // (its draft and api views here, a foreign key from another table or an affordance
        // function by the reconcile); what depends on it and is not ours blocks the drop and is
        // named, rather than vanishing.
        Operation::DropTable { table, .. } => Ok(format!(
            "{}{}DROP TABLE IF EXISTS {};",
            super::versions::drop_views_in_schema_sql("draft", &[table]),
            super::versions::drop_views_in_schema_sql(super::field_views::VIEW_SCHEMA, &[table]),
            quote_qualified(schema, table),
        )),
        // A serial's sequence is named after its table, and keeps the old name through a rename
        // unless it is renamed too: the desired set and the ledger know it by the new one.
        Operation::RenameTable { from, to, .. } => {
            let mut sql = format!(
                "ALTER TABLE {} RENAME TO {};",
                quote_qualified(schema, from),
                quote_ident(to)
            );
            for column in serial_columns(ast, to) {
                sql.push('\n');
                sql.push_str(&rename_serial_sequence_sql(
                    schema,
                    to,
                    &column,
                    &names.sequence(to, &column),
                ));
            }
            Ok(sql)
        }
        Operation::AddColumn {
            table,
            column,
            field,
            ..
        } => add_column_sql(names, ast, schema, table, column, field),
        Operation::DropColumn { table, column, .. } => Ok(format!(
            "ALTER TABLE {} DROP COLUMN IF EXISTS {};",
            quote_qualified(schema, table),
            quote_ident(column)
        )),
        Operation::RenameColumn {
            table, from, to, ..
        } => {
            let mut sql = format!(
                "ALTER TABLE {} RENAME COLUMN {} TO {};",
                quote_qualified(schema, table),
                quote_ident(from),
                quote_ident(to)
            );
            if serial_columns(ast, table).contains(to) {
                sql.push('\n');
                sql.push_str(&rename_serial_sequence_sql(
                    schema,
                    table,
                    to,
                    &names.sequence(table, to),
                ));
            }
            Ok(sql)
        }
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
            changes,
            ..
        } => {
            let recreate = recreate_column_sql(
                names,
                table,
                column,
                field.as_ref(),
                dependencies,
                schema,
                reconciled,
            )?;
            Ok(match changes.get("generated") {
                Some(generated) => {
                    generated_column_sql(schema, table, column, generated, &recreate)
                }
                None => recreate,
            })
        }
        Operation::AddIndex { table, index, .. } => create_index_sql(names, table, index, schema),
        Operation::AddForeignKey {
            table,
            field_name,
            relation,
            ref_table,
            ref_schema,
            ..
        } => add_fk_sql(
            names,
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
        } => Ok(create_junction_table_sql(
            names,
            schema,
            table,
            [
                (fk_a, junction_ref_for_model(ast, table_a)),
                (fk_b, junction_ref_for_model(ast, table_b)),
            ],
        )),
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
        Operation::EnableExtension { name, .. } => Ok(super::extensions::create_sql(name)),
        Operation::RelocateExtension { name, to, .. } => {
            Ok(super::extensions::relocate_sql(name, to))
        }
    }
}

/// `ADD COLUMN` for one column the differ found missing.
fn add_column_sql(
    names: &ObjectNames,
    ast: &SchemaAst,
    schema: &str,
    table: &str,
    column: &str,
    field: &FieldAst,
) -> Result<String> {
    let target = quote_qualified(schema, table);
    // BelongsTo relations produce an FK column typed like the target PK;
    // the FK constraint is a separate AddForeignKey operation.
    if let FieldAst::Relation(rel) = field {
        if matches!(rel.cardinality, RelationCardinality::BelongsTo) {
            let uniq = unique_clause(names, table, column, rel.unique_fk);
            let req = if rel.required { " NOT NULL" } else { "" };
            let pg_type = fk_pg_type_for_model(ast, &rel.target);
            return Ok(format!(
                "ALTER TABLE {target} ADD COLUMN {} {pg_type}{uniq}{req};",
                quote_ident(column)
            ));
        }
    }
    // Composite fields: the differ stores the parent composite FieldAst
    // against each expanded column name, so we emit the right DDL here.
    if let Some(definition) = composite_column_definition(names, table, column, field) {
        return Ok(format!(
            "ALTER TABLE {target} ADD COLUMN IF NOT EXISTS {definition};"
        ));
    }
    let col_def = field_to_column_def(names, table, column, field)?;
    if let Some(backfill) = add_column_backfill_default(field) {
        return Ok(format!(
            "ALTER TABLE {target} ADD COLUMN {col_def} DEFAULT {backfill};\n\
             ALTER TABLE {target} ALTER COLUMN {} DROP DEFAULT;",
            quote_ident(column)
        ));
    }
    Ok(format!("ALTER TABLE {target} ADD COLUMN {col_def};"))
}

/// The definition of a column a composite field (`timestamps`, `publishable`, `softDelete`) expands
/// to, or `None` for any other column.
fn composite_column_definition(
    names: &ObjectNames,
    table: &str,
    column: &str,
    field: &FieldAst,
) -> Option<String> {
    Some(match (field, column) {
        (FieldAst::Timestamps, "created_at") => {
            "\"created_at\" TIMESTAMPTZ NOT NULL DEFAULT NOW()".to_string()
        }
        (FieldAst::Timestamps, "updated_at") => {
            "\"updated_at\" TIMESTAMPTZ NOT NULL DEFAULT NOW()".to_string()
        }
        (FieldAst::Publishable, "status") => publishable_status_definition(names, table),
        (FieldAst::Publishable, "published_at") => "\"published_at\" TIMESTAMPTZ".to_string(),
        (FieldAst::Publishable, "scheduled_at") => "\"scheduled_at\" TIMESTAMPTZ".to_string(),
        (FieldAst::SoftDelete, "deleted_at") => "\"deleted_at\" TIMESTAMPTZ".to_string(),
        _ => return None,
    })
}

/// The `status` column `publishable` adds, with its check.
fn publishable_status_definition(names: &ObjectNames, table: &str) -> String {
    format!(
        "\"status\" TEXT NOT NULL DEFAULT 'draft' CONSTRAINT {} CHECK ({})",
        quote_ident(&names.type_check(table, "status")),
        super::type_checks::publishable_status_check_expr()
    )
}

/// A many-to-many's junction table: one foreign key column per side, the pair its primary key.
/// Each side is its column and `(table, primary key, type)` of the model it references.
fn create_junction_table_sql(
    names: &ObjectNames,
    schema: &str,
    table: &str,
    sides: [(&String, (String, String, String)); 2],
) -> String {
    // Ours by its ledger row, like any table Supatype creates (Phase 4.11), so a removed
    // many-to-many takes its junction with it.
    let keys = [sides[0].0, sides[1].0];
    let columns = sides.map(|(fk, (ref_table, pk, pg_type))| {
        format!(
            "{} {pg_type} NOT NULL CONSTRAINT {} REFERENCES {} ({}) ON DELETE CASCADE,\n    ",
            quote_ident(fk),
            quote_ident(&names.foreign_key(table, fk)),
            quote_qualified(schema, &ref_table),
            quote_ident(&pk)
        )
    });
    format!(
        "CREATE TABLE IF NOT EXISTS {} (\n    {}{}CONSTRAINT {} PRIMARY KEY ({}, {})\n);",
        quote_qualified(schema, table),
        columns[0],
        columns[1],
        quote_ident(&names.primary_key(table)),
        quote_ident(keys[0]),
        quote_ident(keys[1])
    )
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

fn create_table_sql(
    model: &ModelAst,
    schema: &str,
    ast: &SchemaAst,
    names: &ObjectNames,
) -> Result<String> {
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
                        let uniq = unique_clause(names, table, &fk_col, rel.unique_fk);
                        let req = if rel.required { " NOT NULL" } else { "" };
                        let pg_type = fk_pg_type_for_model(ast, &rel.target);
                        col_defs.push(format!("    {} {pg_type}{uniq}{req}", quote_ident(&fk_col)));
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
                    "    {}",
                    publishable_status_definition(names, table)
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
                    field_to_column_def(names, table, field_name, other)?
                ));
            }
        }
    }

    for (column, definition) in option_columns(model) {
        col_defs.push(format!("    {} {definition}", quote_ident(column)));
    }

    let target = quote_qualified(schema, table);
    let mut statements = vec![format!(
        "CREATE TABLE IF NOT EXISTS {target} (\n{}\n);",
        col_defs.join(",\n")
    )];

    // Model-level constraints, as named table constraints. Checks carry no stamp: the ledger
    // records them (plan 3.2) and their comments are the user's.
    for (index, rule) in model.annotations.db.constraints.iter().enumerate() {
        let expr = crate::generator::sql::constraints::constraint_to_expr(rule)?;
        let constraint = names.model_constraint(table, index, rule);
        statements.push(format!(
            "ALTER TABLE {target} ADD CONSTRAINT {} CHECK ({expr});",
            quote_ident(&constraint)
        ));
    }

    // Explicit model-level indexes
    for index in model.indexes() {
        statements.push(create_index_sql(names, table, index, schema)?);
    }

    // And the ones nobody declares. Shared with the reconcile rather than written twice: these
    // are Supatype's by the ledger, so an index the desired set cannot account for is one a push
    // drops, and every push would then drop it and create it again.
    for index in implicit_model_indexes(model) {
        statements.push(create_index_sql(names, table, &index, schema)?);
    }

    // Singleton (global config): enforce exactly one row via a unique index on an expression.
    // Recorded by the ledger (Phase 4.3), so no stamp.
    if model.options.singleton {
        statements.push(format!(
            "CREATE UNIQUE INDEX IF NOT EXISTS {} ON {target} ((TRUE));",
            quote_ident(&names.singleton_index(table))
        ));
    }

    // No ownership stamp (Phase 6): the push records the table in the ledger, which is what lets
    // the differ drop it later and refuse to drop one it merely found. The comment is the user's.
    Ok(statements.join("\n\n"))
}

// The implicit indexes live beside the other declared-field questions, where the WASM build (the
// admin metadata names them) can reach them too.
pub(crate) use crate::parser::accessors::implicit_model_indexes;

// ─── COLUMN DEFINITION ───────────────────────────────────────────────────────

pub(super) fn field_to_column_def(
    names: &ObjectNames,
    table: &str,
    name: &str,
    field: &FieldAst,
) -> Result<String> {
    let qname = quote_ident(name);
    match field {
        FieldAst::Uuid(f) => Ok(scalar_col(names, table, name, "UUID", f, false)),
        FieldAst::Text(f) | FieldAst::RichText(f) | FieldAst::Bytes(f) | FieldAst::Color(f) => {
            let pg = if matches!(field, FieldAst::RichText(_)) {
                "JSONB"
            } else if matches!(field, FieldAst::Bytes(_)) {
                "BYTEA"
            } else {
                "TEXT"
            };
            let rich_text = matches!(field, FieldAst::RichText(_));
            Ok(scalar_col(names, table, name, pg, f, rich_text))
        }
        FieldAst::Email(f) => {
            let mut def = scalar_col(names, table, name, "TEXT", f, false);
            def.push_str(&format!(
                " CONSTRAINT {} CHECK ({})",
                quote_ident(&names.type_check(table, name)),
                super::type_checks::email_check_expr(name)
            ));
            Ok(def)
        }
        FieldAst::Integer(f) => Ok(scalar_col(names, table, name, "INTEGER", f, false)),
        FieldAst::Float(f) => Ok(scalar_col(names, table, name, "DOUBLE PRECISION", f, false)),
        FieldAst::Boolean(f) => Ok(scalar_col(names, table, name, "BOOLEAN", f, false)),
        FieldAst::Datetime(f) => Ok(scalar_col(names, table, name, "TIMESTAMPTZ", f, false)),
        FieldAst::BigInt(f) => Ok(scalar_col(names, table, name, "BIGINT", f, false)),
        FieldAst::SmallInt(f) => Ok(scalar_col(names, table, name, "SMALLINT", f, false)),
        FieldAst::Date(f) => Ok(scalar_col(names, table, name, "DATE", f, false)),
        FieldAst::Timestamp(f) => Ok(scalar_col(names, table, name, "TIMESTAMP", f, false)),
        FieldAst::Serial(f) => {
            // SERIAL is self-declaring: NOT NULL + sequence default are implicit.
            // primary_key / unique flags still apply.
            let pk = primary_key_clause(names, table, f.primary_key);
            let uniq = unique_clause(names, table, name, f.unique && !f.primary_key);
            Ok(format!("{qname} SERIAL{pk}{uniq}"))
        }
        FieldAst::BigSerial(f) => {
            let pk = primary_key_clause(names, table, f.primary_key);
            let uniq = unique_clause(names, table, name, f.unique && !f.primary_key);
            Ok(format!("{qname} BIGSERIAL{pk}{uniq}"))
        }
        FieldAst::Money(f) => Ok(scalar_col(names, table, name, "NUMERIC(19,4)", f, false)),
        FieldAst::Url(f) => {
            let mut def = scalar_col(names, table, name, "TEXT", f, false);
            def.push_str(&format!(
                " CONSTRAINT {} CHECK ({})",
                quote_ident(&names.type_check(table, name)),
                super::type_checks::url_check_expr(name)
            ));
            Ok(def)
        }
        FieldAst::Ip(f) => Ok(scalar_col(names, table, name, "INET", f, false)),
        FieldAst::Cidr(f) => Ok(scalar_col(names, table, name, "CIDR", f, false)),
        FieldAst::Macaddr(f) => Ok(scalar_col(names, table, name, "MACADDR", f, false)),
        FieldAst::Interval(f) => Ok(scalar_col(names, table, name, "INTERVAL", f, false)),
        FieldAst::TsQuery(f) => Ok(scalar_col(names, table, name, "TSQUERY", f, false)),
        FieldAst::TsVector(f) => {
            // tsvector is typically NOT NULL; index is GIN.
            let req = if f.required { " NOT NULL" } else { "" };
            let generation = generation_clause(f);
            Ok(format!("{qname} TSVECTOR{generation}{req}"))
        }
        FieldAst::Xml(f) => Ok(scalar_col(names, table, name, "XML", f, false)),
        FieldAst::Array(f) => {
            let req = if f.required { " NOT NULL" } else { "" };
            let uniq = unique_clause(names, table, name, f.unique);
            let elem = f.element_type.to_uppercase();
            let check = render_check(names, table, name, field);
            Ok(format!("{qname} {elem}[]{req}{uniq}{check}"))
        }
        FieldAst::Slug(f) => {
            let unique = unique_clause(names, table, name, f.unique);
            let req = if f.required { " NOT NULL" } else { "" };
            let check = render_check(names, table, name, field);
            Ok(format!("{qname} TEXT{req}{unique}{check}"))
        }
        FieldAst::Enum(f) => {
            let req = if f.required { " NOT NULL" } else { "" };
            let uniq = unique_clause(names, table, name, f.unique);
            let default = f
                .default
                .as_ref()
                .map(|d| format!(" DEFAULT {}", quote_literal(d)))
                .unwrap_or_default();
            let check_name = quote_ident(&names.type_check(table, name));
            let check = super::type_checks::enum_check_expr(name, &f.values);
            Ok(format!(
                "{qname} TEXT{req}{uniq} CONSTRAINT {check_name} CHECK ({check}){default}"
            ))
        }
        FieldAst::Json(f) => {
            let req = if f.required { " NOT NULL" } else { "" };
            let check = render_check(names, table, name, field);
            Ok(format!("{qname} JSONB{req}{check}"))
        }
        FieldAst::Button(f) => {
            let req = if f.required { " NOT NULL" } else { "" };
            let check = render_check(names, table, name, field);
            Ok(format!("{qname} JSONB{req}{check}"))
        }
        FieldAst::Decimal(f) => {
            let pg = match (f.precision, f.scale) {
                (Some(p), Some(s)) => format!("NUMERIC({p}, {s})"),
                (Some(p), None) => format!("NUMERIC({p})"),
                _ => "NUMERIC".into(),
            };
            let req = if f.required { " NOT NULL" } else { "" };
            let check = render_check(names, table, name, field);
            Ok(format!("{qname} {pg}{req}{check}"))
        }
        FieldAst::Image(f) | FieldAst::File(f) => Ok(scalar_col(
            names,
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
            names,
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
            Ok(format!("{qname} GEOGRAPHY({geo_type}, {srid}){req}"))
        }
        FieldAst::Vector(f) => {
            let req = if f.required { " NOT NULL" } else { "" };
            Ok(format!("{qname} vector({}){req}", f.dimensions))
        }
        // Plugin-defined custom field type: use the declared pg_type directly.
        FieldAst::Custom(f) => {
            let req = if f.required { " NOT NULL" } else { "" };
            let uniq = unique_clause(names, table, name, f.unique);
            let default = f
                .default
                .as_ref()
                .map(|d| format!(" DEFAULT {}", render_default(d)))
                .unwrap_or_default();
            Ok(format!(
                "{qname} {pg}{req}{uniq}{default}",
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
fn render_check(names: &ObjectNames, table: &str, name: &str, field: &FieldAst) -> String {
    field_check_expression(field, name)
        .map(|expr| {
            format!(
                " CONSTRAINT {} CHECK ({expr})",
                quote_ident(&names.bounds(table, name))
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
            "{schema}.localized_{measure}_{direction}({}, {arg})",
            quote_ident(name),
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
                    serde_json::Value::String(s) => quote_literal(s),
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
    names: &ObjectNames,
    table: &str,
    name: &str,
    pg_type: &str,
    f: &ScalarFieldAst,
    rich_text: bool,
) -> String {
    // Localized fields are stored as JSONB regardless of their base type.
    let effective_type = if f.localized { "JSONB" } else { pg_type };
    let pk = primary_key_clause(names, table, f.primary_key);
    let req = if f.required && !f.primary_key {
        " NOT NULL"
    } else {
        ""
    };
    let uniq = unique_clause(names, table, name, f.unique && !f.primary_key);
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
            " CONSTRAINT {} CHECK ({expr})",
            quote_ident(&names.bounds(table, name))
        )
    })
    .unwrap_or_default();
    let generation = generation_clause(f);
    format!(
        "{} {effective_type}{generation}{pk}{req}{uniq}{default}{check}",
        quote_ident(name)
    )
}

/// ` GENERATED ALWAYS AS IDENTITY`, ` GENERATED ALWAYS AS (expression) STORED`, or nothing: how
/// the database fills the column, when the schema says it does (identity-contract).
pub(crate) fn generation_clause(f: &ScalarFieldAst) -> String {
    if let Some(identity) = f.identity {
        return format!(" GENERATED {} AS IDENTITY", identity.as_sql());
    }
    match &f.generated {
        Some(g) => format!(" GENERATED ALWAYS AS ({}) STORED", g.expression),
        None => String::new(),
    }
}

/// ` CONSTRAINT "{table}_pkey" PRIMARY KEY`, or nothing.
///
/// Named explicitly, with the name Postgres would have chosen, so that no object a push creates is
/// named by anyone but us. Postgres names an unnamed constraint after the fact and disambiguates a
/// collision with a digit, and a name only it knows is a name the differ and the ledger cannot
/// look for.
fn primary_key_clause(names: &ObjectNames, table: &str, primary_key: bool) -> String {
    if primary_key {
        format!(
            " CONSTRAINT {} PRIMARY KEY",
            quote_ident(&names.primary_key(table))
        )
    } else {
        String::new()
    }
}

/// ` CONSTRAINT "{table}_{column}_key" UNIQUE`, or nothing. See [`primary_key_clause`].
fn unique_clause(names: &ObjectNames, table: &str, column: &str, unique: bool) -> String {
    if unique {
        format!(
            " CONSTRAINT {} UNIQUE",
            quote_ident(&names.unique(table, column))
        )
    } else {
        String::new()
    }
}

fn render_default(d: &DefaultValueAst) -> String {
    match d {
        DefaultValueAst::Value { value } => match value {
            serde_json::Value::String(s) => quote_literal(s),
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
    let alter = alter_column_prefix(schema, table, column);

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
            "{alter} TYPE {pg_type} USING {using_expr}; -- was: {}",
            comment_text(from_udt)
        ));
    }

    if let Some(null_change) = changes.get("nullability") {
        let to = null_change.get("to").and_then(|v| v.as_str()).unwrap_or("");
        stmts.extend(nullability_sql(
            schema,
            table,
            column,
            (to == "not_null").then_some("set"),
        ));
    }

    // After the nullability: an identity column must be NOT NULL before it can be one.
    if let Some(identity) = changes.get("identity") {
        stmts.extend(identity_change_sql(schema, table, column, identity));
    }

    if changes
        .get("generated")
        .and_then(|g| g.get("action"))
        .and_then(|v| v.as_str())
        == Some("drop_expression")
    {
        stmts.push(format!("{alter} DROP EXPRESSION IF EXISTS;"));
    }

    Ok(stmts.join("\n"))
}

/// `SET NOT NULL` when `set_verb` is given, refused while rows hold NULL with a message saying it
/// could not `<verb>` it (`set` going forward, `restore` in a rollback); `DROP NOT NULL` when not.
pub(crate) fn nullability_sql(
    schema: &str,
    table: &str,
    column: &str,
    set_verb: Option<&str>,
) -> Vec<String> {
    let alter = alter_column_prefix(schema, table, column);
    let Some(verb) = set_verb else {
        return vec![format!("{alter} DROP NOT NULL;")];
    };
    let refused = raise_message(&format!(
        "Cannot {verb} NOT NULL on {table}.{column}: NULL values exist."
    ));
    vec![
        format!(
            "DO $$ BEGIN\n  \
             IF EXISTS (SELECT 1 FROM {} WHERE {} IS NULL) THEN\n    \
             RAISE EXCEPTION {refused};\n  \
             END IF;\n\
             END $$;",
            quote_qualified(schema, table),
            quote_ident(column)
        ),
        format!("{alter} SET NOT NULL;"),
    ]
}

/// `ALTER TABLE "schema"."table" ALTER COLUMN "column"`.
fn alter_column_prefix(schema: &str, table: &str, column: &str) -> String {
    format!(
        "ALTER TABLE {} ALTER COLUMN {}",
        quote_qualified(schema, table),
        quote_ident(column)
    )
}

/// `GENERATED ALWAYS` or `GENERATED BY DEFAULT`, from an identity change's `from` / `to`.
fn identity_keywords(identity: &serde_json::Value, key: &str) -> &'static str {
    match identity.get(key).and_then(|v| v.as_str()) {
        Some("byDefault") => "BY DEFAULT",
        _ => "ALWAYS",
    }
}

/// The statements an identity change makes (identity-contract). Adding identity to a column that
/// has rows starts its new sequence past them, as a serial's conversion would, so the next insert
/// does not collide with a key that is there.
pub(crate) fn identity_change_sql(
    schema: &str,
    table: &str,
    column: &str,
    identity: &serde_json::Value,
) -> Vec<String> {
    let target = quote_qualified(schema, table);
    let alter = alter_column_prefix(schema, table, column);
    // `pg_get_serial_sequence` takes the relation as text it parses, so the quoted name, as a
    // literal.
    let sequence = format!(
        "pg_get_serial_sequence({}, {})",
        quote_literal(&target),
        quote_literal(column)
    );
    match identity.get("action").and_then(|v| v.as_str()) {
        Some("add") => {
            let mut stmts = Vec::new();
            if identity.get("dropDefault").and_then(|v| v.as_bool()) == Some(true) {
                stmts.push(format!("{alter} DROP DEFAULT;"));
            }
            // A serial's own sequence goes with its default, found by its ownership (the default's
            // text names it relative to whatever search path it was read under).
            if identity.get("serial").is_some() {
                stmts.push(format!(
                    "DO $$ BEGIN EXECUTE format('DROP SEQUENCE IF EXISTS %s', {sequence}); END $$;"
                ));
            }
            stmts.push(format!(
                "{alter} ADD GENERATED {} AS IDENTITY;",
                identity_keywords(identity, "to")
            ));
            stmts.push(format!(
                "SELECT setval({sequence}, COALESCE(MAX({}), 0) + 1, false) FROM {target};",
                quote_ident(column)
            ));
            stmts
        }
        Some("drop") => vec![format!("{alter} DROP IDENTITY IF EXISTS;")],
        Some("set") => vec![format!(
            "{alter} SET GENERATED {};",
            identity_keywords(identity, "to")
        )],
        _ => Vec::new(),
    }
}

/// A generated column made again for a new expression (identity-contract). Postgres 17 changes
/// the expression in place (`SET EXPRESSION`, which recomputes every row and keeps the column's
/// indexes, grants and labels); before it, the column is dropped and added again, its values being
/// derived anyway, and `recreate` re-creates what depended on it. Chosen when the migration runs,
/// from the server it runs on. A plain column becoming generated is always made again.
fn generated_column_sql(
    schema: &str,
    table: &str,
    column: &str,
    generated: &serde_json::Value,
    recreate: &str,
) -> String {
    let action = generated.get("action").and_then(|v| v.as_str());
    // Under tier-2 masking the `api` view reads the column, and a column a view reads cannot be
    // dropped. The view is Supatype's alone and is made again later in this migration (with its
    // trigger and privileges), so it goes first; where there is none this does nothing.
    let view = format!(
        "DROP VIEW IF EXISTS {};",
        quote_qualified(super::field_views::VIEW_SCHEMA, table)
    );
    let recreate = format!("{view}\n{recreate}");
    let Some(expression) = generated.get("expression").and_then(|v| v.as_str()) else {
        return recreate;
    };
    if action != Some("set_expression") {
        return recreate;
    }
    let in_place = format!(
        "{} SET EXPRESSION AS ({expression})",
        alter_column_prefix(schema, table, column)
    );
    // One statement per line, as `recreate_column_sql` writes them: one `EXECUTE` each.
    let again: String = recreate
        .as_str()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| format!("    EXECUTE {};\n", dollar_quoted(l, "recreate")))
        .collect();
    format!(
        "DO $generated$\nBEGIN\n  IF current_setting('server_version_num')::int >= 170000 THEN\n    EXECUTE {};\n  ELSE\n{again}  END IF;\nEND\n$generated$;",
        dollar_quoted(&in_place, "expr"),
    )
}

/// `sql` as a dollar-quoted literal whose tag does not occur in it.
pub(super) fn dollar_quoted(sql: &str, tag: &str) -> String {
    let mut tag = format!("${tag}$");
    while sql.contains(&tag) {
        tag.insert(tag.len() - 1, '_');
    }
    format!("{tag}{sql}{tag}")
}

/// `"a", "b"`: each name quoted, comma-separated, for a column list.
pub(super) fn quote_ident_list(names: &[String]) -> String {
    names
        .iter()
        .map(|n| quote_ident(n))
        .collect::<Vec<_>>()
        .join(", ")
}

// ─── INDEX ───────────────────────────────────────────────────────────────────

fn create_index_sql(
    names: &ObjectNames,
    table: &str,
    index: &IndexAst,
    schema: &str,
) -> Result<String> {
    let unique = if index.unique { "UNIQUE " } else { "" };
    let method = index.using.as_sql();
    // Each key with its operator class where the method names one; resolved through the push's
    // search path, so wherever the extension that defines it is installed.
    let cols = match index.operator_class() {
        Some(class) => index
            .fields
            .iter()
            .map(|f| format!("{} {class}", quote_ident(f)))
            .collect::<Vec<_>>()
            .join(", "),
        None => quote_ident_list(&index.fields),
    };
    // The name the desired set records: the one chosen for the whole schema, never the full
    // `{table}_{fields}_idx`, which Postgres would cut to 63 bytes behind our back.
    let idx_name = quote_ident(&names.index(table, index));

    // The `CREATE` alone, no stamp (the ledger is the record, plan section 6) and no drop before
    // it: an index whose shape changed is the reconcile's `Replace`, which drops and recreates.
    Ok(format!(
        "CREATE {unique}INDEX IF NOT EXISTS {idx_name} ON {} USING {method} ({cols});",
        quote_qualified(schema, table)
    ))
}

fn add_unique_constraint_sql(
    table: &str,
    column: &str,
    constraint: &str,
    schema: &str,
) -> Result<String> {
    Ok(format!(
        "ALTER TABLE {} ADD CONSTRAINT {} UNIQUE ({});",
        quote_qualified(schema, table),
        quote_ident(constraint),
        quote_ident(column)
    ))
}

// ─── FOREIGN KEY ─────────────────────────────────────────────────────────────

/// A relation's `ON UPDATE` when it declares no `onUpdate`. Every key was made `ON UPDATE CASCADE`
/// before the option was read, so a project that never set it keeps exactly the keys it has: no
/// diff on its next push, and the same behaviour when a referenced key changes.
const DEFAULT_ON_UPDATE: &str = "cascade";

/// A relation's `onDelete` or `onUpdate`, as the SQL action it names. Case, spaces, `_` and `-`
/// are ignored (`set null`, `setNull`, `SET_NULL`); anything unrecognised is `RESTRICT`.
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
    names: &ObjectNames,
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
    let on_update = normalize_fk_action(rel.on_update.as_deref().unwrap_or(DEFAULT_ON_UPDATE));
    let constraint = names.foreign_key(table, fk_col);

    Ok(format!(
        "ALTER TABLE {} ADD CONSTRAINT {} FOREIGN KEY ({}) REFERENCES {} ({}) \
         ON DELETE {on_delete} ON UPDATE {on_update};",
        quote_qualified(schema, table),
        quote_ident(&constraint),
        quote_ident(fk_col),
        quote_qualified(ref_schema, ref_table),
        quote_ident(ref_col)
    ))
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────

/// The serial columns of the model whose table is `table`, by column name.
pub(crate) fn serial_columns(ast: &SchemaAst, table: &str) -> Vec<String> {
    ast.models
        .iter()
        .filter(|m| m.table_name() == table)
        .flat_map(|m| &m.fields)
        .filter(|(_, f)| crate::parser::accessors::owns_sequence(f))
        .flat_map(|(name, f)| crate::parser::accessors::column_names_for(name, f))
        .collect()
}

/// Renames the sequence `table.column` owns to `name`, if it owns one under another name.
///
/// Postgres names a serial's sequence once, when it makes it, and a table or column rename leaves
/// it as it was, so `posts_id_seq` stays `posts_id_seq` on a table now called `articles`. The
/// desired set and the ledger know it by the name it would have now. Found through the catalog
/// rather than by its old name, which may carry a digit Postgres added on a collision; skipped when
/// the column is not there yet (a rename of its own, later in the same migration, renames it then).
pub(crate) fn rename_serial_sequence_sql(
    schema: &str,
    table: &str,
    column: &str,
    name: &str,
) -> String {
    let relation = quote_literal(&quote_qualified(schema, table));
    let column = quote_literal(column);
    let name = quote_literal(name);
    format!(
        "DO $seq$\nDECLARE\n  seq regclass;\nBEGIN\n  \
         IF EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = {relation}::regclass AND attname = {column} AND NOT attisdropped) THEN\n    \
         seq := pg_get_serial_sequence({relation}, {column})::regclass;\n    \
         IF seq IS NOT NULL AND (SELECT relname FROM pg_class WHERE oid = seq) <> {name} THEN\n      \
         EXECUTE format('ALTER SEQUENCE %s RENAME TO %I', seq, {name});\n    \
         END IF;\n  \
         END IF;\n\
         END;\n$seq$;"
    )
}

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

    /// Renaming `posts` to `post_items` drops the affordance function that takes the old row type
    /// before the rename: afterwards `DROP FUNCTION IF EXISTS can_read_posts(public.posts)` finds no
    /// type of that name, is skipped, and the function is orphaned while its row goes.
    #[test]
    fn a_renamed_tables_affordance_function_is_dropped_before_the_rename() {
        let ast = parser::parse(
            r#"{ "astVersion": 2, "models": [{ "name": "PostItem",
                 "fields": { "id": { "kind": "integer", "primaryKey": true, "required": true,
                     "annotations": { "db": { "pgType": "INTEGER", "unique": false } } } },
                 "options": { "timestamps": false, "softDelete": false },
                 "annotations": { "db": { "tableName": "post_items", "indexes": [] },
                                  "platform": { "access": {} } } }] }"#,
        )
        .unwrap();
        let operations = vec![Operation::RenameTable {
            from: "posts".into(),
            to: "post_items".into(),
            risk: Risk::Cautious,
        }];
        let diff = DiffOutput {
            summary: crate::differ::DiffSummary::of(&operations),
            operations,
            warnings: Vec::new(),
            unmanaged_model_tables: Vec::new(),
            field_masking: Default::default(),
            field_view_plan: Vec::new(),
            rename_candidates: Vec::new(),
            rewrites: Vec::new(),
        };
        let function = crate::desired::ObjectKey {
            kind: crate::introspector::fingerprint::ObjectKind::Function,
            schema: "public".into(),
            parent: String::new(),
            name: "can_read_posts(public.posts)".into(),
        };
        let actions = [reconcile::Action::Drop {
            key: function.clone(),
            recorded_sql: None,
            drifted: None,
        }];
        let up = Migration::render(&diff, &actions, true, "public", &ast)
            .unwrap()
            .up();
        let drop = function.drop_sql().unwrap();
        let at_drop = up.find(&drop).unwrap_or_else(|| panic!("no drop:\n{up}"));
        let at_rename = up.find("RENAME TO \"post_items\"").expect("the rename");
        assert!(at_drop < at_rename, "the drop runs after the rename:\n{up}");
    }

    /// `posts.author_id` to `users`, with the relation's `onUpdate` set to `on_update` when given.
    fn foreign_key_sql_with_on_update(on_update: Option<&str>) -> String {
        let mut relation = serde_json::json!({
            "kind": "relation", "cardinality": "belongsTo", "target": "User",
            "onDelete": "cascade",
            "annotations": { "db": { "foreignKey": "author_id" } }
        });
        if let Some(action) = on_update {
            relation["onUpdate"] = action.into();
        }
        let id = serde_json::json!({ "kind": "integer", "primaryKey": true, "required": true,
            "annotations": { "db": { "pgType": "INTEGER", "unique": false } } });
        let model = |name: &str, table: &str, fields: serde_json::Value| {
            serde_json::json!({ "name": name, "fields": fields,
                "options": { "timestamps": false, "softDelete": false },
                "annotations": { "db": { "tableName": table, "indexes": [] },
                                 "platform": { "access": {} } } })
        };
        let doc = serde_json::json!({ "astVersion": 2, "models": [
            model("User", "users", serde_json::json!({ "id": id })),
            model("Post", "posts", serde_json::json!({ "id": id, "author": relation })),
        ] });
        let ast = parser::parse(&doc.to_string()).unwrap();
        let post = ast.models.iter().find(|m| m.name == "Post").unwrap();
        let Some(crate::parser::ast::FieldAst::Relation(rel)) = post.fields.get("author") else {
            panic!("the fixture's relation");
        };
        let op = Operation::AddForeignKey {
            table: "posts".into(),
            field_name: "author".into(),
            relation: Box::new(rel.clone()),
            ref_table: "users".into(),
            ref_schema: None,
            risk: Risk::Safe,
        };
        render_operation(&op, "public", &ast).unwrap()
    }

    /// A relation's `onUpdate` is the key's `ON UPDATE`, spelled as `onDelete` is; left out, it
    /// stays `CASCADE`, what every key had before the option was read.
    #[test]
    fn a_relations_on_update_is_the_foreign_keys_on_update() {
        for (on_update, expected) in [
            (Some("restrict"), "ON DELETE CASCADE ON UPDATE RESTRICT;"),
            (Some("setNull"), "ON DELETE CASCADE ON UPDATE SET NULL;"),
            (Some("noAction"), "ON DELETE CASCADE ON UPDATE NO ACTION;"),
            (Some("cascade"), "ON DELETE CASCADE ON UPDATE CASCADE;"),
            (None, "ON DELETE CASCADE ON UPDATE CASCADE;"),
        ] {
            let sql = foreign_key_sql_with_on_update(on_update);
            assert!(sql.ends_with(expected), "{on_update:?}: {sql}");
        }
    }
}

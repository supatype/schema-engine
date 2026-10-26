//! One push, for the CLI, the server and the tests alike.
//!
//! Phase 3c and 3d of the managed-object ownership plan (`plans/Managed-Object-Ownership-Plan.md`,
//! section 4). `main.rs` and `server/routes.rs` once carried their own copies of the push and the
//! tests pushed a third way; this is the one implementation.
//!
//! Three steps, because the CLI confirms renames and risky operations before anything is written
//! and `diff` wants the plan without the bootstrap:
//!
//! 1. [`plan`]: everything that reads. Introspect, diff against the live catalog and the previous
//!    schema, build the desired set, load the ledger, reconcile the kinds that have moved onto it
//!    (`MOVED_KINDS`), and ask the database about any same-named object the reconcile could not
//!    place (`ledger::probe`).
//! 2. [`prepare`]: the bootstrap (the engine's own tables, the project-schema guard, Studio
//!    state), then [`plan`].
//! 3. [`apply`]: everything that writes, in one transaction, or nothing: the migration body, the
//!    reconcile's statements, the history row, the ledger rows for every object of a moved kind.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use sqlx::{Executor, PgConnection, PgPool, Postgres, Transaction};

use crate::desired::{desired_objects_for, statements, ObjectKey};
use crate::differ::{self, DiffOutput, Operation};
use crate::generator::sql::migration::{self, Migration};
use crate::generator::sql::migration_errors::{self, CheckSite};
use crate::generator::sql::{constraint_helpers, field_views, rls, storage, versions};
use crate::generator::typescript::admin;
use crate::introspector::fingerprint::{fingerprints, ObjectFingerprint, ObjectKind};
use crate::introspector::{self, catalog, catalog::CatalogState};
use crate::ledger::{self, probe, reconcile, LedgerRow};
use crate::parser::ast::SchemaAst;
use crate::state::database_state::DatabaseState;
use crate::state::{migration_history, studio_state};

/// The kinds the reconcile owns. A kind joins this list in the PR that moves it, and from that PR
/// on the reconcile is its differ: check constraints since Phase 3d, foreign keys since 4.1,
/// triggers and their `_platform` functions since 4.2, indexes since 4.3, cron jobs since 4.4,
/// views since 4.6.
pub const MOVED_KINDS: &[ObjectKind] = &[
    ObjectKind::Check,
    ObjectKind::ForeignKey,
    ObjectKind::Function,
    ObjectKind::Trigger,
    ObjectKind::Index,
    ObjectKind::CronJob,
    ObjectKind::View,
];

/// Advisory lock keys shared with the CLI and the realtime worker (`packages/cli`,
/// `packages/realtime`, `schema-push-lock`). Realtime skips WAL polls while this is held.
const PUSH_LOCK_CLASS: i32 = 872014;
const PUSH_LOCK_ID: i32 = 1;

/// What a push has read and decided, before anything is written.
pub struct Plan<'a> {
    pub ast: &'a SchemaAst,
    pub schema: String,
    /// The CLI may edit this between `prepare` and `apply` (rename confirmations).
    pub diff: DiffOutput,
    pub reconcile: reconcile::Plan,
}

impl Plan<'_> {
    /// The diff as the CLI has always printed it, plus the reconcile's actions under `reconcile`:
    /// one definition for `supatype diff` and the server's `/diff`.
    pub fn to_json(&self) -> Result<serde_json::Value> {
        let mut json = serde_json::to_value(&self.diff)?;
        json["reconcile"] = serde_json::to_value(&self.reconcile.actions)?;
        Ok(json)
    }

    /// The one migration this plan is: what `supatype migrate` prints, what `apply` runs and what
    /// the history records.
    pub fn migration(&self, force: bool) -> Result<Migration> {
        Migration::render(
            &self.diff,
            &self.reconcile.actions,
            force,
            &self.schema,
            self.ast,
        )
    }
}

/// What `apply` was asked to do beyond the plan.
#[derive(Debug, Default)]
pub struct ApplyOptions {
    pub force: bool,
    /// Roll back when the post-apply catalog does not match the schema.
    pub strict: bool,
    pub name: Option<String>,
    pub schema_sources: Option<Vec<u8>>,
    pub schema_sources_manifest: Option<serde_json::Value>,
}

#[derive(Debug)]
pub enum Outcome {
    /// Nothing to apply. The re-asserted layers were refreshed and Studio metadata written.
    UpToDate { warnings: Vec<String> },
    Applied {
        name: String,
        operations: usize,
        /// The schema's own warnings, then what the database looked like once applied.
        warnings: Vec<String>,
    },
}

impl Outcome {
    /// The shape the CLI prints on stdout and the server returns: one definition, read by
    /// `packages/cli`.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Outcome::UpToDate { warnings } => serde_json::json!({
                "status": "up_to_date",
                "operations": 0,
                "admin_refreshed": true,
                "warnings": warnings,
            }),
            Outcome::Applied {
                name,
                operations,
                warnings,
            } => serde_json::json!({
                "status": "applied",
                "name": name,
                "operations": operations,
                "warnings": warnings,
            }),
        }
    }
}

/// What the catalog holds, read the one way the push reads it: before apply, to reconcile, and
/// after apply, to record.
struct Live {
    db: DatabaseState,
    catalog: CatalogState,
    fingerprints: Vec<ObjectFingerprint>,
}

async fn live(conn: &mut PgConnection, schema: &str) -> Result<Live> {
    let db = introspector::introspect_connection(conn, schema).await?;
    let catalog = catalog::read(conn, schema).await?;
    let fingerprints = fingerprints(&db, &catalog);
    Ok(Live {
        db,
        catalog,
        fingerprints,
    })
}

/// The tables the migration drops, as keys, so the reconcile lets their owned objects go with
/// them instead of altering a table that will be gone.
fn dropped_tables(diff: &DiffOutput, schema: &str) -> BTreeSet<ObjectKey> {
    diff.operations
        .iter()
        .filter_map(|op| match op {
            Operation::DropTable { table, .. } => Some(ObjectKey {
                kind: ObjectKind::Table,
                schema: schema.to_string(),
                parent: String::new(),
                name: table.clone(),
            }),
            _ => None,
        })
        .collect()
}

/// Reads and decides, writing nothing. For a database no push has touched the ledger is simply
/// empty. Fails when a declared table exists unmanaged (the error downcasts to
/// [`migration::UnmanagedModelTables`], so a caller can name the tables).
pub async fn plan<'a>(pool: &PgPool, ast: &'a SchemaAst, schema: &str) -> Result<Plan<'a>> {
    let mut conn = pool.acquire().await?;
    // Always the live catalog. A snapshot from the last push cannot see what changed outside
    // Supatype since, so `diff` showed one plan and push applied another.
    let live = live(&mut conn, schema).await?;
    let previous_ast = migration_history::load_latest_schema_ast(pool).await;
    let diff = differ::diff_with_previous(ast, &live.db, previous_ast.as_ref())?;

    // An unchanged schema produces an empty diff, so the renderer's own check would never run and
    // the push would report success while a declared table sat in the API with none of its rules
    // applied. Checked here, before the CLI asks anything about a push it is going to refuse.
    migration::assert_no_unmanaged_model_tables(&diff)?;

    let ledger = ledger::load_if_present(&mut conn).await?;
    let mut reconcile = reconcile_with(
        &diff,
        &ledger,
        &live.fingerprints,
        live.catalog.cron_available,
        schema,
        ast,
    )?;
    let proven = probe::equivalent(&mut conn, &reconcile).await?;
    reconcile.adopt_equivalent(&proven);

    Ok(Plan {
        ast,
        schema: schema.to_string(),
        diff,
        reconcile,
    })
}

/// The reconcile for this push: the desired set against `ledger` and `live`, knowing which
/// objects the migration's own statements create and which tables it drops. Without `pg_cron`
/// the cron jobs are not desired: the layer says so at apply time and there is nothing to record.
fn reconcile_with(
    diff: &DiffOutput,
    ledger: &[LedgerRow],
    live: &[ObjectFingerprint],
    cron_available: bool,
    schema: &str,
    ast: &SchemaAst,
) -> Result<reconcile::Plan> {
    let mut desired = desired_objects_for(ast, schema, &diff.field_view_plan)?;
    if !cron_available {
        desired.retain(|d| d.key.kind != ObjectKind::CronJob);
    }
    let created_by_parent = created_by_parent(diff, schema, ast)?;
    let dropped_tables = dropped_tables(diff, schema);
    Ok(reconcile::reconcile(reconcile::Inputs {
        desired: &desired,
        ledger,
        live,
        created_by_parent: &created_by_parent,
        dropped_tables: &dropped_tables,
        owned_schemas: catalog::OWNED_SCHEMAS,
        kinds: MOVED_KINDS,
    }))
}

/// The migration a push of `ast` against an empty database would apply, with no database to ask:
/// the differ's operations and the reconcile's creations. For the tests that render fixtures a
/// database refuses; everything else goes through [`plan`].
pub fn fresh_migration(ast: &SchemaAst, schema: &str, force: bool) -> Result<Migration> {
    let diff = differ::diff(ast, &DatabaseState::default())?;
    let reconcile = reconcile_with(&diff, &[], &[], true, schema, ast)?;
    Migration::render(&diff, &reconcile.actions, force, schema, ast)
}

/// The objects of a moved kind that the migration's own statements create: a check declared
/// inline in a `CREATE TABLE` or an `ADD COLUMN`, and everything the versions layer writes, which
/// the migration re-asserts as one script because its policies name the functions it defines a
/// line earlier and both need the tables the operations make. Read off the rendered statements by
/// the same attribution Phase 2c proved against every fixture, so the reconcile asks nothing of
/// the AST and is right about whatever the renderer actually writes inline.
fn created_by_parent(
    diff: &DiffOutput,
    schema: &str,
    ast: &SchemaAst,
) -> Result<BTreeSet<ObjectKey>> {
    let mut rendered = Vec::new();
    for op in &diff.operations {
        // Every operation, not only the obvious parents: a versions table is created by its own
        // operation with its status check inline, and the attribution is what knows that.
        rendered.push(migration::render_operation(op, schema, ast)?);
    }
    rendered.push(versions::render_versions_layer(ast, schema)?);
    rendered.push(rls::generate_can_functions(ast, schema));
    rendered.push(field_views::render_field_views(
        ast,
        &diff.field_view_plan,
        schema,
    ));
    rendered.push(constraint_helpers::generate());

    let mut keys = BTreeSet::new();
    for sql in rendered {
        for statement in statements::attribute_all(schema, statements::split_statements(&sql)) {
            keys.extend(
                statement
                    .attribution
                    .keys()
                    .iter()
                    .filter(|k| MOVED_KINDS.contains(&k.kind))
                    .cloned(),
            );
        }
    }
    Ok(keys)
}

/// The bootstrap, then [`plan`]. What a push runs.
pub async fn prepare<'a>(pool: &PgPool, ast: &'a SchemaAst, schema: &str) -> Result<Plan<'a>> {
    migration_history::bootstrap_internal_state(pool)
        .await
        .context("Failed to bootstrap _supatype internal state")?;
    migration_history::assert_project_schema(pool, schema).await?;
    studio_state::bootstrap(pool).await?;
    plan(pool, ast, schema).await
}

pub async fn apply(pool: &PgPool, plan: Plan<'_>, opts: ApplyOptions) -> Result<Outcome> {
    let conflicts: Vec<String> = plan
        .reconcile
        .conflicts()
        .map(|a| a.key().to_string())
        .collect();
    if !conflicts.is_empty() {
        bail!(
            "{} object(s) exist under a name this schema needs, and were not created by Supatype: \
             {}. Run `supatype adopt` to take them over, or rename them.",
            conflicts.len(),
            conflicts.join(", ")
        );
    }

    let outcome = if plan.diff.operations.is_empty() && !plan.reconcile.has_changes() {
        up_to_date(pool, plan).await?
    } else {
        apply_migration(pool, plan, opts).await?
    };
    match &outcome {
        Outcome::UpToDate { .. } => {
            tracing::info!("Schema is up to date; Studio metadata refreshed.")
        }
        Outcome::Applied {
            name, operations, ..
        } => tracing::info!(name = %name, ops = operations, "Migration applied"),
    }
    Ok(outcome)
}

/// The steady-state push. Applied at all because the publishing layer, the trigger functions and
/// the storage rules are exactly the kind of change that produces no DDL: widening
/// `draft_visibility` alters no table, so a steady-state push is the only push that will ever
/// carry it, and skipping it would mean a security setting that reads as applied and is not.
async fn up_to_date(pool: &PgPool, plan: Plan<'_>) -> Result<Outcome> {
    // Rendered before anything is applied, so a schema whose versioned models have no stated
    // visibility fails the push rather than half-applying it.
    let versions_sql = versions::render_versions_layer(plan.ast, &plan.schema)?;
    sqlx::raw_sql(&storage::generate(plan.ast)?)
        .execute(pool)
        .await
        .context("Failed to apply storage schema/policies")?;
    if !versions_sql.trim().is_empty() {
        sqlx::raw_sql(&versions_sql)
            .execute(pool)
            .await
            .context("Failed to apply drafts and publishing layer")?;
    }

    // AST-only changes (widgets, labels) still need admin_config and the snapshot so Studio and
    // tooling see the latest schema without a DDL migration.
    let admin_cfg = admin::generate(plan.ast)?;
    let schema_snap = serde_json::to_value(plan.ast)?;
    migration_history::refresh_metadata_on_up_to_date_push(pool, &admin_cfg, &schema_snap)
        .await
        .context("Failed to refresh Studio metadata on up-to-date push")?;
    Ok(Outcome::UpToDate {
        warnings: plan.diff.warnings,
    })
}

/// Everything rendered for one push, kept together because the failure record needs the same
/// name, hash and statements the success record does.
struct Rendered {
    name: String,
    migration: Migration,
    /// What runs inside the transaction `apply` owns: the migration between the re-asserted
    /// layers.
    apply_body: String,
    sources: migration_history::AppliedMigrationSources,
}

fn render(plan: &Plan<'_>, opts: ApplyOptions) -> Result<Rendered> {
    let migration = plan.migration(opts.force)?;
    // Millisecond precision so rapid retries do not collide on the name.
    let name = opts
        .name
        .unwrap_or_else(|| format!("push_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S_%3f")));
    let apply_body = migration.apply_body(&storage::generate(plan.ast)?);
    Ok(Rendered {
        name,
        apply_body,
        sources: migration_history::AppliedMigrationSources {
            sql_down: Some(migration.down()),
            schema_sources: opts.schema_sources,
            schema_sources_manifest: opts.schema_sources_manifest,
        },
        migration,
    })
}

async fn apply_migration(pool: &PgPool, plan: Plan<'_>, opts: ApplyOptions) -> Result<Outcome> {
    let strict = opts.strict;
    let rendered = render(&plan, opts)?;
    let mut tx = pool.begin().await.context("begin migration transaction")?;
    let applied = match within_transaction(&mut tx, &plan, strict, &rendered).await {
        Ok(applied) => applied,
        Err(e) => {
            migration_history::rollback_push_tx(
                tx,
                pool,
                &rendered.name,
                &rendered.migration.hash,
                &rendered.migration.up(),
                &e.to_string(),
            )
            .await;
            return Err(e);
        }
    };
    tx.commit().await.context("commit migration transaction")?;

    // Studio reads its schema from `_supatype.schema_state`, which was once written only on the
    // up-to-date path, so any project whose last push applied a migration had none. A failure here
    // must not undo an applied migration, so it only warns.
    if let Some((admin_cfg, schema_snap)) = applied.studio_metadata.as_ref() {
        if let Err(e) =
            migration_history::save_studio_metadata_if_present(pool, admin_cfg, schema_snap).await
        {
            eprintln!("Warning: failed to refresh Studio metadata: {e}");
        }
    }

    let operations = plan.diff.operations.len() + rendered.migration.reconciled;
    let mut warnings = plan.diff.warnings;
    warnings.extend(applied.drift_warnings);
    Ok(Outcome::Applied {
        name: rendered.name,
        operations,
        warnings,
    })
}

struct Applied {
    drift_warnings: Vec<String>,
    studio_metadata: Option<(serde_json::Value, serde_json::Value)>,
}

/// The writes, in order. Any error here rolls the whole transaction back and records a failed
/// migration with the same name, hash and batch.
async fn within_transaction(
    tx: &mut Transaction<'_, Postgres>,
    plan: &Plan<'_>,
    strict: bool,
    rendered: &Rendered,
) -> Result<Applied> {
    take_push_lock(tx).await?;

    if let Err(e) = (&mut **tx)
        .execute(sqlx::raw_sql(&rendered.apply_body))
        .await
    {
        let msg = migration_errors::enrich_migration_error(
            &e.to_string(),
            Some(&plan.diff),
            &check_sites(&plan.reconcile),
        );
        return Err(anyhow::anyhow!(msg).context("Failed to apply migration"));
    }

    let after = live(tx, &plan.schema)
        .await
        .context("Failed to introspect after migration")?;

    let drift_warnings = differ::integrity::post_push_warnings(plan.ast, &after.db, &after.catalog);
    if strict && !differ::integrity::post_push_ok(plan.ast, &after.db, &after.catalog, true) {
        bail!(
            "Push rolled back: post-apply schema drift in strict mode ({})",
            drift_warnings.join("; ")
        );
    }

    let schema_snap = serde_json::to_value(plan.ast).ok();
    let admin_cfg = admin::generate(plan.ast).ok();
    let migration_id = migration_history::insert_applied_migration(
        &mut **tx,
        &rendered.name,
        &rendered.migration.hash,
        schema_snap.clone(),
        admin_cfg.clone(),
        &rendered.migration.up(),
        &rendered.sources,
    )
    .await
    .context("Failed to record migration in history")?;

    record_ledger(tx, &plan.reconcile, &after.fingerprints, migration_id).await?;

    migration_history::save_schema_state(&mut **tx, &after.db)
        .await
        .context("Failed to save schema state cache")?;

    // Which mechanism is enforcing the field rules, probed rather than assumed. A failure here is
    // a missing diagnostic, not a broken push: the enforcement itself is the labels, which are
    // already applied in this transaction.
    if let Err(e) = migration_history::record_field_enforcement(
        tx,
        migration_history::labelled_column_count(plan.ast),
    )
    .await
    {
        eprintln!("Warning: failed to record field-enforcement capability: {e}");
    }

    Ok(Applied {
        drift_warnings,
        studio_metadata: admin_cfg.zip(schema_snap),
    })
}

/// The checks this push adds or replaces, for naming the rows that breach one when the apply
/// fails on it.
fn check_sites(plan: &reconcile::Plan) -> Vec<CheckSite<'_>> {
    plan.actions
        .iter()
        .filter(|a| a.key().kind == ObjectKind::Check)
        .filter_map(|a| {
            let key = a.key();
            Some(CheckSite {
                table: &key.parent,
                constraint: &key.name,
                expression: statements::check_expression(a.create_sql()?)?,
            })
        })
        .collect()
}

/// Plan section 4, steps 6 and 7: after apply, every object of a moved kind the reconcile named is
/// re-read from the catalog and its row written with the `CREATE` intended, the fingerprint found
/// and the migration that changed it; rows for objects dropped or already gone are removed.
async fn record_ledger(
    tx: &mut Transaction<'_, Postgres>,
    plan: &reconcile::Plan,
    after: &[ObjectFingerprint],
    migration_id: i32,
) -> Result<()> {
    if plan.actions.is_empty() {
        return Ok(());
    }
    let live: BTreeMap<ObjectKey, &ObjectFingerprint> =
        after.iter().map(|f| (f.key(), f)).collect();
    let mut rows = Vec::new();
    let mut removed = Vec::new();
    for action in &plan.actions {
        let key = action.key();
        match action.row_after() {
            reconcile::RowAfter::Write { create_sql, status } => {
                let fp = live.get(key).with_context(|| {
                    format!("{key} was not found in the catalog after the push applied it")
                })?;
                rows.push(LedgerRow {
                    key: key.clone(),
                    desired_fp: ledger::desired_fingerprint(key.kind, create_sql),
                    desired_sql: create_sql.to_string(),
                    live_fp: fp.fingerprint.clone(),
                    live_def: fp.definition.clone(),
                    status,
                    migration_id: action.is_change().then_some(migration_id),
                });
            }
            reconcile::RowAfter::Remove => removed.push(key.clone()),
            reconcile::RowAfter::Leave => {}
        }
    }
    ledger::upsert(tx, &rows).await?;
    ledger::delete(tx, &removed).await
}

/// A signal to realtime, which skips WAL polls while anyone holds this transaction-level lock;
/// not mutual exclusion. The CLI may already hold it as a session lock from its own backend, so
/// the lock is tried rather than waited for: free, this push holds it until commit; held, the
/// holder is already keeping realtime away and this push proceeds.
async fn take_push_lock(tx: &mut Transaction<'_, Postgres>) -> Result<()> {
    sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1, $2)")
        .bind(PUSH_LOCK_CLASS)
        .bind(PUSH_LOCK_ID)
        .fetch_one(&mut **tx)
        .await
        .context("try the schema-push advisory lock")?;
    Ok(())
}

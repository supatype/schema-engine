//! One push, for the CLI, the server and the tests alike.
//!
//! Phase 3c of the managed-object ownership plan (`plans/Managed-Object-Ownership-Plan.md`,
//! section 4). Until now `main.rs` and `server/routes.rs` each carried their own copy of the push:
//! bootstrap, introspect, diff, render, apply in a transaction, record. The copies had drifted (one
//! took the schema-push advisory lock and the other did not; one re-applied the trigger functions
//! on an up-to-date push and the other did not), and the tests pushed a third way, by rendering
//! `forward_sql` and executing it, so none of them exercised what a user runs.
//!
//! Two steps, because the CLI confirms renames and risky operations between them:
//!
//! 1. [`prepare`]: everything that reads. Bootstrap the engine's own tables, refuse a second
//!    project in the database, introspect, diff against the live catalog and the previous schema,
//!    and, for the kinds that have moved onto the ledger, build the desired set, load the ledger
//!    and reconcile.
//! 2. [`apply`]: everything that writes, in one transaction, or nothing.
//!
//! No kind has moved onto the reconcile yet (`MOVED_KINDS` is empty), so a push today applies
//! exactly what it applied before this module existed, and skips the reads only the reconcile
//! would consume. The first kind arrives with the next PR.

use std::collections::BTreeSet;

use anyhow::{bail, Context, Result};
use sqlx::{Executor, PgPool, Postgres, Transaction};

use crate::desired::desired_objects;
use crate::differ::{self, DiffOutput};
use crate::generator::sql::{migration, migration_errors, rollback, storage, triggers, versions};
use crate::generator::typescript::admin;
use crate::introspector::{self, catalog, fingerprint::fingerprints, fingerprint::ObjectKind};
use crate::ledger::{self, reconcile};
use crate::parser::ast::SchemaAst;
use crate::state::{migration_history, studio_state};

/// The kinds the reconcile owns. A kind joins this list in the PR that moves it, and from that PR
/// on the reconcile is its differ.
pub const MOVED_KINDS: &[ObjectKind] = &[];

/// Advisory lock keys shared with the CLI and the realtime worker (`packages/cli`,
/// `packages/realtime`, `schema-push-lock`). Realtime skips WAL polls while this is held.
const PUSH_LOCK_CLASS: i32 = 872014;
const PUSH_LOCK_ID: i32 = 1;

/// What a push has read and decided, before anything is written.
pub struct Plan<'a> {
    pub ast: &'a SchemaAst,
    pub schema: String,
    pub storage_sql: String,
    /// The CLI may edit this between `prepare` and `apply` (rename confirmations).
    pub diff: DiffOutput,
    pub reconcile: reconcile::Plan,
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

/// Reads and decides. Fails without writing when a declared table exists unmanaged (the error
/// downcasts to [`migration::UnmanagedModelTables`], so a caller can name the tables) or when a
/// second project is already in the database.
pub async fn prepare<'a>(pool: &PgPool, ast: &'a SchemaAst, schema: &str) -> Result<Plan<'a>> {
    let storage_sql = storage::generate(ast)?;

    migration_history::bootstrap_internal_state(pool)
        .await
        .context("Failed to bootstrap _supatype internal state")?;
    migration_history::assert_project_schema(pool, schema).await?;
    studio_state::bootstrap(pool).await?;

    // Always the live catalog. A snapshot from the last push cannot see what changed outside
    // Supatype since, so `diff` showed one plan and push applied another.
    let db_state = introspector::introspect(pool, schema).await?;
    let previous_ast = migration_history::load_latest_schema_ast(pool).await;
    let diff = differ::diff_with_previous(ast, &db_state, previous_ast.as_ref())?;

    // An unchanged schema produces an empty diff, so the renderer's own check would never run and
    // the push would report success while a declared table sat in the API with none of its rules
    // applied. Checked here, before the CLI asks anything about a push it is going to refuse.
    migration::assert_no_unmanaged_model_tables(&diff)?;

    let reconcile = if MOVED_KINDS.is_empty() {
        reconcile::Plan::default()
    } else {
        let desired = desired_objects(ast, schema)?;
        let mut conn = pool.acquire().await?;
        let ledger = ledger::load(&mut conn).await?;
        let catalog = catalog::read(&mut conn, schema).await?;
        let live = fingerprints(&db_state, &catalog);
        let none = BTreeSet::new();
        reconcile::reconcile(reconcile::Inputs {
            desired: &desired,
            ledger: &ledger,
            live: &live,
            stamped: &none,
            equivalent: &none,
            created_by_parent: &none,
            kinds: MOVED_KINDS,
        })
    };

    Ok(Plan {
        ast,
        schema: schema.to_string(),
        storage_sql,
        diff,
        reconcile,
    })
}

pub async fn apply(pool: &PgPool, plan: Plan<'_>, opts: ApplyOptions) -> Result<Outcome> {
    let conflicts: Vec<String> = plan
        .reconcile
        .conflicts()
        .map(|a| {
            let k = a.key();
            format!("{} {}.{}.{}", k.kind.as_str(), k.schema, k.parent, k.name)
        })
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
    sqlx::raw_sql(&plan.storage_sql)
        .execute(pool)
        .await
        .context("Failed to apply storage schema/policies")?;
    let triggers_sql = triggers::generate(plan.ast, &plan.schema)?;
    sqlx::raw_sql(&triggers_sql)
        .execute(pool)
        .await
        .context("Failed to apply trigger functions")?;
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

/// Everything rendered for one migration, kept together because the failure record needs the
/// same name, hash and batch the success record does.
struct Rendered {
    name: String,
    hash: String,
    /// What runs inside the transaction `apply` owns.
    apply_body: String,
    /// The same statements wrapped in `BEGIN`/`COMMIT`, which is what the history stores.
    apply_batch: String,
    sources: migration_history::AppliedMigrationSources,
}

fn render(plan: &Plan<'_>, opts: ApplyOptions) -> Result<Rendered> {
    // The hash covers the migration file as `supatype migrate` would print it, as it always has,
    // so history rows stay comparable across engine versions.
    let migration_sql = migration::generate(&plan.diff, opts.force, &plan.schema, plan.ast)?;
    // Millisecond precision so rapid retries do not collide on the name.
    let name = opts
        .name
        .unwrap_or_else(|| format!("push_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S_%3f")));

    let mut apply_body = migration::push_storage_and_model_apply_body(
        &plan.storage_sql,
        &plan.diff,
        opts.force,
        &plan.schema,
        plan.ast,
    )?;
    let reconcile_sql: Vec<&str> = plan
        .reconcile
        .actions
        .iter()
        .flat_map(reconcile::Action::sql)
        .collect();
    if !reconcile_sql.is_empty() {
        apply_body.push_str("\n-- reconciled objects\n");
        apply_body.push_str(&reconcile_sql.join("\n"));
    }

    Ok(Rendered {
        name,
        hash: migration::migration_hash(&migration_sql),
        apply_batch: migration::batch_sql(&apply_body),
        apply_body,
        sources: migration_history::AppliedMigrationSources {
            sql_down: rollback::generate(&plan.diff, &plan.schema).ok(),
            schema_sources: opts.schema_sources,
            schema_sources_manifest: opts.schema_sources_manifest,
        },
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
                &rendered.hash,
                &rendered.apply_batch,
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

    let operations = plan.diff.operations.len();
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
        let msg = migration_errors::enrich_migration_error(&e.to_string(), Some(&plan.diff));
        return Err(anyhow::anyhow!(msg).context("Failed to apply migration"));
    }

    let new_db_state = introspector::introspect_connection(tx, &plan.schema)
        .await
        .context("Failed to introspect after migration")?;

    let drift_warnings = differ::integrity::post_push_warnings(plan.ast, &new_db_state);
    if strict && !differ::integrity::post_push_ok(plan.ast, &new_db_state, true) {
        bail!(
            "Push rolled back: post-apply schema drift in strict mode ({})",
            drift_warnings.join("; ")
        );
    }

    migration_history::save_schema_state(&mut **tx, &new_db_state)
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

    let schema_snap = serde_json::to_value(plan.ast).ok();
    let admin_cfg = admin::generate(plan.ast).ok();
    migration_history::insert_applied_migration(
        &mut **tx,
        &rendered.name,
        &rendered.hash,
        schema_snap.clone(),
        admin_cfg.clone(),
        &rendered.apply_batch,
        &rendered.sources,
    )
    .await
    .context("Failed to record migration in history")?;

    Ok(Applied {
        drift_warnings,
        studio_metadata: admin_cfg.zip(schema_snap),
    })
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

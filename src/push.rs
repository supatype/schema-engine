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
//!    It first re-reads the ledger and the live objects inside that transaction and refuses if
//!    they are not what [`plan`] decided against.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use sqlx::{Executor, PgConnection, PgPool, Postgres, Transaction};

use crate::desired::{desired_objects_for, statements, FieldEnforcement, ObjectKey};
use crate::differ::{self, DiffOutput, FieldMaskingTier, Operation};
use crate::generator::sql::migration::{self, Migration};
use crate::generator::sql::migration_errors::{self, CheckSite};
use crate::generator::sql::{constraint_helpers, field_views, grants, rls, storage, versions};
use crate::generator::typescript::admin;
use crate::introspector::fingerprint::{
    fingerprints, holding_nothing, ObjectFingerprint, ObjectKind,
};
use crate::introspector::{self, catalog, catalog::CatalogState};
use crate::ledger::{self, drift, probe, reconcile, LedgerRow};
use crate::parser::ast::SchemaAst;
use crate::sql_quote::{quote_literal, quote_qualified};
use crate::state::database_state::DatabaseState;
use crate::state::{migration_history, studio_state};

/// The kinds the reconcile owns. A kind joins this list in the PR that moves it, and from that PR
/// on the reconcile is its differ: check constraints since Phase 3d, foreign keys since 4.1,
/// triggers and their `_platform` functions since 4.2, indexes since 4.3, cron jobs since 4.4,
/// views since 4.6, security labels since 4.7a, policies since 4.7b, grants since 4.7c, RLS
/// enablement since 4.8, columns since 4.9 (recorded; the column differ alters them), primary keys,
/// the engine's schemas and serial sequences since 4.10, tables (recorded; the table differ makes,
/// renames and drops them) and unique constraints since 4.11.
pub const MOVED_KINDS: &[ObjectKind] = &[
    ObjectKind::Check,
    ObjectKind::ForeignKey,
    ObjectKind::Function,
    ObjectKind::Trigger,
    ObjectKind::Index,
    ObjectKind::CronJob,
    ObjectKind::View,
    ObjectKind::SecurityLabel,
    ObjectKind::Policy,
    ObjectKind::TableGrant,
    ObjectKind::RlsAttributes,
    ObjectKind::Column,
    ObjectKind::PrimaryKey,
    ObjectKind::Schema,
    ObjectKind::Sequence,
    ObjectKind::Table,
    ObjectKind::Unique,
];

/// Advisory lock keys shared with the CLI and the realtime worker (`packages/cli`,
/// `packages/realtime`, `schema-push-lock`). Realtime skips WAL polls while this is held.
const PUSH_LOCK_CLASS: i32 = 872014;
const PUSH_LOCK_ID: i32 = 1;
/// The engine's own mutual exclusion, on the same class and the next id: a push, a writing `adopt`
/// and `doctor --rebaseline` each take it for their transaction and refuse while another holds it.
/// Separate from [`PUSH_LOCK_ID`], which the CLI holds from another session around the push it
/// runs, so refusing on that one would refuse every such push. Only this engine takes this key.
const ENGINE_LOCK_ID: i32 = 2;

/// Refused because another push, adopt, rebaseline or rollback holds [`ENGINE_LOCK_ID`]. A type, so a caller
/// can tell it from a failed push and retry: the HTTP server answers it with 409 and
/// [`ENGINE_BUSY`].
#[derive(Debug)]
pub struct EngineBusy;

/// The HTTP refusal reason for [`EngineBusy`].
pub const ENGINE_BUSY: &str = "engine_busy";

impl std::fmt::Display for EngineBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "another push, adopt, rebaseline or rollback is running on this database; try again. \
             Nothing was applied.",
        )
    }
}

impl std::error::Error for EngineBusy {}

/// What a push has read and decided, before anything is written.
pub struct Plan<'a> {
    pub ast: Cow<'a, SchemaAst>,
    pub schema: String,
    /// The CLI may edit this between `prepare` and `apply` (rename confirmations).
    pub diff: DiffOutput,
    pub reconcile: reconcile::Plan,
    /// What `reconcile` was decided from, checked again inside the apply's transaction.
    inputs: ReconcileInputs,
}

/// The ledger and the live objects a reconcile was decided from, each in key order.
///
/// The plan reads them on a pooled connection before the apply's transaction begins, and the CLI
/// may wait on a confirmation between the two. A push or a hand edit landing in that gap would
/// otherwise be overwritten by statements decided against a database that no longer exists: a
/// drop of an object that has since become someone else's, a ledger row written over one just
/// recorded. [`ReconcileInputs::assert_current`] compares them with a re-read inside the apply's
/// transaction, once the push lock is taken, and refuses when they moved.
struct ReconcileInputs {
    ledger: Vec<LedgerRow>,
    fingerprints: Vec<ObjectFingerprint>,
}

impl ReconcileInputs {
    fn of(state: &State) -> ReconcileInputs {
        let mut ledger = state.ledger.clone();
        ledger.sort_by(|a, b| a.key.cmp(&b.key));
        let mut fingerprints = state.fingerprints.clone();
        fingerprints.sort();
        ReconcileInputs {
            ledger,
            fingerprints,
        }
    }

    /// Refuse when `now` is not what the plan was decided from, naming what moved.
    fn assert_current(&self, now: &State) -> Result<()> {
        let now = ReconcileInputs::of(now);
        let mut moved: BTreeSet<String> = BTreeSet::new();
        let ledger = |rows: &[LedgerRow]| -> BTreeMap<ObjectKey, LedgerRow> {
            rows.iter().map(|r| (r.key.clone(), r.clone())).collect()
        };
        let (was, is) = (ledger(&self.ledger), ledger(&now.ledger));
        for key in was.keys().chain(is.keys()) {
            if was.get(key) != is.get(key) {
                moved.insert(format!("{key} (ledger)"));
            }
        }
        let live = |fps: &[ObjectFingerprint]| -> BTreeMap<ObjectKey, ObjectFingerprint> {
            fps.iter().map(|f| (f.key(), f.clone())).collect()
        };
        let (was, is) = (live(&self.fingerprints), live(&now.fingerprints));
        for key in was.keys().chain(is.keys()) {
            if was.get(key) != is.get(key) {
                moved.insert(key.to_string());
            }
        }
        if moved.is_empty() {
            return Ok(());
        }
        let shown: Vec<String> = moved.iter().take(10).cloned().collect();
        bail!(
            "The database changed after this push was planned, so nothing was applied: {}{}. \
             Another push or a change outside Supatype landed in between. Run the push again to \
             plan it against the database as it is now.",
            shown.join(", "),
            match moved.len() - shown.len() {
                0 => String::new(),
                more => format!(" and {more} more"),
            }
        )
    }
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
            &self.ast,
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
    /// Put back a policy, grant, label or RLS attribute changed or removed outside Supatype (plan
    /// 3.5). Without it the push refuses with [`drift::SecurityDrift`].
    pub overwrite_drift: bool,
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

/// Read under a pinned `search_path` (`introspector::pin_search_path`), so a fingerprint does not
/// depend on the session's, and with the session's put back after, error or not.
async fn live(conn: &mut PgConnection, schema: &str) -> Result<Live> {
    let saved = introspector::pin_search_path(conn).await?;
    let read = read_live(conn, schema).await;
    let restored = introspector::restore_search_path(conn, &saved).await;
    let live = read?;
    restored?;
    Ok(live)
}

async fn read_live(conn: &mut PgConnection, schema: &str) -> Result<Live> {
    let db = introspector::introspect_connection(conn, schema).await?;
    let catalog = catalog::read(conn, schema).await?;
    let fingerprints = fingerprints(&db, &catalog);
    Ok(Live {
        db,
        catalog,
        fingerprints,
    })
}

/// What a push reads before it decides, read once: the live state, its catalog and fingerprints,
/// and the ledger (empty where no push has made one), with the ledger's word on which tables are
/// ours already in the state (Phase 4.11). `doctor`, `adopt` and `--rebaseline` read through this
/// too, so they see exactly what a push would.
pub struct State {
    pub db: DatabaseState,
    pub catalog: CatalogState,
    pub fingerprints: Vec<ObjectFingerprint>,
    pub ledger: Vec<LedgerRow>,
}

impl State {
    /// A state from parts already read, for a caller with no connection (a test, a report).
    pub fn of(mut db: DatabaseState, catalog: CatalogState, ledger: Vec<LedgerRow>) -> State {
        db.set_table_ownership(&ledger);
        let fingerprints = fingerprints(&db, &catalog);
        State {
            db,
            catalog,
            fingerprints,
            ledger,
        }
    }
}

pub async fn read_state(conn: &mut PgConnection, schema: &str) -> Result<State> {
    let Live {
        mut db,
        catalog,
        fingerprints,
    } = live(conn, schema).await?;
    let ledger = ledger::load_if_present(conn).await?;
    db.set_table_ownership(&ledger);
    Ok(State {
        db,
        catalog,
        fingerprints,
        ledger,
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
    // Which tables are ours is the ledger's to say (Phase 4.11), so the table and column differs
    // drop, rename and attach rules only where it does: `read_state` puts that in the state.
    let (
        state,
        Decision {
            diff, reconcile, ..
        },
    ) = read_and_decide(&mut conn, pool, ast, schema).await?;

    // An unchanged schema produces an empty diff, so the renderer's own check would never run and
    // the push would report success while a declared table sat in the API with none of its rules
    // applied. Checked here, before the CLI asks anything about a push it is going to refuse.
    migration::assert_no_unmanaged_model_tables(&diff)?;

    Ok(Plan {
        // Rendered with the names the ledger records, as the decision was (F2d).
        ast: with_recorded_names(ast, &state.ledger, schema),
        schema: schema.to_string(),
        diff,
        reconcile,
        inputs: ReconcileInputs::of(&state),
    })
}

/// What a push decides against `state`: the migration diff, gated on the ledger, and the reconcile,
/// with the desired set they were made from. `doctor`, `adopt`, `--rebaseline` and the check after
/// a push all start here too, so none of them can disagree with a push.
pub struct Decision {
    pub diff: DiffOutput,
    pub reconcile: reconcile::Plan,
    pub desired: Vec<crate::desired::DesiredObject>,
}

/// The schema a state was read from. A state built by hand (a test) may not name its schema.
fn project_schema(state: &State) -> &str {
    match state.db.schema.as_str() {
        "" => "public",
        named => named,
    }
}

/// `ast` with the names the ledger records for its keys, checks and indexes, which keep them
/// (F2d), or `ast` itself when the ledger records none. A released row is the user's, and its name
/// is not one of ours.
pub fn with_recorded_names<'a>(
    ast: &'a SchemaAst,
    ledger: &[LedgerRow],
    schema: &str,
) -> Cow<'a, SchemaAst> {
    let mut recorded = crate::managed::RecordedNames::default();
    for row in ledger
        .iter()
        .filter(|r| r.key.schema == schema && r.status != ledger::Status::Released)
    {
        let group = match row.key.kind {
            ObjectKind::PrimaryKey => "pkey",
            ObjectKind::Unique => "key",
            ObjectKind::ForeignKey => "fkey",
            ObjectKind::Check => "check",
            ObjectKind::Index => "index",
            _ => continue,
        };
        let columns = reconcile::parse_definition(&row.live_def)
            .get("columns")
            .copied();
        recorded.record(&row.key.parent, group, &row.key.name, columns);
    }
    if recorded.is_empty() {
        return Cow::Borrowed(ast);
    }
    let mut ast = ast.clone();
    ast.recorded_names = recorded;
    Cow::Owned(ast)
}

/// [`Decision`] without asking the database anything: an unstamped same-named check the database
/// would deparse to ours is still a conflict here. `previous` is the schema of the last push, for
/// telling a renamed table or column from a dropped and added one.
pub fn decide(ast: &SchemaAst, state: &State, previous: Option<&SchemaAst>) -> Result<Decision> {
    let schema = project_schema(state);
    let recorded = with_recorded_names(ast, &state.ledger, schema);
    let kept = serials_kept(&recorded, &state.db);
    let ast = kept.as_ref().unwrap_or(&recorded);
    let mut diff = differ::diff_with_previous(ast, &state.db, previous)?;
    // D4: the column differ drops only a column the ledger records as ours. One someone added to
    // a managed table, one released with `adopt --release`, or one an older engine made that this
    // push has not recorded yet, stays.
    // A column adopted with `supatype adopt --key column:<table>.<column>` while the schema does not
    // declare it is kept: Supatype knows of it (and a narrowed write grant includes it), but has
    // no definition to bring it to.
    // A table this push renames still has its rows under its old name, so its columns are
    // looked up there.
    let renamed_from: BTreeMap<String, String> = diff
        .operations
        .iter()
        .filter_map(|op| match op {
            Operation::RenameTable { from, to, .. } => Some((to.clone(), from.clone())),
            _ => None,
        })
        .collect();
    let recorded_as = |table: &str| {
        renamed_from
            .get(table)
            .cloned()
            .unwrap_or_else(|| table.to_string())
    };
    let adopted: BTreeSet<(&str, &str)> = state
        .ledger
        .iter()
        .filter(|r| {
            r.key.kind == ObjectKind::Column
                && r.key.schema == schema
                && r.status == ledger::Status::Adopted
        })
        .map(|r| (r.key.parent.as_str(), r.key.name.as_str()))
        .collect();
    diff.operations.retain(|op| {
        !matches!(op, Operation::DropColumn { table, column, .. }
            if adopted.contains(&(recorded_as(table).as_str(), column.as_str())))
    });
    diff.summary = differ::DiffSummary::of(&diff.operations);
    diff.leave_released_columns(|table, column| {
        state.db.column_owned(&recorded_as(table), column) == Some(false)
    });
    diff.keep_columns_not_ours(|table, column| {
        state.db.column_owned(&recorded_as(table), column) == Some(true)
    });
    let narrowed = NarrowedColumns::of(ast, state, &diff, schema);
    diff.warnings.extend(narrowed.warnings());
    let mut desired = desired_here(&diff, &state.catalog, schema, ast)?;
    narrowed.grant_adopted(&mut desired, ast, &diff, schema);
    let live = with_grants_of_nothing(&state.fingerprints, state.ledger.iter().map(|r| &r.key));
    let named = named_by_the_engine(previous, &state.db, schema);
    let mut reconcile =
        reconcile_desired(&diff, &state.ledger, &live, &desired, schema, ast, &named)?;
    reconcile.actions.extend(previously_declared_columns(
        state, previous, &desired, schema,
    ));
    diff.warnings.extend(rebuild_warnings(&reconcile));
    Ok(Decision {
        diff,
        reconcile,
        desired,
    })
}

/// F2(a), said in the plan: each foreign key the push drops and makes again, unchanged, because
/// the key it references is rebuilt.
fn rebuild_warnings(plan: &reconcile::Plan) -> Vec<String> {
    plan.actions
        .iter()
        .filter_map(|action| match action {
            reconcile::Action::Rebuild { key, because, .. } => Some(format!(
                "{key} references {because}, which this push drops and makes again: the foreign \
                 key is dropped before it and made again after it, unchanged"
            )),
            _ => None,
        })
        .collect()
}

/// `ast` with each `AutoIncrement` field whose column is a live `SERIAL` declared as the serial it
/// is, or `None` when there is none.
///
/// `AutoIncrement` made a serial before it meant an identity column generated by default, and a
/// column made then satisfies it: the push, the ledger and doctor see the declaration that made it,
/// so nothing about it changes, is re-recorded or is reported, on this push or any other. Only a
/// new column is made an identity column. An explicit `Identity` is not this, and converts it.
fn serials_kept(ast: &SchemaAst, db: &DatabaseState) -> Option<SchemaAst> {
    use crate::parser::ast::FieldAst;
    let is_serial = |table: &str, column: &str| {
        db.tables
            .iter()
            .find(|t| t.name == table)
            .and_then(|t| t.columns.iter().find(|c| c.name == column))
            .is_some_and(|c| {
                !c.is_identity
                    && c.default
                        .as_deref()
                        .is_some_and(|d| d.starts_with("nextval("))
            })
    };
    let mut kept = None;
    for (m, model) in ast.models.iter().enumerate() {
        for (name, field) in &model.fields {
            let serial = match field {
                FieldAst::Integer(f) if f.auto_increment => ("SERIAL", f),
                FieldAst::BigInt(f) if f.auto_increment => ("BIGSERIAL", f),
                _ => continue,
            };
            let columns = crate::parser::accessors::column_names_for(name, field);
            if !columns.iter().any(|c| is_serial(model.table_name(), c)) {
                continue;
            }
            let (pg_type, f) = serial;
            let mut f = f.clone();
            f.identity = None;
            f.auto_increment = false;
            f.pg_type = pg_type.to_string();
            f.annotations.db.pg_type = pg_type.to_string();
            let field = if pg_type == "SERIAL" {
                FieldAst::Serial(f)
            } else {
                FieldAst::BigSerial(f)
            };
            let out = kept.get_or_insert_with(|| ast.clone());
            out.models[m].fields.insert(name.clone(), field);
        }
    }
    kept
}

/// The columns an older engine made that the schema has stopped declaring in the first push after
/// an upgrade: no row records them, so this push withholds their drop (D4), but the last push's
/// schema declared them on a table that is ours, so they are recorded here, with the `CREATE` that
/// schema asked for, and the next push drops them. A column no schema declared is never claimed.
fn previously_declared_columns(
    state: &State,
    previous: Option<&SchemaAst>,
    desired: &[crate::desired::DesiredObject],
    schema: &str,
) -> Vec<reconcile::Action> {
    let Some(previous) = previous else {
        return Vec::new();
    };
    let Ok(before) = desired_objects_for(previous, schema, FieldEnforcement::Labels) else {
        return Vec::new();
    };
    let wanted: BTreeSet<&ObjectKey> = desired.iter().map(|d| &d.key).collect();
    let live: BTreeSet<ObjectKey> = state
        .fingerprints
        .iter()
        .filter(|f| f.kind == ObjectKind::Column)
        .map(ObjectFingerprint::key)
        .collect();
    before
        .into_iter()
        .filter(|d| {
            let key = &d.key;
            key.kind == ObjectKind::Column
                && live.contains(key)
                && !wanted.contains(key)
                && state.db.column_owned(&key.parent, &key.name).is_none()
                && state
                    .db
                    .tables
                    .iter()
                    .any(|t| t.name == key.parent && state.db.owns_table(t))
        })
        .map(|d| reconcile::Action::Adopt {
            key: d.key,
            reason: reconcile::AdoptReason::PreviouslyDeclared,
            create_sql: d.create_sql,
            comment: None,
            renamed_from: None,
            status: ledger::Status::Managed,
        })
        .collect()
}

/// Everything a push knows before it writes: [`read_state`] on `conn` (a transaction, for a caller
/// that then writes), then [`decide_probed`] against the schema of the last push.
pub async fn read_and_decide(
    conn: &mut PgConnection,
    pool: &PgPool,
    ast: &SchemaAst,
    schema: &str,
) -> Result<(State, Decision)> {
    let state = read_state(conn, schema).await?;
    let previous = migration_history::load_latest_schema_ast(pool).await;
    let decision = decide_probed(conn, ast, &state, previous.as_ref()).await?;
    Ok((state, decision))
}

/// [`decide`], then asking the database to settle what it can (`ledger::probe`): a same-named
/// object it proves equivalent to ours is adopted rather than refused. A probe the database cannot
/// run (a read-only role or a standby, which cannot make the temporary table; a declared check on a
/// column the table does not have yet) proves nothing, so those objects stay conflicts: `doctor`
/// must still report, and a push still refuses them by name rather than failing on the probe.
pub async fn decide_probed(
    conn: &mut PgConnection,
    ast: &SchemaAst,
    state: &State,
    previous: Option<&SchemaAst>,
) -> Result<Decision> {
    let mut decision = decide(ast, state, previous)?;
    let proven = match probe::equivalent(conn, &decision.reconcile).await {
        Ok(proven) => proven,
        Err(e) => {
            tracing::warn!("equivalence probe not run, conflicts stand: {e:#}");
            BTreeSet::new()
        }
    };
    decision.reconcile.adopt_equivalent(&proven);
    upgrade_hand_edits(conn, state, &mut decision, previous).await;
    Ok(decision)
}

/// The first push after an upgrade finds every policy, grant, label and RLS attribute an older
/// engine made with no ledger row, and replaces each with the schema's definition, as its name or
/// location makes it ours. One edited by hand under the older engine would be overwritten silently,
/// where the same edit made after the upgrade needs consent (plan 3.5). So each is compared with
/// what the last push's schema makes of it: that schema's statements are run in a transaction that
/// is always rolled back, each object read back, and one whose live fingerprint differs is a hand
/// edit: its `Replace` carries it, so the push asks before overwriting it and doctor reports it as
/// drift. One the last schema did not declare was not that engine's, and is taken over as before.
/// Without a last schema there is nothing to compare with, and the push says so.
///
/// Grants are compared with what that engine left rather than with the exact set (D7) the last
/// schema renders today. An older engine granted and revoked only the four privileges the rules
/// govern, on top of the database's default privileges, so on the supatype image every API role it
/// left also holds `REFERENCES`, `TRIGGER`, `TRUNCATE` (and `MAINTAIN`) from them. What it made is
/// therefore the rendered set plus whatever else the defaults give that role on that table
/// ([`older_engine_grant_sql`]); a clean upgrade matches it, and a privilege beyond it, or one
/// taken away, is a hand edit and asks first.
async fn upgrade_hand_edits(
    conn: &mut PgConnection,
    state: &State,
    decision: &mut Decision,
    previous: Option<&SchemaAst>,
) {
    let recorded: BTreeSet<&ObjectKey> = state.ledger.iter().map(|r| &r.key).collect();
    let candidates: Vec<usize> = decision
        .reconcile
        .actions
        .iter()
        .enumerate()
        .filter(|(_, a)| {
            matches!(a, reconcile::Action::Replace { key, drifted: None, .. }
                if crate::desired::security_relevant(key.kind)
                    && !recorded.contains(key))
        })
        .map(|(i, _)| i)
        .collect();
    if candidates.is_empty() {
        return;
    }
    let keys = |indices: &[usize]| {
        indices
            .iter()
            .map(|&i| decision.reconcile.actions[i].key().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let Some(previous) = previous else {
        let warning = format!(
            "{} object(s) that decide who may read or write have no record and there is no \
             earlier schema to compare them with, so they are replaced with the schema's \
             definition without checking for changes made by hand: {}",
            candidates.len(),
            keys(&candidates)
        );
        decision.diff.warnings.push(warning);
        return;
    };
    let schema = project_schema(state);
    let plan = field_views::field_view_plan(previous, &state.db);
    let fields = match decision.diff.field_masking {
        FieldMaskingTier::Views => FieldEnforcement::Views(&plan),
        FieldMaskingTier::None | FieldMaskingTier::Extension => FieldEnforcement::Labels,
    };
    let before: BTreeMap<ObjectKey, String> = match desired_objects_for(previous, schema, fields) {
        Ok(objects) => objects.into_iter().map(|d| (d.key, d.create_sql)).collect(),
        Err(e) => {
            decision.diff.warnings.push(format!(
                "the last push's schema could not be rendered ({e:#}), so {} are replaced \
                 without checking for changes made by hand",
                keys(&candidates)
            ));
            return;
        }
    };
    let probes: Vec<(ObjectKey, String)> = candidates
        .iter()
        .filter_map(|&i| {
            let key = decision.reconcile.actions[i].key();
            let sql = before.get(key)?;
            let mut probe = format!("{}\n{sql}", reset_sql(key));
            // Under tier 2 that engine took every privilege off the base table, defaults included.
            if key.kind == ObjectKind::TableGrant
                && decision.diff.field_masking != FieldMaskingTier::Views
            {
                probe.push('\n');
                probe.push_str(&older_engine_grant_sql(&key.schema, &key.parent, &key.name));
            }
            Some((key.clone(), probe))
        })
        .collect();
    let (made, failed) = match made_by(conn, schema, &probes).await {
        Ok(made) => made,
        Err(e) => {
            decision.diff.warnings.push(format!(
                "{} could not be compared with the last push's schema ({e:#}): they are replaced \
                 without checking for changes made by hand",
                keys(&candidates)
            ));
            return;
        }
    };
    let live: BTreeMap<ObjectKey, &ObjectFingerprint> =
        state.fingerprints.iter().map(|f| (f.key(), f)).collect();
    let mut unchecked = Vec::new();
    for i in candidates {
        let reconcile::Action::Replace { key, drifted, .. } = &mut decision.reconcile.actions[i]
        else {
            continue;
        };
        let Some(l) = live.get(key) else { continue };
        // One the last push's schema did not declare is not an older engine's (a table adopted
        // since, say, whose RLS the schema now asks for): taken over as before.
        if !before.contains_key(key) {
            continue;
        }
        if failed.contains(key) {
            unchecked.push(key.to_string());
            continue;
        }
        let expected = made.get(key).cloned();
        let differs = expected
            .as_ref()
            .is_none_or(|e| e.fingerprint != l.fingerprint);
        if differs {
            *drifted = Some(reconcile::HandEdit {
                recorded_def: expected.map(|e| e.definition).unwrap_or_else(|| {
                    "(nothing: the schema of the last push makes no such object)".to_string()
                }),
                live_def: l.definition.clone(),
                live_fp: l.fingerprint.clone(),
            });
        }
    }
    if !unchecked.is_empty() {
        decision.diff.warnings.push(format!(
            "{} could not be compared with the last push's schema: they are replaced without \
             checking for changes made by hand",
            unchecked.join(", ")
        ));
    }
}

/// What an older engine's grant to `role` on a table held beyond the four privileges the rules
/// govern: what the database's default privileges give that role on a table its owner creates in
/// its schema (`ALTER DEFAULT PRIVILEGES`, global and per schema), read from `pg_default_acl` as
/// the table's `CREATE` applied them. That engine granted and revoked only `SELECT`, `INSERT`,
/// `UPDATE` and `DELETE`, so everything else the defaults gave stayed. Granted after the last
/// schema's statement, which revokes everything first; guarded on the role and the table, as the
/// grant itself is.
fn older_engine_grant_sql(schema: &str, table: &str, role: &str) -> String {
    let role_lit = quote_literal(role);
    let target_lit = quote_literal(&quote_qualified(schema, table));
    format!(
        "DO $defaults$\nDECLARE\n  privileges text;\nBEGIN\n  \
         IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {role_lit}) AND to_regclass({target_lit}) IS NOT NULL THEN\n    \
         SELECT string_agg(DISTINCT a.privilege_type, ', ')\n      INTO privileges\n      \
         FROM pg_class c\n      \
         JOIN pg_default_acl d ON d.defaclrole = c.relowner AND d.defaclobjtype = 'r'\n                           \
         AND d.defaclnamespace IN (0, c.relnamespace)\n      \
         CROSS JOIN LATERAL aclexplode(d.defaclacl) a\n     \
         WHERE c.oid = to_regclass({target_lit})\n       \
         AND a.grantee = (SELECT oid FROM pg_roles WHERE rolname = {role_lit})\n       \
         AND a.privilege_type NOT IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE');\n    \
         IF privileges IS NOT NULL THEN\n      \
         EXECUTE format('GRANT %s ON %s TO %I', privileges, {target_lit}, {role_lit});\n    \
         END IF;\n  \
         END IF;\nEND\n$defaults$;"
    )
}

/// What clears an object before the last schema's statement for it runs: its drop, or for row-level
/// security, both attributes off, since that statement only turns on what it asks for.
fn reset_sql(key: &ObjectKey) -> String {
    match key.kind {
        ObjectKind::RlsAttributes => {
            let target = quote_qualified(&key.schema, &key.parent);
            format!(
                "ALTER TABLE {target} NO FORCE ROW LEVEL SECURITY;\n\
                 ALTER TABLE {target} DISABLE ROW LEVEL SECURITY;"
            )
        }
        _ => key.drop_sql().unwrap_or_default(),
    }
}

/// Each probe's statements run in a transaction that is always rolled back, every one in a
/// savepoint of its own, and the objects read back as a push reads them: the fingerprints found,
/// and the keys whose statements the database refused.
async fn made_by(
    conn: &mut PgConnection,
    schema: &str,
    probes: &[(ObjectKey, String)],
) -> Result<(BTreeMap<ObjectKey, ObjectFingerprint>, BTreeSet<ObjectKey>)> {
    use sqlx::Connection;
    let mut tx = conn.begin().await.context("begin the upgrade comparison")?;
    let result = async {
        // Never wait on a table someone is using: a comparison that cannot lock is skipped.
        sqlx::query("SET LOCAL lock_timeout = '2s'")
            .execute(&mut *tx)
            .await?;
        let mut failed = BTreeSet::new();
        for (key, sql) in probes {
            let mut one = (*tx).begin().await?;
            match (&mut *one).execute(sqlx::raw_sql(sql)).await {
                Ok(_) => one.commit().await?,
                Err(e) => {
                    tracing::debug!("{key} not compared with the last push's schema: {e}");
                    one.rollback().await?;
                    failed.insert(key.clone());
                }
            }
        }
        let after = live(&mut tx, schema).await?;
        let made = after
            .fingerprints
            .into_iter()
            .map(|f| (f.key(), f))
            .filter(|(k, _)| probes.iter().any(|(p, _)| p == k))
            .collect();
        anyhow::Ok((made, failed))
    }
    .await;
    tx.rollback()
        .await
        .context("roll the upgrade comparison back")?;
    result
}

/// The reconcile for this push: the desired set against `ledger` and `live`, knowing which
/// objects the migration's own statements create and which tables it drops.
fn reconcile_with(
    diff: &DiffOutput,
    ledger: &[LedgerRow],
    live: &[ObjectFingerprint],
    catalog: &CatalogState,
    schema: &str,
    ast: &SchemaAst,
) -> Result<reconcile::Plan> {
    let desired = desired_here(diff, catalog, schema, ast)?;
    let live = with_grants_of_nothing(live, ledger.iter().map(|r| &r.key));
    reconcile_desired(diff, ledger, &live, &desired, schema, ast, &BTreeSet::new())
}

/// What a push of `ast` desires on this database. What the database can hold decides it (plan
/// section 10): without `pg_cron` the cron jobs are not desired, as the layer says so at apply time
/// and there is nothing to record; a grant to an API role this database does not have is desired
/// nowhere.
fn desired_here(
    diff: &DiffOutput,
    catalog: &CatalogState,
    schema: &str,
    ast: &SchemaAst,
) -> Result<Vec<crate::desired::DesiredObject>> {
    let fields = match diff.field_masking {
        FieldMaskingTier::Views => FieldEnforcement::Views(&diff.field_view_plan),
        FieldMaskingTier::None | FieldMaskingTier::Extension => FieldEnforcement::Labels,
    };
    let mut desired = desired_objects_for(ast, schema, fields)?;
    desired.retain(|d| match d.key.kind {
        ObjectKind::CronJob => catalog.cron_available,
        ObjectKind::TableGrant => catalog.granted_roles.contains(&d.key.name),
        _ => true,
    });
    sequences_as_created(&mut desired, &catalog.sequences, schema);
    Ok(desired)
}

/// The desired sequences under the names Postgres actually gave them. A serial's sequence is
/// named by Postgres when its column is created, free of whatever the schema held at that moment,
/// so the name the engine predicts from the schema alone can be another serial's: `order.item_id`
/// and `order_item.id` both make `order_item_id_seq`, and which one has it depends on which table
/// was created first, possibly pushes apart. A sequence is known by the column that owns it, so
/// one whose column exists takes its live name; one still to be made, whose predicted name a live
/// sequence holds, is predicted again free of every name in use, as Postgres will choose it. The
/// push then records each under the name it found ([`record_ledger`]).
fn sequences_as_created(
    desired: &mut [crate::desired::DesiredObject],
    live: &[catalog::DbSequence],
    schema: &str,
) {
    let live: Vec<&catalog::DbSequence> = live.iter().filter(|s| s.schema == schema).collect();
    let live_name = |owner: &str| {
        live.iter()
            .find(|s| s.owned_by.as_deref() == Some(owner))
            .map(|s| s.name.clone())
    };
    let owner = |d: &crate::desired::DesiredObject| d.structure.get("owned_by").cloned();
    let mut unresolved = Vec::new();
    for (i, d) in desired.iter_mut().enumerate() {
        if d.key.kind != ObjectKind::Sequence || d.key.schema != schema {
            continue;
        }
        let Some(owner) = owner(d) else { continue };
        match live_name(&owner) {
            Some(name) => rename_sequence(d, schema, &owner, &name),
            None => unresolved.push(i),
        }
    }
    let mut taken = crate::managed::NameChooser::default();
    for s in &live {
        taken.claim(&s.name);
    }
    for (i, d) in desired.iter().enumerate() {
        let relation = matches!(
            d.key.kind,
            ObjectKind::Table | ObjectKind::Index | ObjectKind::Sequence | ObjectKind::View
        );
        if relation && d.key.schema == schema && !unresolved.contains(&i) {
            taken.claim(&d.key.name);
        }
    }
    for i in unresolved {
        let d = &mut desired[i];
        let Some(owner) = owner(d) else { continue };
        let Some((table, column)) = owner.split_once('.') else {
            continue;
        };
        if live.iter().all(|s| s.name != d.key.name) {
            taken.claim(&d.key.name);
            continue;
        }
        let name = taken.choose(table, Some(column), "seq");
        rename_sequence(d, schema, &owner, &name);
    }
}

fn rename_sequence(d: &mut crate::desired::DesiredObject, schema: &str, owner: &str, name: &str) {
    let Some((table, column)) = owner.split_once('.') else {
        return;
    };
    d.key.name = name.to_string();
    d.create_sql = crate::desired::sequence_owned_by_sql(schema, name, table, column);
}

/// The `table.column` a sequence's recorded `ALTER SEQUENCE ... OWNED BY` names.
fn sequence_owner(create_sql: &str) -> Option<String> {
    let (_, target) = create_sql.rsplit_once(" OWNED BY ")?;
    let parts: Vec<&str> = target
        .trim_end()
        .trim_end_matches(';')
        .split("\".\"")
        .collect();
    match parts.as_slice() {
        [_, table, column] => Some(format!(
            "{}.{}",
            table.trim_matches('"'),
            column.trim_matches('"')
        )),
        _ => None,
    }
}

/// The columns of model tables whose write privilege a field rule narrows that the schema does not
/// declare (#63). A narrowed grant names the declared columns, so such a column gets no write
/// privilege for the narrowed role: one the ledger has no row for was added outside Supatype and
/// is reported, with how to include it; one adopted (`supatype adopt --key column:<table>.<column>`) is
/// granted beside the declared ones.
pub struct NarrowedColumns {
    /// `(table, column)` adopted while undeclared, in the table's column order.
    adopted: Vec<(String, String)>,
    /// `(table, column, roles)` with no row, and the narrowed roles it gets no write grant for.
    pub ungranted: Vec<(String, String, Vec<&'static str>)>,
}

impl NarrowedColumns {
    pub fn of(ast: &SchemaAst, state: &State, diff: &DiffOutput, schema: &str) -> NarrowedColumns {
        let status = |table: &str, column: &str| {
            state
                .ledger
                .iter()
                .find(|r| {
                    r.key.kind == ObjectKind::Column
                        && r.key.schema == schema
                        && r.key.parent == table
                        && r.key.name == column
                })
                .map(|r| r.status)
        };
        let mut adopted = Vec::new();
        let mut ungranted: Vec<(String, String, Vec<&'static str>)> = Vec::new();
        for grant in grants::table_grants(ast, views(diff)) {
            if grant.narrowed.is_empty() {
                continue;
            }
            let Some(table) = state.db.tables.iter().find(|t| t.name == grant.table) else {
                continue;
            };
            for column in &table.columns {
                if grant.columns.contains(&column.name) {
                    continue;
                }
                let at = (grant.table.clone(), column.name.clone());
                match status(&grant.table, &column.name) {
                    Some(ledger::Status::Adopted) if !adopted.contains(&at) => adopted.push(at),
                    None => match ungranted
                        .iter_mut()
                        .find(|(t, c, _)| (t, c) == (&at.0, &at.1))
                    {
                        Some((_, _, roles)) => roles.push(grant.role),
                        None => ungranted.push((at.0, at.1, vec![grant.role])),
                    },
                    _ => {}
                }
            }
        }
        NarrowedColumns { adopted, ungranted }
    }

    /// One line per column added outside Supatype that a narrowed grant leaves unwritable.
    pub fn warnings(&self) -> Vec<String> {
        self.ungranted
            .iter()
            .map(|(table, column, roles)| ungranted_message(table, column, roles))
            .collect()
    }

    /// The narrowed grants of `desired` with the adopted columns of their table added to the
    /// columns they grant on.
    fn grant_adopted(
        &self,
        desired: &mut [crate::desired::DesiredObject],
        ast: &SchemaAst,
        diff: &DiffOutput,
        schema: &str,
    ) {
        if self.adopted.is_empty() {
            return;
        }
        for mut grant in grants::table_grants(ast, views(diff)) {
            if grant.narrowed.is_empty() {
                continue;
            }
            let extra = self
                .adopted
                .iter()
                .filter(|(t, _)| *t == grant.table)
                .map(|(_, c)| c.clone());
            grant.columns.extend(extra);
            if let Some(d) = desired.iter_mut().find(|d| {
                d.key.kind == ObjectKind::TableGrant
                    && d.key.schema == schema
                    && d.key.parent == grant.table
                    && d.key.name == grant.role
            }) {
                d.create_sql = grant.create_sql(schema);
            }
        }
    }
}

/// What push and doctor say of a column added outside Supatype on a table whose write grant a
/// field rule narrows.
pub fn ungranted_message(table: &str, column: &str, roles: &[&str]) -> String {
    format!(
        "column {table}.{column} was added outside Supatype and has no write grant for {}; run \
         `supatype adopt --key column:{table}.{column}` to include it",
        roles.join(", ")
    )
}

/// Whether field rules are enforced by the `api` views, whose base tables hold nothing.
fn views(diff: &DiffOutput) -> bool {
    matches!(diff.field_masking, FieldMaskingTier::Views)
}

fn reconcile_desired(
    diff: &DiffOutput,
    ledger: &[LedgerRow],
    live: &[ObjectFingerprint],
    desired: &[crate::desired::DesiredObject],
    schema: &str,
    ast: &SchemaAst,
    named_by_the_engine: &BTreeSet<ObjectKey>,
) -> Result<reconcile::Plan> {
    let created_by_parent = created_by_parent(diff, schema, ast)?;
    let dropped_tables = dropped_tables(diff, schema);
    let renamed_tables = renamed_tables(diff, schema);
    Ok(reconcile::reconcile(reconcile::Inputs {
        desired,
        ledger,
        live,
        created_by_parent: &created_by_parent,
        dropped_tables: &dropped_tables,
        location,
        named_by_the_engine,
        renamed_tables: &renamed_tables,
        kinds: MOVED_KINDS,
    }))
}

/// Refuse when the reconcile renames objects with a table rename the diff no longer holds: the CLI
/// may edit the diff between `prepare` and `apply` (a declined rename), and those renames would then
/// run against a table that was never renamed. Planning again decides them against the diff as it
/// is.
fn assert_renames_still_planned(plan: &Plan<'_>) -> Result<()> {
    let renamed = renamed_tables(&plan.diff, &plan.schema);
    let stale: Vec<String> = plan
        .reconcile
        .actions
        .iter()
        .filter_map(|action| match action {
            reconcile::Action::Rename { key, from, .. }
                if renamed
                    .iter()
                    .all(|(table, to)| table.name != from.parent || *to != key.parent) =>
            {
                Some(from.to_string())
            }
            _ => None,
        })
        .collect();
    if stale.is_empty() {
        return Ok(());
    }
    bail!(
        "This push was planned with a table rename that is no longer part of it, so nothing was \
         applied ({}). Run the push again to plan it against the renames you confirmed.",
        stale.join(", ")
    )
}

/// The tables the migration renames, keyed by their key under the old name, with the new name, so
/// the reconcile renames what is on them rather than dropping and making it again.
fn renamed_tables(diff: &DiffOutput, schema: &str) -> BTreeMap<ObjectKey, String> {
    diff.operations
        .iter()
        .filter_map(|op| match op {
            Operation::RenameTable { from, to, .. } => Some((
                ObjectKey {
                    kind: ObjectKind::Table,
                    schema: schema.to_string(),
                    parent: String::new(),
                    name: from.clone(),
                },
                to.clone(),
            )),
            _ => None,
        })
        .collect()
}

/// Legacy ownership by engine naming (section 7): an older engine stamped nothing and the ledger
/// has no row, so an object it made is known only by its name. The functions, triggers and views
/// a push of the last push's schema would create, under either field enforcement, in the engine's
/// own schemas; and in the project schema, the triggers and the `can_*` affordance functions,
/// whose names the engine derives from a model's table. The last push's schema, not this one's:
/// the engine made what that schema asked for, while a name only this schema asks for may be a
/// user's object, which still refuses the push. A user's object under any other name
/// (`can_do_things`, a `_platform` helper of their own) is never among them.
fn named_by_the_engine(
    previous: Option<&SchemaAst>,
    db: &DatabaseState,
    schema: &str,
) -> BTreeSet<ObjectKey> {
    let engine_named = |key: &ObjectKey| match key.kind {
        ObjectKind::Function | ObjectKind::Trigger | ObjectKind::View
            if catalog::OWNED_SCHEMAS.contains(&key.schema.as_str()) =>
        {
            true
        }
        ObjectKind::Trigger => key.schema == schema,
        ObjectKind::Function => key.schema == schema && key.name.starts_with("can_"),
        _ => false,
    };
    let mut named = BTreeSet::new();
    let Some(previous) = previous else {
        return named;
    };
    let plan = field_views::field_view_plan(previous, db);
    for fields in [FieldEnforcement::Labels, FieldEnforcement::Views(&plan)] {
        if let Ok(objects) = desired_objects_for(previous, schema, fields) {
            named.extend(objects.into_iter().map(|d| d.key).filter(engine_named));
        }
    }
    // And the names 0.6.0 gave what Postgres cut to 63 bytes, which no name this engine
    // chooses matches (F8).
    named.extend(crate::legacy_names::engine_0_6_names(previous, schema));
    named
}

/// `live`, plus a fingerprint of "holds nothing" for every grant among `keys` the catalog has no
/// row for. A role with no privilege on a table has no `aclexplode` row, so without this a grant
/// of nothing the ledger recorded would read as dropped by hand on every push.
fn with_grants_of_nothing<'k>(
    live: &[ObjectFingerprint],
    keys: impl Iterator<Item = &'k ObjectKey>,
) -> Vec<ObjectFingerprint> {
    let present: BTreeSet<ObjectKey> = live.iter().map(ObjectFingerprint::key).collect();
    let mut out = live.to_vec();
    out.extend(
        keys.filter(|k| k.kind == ObjectKind::TableGrant && !present.contains(k))
            .map(holding_nothing),
    );
    out
}

/// What a live object's location says about whose it is when the ledger has no row (plan 3.4 and
/// section 5). Only the engine writes labels under its provider or names bucket policies
/// `storage_<label>_sel|ins|del`, so those are ours outright; the engine's own schemas hold only
/// what an engine put there. Not `api` (F12): it is the schema the API serves, where a project may
/// keep views and functions of its own, so an object there is ours only when the ledger or the
/// last push's schema records it ([`named_by_the_engine`]), and anything else under one of our
/// names is a conflict the push refuses until it is adopted.
fn location(key: &ObjectKey) -> reconcile::Location {
    let exclusive = match key.kind {
        ObjectKind::SecurityLabel => key.name == rls::MASK_PROVIDER,
        ObjectKind::Policy => {
            storage::is_unmarked_bucket_policy(&key.schema, &key.parent, &key.name)
        }
        _ => false,
    };
    let schema = key.schema.as_str();
    if exclusive {
        reconcile::Location::Exclusive
    } else if catalog::OWNED_SCHEMAS.contains(&schema) && schema != field_views::VIEW_SCHEMA {
        reconcile::Location::Owned
    } else {
        reconcile::Location::Neutral
    }
}

/// The migration a push of `ast` against an empty database would apply, with no database to ask:
/// the differ's operations and the reconcile's creations. For the tests that render fixtures a
/// database refuses; everything else goes through [`plan`].
pub fn fresh_migration(ast: &SchemaAst, schema: &str, force: bool) -> Result<Migration> {
    let diff = differ::diff(ast, &DatabaseState::default())?;
    // A database that can hold everything: `pg_cron` loaded and both API roles present.
    let catalog = CatalogState {
        cron_available: true,
        granted_roles: grants::GRANTED_ROLES.map(String::from).to_vec(),
        ..CatalogState::default()
    };
    let reconcile = reconcile_with(&diff, &[], &[], &catalog, schema, ast)?;
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
    assert_renames_still_planned(&plan)?;

    // Plan 3.5: access changed outside Supatype is put back only with consent.
    if !opts.overwrite_drift {
        let objects = drift::security_drift(&plan.reconcile);
        if !objects.is_empty() {
            return Err(drift::SecurityDrift { objects }.into());
        }
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
    let versions_sql = versions::render_versions_layer(&plan.ast, &plan.schema)?;
    let storage_sql = storage::generate(&plan.ast)?;
    // AST-only changes (widgets, labels) still need admin_config and the snapshot so Studio and
    // tooling see the latest schema without a DDL migration.
    let admin_cfg = admin::generate(&plan.ast)?;
    let schema_snap = serde_json::to_value(&plan.ast)?;

    // These are writes too: under the engine's lock like any other, and only to the database the
    // plan found up to date.
    let mut tx = pool.begin().await.context("begin up-to-date push")?;
    take_engine_lock(&mut tx).await?;
    take_push_lock(&mut tx).await?;
    let now = read_state(&mut tx, &plan.schema)
        .await
        .context("Failed to re-read the database before applying")?;
    plan.inputs.assert_current(&now)?;
    restate_rows(&mut tx, &plan.reconcile, &now.fingerprints).await?;

    (&mut *tx)
        .execute(sqlx::raw_sql(&storage_sql))
        .await
        .context("Failed to apply storage schema/policies")?;
    if !versions_sql.trim().is_empty() {
        (&mut *tx)
            .execute(sqlx::raw_sql(&versions_sql))
            .await
            .context("Failed to apply drafts and publishing layer")?;
    }
    migration_history::refresh_metadata_on_up_to_date_push(&mut tx, &admin_cfg, &schema_snap)
        .await
        .context("Failed to refresh Studio metadata on up-to-date push")?;
    tx.commit().await.context("commit up-to-date push")?;
    Ok(Outcome::UpToDate {
        warnings: plan.diff.warnings,
    })
}

/// F2(c) on a push with nothing to apply: each restated row rewritten to this push's statement,
/// with the object as the catalog holds it now, so the ledger stops recording an older engine's
/// wording. No migration changed anything, so no row is linked to one.
async fn restate_rows(
    tx: &mut PgConnection,
    plan: &reconcile::Plan,
    live: &[ObjectFingerprint],
) -> Result<()> {
    let live: BTreeMap<ObjectKey, &ObjectFingerprint> = live.iter().map(|f| (f.key(), f)).collect();
    let rows: Vec<LedgerRow> = plan
        .actions
        .iter()
        .filter_map(|action| match action {
            reconcile::Action::Restate {
                key,
                create_sql,
                status,
                ..
            } => live.get(key).map(|fp| LedgerRow {
                key: key.clone(),
                desired_fp: ledger::desired_fingerprint(key.kind, create_sql),
                desired_sql: create_sql.clone(),
                live_fp: fp.fingerprint.clone(),
                live_def: fp.definition.clone(),
                status: *status,
                migration_id: None,
            }),
            _ => None,
        })
        .collect();
    ledger::upsert(tx, &rows).await
}

/// Everything rendered for one push, kept together because the failure record needs the same
/// name, hash and statements the success record does.
struct Rendered {
    name: String,
    migration: Migration,
    /// What runs inside the transaction `apply` owns: the migration after the re-asserted storage
    /// layer. What the history stores as `sql_up`, on success and on failure alike, so the record
    /// holds the statement that failed.
    apply_body: String,
    sources: migration_history::AppliedMigrationSources,
}

fn render(plan: &Plan<'_>, opts: ApplyOptions) -> Result<Rendered> {
    let migration = plan.migration(opts.force)?;
    // Millisecond precision so rapid retries do not collide on the name.
    let name = opts
        .name
        .unwrap_or_else(|| format!("push_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S_%3f")));
    let apply_body = migration.apply_body();
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
    // Before anything is written, so a refusal records no failed migration.
    take_engine_lock(&mut tx).await?;
    let applied = match within_transaction(&mut tx, &plan, strict, &rendered).await {
        Ok(applied) => applied,
        Err(e) => {
            migration_history::rollback_push_tx(
                tx,
                pool,
                &rendered.name,
                &rendered.migration.hash,
                &rendered.apply_body,
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
    // The reconcile's inputs, read again inside this transaction: what it decided is applied only
    // to the database it decided it against.
    let now = read_state(tx, &plan.schema)
        .await
        .context("Failed to re-read the database before applying")?;
    plan.inputs.assert_current(&now)?;

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

    let schema_snap = serde_json::to_value(&plan.ast).ok();
    let admin_cfg = admin::generate(&plan.ast).ok();
    let migration_id = migration_history::insert_applied_migration(
        &mut **tx,
        &rendered.name,
        &rendered.migration.hash,
        schema_snap.clone(),
        admin_cfg.clone(),
        &rendered.apply_body,
        &rendered.sources,
    )
    .await
    .context("Failed to record migration in history")?;

    record_ledger(
        tx,
        &plan.reconcile,
        &after.fingerprints,
        &after.catalog.sequences,
        &plan.schema,
        migration_id,
    )
    .await?;

    migration_history::save_schema_state(&mut **tx, &after.db)
        .await
        .context("Failed to save schema state cache")?;

    // Which mechanism is enforcing the field rules, probed rather than assumed. A failure here is
    // a missing diagnostic, not a broken push: the enforcement itself is the labels, which are
    // already applied in this transaction.
    if let Err(e) = migration_history::record_field_enforcement(
        tx,
        migration_history::labelled_column_count(&plan.ast),
    )
    .await
    {
        eprintln!("Warning: failed to record field-enforcement capability: {e}");
    }

    // Checked last, with the rows just written, so it reads the database as the next push will.
    let check = differ::integrity::post_push(&plan.ast, &after_push(after, tx).await?);
    if strict && !check.settled {
        bail!(
            "Push rolled back: post-apply schema drift in strict mode ({})",
            check.warnings.join("; ")
        );
    }

    Ok(Applied {
        drift_warnings: check.warnings,
        studio_metadata: admin_cfg.zip(schema_snap),
    })
}

/// The state after apply, with the ledger as this push has just recorded it.
async fn after_push(after: Live, tx: &mut Transaction<'_, Postgres>) -> Result<State> {
    let ledger = ledger::load(tx).await?;
    let Live {
        mut db,
        catalog,
        fingerprints,
    } = after;
    db.set_table_ownership(&ledger);
    Ok(State {
        db,
        catalog,
        fingerprints,
        ledger,
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
    sequences: &[catalog::DbSequence],
    schema: &str,
    migration_id: i32,
) -> Result<()> {
    if plan.actions.is_empty() {
        return Ok(());
    }
    // A grant of nothing leaves no catalog row to record, so it is recorded as holding nothing.
    let after = with_grants_of_nothing(after, plan.actions.iter().map(reconcile::Action::key));
    let live: BTreeMap<ObjectKey, &ObjectFingerprint> =
        after.iter().map(|f| (f.key(), f)).collect();
    let mut rows = Vec::new();
    let mut removed = Vec::new();
    for action in &plan.actions {
        let key = action.key();
        match action.row_after() {
            reconcile::RowAfter::Write { create_sql, status } => {
                // A sequence this push made is recorded under the name Postgres gave it, found by
                // its column: the name predicted for it may be another serial's.
                let (key, create_sql) = match created_sequence(key, create_sql, sequences, schema) {
                    Some((key, sql)) => (std::borrow::Cow::Owned(key), sql),
                    None => (std::borrow::Cow::Borrowed(key), create_sql.to_string()),
                };
                let key = key.as_ref();
                let create_sql = create_sql.as_str();
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
        // A renamed object's row under its old name goes; its new one was just written.
        removed.extend(action.found_as());
    }
    // What each row was before this push, so rolling the push back puts the ledger back too.
    let touched: Vec<ObjectKey> = rows
        .iter()
        .map(|r| r.key.clone())
        .chain(removed.iter().cloned())
        .collect();
    ledger::undo::remember(tx, migration_id, &touched).await?;
    ledger::upsert(tx, &rows).await?;
    ledger::delete(tx, &removed).await
}

/// For a sequence row, the key and statement naming the sequence its column owns after apply,
/// when that is not the one the plan named.
fn created_sequence(
    key: &ObjectKey,
    create_sql: &str,
    sequences: &[catalog::DbSequence],
    schema: &str,
) -> Option<(ObjectKey, String)> {
    if key.kind != ObjectKind::Sequence {
        return None;
    }
    let owner = sequence_owner(create_sql)?;
    let actual = sequences
        .iter()
        .find(|s| s.schema == key.schema && s.owned_by.as_deref() == Some(owner.as_str()))?;
    if actual.name == key.name {
        return None;
    }
    let (table, column) = owner.split_once('.')?;
    let key = ObjectKey {
        name: actual.name.clone(),
        ..key.clone()
    };
    let sql = crate::desired::sequence_owned_by_sql(schema, &actual.name, table, column);
    Some((key, sql))
}

/// A signal to realtime, which skips WAL polls while anyone holds this transaction-level lock;
/// not mutual exclusion. The CLI may already hold it as a session lock from its own backend, so
/// the lock is tried rather than waited for: free, this push holds it until commit; held, the
/// holder is already keeping realtime away and this push proceeds. `adopt` and
/// `doctor --rebaseline` take it too, for their ledger writes.
pub(crate) async fn take_push_lock(tx: &mut PgConnection) -> Result<()> {
    sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1, $2)")
        .bind(PUSH_LOCK_CLASS)
        .bind(PUSH_LOCK_ID)
        .fetch_one(&mut *tx)
        .await
        .context("try the schema-push advisory lock")?;
    Ok(())
}

/// [`ENGINE_LOCK_ID`] for this transaction, or [`EngineBusy`] when another session holds it. Tried,
/// never waited for: a second writer refuses at once rather than queueing behind the first.
pub(crate) async fn take_engine_lock(tx: &mut PgConnection) -> Result<()> {
    let taken = sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1, $2)")
        .bind(PUSH_LOCK_CLASS)
        .bind(ENGINE_LOCK_ID)
        .fetch_one(&mut *tx)
        .await
        .context("try the engine's advisory lock")?;
    if !taken {
        return Err(EngineBusy.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sequence(name: &str, owned_by: Option<&str>) -> catalog::DbSequence {
        catalog::DbSequence {
            schema: "public".into(),
            name: name.into(),
            owned_by: owned_by.map(String::from),
            comment: None,
        }
    }

    /// `order_item.id` was created first and holds `order_item_id_seq`: the desired sequence of
    /// that column is known by its live name, and `order.item_id`'s, still to be created, is
    /// predicted free of it.
    #[test]
    fn a_desired_sequence_takes_the_name_its_column_has() {
        let doc = serde_json::json!({ "astVersion": 2, "models": [
            { "name": "Order", "fields": {
                "id": { "kind": "integer", "primaryKey": true, "required": true },
                "item_id": { "kind": "serial", "required": true } },
              "options": { "timestamps": false, "softDelete": false, "singleton": false },
              "annotations": { "db": { "tableName": "order", "indexes": [] }, "platform": {} } },
            { "name": "OrderItem", "fields": {
                "id": { "kind": "serial", "primaryKey": true, "required": true } },
              "options": { "timestamps": false, "softDelete": false, "singleton": false },
              "annotations": { "db": { "tableName": "order_item", "indexes": [] }, "platform": {} } }
        ]});
        let ast = crate::parser::parse(&doc.to_string()).unwrap();
        let mut desired = desired_objects_for(&ast, "public", FieldEnforcement::Labels).unwrap();
        sequences_as_created(
            &mut desired,
            &[sequence("order_item_id_seq", Some("order_item.id"))],
            "public",
        );
        let mut sequences: Vec<(String, String)> = desired
            .iter()
            .filter(|d| d.key.kind == ObjectKind::Sequence)
            .map(|d| (d.key.name.clone(), sequence_owner(&d.create_sql).unwrap()))
            .collect();
        sequences.sort();
        assert_eq!(
            sequences,
            [
                ("order_item_id_seq".to_string(), "order_item.id".to_string()),
                (
                    "order_item_id_seq1".to_string(),
                    "order.item_id".to_string()
                ),
            ]
        );
    }
    use crate::introspector::tables::{DbColumn, DbTable};
    use crate::ledger::Status;

    /// `posts` with a field rule that narrows `authenticated`'s update to every column but
    /// `locked`, on a database that can load the masking extension.
    fn narrowed() -> SchemaAst {
        crate::parser::parse(
            r#"{"astVersion":2,"models":[{"name":"Post","fields":{
                "id":{"kind":"integer","primaryKey":true,"required":true,"annotations":{"db":{"pgType":"INTEGER","unique":false}}},
                "title":{"kind":"text","required":true,"annotations":{"db":{"pgType":"TEXT","unique":false}}},
                "locked":{"kind":"text","annotations":{"db":{"pgType":"TEXT","unique":false}}}
              },"options":{"timestamps":false,"softDelete":false,"singleton":false},
              "annotations":{"db":{"tableName":"posts","indexes":[]},"platform":{"access":{
                "read":{"type":"public"},"update":{"type":"authenticated"},
                "fields":{"locked":{"write":{"type":"private"}}}}}}}]}"#,
        )
        .unwrap()
    }

    fn row(kind: ObjectKind, parent: &str, name: &str, status: Status) -> LedgerRow {
        LedgerRow {
            key: ObjectKey {
                kind,
                schema: "public".into(),
                parent: parent.into(),
                name: name.into(),
            },
            desired_fp: String::new(),
            desired_sql: String::new(),
            live_fp: String::new(),
            live_def: String::new(),
            status,
            migration_id: Some(1),
        }
    }

    /// `posts` live with the declared columns and `extra`, which the schema does not declare.
    fn state(extra: Option<Status>) -> State {
        let column = |name: &str| DbColumn {
            name: name.into(),
            data_type: "text".into(),
            udt_name: "text".into(),
            nullable: true,
            ..Default::default()
        };
        let db = DatabaseState {
            schema: "public".into(),
            tables: vec![DbTable {
                schema: "public".into(),
                name: "posts".into(),
                columns: ["id", "title", "locked", "extra"]
                    .into_iter()
                    .map(column)
                    .collect(),
                comment: None,
            }],
            extensions: vec![rls::MASK_EXTENSION.to_string()],
            ..Default::default()
        };
        let catalog = CatalogState {
            granted_roles: ["anon", "authenticated"].map(String::from).into(),
            ..Default::default()
        };
        let mut ledger = vec![row(ObjectKind::Table, "", "posts", Status::Managed)];
        ledger.extend(extra.map(|status| row(ObjectKind::Column, "posts", "extra", status)));
        State::of(db, catalog, ledger)
    }

    fn update_grant(decision: &Decision) -> &str {
        &decision
            .desired
            .iter()
            .find(|d| {
                d.key.kind == ObjectKind::TableGrant
                    && d.key.parent == "posts"
                    && d.key.name == "authenticated"
            })
            .expect("authenticated's grant")
            .create_sql
    }

    /// #63: a narrowed write grant names the declared columns, so a column added outside
    /// Supatype gets no write privilege from it. Push and doctor say so and how to include it;
    /// adopted, it is granted beside the declared ones, kept rather than dropped, and no longer
    /// reported.
    #[test]
    fn a_column_added_outside_supatype_is_flagged_until_adopted_then_granted() {
        let ast = narrowed();
        let flag = "column posts.extra was added outside Supatype and has no write grant for \
                    authenticated; run `supatype adopt --key column:posts.extra` to include it";

        let found = state(None);
        let decision = decide(&ast, &found, None).unwrap();
        assert!(
            decision.diff.warnings.iter().any(|w| w == flag),
            "{:?}",
            decision.diff.warnings
        );
        assert!(!update_grant(&decision).contains("'extra'"));
        let report = crate::differ::doctor::report_of(&ast, &found, &decision);
        assert!(
            report
                .unmanaged_drift
                .iter()
                .any(|i| i.name == "extra" && i.message == flag),
            "{report:#?}"
        );
        // Not ours: never dropped.
        assert!(!decision
            .diff
            .operations
            .iter()
            .any(|op| matches!(op, Operation::DropColumn { column, .. } if column == "extra")));

        let adopted = state(Some(Status::Adopted));
        let decision = decide(&ast, &adopted, None).unwrap();
        assert!(
            !decision
                .diff
                .warnings
                .iter()
                .any(|w| w.contains("posts.extra")),
            "{:?}",
            decision.diff.warnings
        );
        let grant = update_grant(&decision);
        assert!(
            grant.contains("'id', 'title', 'extra'"),
            "the adopted column is granted after the declared ones: {grant}"
        );
        assert!(!grant.contains("'locked'"), "{grant}");
        assert!(!decision
            .diff
            .operations
            .iter()
            .any(|op| matches!(op, Operation::DropColumn { column, .. } if column == "extra")));
        assert!(
            decision.reconcile.actions.iter().any(|a| matches!(
                a,
                reconcile::Action::Keep { key, .. } if key.kind == ObjectKind::Column && key.name == "extra"
            )),
            "the adopted column's row is kept: {:?}",
            decision.reconcile.actions
        );
        let report = crate::differ::doctor::report_of(&ast, &adopted, &decision);
        assert!(
            !report.unmanaged_drift.iter().any(|i| i.name == "extra"),
            "{report:#?}"
        );

        // Ours by a managed row, undeclared: still the differ's to drop, and not flagged.
        let managed = state(Some(Status::Managed));
        let decision = decide(&ast, &managed, None).unwrap();
        assert!(decision
            .diff
            .operations
            .iter()
            .any(|op| matches!(op, Operation::DropColumn { column, .. } if column == "extra")));
        assert!(!decision.diff.warnings.iter().any(|w| w == flag));
    }
}

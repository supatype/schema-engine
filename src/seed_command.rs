//! The `seed` subcommand: validate, plan, execute, record, report.
//!
//! Kept out of `main.rs` because it is five phases rather than a call, and because the
//! shape of what it prints is a contract. Seven runners read this JSON, and each of them
//! formatting a seed's outcome for itself is how they end up disagreeing about what
//! "applied" means.

use anyhow::{Context as _, Result};
use serde_json::json;
use sqlx::{PgPool, Postgres, Transaction};
use std::time::Instant;
use supatype_engine::parser::ast::SchemaAst;
use supatype_engine::seed::errors::{constraint_index_for, SeedError, SeedFailure};
use supatype_engine::seed::execute::{execute_in, rolling_back, Context, Report};
use supatype_engine::seed::ledger::{
    already_applied, has_drifted, ir_hash, latest_per_file, record, record_rolled_back, RunStatus,
    SeedRun,
};
use supatype_engine::seed::{fingerprint, plan::plan, validate::validate, SeedIr};

/// What the runner asked for.
pub struct SeedArgs {
    pub database_url: String,
    pub schema: String,
    /// One path per seed document, in the order the runner wants them applied.
    pub ir: Vec<String>,
    pub environment: Option<String>,
    /// Every document in one transaction, rather than one each.
    pub atomic: bool,
    /// Skip a document already committed with this exact content.
    pub run_once: bool,
}

/// Exit codes, from the plan: the split lets CI tell "the seed data is wrong" from "this
/// environment is not set up".
pub const EXIT_FAILED: i32 = 1;
pub const EXIT_COULD_NOT_START: i32 = 2;

/// One document, read and prepared.
struct Document {
    /// The path as the runner named it, which is what links a ledger row to its source.
    file: String,
    ir: SeedIr,
    hash: String,
}

/// Connect, or say that the environment is the thing that is wrong.
///
/// Its own step because the exit code turns on it: a runner that cannot tell "the seed
/// data is wrong" from "this database is not reachable" retries the wrong one in CI.
async fn connect(database_url: &str) -> std::result::Result<PgPool, i32> {
    match PgPool::connect(database_url).await {
        Ok(pool) => Ok(pool),
        Err(e) => {
            print_result(&json!({
                "ok": false,
                "files": [],
                "error": {
                    "kind": "connection",
                    "message": format!("could not connect to the database: {e}"),
                    "remedy": "Check the connection string, and that the stack is running.",
                },
            }));
            Err(EXIT_COULD_NOT_START)
        }
    }
}

/// `--status`: what has been applied here, and what has changed since.
pub async fn status(database_url: &str) -> Result<i32> {
    let pool = match connect(database_url).await {
        Ok(pool) => pool,
        Err(code) => return Ok(code),
    };

    let mut files = Vec::new();
    for entry in latest_per_file(&pool).await? {
        files.push(json!({
            "file": entry.run.file,
            "appliedAt": entry.applied_at,
            "status": entry.run.status.as_str(),
            "durationMs": entry.run.duration_ms,
            "rowsWritten": entry.run.rows_written,
            "irHash": entry.run.ir_hash,
            "schemaFingerprint": entry.run.schema_fingerprint,
            "engineVersion": entry.run.engine_version,
            "errorMessage": entry.run.error_message,
            // The question the ledger exists to answer, and the one a single row cannot.
            "drifted": has_drifted(&pool, &entry.run.file).await?,
        }));
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({ "files": files }))?
    );
    Ok(0)
}

/// Run every document the runner named.
pub async fn run(ast: SchemaAst, args: SeedArgs) -> Result<i32> {
    let expected = fingerprint::fingerprint(&ast);

    // A document that cannot be read is the environment being wrong, not the seed: the
    // file is missing or unreadable, which is the same class of problem as a bad DSN.
    let documents = match read_documents(&args.ir) {
        Ok(documents) => documents,
        Err(message) => {
            print_result(&json!({
                "ok": false,
                "files": [],
                "error": { "kind": "document", "message": message },
            }));
            return Ok(EXIT_COULD_NOT_START);
        }
    };

    // Validation first, for every document, before a single statement runs. A run that
    // writes the first file and then refuses the second has left the database in a state
    // nobody asked for, and the second file's mistake was knowable before any of it.
    for document in &documents {
        if let Err(error) = validate(&document.ir, &ast, &expected) {
            print_result(&json!({
                "ok": false,
                "files": documents
                    .iter()
                    .map(|d| json!({ "file": d.file, "status": "notRun" }))
                    .collect::<Vec<_>>(),
                "error": {
                    "kind": "validation",
                    "file": document.file,
                    "path": error.path,
                    "opId": error.op_id,
                    "message": error.message,
                    "remedy": error.remedy,
                },
            }));
            // The seed is wrong, not the environment.
            return Ok(EXIT_FAILED);
        }
    }

    let pool = match connect(&args.database_url).await {
        Ok(pool) => pool,
        Err(code) => return Ok(code),
    };

    let constraints = constraint_index_for(&ast);
    let cx = Context {
        ast: &ast,
        constraints: &constraints,
        schema: &args.schema,
        environment: args.environment.as_deref(),
    };

    if args.atomic {
        atomically(&pool, &documents, cx, &args, &expected).await
    } else {
        one_at_a_time(&pool, &documents, cx, &args, &expected).await
    }
}

/// The seed file a document came from, when the runner said.
///
/// Read beside the IR rather than as part of it: `file` is the runner's note about where the
/// document originated, not something the seed itself describes, and every SDK would
/// otherwise have to put it in the same place inside the document.
fn source_file(text: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let named = value.get("file")?.as_str()?.trim();
    (!named.is_empty()).then(|| named.to_string())
}

fn read_documents(paths: &[String]) -> std::result::Result<Vec<Document>, String> {
    let mut documents = Vec::with_capacity(paths.len());
    for path in paths {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("could not read the seed document at {path}: {e}"))?;
        let ir: SeedIr = serde_json::from_str(&text)
            .map_err(|e| format!("the seed document at {path} is not valid IR: {e}"))?;
        documents.push(Document {
            file: source_file(&text).unwrap_or_else(|| path.clone()),
            // Over the text as written, so a document that round-trips differently is
            // still the same document to the ledger.
            hash: ir_hash(&text),
            ir,
        });
    }
    Ok(documents)
}

/// Each document in its own transaction.
///
/// A failure in the third of five leaves the first two committed, which is why the report
/// names every document and what happened to it rather than reporting one failure.
async fn one_at_a_time(
    pool: &PgPool,
    documents: &[Document],
    cx: Context<'_>,
    args: &SeedArgs,
    fingerprint: &str,
) -> Result<i32> {
    let mut applied: Vec<serde_json::Value> = Vec::new();

    for (position, document) in documents.iter().enumerate() {
        if skip(pool, document, args).await? {
            applied.push(outcome(document, "skipped", &Report::default(), 0));
            continue;
        }

        let started = Instant::now();
        let mut tx = begin(pool).await?;
        let plan = match plan(&document.ir, cx.ast) {
            Ok(plan) => plan,
            Err(cycle) => {
                report_cycle(document, &cycle.to_string(), &applied, documents, position);
                return Ok(EXIT_FAILED);
            }
        };

        match execute_in(&mut tx, &plan, cx).await {
            Ok(report) => {
                let elapsed = started.elapsed().as_millis() as i64;
                let run = committed_run(document, fingerprint, &report, elapsed);
                record(&mut tx, &run).await?;
                tx.commit()
                    .await
                    .context("the seed could not be committed")?;
                applied.push(outcome(document, "committed", &report, elapsed));
            }
            Err(error) => {
                let error = rolling_back(tx, error).await;
                let elapsed = started.elapsed().as_millis() as i64;
                record_rolled_back(pool, &failed_run(document, fingerprint, &error, elapsed)).await;
                report_failure(document, &error, &applied, documents, position);
                return Ok(EXIT_FAILED);
            }
        }
    }

    report_success(&applied);
    Ok(0)
}

/// Every document in one transaction.
async fn atomically(
    pool: &PgPool,
    documents: &[Document],
    cx: Context<'_>,
    args: &SeedArgs,
    fingerprint: &str,
) -> Result<i32> {
    let started = Instant::now();
    let mut tx = begin(pool).await?;
    let mut applied: Vec<serde_json::Value> = Vec::new();
    let mut runs: Vec<SeedRun> = Vec::new();

    for (position, document) in documents.iter().enumerate() {
        // Asked on the pool, not on the transaction: the ledger rows this reads are ones
        // earlier runs committed, and the ones this run is writing are not applied yet.
        if skip(pool, document, args).await? {
            applied.push(outcome(document, "skipped", &Report::default(), 0));
            continue;
        }

        let plan = match plan(&document.ir, cx.ast) {
            Ok(plan) => plan,
            Err(cycle) => {
                report_cycle(document, &cycle.to_string(), &[], documents, position);
                return Ok(EXIT_FAILED);
            }
        };

        match execute_in(&mut tx, &plan, cx).await {
            Ok(report) => {
                let elapsed = started.elapsed().as_millis() as i64;
                runs.push(committed_run(document, fingerprint, &report, elapsed));
                applied.push(outcome(document, "committed", &report, elapsed));
            }
            Err(error) => {
                let error = rolling_back(tx, error).await;
                let elapsed = started.elapsed().as_millis() as i64;
                record_rolled_back(pool, &failed_run(document, fingerprint, &error, elapsed)).await;
                // Everything before this rolled back with it, so none of it is "committed"
                // any more. Saying otherwise would be the one thing this report must not do.
                report_atomic_failure(document, &error, documents, position);
                return Ok(EXIT_FAILED);
            }
        }
    }

    for run in &runs {
        record(&mut tx, run).await?;
    }
    tx.commit()
        .await
        .context("the seed could not be committed")?;

    report_success(&applied);
    Ok(0)
}

async fn begin(pool: &PgPool) -> Result<Transaction<'_, Postgres>> {
    pool.begin()
        .await
        .context("Failed to start a transaction for the seed")
}

/// Whether `runOnce` says this exact document has already been applied.
async fn skip(pool: &PgPool, document: &Document, args: &SeedArgs) -> Result<bool> {
    if !args.run_once {
        return Ok(false);
    }
    already_applied(pool, &document.file, &document.hash).await
}

fn committed_run(
    document: &Document,
    fingerprint: &str,
    report: &Report,
    duration_ms: i64,
) -> SeedRun {
    SeedRun {
        file: document.file.clone(),
        ir_hash: document.hash.clone(),
        schema_fingerprint: fingerprint.to_string(),
        status: RunStatus::Committed,
        duration_ms,
        rows_written: written(report),
        error_message: None,
        engine_version: env!("ENGINE_VERSION").to_string(),
    }
}

fn failed_run(
    document: &Document,
    fingerprint: &str,
    error: &SeedError,
    duration_ms: i64,
) -> SeedRun {
    SeedRun {
        file: document.file.clone(),
        ir_hash: document.hash.clone(),
        schema_fingerprint: fingerprint.to_string(),
        status: RunStatus::RolledBack,
        duration_ms,
        rows_written: json!({}),
        error_message: Some(error.to_string()),
        engine_version: env!("ENGINE_VERSION").to_string(),
    }
}

fn written(report: &Report) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (model, count) in &report.written {
        map.insert(model.clone(), json!(count));
    }
    serde_json::Value::Object(map)
}

// --- The result document ---

fn outcome(
    document: &Document,
    status: &str,
    report: &Report,
    duration_ms: i64,
) -> serde_json::Value {
    json!({
        "file": document.file,
        "status": status,
        "written": written(report),
        // Reported rather than omitted: a seed that quietly did nothing should not look
        // like one that did everything.
        "skippedGroups": report.skipped,
        "durationMs": duration_ms,
    })
}

fn report_success(applied: &[serde_json::Value]) {
    print_result(&json!({ "ok": true, "files": applied }));
}

fn report_failure(
    document: &Document,
    error: &SeedError,
    applied: &[serde_json::Value],
    documents: &[Document],
    position: usize,
) {
    let mut files: Vec<serde_json::Value> = applied.to_vec();
    files.push(json!({ "file": document.file, "status": "rolledBack" }));
    files.extend(not_run(documents, position));
    print_result(&json!({
        "ok": false,
        "files": files,
        "error": describe(error, &document.file),
    }));
}

fn report_atomic_failure(
    document: &Document,
    error: &SeedError,
    documents: &[Document],
    position: usize,
) {
    let mut files: Vec<serde_json::Value> = documents
        .iter()
        .take(position)
        .map(|d| json!({ "file": d.file, "status": "rolledBack" }))
        .collect();
    files.push(json!({ "file": document.file, "status": "rolledBack" }));
    files.extend(not_run(documents, position));
    print_result(&json!({
        "ok": false,
        "atomic": true,
        "files": files,
        "error": describe(error, &document.file),
    }));
}

/// A dependency cycle: the seed's own shape, so it reports like any other seed failure.
fn report_cycle(
    document: &Document,
    message: &str,
    applied: &[serde_json::Value],
    documents: &[Document],
    position: usize,
) {
    let mut files: Vec<serde_json::Value> = applied.to_vec();
    files.push(json!({ "file": document.file, "status": "notRun" }));
    files.extend(not_run(documents, position));
    print_result(&json!({
        "ok": false,
        "files": files,
        "error": {
            "kind": "cycle",
            "file": document.file,
            "message": message,
        },
    }));
}

fn not_run(documents: &[Document], position: usize) -> Vec<serde_json::Value> {
    documents
        .iter()
        .skip(position + 1)
        .map(|d| json!({ "file": d.file, "status": "notRun" }))
        .collect()
}

fn print_result(value: &serde_json::Value) {
    match serde_json::to_string_pretty(value) {
        Ok(text) => println!("{text}"),
        Err(e) => eprintln!("could not render the seed result: {e}"),
    }
}

/// The error, in schema terms rather than Postgres ones.
fn describe(error: &SeedError, file: &str) -> serde_json::Value {
    let mut described = match &*error.failure {
        SeedFailure::Constraint {
            kind,
            model,
            fields,
            sqlstate,
        } => json!({
            "kind": "constraint",
            "constraint": kind.as_str(),
            "model": model,
            "fields": fields,
            "sqlstate": sqlstate,
        }),
        SeedFailure::SchemaDrift { missing, remedy } => json!({
            "kind": "schemaDrift",
            "message": missing,
            "remedy": remedy,
        }),
        SeedFailure::InvalidValue { detail } => json!({
            "kind": "invalidValue",
            "message": detail,
        }),
        SeedFailure::Database { sqlstate, message } => json!({
            "kind": "database",
            "sqlstate": sqlstate,
            "message": message,
        }),
        SeedFailure::Other { message } => json!({
            "kind": "other",
            "message": message,
        }),
    };

    if let Some(object) = described.as_object_mut() {
        object.insert("file".to_string(), json!(file));
        object.insert("path".to_string(), json!(error.path));
        object.insert("opId".to_string(), json!(error.op_id));
        object.insert("message".to_string(), json!(error.failure.to_string()));
        if let Some(rollback) = &error.rollback_error {
            object.insert("rollbackError".to_string(), json!(rollback));
        }
    }
    described
}

mod seed_command;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;
use std::io::{self, Read};
use tracing::info;

#[derive(Parser)]
#[command(
    name = "supatype-engine",
    version = env!("ENGINE_VERSION"),
    about = "Supatype schema engine"
)]
struct Cli {
    #[arg(long, short, global = true, help = "Input file path, or '-' for stdin")]
    input: Option<String>,

    #[arg(
        long,
        short,
        global = true,
        help = "Output file path, or '-' for stdout"
    )]
    output: Option<String>,

    #[arg(long, global = true, default_value = "warn")]
    log: String,

    #[arg(long, global = true, help = "License key for gated features")]
    license: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse and validate a schema AST
    Parse,
    /// Introspect current database state
    Introspect {
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        #[arg(long, default_value = "public")]
        schema: String,
    },
    /// Compute diff between target schema and current database state
    Diff {
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        #[arg(long, default_value = "public")]
        schema: String,
    },
    /// Generate SQL migration from a diff (print only, does not apply)
    Migrate {
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        #[arg(long, default_value = "public")]
        schema: String,
        #[arg(long, help = "Allow destructive operations without prompting")]
        force: bool,
    },
    /// Apply schema to database and record in migration history
    Push {
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        #[arg(long, default_value = "public")]
        schema: String,
        #[arg(long, help = "Allow destructive operations without prompting")]
        force: bool,
        #[arg(long, help = "Human-readable name for the migration record")]
        name: Option<String>,
        #[arg(long, help = "Skip interactive rename confirmation prompts (for CI)")]
        non_interactive: bool,
        /// No longer does anything: the database is always read live. Accepted for one release so
        /// scripts that pass it keep working, and says so.
        #[arg(long, hide = true)]
        no_cache: bool,
        #[arg(
            long,
            help = "Fail push when post-apply drift remains (missing or stale managed objects)"
        )]
        strict: bool,
        #[arg(long, help = "Path to gzip-compressed tar of schema source files")]
        schema_sources_gz: Option<String>,
        #[arg(long, help = "Path to schema_sources manifest JSON")]
        schema_sources_manifest: Option<String>,
        #[arg(
            long,
            help = "Put back policies, grants, labels and RLS changed outside Supatype without asking"
        )]
        overwrite_drift: bool,
    },
    /// Generate typed client code (TypeScript by default; use --lang for other languages)
    Generate {
        /// Target language: typescript (default), python, go, php, swift, kotlin, dart
        #[arg(long, default_value = "typescript")]
        lang: String,
        /// Which artifact: types (default), seed, augmentation
        #[arg(long, default_value = "types")]
        artifact: String,
    },
    /// Generate trigger SQL (updated_at + slug)
    Triggers {
        #[arg(long, default_value = "public")]
        schema: String,
    },
    /// Generate RLS policy SQL
    Rls {
        #[arg(long, default_value = "public")]
        schema: String,
    },
    /// Generate storage schema SQL (bucket DDL + storage RLS)
    Storage,
    /// Generate PostgREST configuration
    Postgrest {
        #[arg(long, default_value = "public")]
        schema: String,
    },
    /// Generate admin panel configuration JSON
    Admin,
    /// Generate auth helper SQL functions (auth.uid, auth.role, auth.email, auth.jwt)
    AuthFunctions {
        #[arg(
            long,
            default_value = "",
            help = "Project reference for cloud mode (e.g., kxv4m2np)"
        )]
        project_ref: String,
        #[arg(
            long,
            default_value = "auth",
            help = "Schema where auth functions are created"
        )]
        auth_schema: String,
    },
    /// Generate SSO / OIDC provider schema SQL (_sso schema + oauth_* tables + RLS)
    Sso,
    /// Generate Studio metadata JSON for the Visual Schema Designer
    Studio,
    /// Generate OpenAPI 3.0 specification from the schema
    Openapi,
    /// List all recorded migrations from the database
    Migrations {
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        /// When set, return schema source snapshot for this migration name
        #[arg(long)]
        name: Option<String>,
    },
    /// Roll back the last applied migration
    Rollback {
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        #[arg(long, default_value = "public")]
        schema: String,
    },
    /// Validate a migration is safe to apply
    Validate {
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Report schema drift between AST and live database (read-only)
    Doctor {
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        #[arg(long, default_value = "public")]
        schema: String,
        #[arg(
            long,
            help = "Exit non-zero when a push would change or refuse something"
        )]
        strict: bool,
        /// Record every drifted object's live definition as its baseline, changing no object, and
        /// list each one (plan 3.2: after a Postgres upgrade reformats definitions).
        #[arg(long)]
        rebaseline: bool,
    },
    /// Apply a seed IR document to the database
    Seed {
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        #[arg(long, default_value = "public")]
        schema: String,
        #[arg(
            long,
            help = "Seed IR document, repeatable; applied in the order given"
        )]
        ir: Vec<String>,
        #[arg(long, help = "Environment name, for an `environment` condition")]
        environment: Option<String>,
        #[arg(long, help = "Run every document in one transaction")]
        atomic: bool,
        #[arg(
            long,
            help = "Skip a document already committed with this exact content"
        )]
        run_once: bool,
        #[arg(
            long,
            help = "Report what has been applied, and what has changed since"
        )]
        status: bool,
    },
    /// Hand objects a push refuses (their names are taken) to Supatype, or take objects back with
    /// `--release`. Writes ledger rows only; never edits an object.
    Adopt {
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        #[arg(long, default_value = "public")]
        schema: String,
        #[arg(long, help = "Write the ledger rows instead of previewing them")]
        yes: bool,
        /// An object every push should leave alone, as doctor names it: `kind:table.name`, or
        /// `kind:name` for a table-level object. Repeatable.
        #[arg(long)]
        release: Vec<String>,
        /// No longer does anything: the database is always read live. Accepted for one release so
        /// scripts that pass it keep working, and says so.
        #[arg(long, hide = true)]
        no_cache: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(&cli.log)
        .with_writer(io::stderr)
        .init();

    info!(
        version = env!("ENGINE_VERSION"),
        target = env!("BUILD_TARGET"),
        "supatype-engine starting"
    );

    let _license = supatype_engine::licensing::License::new(cli.license.as_deref());

    let input = match &cli.command {
        Command::Migrations { .. } | Command::Rollback { .. } => String::new(),
        Command::Seed { status: true, .. } => String::new(),
        _ => read_input(cli.input.as_deref())?,
    };

    match cli.command {
        Command::Parse => {
            let ast = supatype_engine::parser::parse(&input)?;
            println!("{}", serde_json::to_string_pretty(&ast)?);
        }
        Command::Introspect {
            database_url,
            schema,
        } => {
            let pool = sqlx::PgPool::connect(&database_url)
                .await
                .context("Failed to connect to database")?;
            let state = supatype_engine::introspector::introspect(&pool, &schema).await?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        Command::Diff {
            database_url,
            schema,
        } => {
            let ast = supatype_engine::parser::parse(&input)?;
            let pool = sqlx::PgPool::connect(&database_url).await?;
            // The plan a push would apply: the differ's operations and, under `reconcile`, what
            // the ledger would do about the kinds it owns.
            let plan = supatype_engine::push::plan(&pool, &ast, &schema).await?;
            println!("{}", serde_json::to_string_pretty(&plan.to_json()?)?);
        }
        Command::Migrate {
            database_url,
            schema,
            force,
        } => {
            let ast = supatype_engine::parser::parse(&input)?;
            let pool = sqlx::PgPool::connect(&database_url).await?;
            // The same plan a push would apply, printed as a file instead.
            let plan = supatype_engine::push::plan(&pool, &ast, &schema).await?;
            println!("{}", plan.migration(force)?.file());
        }
        Command::Push {
            database_url,
            schema,
            force,
            name,
            non_interactive,
            no_cache,
            strict,
            schema_sources_gz,
            schema_sources_manifest,
            overwrite_drift,
        } => {
            use supatype_engine::generator::sql::migration::{
                UnmanagedModelTables, UNMANAGED_MODEL_TABLES,
            };
            use supatype_engine::push;

            let ast = supatype_engine::parser::parse(&input)?;
            let pool = sqlx::PgPool::connect(&database_url)
                .await
                .context("Failed to connect to database")?;

            let schema_sources = schema_sources_gz
                .as_deref()
                .map(std::fs::read)
                .transpose()
                .with_context(|| "Failed to read schema_sources_gz")?;
            let schema_sources_manifest = schema_sources_manifest
                .as_deref()
                .map(std::fs::read_to_string)
                .transpose()
                .with_context(|| "Failed to read schema_sources_manifest")?
                .map(|s| serde_json::from_str(&s))
                .transpose()
                .context("Failed to parse schema_sources_manifest JSON")?;

            if no_cache {
                eprintln!(
                    "{}",
                    supatype_engine::state::migration_history::NO_CACHE_NOTICE
                );
            }

            // A refusal goes on stdout too, where the CLI reads the push result, so it can name
            // the tables and offer to adopt them. The message still reaches stderr via the error.
            let mut plan = match push::prepare(&pool, &ast, &schema).await {
                Ok(plan) => plan,
                Err(e) => {
                    if let Some(refusal) = e.downcast_ref::<UnmanagedModelTables>() {
                        println!(
                            "{}",
                            serde_json::json!({
                                "status": "refused",
                                "reason": UNMANAGED_MODEL_TABLES,
                                "tables": refusal.tables,
                            })
                        );
                    }
                    return Err(e);
                }
            };

            // Interactive rename confirmation (skipped in CI with --non-interactive)
            let mut overwrite_drift = overwrite_drift;
            if !non_interactive {
                plan.diff = confirm_renames(plan.diff)?;
                confirm_risky_changes(&plan.diff)?;
                overwrite_drift = overwrite_drift || confirm_security_drift(&plan.reconcile)?;
            }

            let options = push::ApplyOptions {
                force,
                strict,
                name,
                schema_sources,
                schema_sources_manifest,
                overwrite_drift,
            };
            // A refusal goes on stdout too, so the CLI can show the objects and ask (plan 3.5).
            let outcome = match push::apply(&pool, plan, options).await {
                Ok(outcome) => outcome,
                Err(e) => {
                    use supatype_engine::ledger::drift::{SecurityDrift, SECURITY_DRIFT};
                    if let Some(drift) = e.downcast_ref::<SecurityDrift>() {
                        println!(
                            "{}",
                            serde_json::json!({
                                "status": "refused",
                                "reason": SECURITY_DRIFT,
                                "objects": drift.objects,
                            })
                        );
                    }
                    return Err(e);
                }
            };
            println!("{}", outcome.to_json());
        }
        Command::Generate { lang, artifact } => {
            let ast = supatype_engine::parser::parse(&input)?;
            let typescript = matches!(lang.as_str(), "typescript" | "ts");
            let output = match (typescript, artifact.as_str()) {
                (true, "types") => supatype_engine::generator::typescript::types::generate(&ast)?,
                (true, "seed") => supatype_engine::generator::typescript::seed::generate(&ast)?,
                (true, "augmentation") => {
                    supatype_engine::generator::typescript::augmentation::generate(&ast)?
                }
                (false, "types") => supatype_engine::generator::sdk::generate(&ast, &lang)?,
                // Named rather than silently falling back to the type artifact: a runner
                // that asked for a builder and got a types file would fail later, at an
                // import, with nothing pointing back here.
                (false, other) => anyhow::bail!(
                    "The `{other}` artifact is generated for TypeScript only.                      The other languages are tracked separately."
                ),
                (true, other) => anyhow::bail!(
                    "Unknown artifact '{other}'. Supported: types, seed, augmentation."
                ),
            };
            println!("{output}");
        }
        Command::Seed {
            database_url,
            schema,
            ir,
            environment,
            atomic,
            run_once,
            status,
        } => {
            let code = if status {
                seed_command::status(&database_url).await?
            } else {
                if ir.is_empty() {
                    anyhow::bail!("`seed` needs at least one `--ir <document.json>`.");
                }
                let ast = supatype_engine::parser::parse(&input)?;
                seed_command::run(
                    ast,
                    seed_command::SeedArgs {
                        database_url,
                        schema,
                        ir,
                        environment,
                        atomic,
                        run_once,
                    },
                )
                .await?
            };
            // The result document is the answer, so a failed seed still exits through the
            // code rather than through an error that would print twice.
            if code != 0 {
                std::process::exit(code);
            }
        }
        Command::Triggers { schema } => {
            let ast = supatype_engine::parser::parse(&input)?;
            let sql = supatype_engine::generator::sql::triggers::generate(&ast, &schema)?;
            println!("{sql}");
        }
        Command::Rls { schema } => {
            let ast = supatype_engine::parser::parse(&input)?;
            println!(
                "{}",
                supatype_engine::generator::sql::rls::generate_auth_helpers()
            );
            println!(
                "{}",
                supatype_engine::generator::sql::rls::generate(&ast, &schema)?
            );
        }
        Command::Storage => {
            let ast = supatype_engine::parser::parse(&input)?;
            let sql = supatype_engine::generator::sql::storage::generate(&ast)?;
            println!("{sql}");
        }
        Command::Postgrest { schema } => {
            let ast = supatype_engine::parser::parse(&input)?;
            let config = supatype_engine::generator::config::postgrest::generate(&ast, &schema)?;
            println!("{}", serde_json::to_string_pretty(&config)?);
        }
        Command::AuthFunctions {
            project_ref,
            auth_schema,
        } => {
            let config = supatype_engine::generator::sql::auth_functions::AuthFunctionConfig {
                project_ref,
                auth_schema,
            };
            let sql =
                supatype_engine::generator::sql::auth_functions::generate_auth_functions(&config);
            println!("{sql}");
        }
        Command::Sso => {
            let ast = supatype_engine::parser::parse(&input)?;
            match &ast.sso {
                Some(sso_cfg) => {
                    let sql = supatype_engine::generator::sql::sso::generate(sso_cfg)?;
                    println!("{sql}");
                }
                None => {
                    println!("-- SSO not configured in this schema.");
                }
            }
        }
        Command::Admin => {
            let ast = supatype_engine::parser::parse(&input)?;
            let config = supatype_engine::generator::typescript::admin::generate(&ast)?;
            println!("{}", serde_json::to_string_pretty(&config)?);
        }
        Command::Studio => {
            let ast = supatype_engine::parser::parse(&input)?;
            let metadata = supatype_engine::generator::studio::generate(&ast)?;
            println!("{}", serde_json::to_string_pretty(&metadata)?);
        }
        Command::Openapi => {
            let ast = supatype_engine::parser::parse(&input)?;
            let spec = supatype_engine::generator::openapi::generate(&ast)?;
            println!("{}", serde_json::to_string_pretty(&spec)?);
        }
        Command::Migrations { database_url, name } => {
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            use supatype_engine::state::migration_history;
            let pool = sqlx::PgPool::connect(&database_url)
                .await
                .context("Failed to connect to database")?;
            for col_sql in migration_history::ensure_all_migration_columns_sql() {
                sqlx::raw_sql(&col_sql).execute(&pool).await?;
            }
            if let Some(migration_name) = name.filter(|n| !n.trim().is_empty()) {
                let sources = migration_history::load_migration_sources(&pool, &migration_name)
                    .await
                    .context("Failed to load migration sources")?;
                let payload = match sources {
                    Some((bytes, manifest)) => serde_json::json!({
                        "name": migration_name,
                        "schema_sources_base64": B64.encode(bytes),
                        "schema_sources_manifest": manifest,
                    }),
                    None => {
                        anyhow::bail!("Migration {migration_name} has no schema snapshot")
                    }
                };
                println!("{}", serde_json::to_string(&payload)?);
            } else {
                let migrations = migration_history::list_migrations_summary(&pool).await?;
                println!("{}", serde_json::to_string_pretty(&migrations)?);
            }
        }
        Command::Rollback {
            database_url,
            schema,
        } => {
            use supatype_engine::state::migration_history;
            let pool = sqlx::PgPool::connect(&database_url)
                .await
                .context("Failed to connect to database")?;
            for col_sql in migration_history::ensure_all_migration_columns_sql() {
                sqlx::raw_sql(&col_sql).execute(&pool).await?;
            }
            let result = migration_history::apply_rollback(&pool, &schema).await?;
            println!("{}", serde_json::to_string(&result)?);
        }
        Command::Validate { database_url } => {
            let diff: supatype_engine::differ::DiffOutput =
                serde_json::from_str(&input).context("Failed to parse diff JSON")?;
            let pool = sqlx::PgPool::connect(&database_url).await?;
            let report = supatype_engine::differ::risk_analyser::validate(&diff, &pool).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Doctor {
            database_url,
            schema,
            strict,
            rebaseline,
        } => {
            let ast = supatype_engine::parser::parse(&input)?;
            let pool = sqlx::PgPool::connect(&database_url).await?;
            let report = supatype_engine::inspect::doctor(&pool, &ast, &schema, rebaseline).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if strict && supatype_engine::differ::doctor::has_strict_issues(&report) {
                std::process::exit(1);
            }
        }
        Command::Adopt {
            database_url,
            schema,
            yes,
            release,
            no_cache,
        } => {
            use supatype_engine::state::migration_history;
            let ast = supatype_engine::parser::parse(&input)?;
            let pool = sqlx::PgPool::connect(&database_url).await?;
            migration_history::assert_project_schema(&pool, &schema).await?;
            if no_cache {
                eprintln!("{}", migration_history::NO_CACHE_NOTICE);
            }
            let outcome = supatype_engine::adopt::run(&pool, &ast, &schema, &release, yes).await?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
    }

    Ok(())
}

/// For each rename operation, prompt the user to confirm it's a rename.
/// If the user declines, the rename is converted to the destructive drop + create equivalent.
fn confirm_renames(
    mut diff: supatype_engine::differ::DiffOutput,
) -> Result<supatype_engine::differ::DiffOutput> {
    use std::io::BufRead;
    use supatype_engine::differ::{Operation, Risk};

    let mut final_ops: Vec<Operation> = Vec::new();

    for op in diff.operations {
        match &op {
            Operation::RenameTable { from, to, .. } => {
                prompt_rename(
                    &format!("Table '{}' → '{}'", from.bold(), to.bold()),
                    "All existing data will be preserved via ALTER TABLE RENAME.",
                )?;

                let mut line = String::new();
                io::stdin().lock().read_line(&mut line)?;
                let answer = line.trim().to_lowercase();

                if answer == "n" || answer == "no" {
                    final_ops.push(Operation::DropTable {
                        table: from.clone(),
                        risk: Risk::Destructive,
                    });
                    eprintln!(
                        "  {} Rename declined for '{}' → '{}'. Re-run {} to apply the DROP + CREATE.",
                        "!".red().bold(),
                        from.bold(),
                        to.bold(),
                        "supatype push".cyan()
                    );
                } else {
                    final_ops.push(op);
                }
            }
            Operation::RenameColumn {
                table, from, to, ..
            } => {
                prompt_rename(
                    &format!(
                        "Column '{}' → '{}' on table '{}'",
                        from.bold(),
                        to.bold(),
                        table.bold()
                    ),
                    "Column data will be preserved via ALTER TABLE RENAME COLUMN.",
                )?;

                let mut line = String::new();
                io::stdin().lock().read_line(&mut line)?;
                let answer = line.trim().to_lowercase();

                if answer == "n" || answer == "no" {
                    // User declined, so emit DropColumn + AddColumn instead
                    final_ops.push(Operation::DropColumn {
                        table: table.clone(),
                        column: from.clone(),
                        risk: Risk::Destructive,
                    });
                    final_ops.push(Operation::AddColumn {
                        table: table.clone(),
                        column: to.clone(),
                        field: Box::new(supatype_engine::parser::ast::FieldAst::Text(
                            supatype_engine::parser::ast::ScalarFieldAst {
                                required: false,
                                ..Default::default()
                            },
                        )),
                        risk: Risk::Safe,
                    });
                } else {
                    final_ops.push(op);
                }
            }
            _ => final_ops.push(op),
        }
    }

    let safe = final_ops
        .iter()
        .filter(|o| matches!(supatype_engine::differ::risk_of(o), Risk::Safe))
        .count();
    let cautious = final_ops
        .iter()
        .filter(|o| matches!(supatype_engine::differ::risk_of(o), Risk::Cautious))
        .count();
    let destructive = final_ops
        .iter()
        .filter(|o| matches!(supatype_engine::differ::risk_of(o), Risk::Destructive))
        .count();

    diff.operations = final_ops;
    diff.summary.safe = safe;
    diff.summary.cautious = cautious;
    diff.summary.destructive = destructive;
    diff.summary.is_destructive = destructive > 0;

    Ok(diff)
}

/// Prints a styled [INPUT REQUIRED] prompt to stderr and leaves the cursor
/// on the same line as the `[Y/n]:` tag, ready for the caller to read a line.
fn prompt_rename(subject: &str, hint: &str) -> Result<()> {
    use std::io::Write;
    eprintln!(
        "\n  {} {}",
        " INPUT REQUIRED ".on_yellow().black().bold(),
        subject,
    );
    eprintln!("  {}  {}", "↳".yellow(), hint.dimmed(),);
    eprint!(
        "  {} Treat as rename? {} ",
        "›".yellow().bold(),
        "[Y/n]:".bold(),
    );
    let _ = io::stderr().flush();
    Ok(())
}

/// Prompt once before applying risky column conversions or destructive operations.
fn confirm_risky_changes(diff: &supatype_engine::differ::DiffOutput) -> Result<()> {
    use std::io::BufRead;
    use std::io::Write;

    let risky_summaries: Vec<String> = diff
        .operations
        .iter()
        .filter_map(risky_op_summary)
        .collect();

    if risky_summaries.is_empty() {
        return Ok(());
    }

    let cautious = diff.summary.cautious;
    let destructive = diff.summary.destructive;

    eprintln!(
        "\n  {} {} risky operation(s) detected in this push ({} cautious, {} destructive).",
        " INPUT REQUIRED ".on_yellow().black().bold(),
        (cautious + destructive).to_string().bold(),
        cautious,
        destructive,
    );
    eprintln!(
        "  {}  {}",
        "↳".yellow(),
        "Column type/kind changes may transform or discard existing data.".dimmed()
    );
    for item in &risky_summaries {
        eprintln!("    - {}", item);
    }
    eprint!(
        "  {} Continue and apply these changes? {} ",
        "›".yellow().bold(),
        "[y/N]:".bold(),
    );
    let _ = io::stderr().flush();

    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if !destructive_confirmed(line.trim()) {
        anyhow::bail!("Aborted: risky changes were not confirmed");
    }

    Ok(())
}

/// Plan 3.5, interactively: show every policy, grant, label or RLS attribute changed or removed
/// outside Supatype, and put them back only if the person says so. Returns whether to overwrite;
/// declining aborts the push, since a push cannot apply the rest and leave these as they are.
fn confirm_security_drift(plan: &supatype_engine::ledger::reconcile::Plan) -> Result<bool> {
    use std::io::BufRead;
    use std::io::Write;

    let drifted = supatype_engine::ledger::drift::security_drift(plan);
    if drifted.is_empty() {
        return Ok(false);
    }
    eprintln!(
        "\n  {} {} object(s) that decide who may read or write were changed outside Supatype.",
        " INPUT REQUIRED ".on_yellow().black().bold(),
        drifted.len().to_string().bold(),
    );
    for object in &drifted {
        eprintln!("\n    {}", object.key.to_string().bold());
        eprintln!("      {}", "Supatype's:".dimmed());
        for line in object.recorded.lines() {
            eprintln!("        {line}");
        }
        match &object.live {
            Some(live) => {
                eprintln!("      {}", "Now:".dimmed());
                for line in live.lines() {
                    eprintln!("        {line}");
                }
            }
            None => eprintln!("      {}", "Now: removed".dimmed()),
        }
    }
    eprint!(
        "\n  {} Put Supatype's definitions back? {} ",
        "›".yellow().bold(),
        "[y/N]:".bold(),
    );
    let _ = io::stderr().flush();
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if !destructive_confirmed(line.trim()) {
        anyhow::bail!("Aborted: access changed outside Supatype was kept, and nothing was applied");
    }
    Ok(true)
}

fn risky_op_summary(op: &supatype_engine::differ::Operation) -> Option<String> {
    use supatype_engine::differ::{risk_of, Operation, Risk};
    match risk_of(op) {
        Risk::Safe => None,
        Risk::Cautious | Risk::Destructive => {
            match op {
                Operation::AlterColumn {
                    table,
                    column,
                    warning,
                    ..
                } => Some(warning.clone().unwrap_or_else(|| {
                    format!("Alter column '{table}.{column}' (lossy conversion)")
                })),
                Operation::RecreateColumn {
                    table,
                    column,
                    warning,
                    ..
                } => {
                    Some(warning.clone().unwrap_or_else(|| {
                        format!("Recreate column '{table}.{column}' (data loss)")
                    }))
                }
                other => Some(destructive_op_summary(other)),
            }
        }
    }
}

/// Prompt once before applying any destructive operations in interactive mode.
#[allow(dead_code)]
fn confirm_destructive_changes(diff: &supatype_engine::differ::DiffOutput) -> Result<()> {
    confirm_risky_changes(diff)
}

#[allow(dead_code)]
fn has_destructive_ops(diff: &supatype_engine::differ::DiffOutput) -> bool {
    use supatype_engine::differ::{risk_of, Risk};
    diff.operations
        .iter()
        .any(|op| matches!(risk_of(op), Risk::Destructive))
}

fn destructive_confirmed(answer: &str) -> bool {
    matches!(answer.trim().to_lowercase().as_str(), "y" | "yes")
}

fn destructive_op_summary(op: &supatype_engine::differ::Operation) -> String {
    use supatype_engine::differ::Operation;
    match op {
        Operation::DropTable { table, .. } => format!("Drop table '{}'", table),
        Operation::DropColumn { table, column, .. } => {
            format!("Drop column '{}.{}'", table, column)
        }
        Operation::RecreateColumn { table, column, .. } => {
            format!("Recreate column (data loss): '{table}.{column}'")
        }
        Operation::AlterColumn {
            table,
            column,
            warning,
            ..
        } => warning
            .clone()
            .unwrap_or_else(|| format!("Alter column '{table}.{column}'")),
        other => format!("Destructive change: {:?}", other),
    }
}

fn read_input(path: Option<&str>) -> Result<String> {
    match path {
        None | Some("-") => {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .context("Failed to read from stdin")?;
            Ok(buf)
        }
        Some(p) => std::fs::read_to_string(p).with_context(|| format!("Failed to read {p}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{destructive_confirmed, destructive_op_summary, has_destructive_ops};
    use supatype_engine::differ::{DiffOutput, DiffSummary, Operation, Risk};

    #[test]
    fn destructive_confirmation_accepts_only_yes() {
        assert!(destructive_confirmed("y"));
        assert!(destructive_confirmed("Y"));
        assert!(destructive_confirmed(" yes "));
        assert!(!destructive_confirmed(""));
        assert!(!destructive_confirmed("n"));
        assert!(!destructive_confirmed("no"));
    }

    #[test]
    fn has_destructive_ops_detects_drop_table() {
        let diff = DiffOutput {
            operations: vec![Operation::DropTable {
                table: "example".into(),
                risk: Risk::Destructive,
            }],
            summary: DiffSummary {
                safe: 0,
                cautious: 0,
                destructive: 1,
                is_destructive: true,
            },
            warnings: vec![],
            unmanaged_model_tables: vec![],
            field_masking: supatype_engine::differ::FieldMaskingTier::None,
            field_view_plan: Vec::new(),
        };
        assert!(has_destructive_ops(&diff));
    }

    #[test]
    fn destructive_op_summary_is_human_readable() {
        let op = Operation::DropColumn {
            table: "comment".into(),
            column: "legacy_col".into(),
            risk: Risk::Destructive,
        };
        assert_eq!(
            destructive_op_summary(&op),
            "Drop column 'comment.legacy_col'"
        );
    }
}

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
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

    #[arg(long, short, global = true, help = "Output file path, or '-' for stdout")]
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
    /// Generate SQL migration from a diff (print only — does not apply)
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
        #[arg(long, help = "Bypass schema state cache and do a full DB introspection")]
        no_cache: bool,
    },
    /// Generate TypeScript type definitions
    Generate,
    /// Generate trigger SQL (updated_at + slug)
    Triggers,
    /// Generate RLS policy SQL
    Rls,
    /// Generate storage schema SQL (bucket DDL + storage RLS)
    Storage,
    /// Generate PostgREST configuration
    Postgrest,
    /// Generate admin panel configuration JSON
    Admin,
    /// Generate Studio metadata JSON for the Visual Schema Designer
    Studio,
    /// Generate OpenAPI 3.0 specification from the schema
    Openapi,
    /// List all recorded migrations from the database
    Migrations {
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Validate a migration is safe to apply
    Validate {
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(&cli.log)
        .with_writer(io::stderr)
        .init();

    info!(version = env!("ENGINE_VERSION"), target = env!("BUILD_TARGET"), "supatype-engine starting");

    let _license = supatype_engine::licensing::License::new(cli.license.as_deref());

    let input = read_input(cli.input.as_deref())?;

    match cli.command {
        Command::Parse => {
            let ast = supatype_engine::parser::parse(&input)?;
            println!("{}", serde_json::to_string_pretty(&ast)?);
        }
        Command::Introspect { database_url, schema } => {
            let pool = sqlx::PgPool::connect(&database_url)
                .await
                .context("Failed to connect to database")?;
            let state = supatype_engine::introspector::introspect(&pool, &schema).await?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        Command::Diff { database_url, schema } => {
            let ast = supatype_engine::parser::parse(&input)?;
            let pool = sqlx::PgPool::connect(&database_url).await?;
            let db_state = supatype_engine::introspector::introspect(&pool, &schema).await?;
            let diff = supatype_engine::differ::diff(&ast, &db_state)?;
            println!("{}", serde_json::to_string_pretty(&diff)?);
        }
        Command::Migrate { database_url, schema, force } => {
            let ast = supatype_engine::parser::parse(&input)?;
            let pool = sqlx::PgPool::connect(&database_url).await?;
            let db_state = supatype_engine::introspector::introspect(&pool, &schema).await?;
            let diff = supatype_engine::differ::diff(&ast, &db_state)?;
            let migration = supatype_engine::generator::sql::migration::generate(&diff, force)?;
            println!("{migration}");
        }
        Command::Push { database_url, schema, force, name, non_interactive, no_cache } => {
            use supatype_engine::state::migration_history;
            let ast = supatype_engine::parser::parse(&input)?;
            let pool = sqlx::PgPool::connect(&database_url).await
                .context("Failed to connect to database")?;

            // Ensure migration history schema/table exists
            sqlx::raw_sql(migration_history::create_migrations_table_sql())
                .execute(&pool)
                .await
                .context("Failed to create _platform schema tables")?;

            // Load DB state: from cache unless --no-cache
            let db_state = if !no_cache {
                migration_history::load_schema_state(&pool).await
            } else {
                None
            };
            let db_state = match db_state {
                Some(cached) => {
                    info!("Using cached schema state (use --no-cache to force full introspection)");
                    cached
                }
                None => supatype_engine::introspector::introspect(&pool, &schema).await?,
            };

            let mut diff = supatype_engine::differ::diff(&ast, &db_state)?;

            // Interactive rename confirmation (skipped in CI with --non-interactive)
            if !non_interactive {
                diff = confirm_renames(diff)?;
            }

            if diff.operations.is_empty() {
                info!("Schema is up to date — no changes to apply.");
                println!("{{\"status\":\"up_to_date\",\"operations\":0}}");
                return Ok(());
            }

            let migration_sql = supatype_engine::generator::sql::migration::generate(&diff, force)?;
            let migration_name = name.unwrap_or_else(|| {
                format!("push_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"))
            });

            // Apply migration
            sqlx::raw_sql(&migration_sql).execute(&pool).await
                .context("Failed to apply migration")?;

            // Refresh and cache post-migration DB state
            let new_db_state = supatype_engine::introspector::introspect(&pool, &schema).await?;
            migration_history::save_schema_state(&pool, &new_db_state).await
                .context("Failed to save schema state cache")?;

            // Record in history
            let hash = format!("sha256:{}", {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(migration_sql.as_bytes());
                hex::encode(h.finalize())
            });
            sqlx::query(
                "INSERT INTO _platform.migrations (name, hash, engine_version, schema_snapshot) \
                 VALUES ($1, $2, $3, $4)"
            )
            .bind(&migration_name)
            .bind(&hash)
            .bind(env!("ENGINE_VERSION"))
            .bind(serde_json::to_value(&ast).ok())
            .execute(&pool)
            .await
            .context("Failed to record migration in history")?;

            info!(name = %migration_name, ops = diff.operations.len(), "Migration applied");
            println!(
                "{{\"status\":\"applied\",\"name\":\"{}\",\"operations\":{}}}",
                migration_name, diff.operations.len()
            );
        }
        Command::Generate => {
            let ast = supatype_engine::parser::parse(&input)?;
            let ts = supatype_engine::generator::typescript::types::generate(&ast)?;
            println!("{ts}");
        }
        Command::Triggers => {
            let ast = supatype_engine::parser::parse(&input)?;
            let sql = supatype_engine::generator::sql::triggers::generate(&ast)?;
            println!("{sql}");
        }
        Command::Rls => {
            let ast = supatype_engine::parser::parse(&input)?;
            println!("{}", supatype_engine::generator::sql::rls::generate_auth_helpers());
            println!("{}", supatype_engine::generator::sql::rls::generate(&ast)?);
        }
        Command::Storage => {
            let ast = supatype_engine::parser::parse(&input)?;
            let sql = supatype_engine::generator::sql::storage::generate(&ast)?;
            println!("{sql}");
        }
        Command::Postgrest => {
            let ast = supatype_engine::parser::parse(&input)?;
            let config = supatype_engine::generator::config::postgrest::generate(&ast)?;
            println!("{}", serde_json::to_string_pretty(&config)?);
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
        Command::Migrations { database_url } => {
            use supatype_engine::state::migration_history;
            let pool = sqlx::PgPool::connect(&database_url).await
                .context("Failed to connect to database")?;
            let migrations = migration_history::list_migrations(&pool).await?;
            println!("{}", serde_json::to_string_pretty(&migrations)?);
        }
        Command::Validate { database_url } => {
            let diff: supatype_engine::differ::DiffOutput =
                serde_json::from_str(&input).context("Failed to parse diff JSON")?;
            let pool = sqlx::PgPool::connect(&database_url).await?;
            let report = supatype_engine::differ::risk_analyser::validate(&diff, &pool).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }

    Ok(())
}

/// For each RenameColumn operation, prompt the user to confirm it's a rename.
/// If the user declines, replace the RenameColumn with DropColumn + AddColumn.
fn confirm_renames(mut diff: supatype_engine::differ::DiffOutput) -> Result<supatype_engine::differ::DiffOutput> {
    use supatype_engine::differ::{Operation, Risk};
    use std::io::{BufRead, Write};

    let mut final_ops: Vec<Operation> = Vec::new();

    for op in diff.operations {
        match &op {
            Operation::RenameColumn { table, from, to, .. } => {
                eprint!(
                    "  ? Column '{from}' removed and '{to}' added on '{table}'. \
                     Treat as rename? [Y/n] "
                );
                let _ = io::stderr().flush();

                let mut line = String::new();
                io::stdin().lock().read_line(&mut line)?;
                let answer = line.trim().to_lowercase();

                if answer == "n" || answer == "no" {
                    // User declined — emit DropColumn + AddColumn instead
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
                            }
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

    let safe = final_ops.iter().filter(|o| matches!(supatype_engine::differ::risk_of(o), Risk::Safe)).count();
    let cautious = final_ops.iter().filter(|o| matches!(supatype_engine::differ::risk_of(o), Risk::Cautious)).count();
    let destructive = final_ops.iter().filter(|o| matches!(supatype_engine::differ::risk_of(o), Risk::Destructive)).count();

    diff.operations = final_ops;
    diff.summary.safe = safe;
    diff.summary.cautious = cautious;
    diff.summary.destructive = destructive;
    diff.summary.is_destructive = destructive > 0;

    Ok(diff)
}

fn read_input(path: Option<&str>) -> Result<String> {
    match path {
        None | Some("-") => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf).context("Failed to read from stdin")?;
            Ok(buf)
        }
        Some(p) => std::fs::read_to_string(p).with_context(|| format!("Failed to read {p}")),
    }
}

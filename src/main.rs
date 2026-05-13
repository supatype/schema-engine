use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;
use sqlx::Executor;
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
        #[arg(
            long,
            help = "Bypass schema state cache and do a full DB introspection"
        )]
        no_cache: bool,
    },
    /// Generate typed client code (TypeScript by default; use --lang for other languages)
    Generate {
        /// Target language: typescript (default), python, go, php, swift, kotlin, dart
        #[arg(long, default_value = "typescript")]
        lang: String,
    },
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

    info!(
        version = env!("ENGINE_VERSION"),
        target = env!("BUILD_TARGET"),
        "supatype-engine starting"
    );

    let _license = supatype_engine::licensing::License::new(cli.license.as_deref());

    let input = read_input(cli.input.as_deref())?;

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
            let db_state = supatype_engine::introspector::introspect(&pool, &schema).await?;
            let diff = supatype_engine::differ::diff(&ast, &db_state)?;
            println!("{}", serde_json::to_string_pretty(&diff)?);
        }
        Command::Migrate {
            database_url,
            schema,
            force,
        } => {
            let ast = supatype_engine::parser::parse(&input)?;
            let pool = sqlx::PgPool::connect(&database_url).await?;
            let db_state = supatype_engine::introspector::introspect(&pool, &schema).await?;
            let diff = supatype_engine::differ::diff(&ast, &db_state)?;
            let migration =
                supatype_engine::generator::sql::migration::generate(&diff, force, &schema, &ast)?;
            println!("{migration}");
        }
        Command::Push {
            database_url,
            schema,
            force,
            name,
            non_interactive,
            no_cache,
        } => {
            use supatype_engine::state::{migration_history, studio_state};
            let ast = supatype_engine::parser::parse(&input)?;
            let storage_sql = supatype_engine::generator::sql::storage::generate(&ast)?;
            let pool = sqlx::PgPool::connect(&database_url)
                .await
                .context("Failed to connect to database")?;

            // Ensure _supatype schema and internal tables exist
            sqlx::raw_sql(migration_history::create_internal_schema_sql())
                .execute(&pool)
                .await
                .context("Failed to create _supatype schema")?;
            sqlx::raw_sql(&migration_history::create_migrations_table_sql())
                .execute(&pool)
                .await
                .context("Failed to create migrations table")?;
            sqlx::raw_sql(&migration_history::create_schema_state_table_sql())
                .execute(&pool)
                .await
                .context("Failed to create schema_state table")?;
            sqlx::raw_sql(&migration_history::ensure_migrations_admin_config_column_sql())
                .execute(&pool)
                .await
                .context("Failed to ensure admin_config column")?;
            sqlx::raw_sql(&migration_history::ensure_migrations_sql_up_column_sql())
                .execute(&pool)
                .await
                .context("Failed to ensure sql_up column")?;
            sqlx::raw_sql(&migration_history::ensure_migrations_status_columns_sql())
                .execute(&pool)
                .await
                .context("Failed to ensure status/error_message columns")?;

            // Ensure supatype schema and studio tables exist
            sqlx::raw_sql(studio_state::create_studio_schema_sql())
                .execute(&pool)
                .await
                .context("Failed to create supatype schema")?;
            sqlx::raw_sql(studio_state::grant_studio_schema_sql())
                .execute(&pool)
                .await
                .context("Failed to grant supatype schema usage")?;
            sqlx::raw_sql(&studio_state::create_dashboard_views_table_sql())
                .execute(&pool)
                .await
                .context("Failed to create supatype.dashboard_views table")?;
            sqlx::raw_sql(&studio_state::create_storage_stats_function_sql())
                .execute(&pool)
                .await
                .context("Failed to create supatype.storage_stats function")?;
            sqlx::raw_sql(&studio_state::create_db_stats_function_sql())
                .execute(&pool)
                .await
                .context("Failed to create supatype.db_stats function")?;
            sqlx::raw_sql(&studio_state::create_daily_signups_function_sql())
                .execute(&pool)
                .await
                .context("Failed to create supatype.daily_signups function")?;
            sqlx::raw_sql(&studio_state::create_daily_content_creates_function_sql())
                .execute(&pool)
                .await
                .context("Failed to create supatype.daily_content_creates function")?;

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
                confirm_destructive_changes(&diff)?;
            }

            if diff.operations.is_empty() {
                // Storage materialization is not part of the model diff; apply it before the
                // admin-only migration refresh path.
                sqlx::raw_sql(&storage_sql)
                    .execute(&pool)
                    .await
                    .context("Failed to apply storage schema/policies")?;

                // AST-only changes (widgets, labels, etc.) still need admin_config / snapshot
                // so Studio and tooling see the latest schema without a DDL migration.
                info!("Schema is up to date — refreshing admin_config on latest migration record.");
                let admin_cfg = supatype_engine::generator::typescript::admin::generate(&ast)?;
                let schema_snap = serde_json::to_value(&ast)?;
                let n = migration_history::update_latest_migration_admin(&pool, &admin_cfg, &schema_snap)
                    .await
                    .context("Failed to update admin_config on latest migration")?;
                if n == 0 {
                    let migration_name = format!(
                        "admin_refresh_{}",
                        chrono::Utc::now().format("%Y%m%d_%H%M%S_%3f")
                    );
                    let hash = format!("sha256:{}", {
                        use sha2::{Digest, Sha256};
                        let mut h = Sha256::new();
                        h.update(schema_snap.to_string().as_bytes());
                        hex::encode(h.finalize())
                    });
                    sqlx::query(&migration_history::insert_migration_sql())
                        .bind(&migration_name)
                        .bind(&hash)
                        .bind(env!("ENGINE_VERSION"))
                        .bind(&schema_snap)
                        .bind(&admin_cfg)
                        .bind(None::<String>)
                        .execute(&pool)
                        .await
                        .context("Failed to insert admin-only migration record")?;
                }
                println!(
                    "{{\"status\":\"up_to_date\",\"operations\":0,\"admin_refreshed\":true}}"
                );
                return Ok(());
            }

            let migration_sql =
                supatype_engine::generator::sql::migration::generate(&diff, force, &schema, &ast)?;
            // Use millisecond precision so rapid retries don't collide on name.
            let migration_name = name
                .unwrap_or_else(|| format!("push_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S_%3f")));

            // Pre-compute hash so it's available for the failure record too.
            let hash = format!("sha256:{}", {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(migration_sql.as_bytes());
                hex::encode(h.finalize())
            });

            let apply_body =
                supatype_engine::generator::sql::migration::push_storage_and_model_apply_body(
                    &storage_sql,
                    &diff,
                    force,
                    &schema,
                    &ast,
                )?;
            let apply_batch =
                supatype_engine::generator::sql::migration::push_storage_and_model_batch_sql(
                    &storage_sql,
                    &diff,
                    force,
                    &schema,
                    &ast,
                )?;

            let mut tx = pool
                .begin()
                .await
                .context("begin migration transaction")?;

            if let Err(e) = (&mut *tx)
                .execute(sqlx::raw_sql(&apply_body))
                .await
                .map_err(anyhow::Error::from)
            {
                migration_history::rollback_push_tx(
                    tx,
                    &pool,
                    &migration_name,
                    &hash,
                    &apply_batch,
                    &e.to_string(),
                )
                .await;
                return Err(e.context("Failed to apply migration"));
            }

            let new_db_state = match supatype_engine::introspector::introspect_connection(&mut *tx, &schema).await {
                Ok(s) => s,
                Err(e) => {
                    migration_history::rollback_push_tx(
                        tx,
                        &pool,
                        &migration_name,
                        &hash,
                        &apply_batch,
                        &e.to_string(),
                    )
                    .await;
                    return Err(e.context("Failed to introspect after migration"));
                }
            };

            if let Err(e) = migration_history::save_schema_state(&mut *tx, &new_db_state).await {
                migration_history::rollback_push_tx(
                    tx,
                    &pool,
                    &migration_name,
                    &hash,
                    &apply_batch,
                    &e.to_string(),
                )
                .await;
                return Err(e.context("Failed to save schema state cache"));
            }

            let admin_cfg = supatype_engine::generator::typescript::admin::generate(&ast).ok();
            if let Err(e) = migration_history::insert_applied_migration(
                &mut *tx,
                &migration_name,
                &hash,
                serde_json::to_value(&ast).ok(),
                admin_cfg,
                &apply_batch,
            )
            .await
            {
                migration_history::rollback_push_tx(
                    tx,
                    &pool,
                    &migration_name,
                    &hash,
                    &apply_batch,
                    &e.to_string(),
                )
                .await;
                return Err(e.context("Failed to record migration in history"));
            }

            tx.commit()
                .await
                .context("commit migration transaction")?;

            info!(name = %migration_name, ops = diff.operations.len(), "Migration applied");
            println!(
                "{{\"status\":\"applied\",\"name\":\"{}\",\"operations\":{}}}",
                migration_name,
                diff.operations.len()
            );
        }
        Command::Generate { lang } => {
            let ast = supatype_engine::parser::parse(&input)?;
            let output = match lang.as_str() {
                "typescript" | "ts" => {
                    supatype_engine::generator::typescript::types::generate(&ast)?
                }
                other => supatype_engine::generator::sdk::generate(&ast, other)?,
            };
            println!("{output}");
        }
        Command::Triggers => {
            let ast = supatype_engine::parser::parse(&input)?;
            let sql = supatype_engine::generator::sql::triggers::generate(&ast)?;
            println!("{sql}");
        }
        Command::Rls => {
            let ast = supatype_engine::parser::parse(&input)?;
            println!(
                "{}",
                supatype_engine::generator::sql::rls::generate_auth_helpers()
            );
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
        Command::Migrations { database_url } => {
            use supatype_engine::state::migration_history;
            let pool = sqlx::PgPool::connect(&database_url)
                .await
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
    eprintln!(
        "  {}  {}",
        "↳".yellow(),
        hint.dimmed(),
    );
    eprint!(
        "  {} Treat as rename? {} ",
        "›".yellow().bold(),
        "[Y/n]:".bold(),
    );
    let _ = io::stderr().flush();
    Ok(())
}

/// Prompt once before applying any destructive operations in interactive mode.
/// This runs even when --force is set, so users get a last safety check in `push`.
fn confirm_destructive_changes(diff: &supatype_engine::differ::DiffOutput) -> Result<()> {
    use std::io::BufRead;
    use std::io::Write;
    use supatype_engine::differ::{risk_of, Risk};

    if !has_destructive_ops(diff) {
        return Ok(());
    }

    let destructive_summaries: Vec<String> = diff
        .operations
        .iter()
        .filter(|op| matches!(risk_of(op), Risk::Destructive))
        .map(destructive_op_summary)
        .collect();

    eprintln!(
        "\n  {} {} destructive operation(s) detected in this push.",
        " INPUT REQUIRED ".on_yellow().black().bold(),
        diff.summary.destructive.to_string().bold()
    );
    eprintln!(
        "  {}  {}",
        "↳".yellow(),
        "These can remove data or schema objects.".dimmed()
    );
    for item in &destructive_summaries {
        eprintln!("    - {}", item);
    }
    eprint!(
        "  {} Continue and apply destructive changes? {} ",
        "›".yellow().bold(),
        "[y/N]:".bold(),
    );
    let _ = io::stderr().flush();

    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if !destructive_confirmed(line.trim()) {
        anyhow::bail!("Aborted: destructive changes were not confirmed");
    }

    Ok(())
}

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
        Operation::DropForeignKey {
            table, constraint, ..
        } => format!("Drop foreign key '{}.{}'", table, constraint),
        Operation::DropEnum { name, .. } => format!("Drop enum type '{}'", name),
        Operation::RemoveEnumValue {
            enum_name, value, ..
        } => format!("Remove enum value '{}' from '{}'", value, enum_name),
        other => format!("Destructive change: {:?}", other),
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

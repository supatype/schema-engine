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
        #[arg(
            long,
            help = "Fail push when post-apply drift remains (missing or stale managed objects)"
        )]
        strict: bool,
        #[arg(long, help = "Path to gzip-compressed tar of schema source files")]
        schema_sources_gz: Option<String>,
        #[arg(long, help = "Path to schema_sources manifest JSON")]
        schema_sources_manifest: Option<String>,
    },
    /// Generate typed client code (TypeScript by default; use --lang for other languages)
    Generate {
        /// Target language: typescript (default), python, go, php, swift, kotlin, dart
        #[arg(long, default_value = "typescript")]
        lang: String,
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
            help = "Exit non-zero when missing or stale managed drift exists"
        )]
        strict: bool,
    },
    /// Stamp managed comments on DB objects matching the AST (adoption ceremony)
    Adopt {
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        #[arg(long, default_value = "public")]
        schema: String,
        #[arg(long, help = "Apply stamp SQL without interactive confirmation")]
        yes: bool,
        #[arg(
            long,
            help = "Bypass schema state cache and do a full DB introspection"
        )]
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
            strict,
            schema_sources_gz,
            schema_sources_manifest,
        } => {
            use supatype_engine::state::{migration_history, studio_state};
            let ast = supatype_engine::parser::parse(&input)?;
            let storage_sql = supatype_engine::generator::sql::storage::generate(&ast)?;
            let pool = sqlx::PgPool::connect(&database_url)
                .await
                .context("Failed to connect to database")?;

            // Ensure _supatype schema and internal tables exist
            // Internal bookkeeping + auth helpers (shared with the server push path).
            migration_history::bootstrap_internal_state(&pool)
                .await
                .context("Failed to bootstrap _supatype internal state")?;

            let schema_sources_bytes = schema_sources_gz
                .as_deref()
                .map(std::fs::read)
                .transpose()
                .with_context(|| "Failed to read schema_sources_gz")?;
            let schema_sources_manifest_json = schema_sources_manifest
                .as_deref()
                .map(std::fs::read_to_string)
                .transpose()
                .with_context(|| "Failed to read schema_sources_manifest")?
                .map(|s| serde_json::from_str(&s))
                .transpose()
                .context("Failed to parse schema_sources_manifest JSON")?;

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

            let previous_ast = if !no_cache {
                migration_history::load_latest_schema_snapshot(&pool)
                    .await
                    .and_then(|v| serde_json::from_value(v).ok())
            } else {
                None
            };

            let mut diff = supatype_engine::differ::diff_with_previous(
                &ast,
                &db_state,
                previous_ast.as_ref(),
            )?;

            // Interactive rename confirmation (skipped in CI with --non-interactive)
            if !non_interactive {
                diff = confirm_renames(diff)?;
                confirm_risky_changes(&diff)?;
            }

            // Before either branch: an unchanged schema produces an empty diff, so the renderer's
            // own check would never run and the push would report success while a declared table sat
            // in the API with none of its rules applied.
            supatype_engine::generator::sql::migration::assert_no_unmanaged_model_tables(&diff)?;

            // The field-masking tier is decided from the introspected extension list. A cached schema
            // state that predates extension introspection would claim there are none, silently
            // switching a tier-1 database to views *and* revoking the API roles' access to its base
            // tables. Cheap to rule out while a connection is open, and not something to discover
            // afterwards.
            if diff.field_masking == supatype_engine::differ::FieldMaskingTier::Views {
                let installed: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = $1)",
                )
                .bind(supatype_engine::generator::sql::rls::MASK_EXTENSION)
                .fetch_one(&pool)
                .await?;
                if installed {
                    anyhow::bail!(
                        "This database has {ext} installed, but the schema state used for this diff                          says otherwise — so the push was about to switch field masking to generated                          views and take the API roles off your tables.
                         
                         Re-run with --no-cache to diff against the live database.",
                        ext = supatype_engine::generator::sql::rls::MASK_EXTENSION
                    );
                }
            }

            if diff.operations.is_empty() {
                // Rendered before anything is applied, so a schema whose versioned models have no
                // stated visibility fails the push rather than half-applying it.
                //
                // Applied on this path at all because the publishing layer is exactly the kind of
                // change that produces no DDL: widening `draft_visibility` in the config alters no
                // table, so a steady-state push is the only push that will ever carry it. Skipping
                // it here would mean a security setting that reads as applied and is not.
                let versions_sql =
                    supatype_engine::generator::sql::versions::render_versions_layer(&ast, &schema)?;

                // Storage materialization is not part of the model diff; apply it before the
                // admin-only migration refresh path.
                sqlx::raw_sql(&storage_sql)
                    .execute(&pool)
                    .await
                    .context("Failed to apply storage schema/policies")?;

                // Trigger functions (slug / updated_at) are idempotent and not part of
                // the model diff — ensure they exist on every push so an up-to-date
                // schema still gets its slug/updated_at triggers installed.
                let triggers_sql =
                    supatype_engine::generator::sql::triggers::generate(&ast, &schema)?;
                sqlx::raw_sql(&triggers_sql)
                    .execute(&pool)
                    .await
                    .context("Failed to apply trigger functions")?;

                if !versions_sql.trim().is_empty() {
                    sqlx::raw_sql(&versions_sql)
                        .execute(&pool)
                        .await
                        .context("Failed to apply drafts and publishing layer")?;
                }

                // AST-only changes (widgets, labels, etc.) still need admin_config / snapshot
                // so Studio and tooling see the latest schema without a DDL migration.
                info!("Schema is up to date — refreshing Studio metadata.");
                let admin_cfg = supatype_engine::generator::typescript::admin::generate(&ast)?;
                let schema_snap = serde_json::to_value(&ast)?;
                migration_history::refresh_metadata_on_up_to_date_push(
                    &pool,
                    &admin_cfg,
                    &schema_snap,
                )
                .await
                .context("Failed to refresh Studio metadata on up-to-date push")?;
                println!("{{\"status\":\"up_to_date\",\"operations\":0,\"admin_refreshed\":true}}");
                return Ok(());
            }

            let migration_sql =
                supatype_engine::generator::sql::migration::generate(&diff, force, &schema, &ast)?;
            // Use millisecond precision so rapid retries don't collide on name.
            let migration_name = name.unwrap_or_else(|| {
                format!("push_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S_%3f"))
            });

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
            let sql_down = supatype_engine::generator::sql::rollback::generate(&diff, &schema).ok();

            let mut tx = pool.begin().await.context("begin migration transaction")?;

            // Coordinate with realtime: skip WAL polls while this xact lock is held.
            // Keys must match packages/cli + packages/realtime schema-push-lock constants.
            // If the CLI already holds a session lock on the same keys, skip to avoid deadlock.
            {
                let lock_held: bool = sqlx::query_scalar(
                    r#"
                    SELECT EXISTS (
                      SELECT 1 FROM pg_locks
                      WHERE locktype = 'advisory'
                        AND classid = 872014
                        AND objid = 1
                        AND granted
                    )
                    "#,
                )
                .fetch_one(&mut *tx)
                .await
                .unwrap_or(false);
                if !lock_held {
                    sqlx::query("SELECT pg_advisory_xact_lock(872014, 1)")
                        .execute(&mut *tx)
                        .await
                        .context("acquire schema-push advisory lock")?;
                }
            }

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
                let msg = supatype_engine::generator::sql::migration_errors::enrich_migration_error(
                    &e.to_string(),
                    Some(&diff),
                );
                return Err(anyhow::anyhow!(msg).context("Failed to apply migration"));
            }

            let new_db_state = match supatype_engine::introspector::introspect_connection(
                &mut tx, &schema,
            )
            .await
            {
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

            let drift_warnings =
                supatype_engine::differ::integrity::post_push_warnings(&ast, &new_db_state);
            if strict
                && !supatype_engine::differ::integrity::post_push_ok(&ast, &new_db_state, true)
            {
                let msg = drift_warnings.join("; ");
                migration_history::rollback_push_tx(
                    tx,
                    &pool,
                    &migration_name,
                    &hash,
                    &apply_batch,
                    &msg,
                )
                .await;
                return Err(anyhow::anyhow!(
                    "Push rolled back: post-apply schema drift in strict mode ({msg})"
                ));
            }

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

            // Which mechanism is enforcing the field rules, probed rather than assumed.
            // A failure here is a missing diagnostic, not a broken push: the enforcement
            // itself is the labels, which are already applied in this transaction.
            if let Err(e) = migration_history::record_field_enforcement(
                &mut tx,
                migration_history::labelled_column_count(&ast),
            )
            .await
            {
                eprintln!("Warning: failed to record field-enforcement capability: {e}");
            }

            let admin_cfg = supatype_engine::generator::typescript::admin::generate(&ast).ok();
            // Kept for the schema_state refresh after commit: Studio reads its schema
            // from `_supatype.schema_state`, which was only written on the up-to-date
            // branch — so any project whose last push applied a migration had none.
            let studio_metadata = admin_cfg.clone().zip(serde_json::to_value(&ast).ok());
            let migration_sources = migration_history::AppliedMigrationSources {
                sql_down,
                schema_sources: schema_sources_bytes,
                schema_sources_manifest: schema_sources_manifest_json,
            };
            if let Err(e) = migration_history::insert_applied_migration(
                &mut *tx,
                &migration_name,
                &hash,
                serde_json::to_value(&ast).ok(),
                admin_cfg,
                &apply_batch,
                &migration_sources,
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

            tx.commit().await.context("commit migration transaction")?;

            if let Some((admin_cfg, schema_snap)) = studio_metadata.as_ref() {
                if let Err(e) = migration_history::save_studio_metadata_if_present(
                    &pool,
                    admin_cfg,
                    schema_snap,
                )
                .await
                {
                    eprintln!("Warning: failed to refresh Studio metadata: {e}");
                }
            }

            info!(name = %migration_name, ops = diff.operations.len(), "Migration applied");
            let warnings_json = serde_json::to_string(&drift_warnings)?;
            println!(
                "{{\"status\":\"applied\",\"name\":\"{}\",\"operations\":{},\"warnings\":{}}}",
                migration_name,
                diff.operations.len(),
                warnings_json
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
        } => {
            let ast = supatype_engine::parser::parse(&input)?;
            let pool = sqlx::PgPool::connect(&database_url).await?;
            let db_state = supatype_engine::introspector::introspect(&pool, &schema).await?;
            let report = supatype_engine::differ::doctor::report(&ast, &db_state);
            println!("{}", serde_json::to_string_pretty(&report)?);
            if strict && supatype_engine::differ::doctor::has_strict_issues(&report) {
                std::process::exit(1);
            }
        }
        Command::Adopt {
            database_url,
            schema,
            yes,
            no_cache,
        } => {
            use supatype_engine::state::migration_history;
            let ast = supatype_engine::parser::parse(&input)?;
            let pool = sqlx::PgPool::connect(&database_url).await?;

            // Internal bookkeeping + auth helpers (shared with the server push path).
            migration_history::bootstrap_internal_state(&pool)
                .await
                .context("Failed to bootstrap _supatype internal state")?;

            let db_state = if no_cache {
                supatype_engine::introspector::introspect(&pool, &schema).await?
            } else if let Some(cached) = migration_history::load_schema_state(&pool).await {
                cached
            } else {
                supatype_engine::introspector::introspect(&pool, &schema).await?
            };

            let stamp_sql =
                supatype_engine::differ::doctor::adopt_stamp_sql(&ast, &db_state, &schema);
            let doctor_report = supatype_engine::differ::doctor::report(&ast, &db_state);

            if !yes {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "preview",
                        "stampStatements": stamp_sql,
                        "doctor": doctor_report,
                    }))?
                );
                return Ok(());
            }

            if stamp_sql.is_empty() {
                println!("{{\"status\":\"nothing_to_stamp\"}}");
                return Ok(());
            }

            let batch = stamp_sql.join("\n");
            sqlx::raw_sql(&batch).execute(&pool).await?;

            let fresh = supatype_engine::introspector::introspect(&pool, &schema).await?;
            migration_history::save_schema_state(&pool, &fresh).await?;

            let migration_name = format!("adopt_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
            let admin_cfg = supatype_engine::generator::typescript::admin::generate(&ast).ok();
            migration_history::insert_applied_migration(
                &pool,
                &migration_name,
                "adopt",
                serde_json::to_value(&ast).ok(),
                admin_cfg,
                &batch,
                &migration_history::AppliedMigrationSources::default(),
            )
            .await?;

            println!(
                "{{\"status\":\"adopted\",\"stamped\":{},\"name\":\"{}\"}}",
                stamp_sql.len(),
                migration_name
            );
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
        Operation::DropForeignKey {
            table, constraint, ..
        } => format!("Drop foreign key '{}.{}'", table, constraint),
        Operation::DropEnum { name, .. } => format!("Drop enum type '{}'", name),
        Operation::RemoveEnumValue {
            enum_name, value, ..
        } => format!("Remove enum value '{}' from '{}'", value, enum_name),
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

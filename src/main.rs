use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::{self, Read};
use tracing::info;

#[derive(Parser)]
#[command(
    name = "definatype-engine",
    version = env!("ENGINE_VERSION"),
    about = "Definatype schema engine"
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
    /// Generate SQL migration from a diff
    Migrate {
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        #[arg(long, default_value = "public")]
        schema: String,
        #[arg(long, help = "Allow destructive operations without prompting")]
        force: bool,
    },
    /// Generate TypeScript type definitions
    Generate,
    /// Generate RLS policy SQL
    Rls,
    /// Generate PostgREST configuration
    Postgrest,
    /// Generate admin panel configuration JSON
    Admin,
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

    info!(version = env!("ENGINE_VERSION"), target = env!("BUILD_TARGET"), "definatype-engine starting");

    let _license = definatype_engine::licensing::License::new(cli.license.as_deref());

    let input = read_input(cli.input.as_deref())?;

    match cli.command {
        Command::Parse => {
            let ast = definatype_engine::parser::parse(&input)?;
            println!("{}", serde_json::to_string_pretty(&ast)?);
        }
        Command::Introspect { database_url, schema } => {
            let pool = sqlx::PgPool::connect(&database_url)
                .await
                .context("Failed to connect to database")?;
            let state = definatype_engine::introspector::introspect(&pool, &schema).await?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        Command::Diff { database_url, schema } => {
            let ast = definatype_engine::parser::parse(&input)?;
            let pool = sqlx::PgPool::connect(&database_url).await?;
            let db_state = definatype_engine::introspector::introspect(&pool, &schema).await?;
            let diff = definatype_engine::differ::diff(&ast, &db_state)?;
            println!("{}", serde_json::to_string_pretty(&diff)?);
        }
        Command::Migrate { database_url, schema, force } => {
            let ast = definatype_engine::parser::parse(&input)?;
            let pool = sqlx::PgPool::connect(&database_url).await?;
            let db_state = definatype_engine::introspector::introspect(&pool, &schema).await?;
            let diff = definatype_engine::differ::diff(&ast, &db_state)?;
            let migration = definatype_engine::generator::sql::migration::generate(&diff, force)?;
            println!("{migration}");
        }
        Command::Generate => {
            let ast = definatype_engine::parser::parse(&input)?;
            let ts = definatype_engine::generator::typescript::types::generate(&ast)?;
            println!("{ts}");
        }
        Command::Rls => {
            let ast = definatype_engine::parser::parse(&input)?;
            let sql = definatype_engine::generator::sql::rls::generate(&ast)?;
            println!("{sql}");
        }
        Command::Postgrest => {
            let ast = definatype_engine::parser::parse(&input)?;
            let config = definatype_engine::generator::config::postgrest::generate(&ast)?;
            println!("{}", serde_json::to_string_pretty(&config)?);
        }
        Command::Admin => {
            let ast = definatype_engine::parser::parse(&input)?;
            let config = definatype_engine::generator::typescript::admin::generate(&ast)?;
            println!("{}", serde_json::to_string_pretty(&config)?);
        }
        Command::Validate { database_url } => {
            let diff: definatype_engine::differ::DiffOutput =
                serde_json::from_str(&input).context("Failed to parse diff JSON")?;
            let pool = sqlx::PgPool::connect(&database_url).await?;
            let report = definatype_engine::differ::risk_analyser::validate(&diff, &pool).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }

    Ok(())
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

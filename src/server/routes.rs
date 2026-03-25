use axum::http::StatusCode;
use axum::Json;
use sqlx::PgPool;
use tracing::{error, info};

use super::types::*;

type EngineResponse<T> = Result<Json<T>, (StatusCode, Json<ErrorResponse>)>;

// ── Health ──────────────────────────────────────────────────────────────────

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("ENGINE_VERSION"),
    })
}

// ── Parse (no DB) ───────────────────────────────────────────────────────────

pub async fn parse(Json(req): Json<AstRequest>) -> EngineResponse<serde_json::Value> {
    let input = serde_json::to_string(&req.ast).unwrap_or_default();
    match crate::parser::parse(&input) {
        Ok(ast) => Ok(Json(serde_json::to_value(&ast).unwrap())),
        Err(e) => Err(engine_error(e)),
    }
}

// ── Introspect (DB) ─────────────────────────────────────────────────────────

pub async fn introspect(Json(req): Json<DbRequest>) -> EngineResponse<serde_json::Value> {
    let pool = connect_db(&req.database_url).await?;
    match crate::introspector::introspect(&pool, &req.schema).await {
        Ok(state) => Ok(Json(serde_json::to_value(&state).unwrap())),
        Err(e) => Err(engine_error(e)),
    }
}

// ── Diff (DB) ───────────────────────────────────────────────────────────────

pub async fn diff(Json(req): Json<DbRequest>) -> EngineResponse<serde_json::Value> {
    let ast_json = require_ast(&req.ast)?;
    let ast = parse_ast(&ast_json)?;
    let pool = connect_db(&req.database_url).await?;
    let db_state = crate::introspector::introspect(&pool, &req.schema)
        .await
        .map_err(engine_error)?;
    let diff = crate::differ::diff(&ast, &db_state).map_err(engine_error)?;
    Ok(Json(serde_json::to_value(&diff).unwrap()))
}

// ── Migrate (DB — generate SQL only, does not apply) ────────────────────────

pub async fn migrate(Json(req): Json<DbRequest>) -> EngineResponse<SqlResponse> {
    let ast_json = require_ast(&req.ast)?;
    let ast = parse_ast(&ast_json)?;
    let pool = connect_db(&req.database_url).await?;
    let db_state = crate::introspector::introspect(&pool, &req.schema)
        .await
        .map_err(engine_error)?;
    let diff = crate::differ::diff(&ast, &db_state).map_err(engine_error)?;
    let sql = crate::generator::sql::migration::generate(&diff, req.force)
        .map_err(engine_error)?;
    Ok(Json(SqlResponse { sql }))
}

// ── Push (DB — diff + apply + record in history) ────────────────────────────

pub async fn push(Json(req): Json<DbRequest>) -> EngineResponse<serde_json::Value> {
    use crate::state::migration_history;

    let ast_json = require_ast(&req.ast)?;
    let ast = parse_ast(&ast_json)?;
    let pool = connect_db(&req.database_url).await?;

    // Ensure migration history schema/table exists
    sqlx::raw_sql(migration_history::create_migrations_table_sql())
        .execute(&pool)
        .await
        .map_err(|e| engine_error(e))?;

    // Load DB state: from cache unless no_cache
    let db_state = if !req.no_cache {
        migration_history::load_schema_state(&pool).await
    } else {
        None
    };
    let db_state = match db_state {
        Some(cached) => {
            info!("Using cached schema state");
            cached
        }
        None => crate::introspector::introspect(&pool, &req.schema)
            .await
            .map_err(engine_error)?,
    };

    let diff = crate::differ::diff(&ast, &db_state).map_err(engine_error)?;

    if diff.operations.is_empty() {
        return Ok(Json(serde_json::json!({
            "status": "up_to_date",
            "operations": 0
        })));
    }

    let migration_sql =
        crate::generator::sql::migration::generate(&diff, req.force)
            .map_err(engine_error)?;
    let apply_sql =
        crate::generator::sql::migration::forward_sql(&diff, req.force)
            .map_err(engine_error)?;

    let migration_name = req.name.unwrap_or_else(|| {
        format!(
            "push_{}",
            chrono::Utc::now().format("%Y%m%d_%H%M%S")
        )
    });

    // Apply forward-only SQL
    sqlx::raw_sql(&apply_sql)
        .execute(&pool)
        .await
        .map_err(|e| engine_error(e))?;

    // Refresh and cache post-migration DB state
    let new_db_state = crate::introspector::introspect(&pool, &req.schema)
        .await
        .map_err(engine_error)?;
    migration_history::save_schema_state(&pool, &new_db_state)
        .await
        .map_err(engine_error)?;

    // Record in history
    let hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(migration_sql.as_bytes());
        format!("sha256:{}", hex::encode(h.finalize()))
    };
    sqlx::query(
        "INSERT INTO _platform.migrations (name, hash, engine_version, schema_snapshot) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&migration_name)
    .bind(&hash)
    .bind(env!("ENGINE_VERSION"))
    .bind(serde_json::to_value(&ast).ok())
    .execute(&pool)
    .await
    .map_err(|e| engine_error(e))?;

    info!(name = %migration_name, ops = diff.operations.len(), "Migration applied");
    Ok(Json(serde_json::json!({
        "status": "applied",
        "name": migration_name,
        "operations": diff.operations.len()
    })))
}

// ── Generate (no DB) ────────────────────────────────────────────────────────

pub async fn generate(Json(req): Json<GenerateRequest>) -> EngineResponse<CodeResponse> {
    let input = serde_json::to_string(&req.ast).unwrap_or_default();
    let ast = parse_ast(&input)?;
    let code = match req.lang.as_str() {
        "typescript" | "ts" => {
            crate::generator::typescript::types::generate(&ast).map_err(engine_error)?
        }
        other => {
            crate::generator::sdk::generate(&ast, other).map_err(engine_error)?
        }
    };
    Ok(Json(CodeResponse { code }))
}

// ── Triggers (no DB) ────────────────────────────────────────────────────────

pub async fn triggers(Json(req): Json<AstRequest>) -> EngineResponse<SqlResponse> {
    let input = serde_json::to_string(&req.ast).unwrap_or_default();
    let ast = parse_ast(&input)?;
    let sql = crate::generator::sql::triggers::generate(&ast).map_err(engine_error)?;
    Ok(Json(SqlResponse { sql }))
}

// ── RLS (no DB) ─────────────────────────────────────────────────────────────

pub async fn rls(Json(req): Json<AstRequest>) -> EngineResponse<SqlResponse> {
    let input = serde_json::to_string(&req.ast).unwrap_or_default();
    let ast = parse_ast(&input)?;
    let helpers = crate::generator::sql::rls::generate_auth_helpers();
    let policies = crate::generator::sql::rls::generate(&ast).map_err(engine_error)?;
    let sql = format!("{helpers}\n{policies}");
    Ok(Json(SqlResponse { sql }))
}

// ── Storage (no DB) ─────────────────────────────────────────────────────────

pub async fn storage(Json(req): Json<AstRequest>) -> EngineResponse<SqlResponse> {
    let input = serde_json::to_string(&req.ast).unwrap_or_default();
    let ast = parse_ast(&input)?;
    let sql = crate::generator::sql::storage::generate(&ast).map_err(engine_error)?;
    Ok(Json(SqlResponse { sql }))
}

// ── PostgREST config (no DB) ────────────────────────────────────────────────

pub async fn postgrest(Json(req): Json<AstRequest>) -> EngineResponse<serde_json::Value> {
    let input = serde_json::to_string(&req.ast).unwrap_or_default();
    let ast = parse_ast(&input)?;
    let config =
        crate::generator::config::postgrest::generate(&ast).map_err(engine_error)?;
    Ok(Json(config))
}

// ── Auth functions (no DB) ──────────────────────────────────────────────────

pub async fn auth_functions(Json(req): Json<AuthFunctionsRequest>) -> Json<SqlResponse> {
    let config = crate::generator::sql::auth_functions::AuthFunctionConfig {
        project_ref: req.project_ref,
        auth_schema: req.auth_schema,
    };
    let sql = crate::generator::sql::auth_functions::generate_auth_functions(&config);
    Json(SqlResponse { sql })
}

// ── SSO (no DB) ─────────────────────────────────────────────────────────────

pub async fn sso(Json(req): Json<AstRequest>) -> EngineResponse<SqlResponse> {
    let input = serde_json::to_string(&req.ast).unwrap_or_default();
    let ast = parse_ast(&input)?;
    let sql = match &ast.sso {
        Some(sso_cfg) => {
            crate::generator::sql::sso::generate(sso_cfg).map_err(engine_error)?
        }
        None => "-- SSO not configured in this schema.".to_string(),
    };
    Ok(Json(SqlResponse { sql }))
}

// ── Admin (no DB) ───────────────────────────────────────────────────────────

pub async fn admin(Json(req): Json<AstRequest>) -> EngineResponse<serde_json::Value> {
    let input = serde_json::to_string(&req.ast).unwrap_or_default();
    let ast = parse_ast(&input)?;
    let config =
        crate::generator::typescript::admin::generate(&ast).map_err(engine_error)?;
    Ok(Json(config))
}

// ── Studio (no DB) ──────────────────────────────────────────────────────────

pub async fn studio(Json(req): Json<AstRequest>) -> EngineResponse<serde_json::Value> {
    let input = serde_json::to_string(&req.ast).unwrap_or_default();
    let ast = parse_ast(&input)?;
    let metadata = crate::generator::studio::generate(&ast).map_err(engine_error)?;
    Ok(Json(metadata))
}

// ── OpenAPI (no DB) ─────────────────────────────────────────────────────────

pub async fn openapi(Json(req): Json<AstRequest>) -> EngineResponse<serde_json::Value> {
    let input = serde_json::to_string(&req.ast).unwrap_or_default();
    let ast = parse_ast(&input)?;
    let spec = crate::generator::openapi::generate(&ast).map_err(engine_error)?;
    Ok(Json(spec))
}

// ── Migrations list (DB) ────────────────────────────────────────────────────

pub async fn migrations(Json(req): Json<DbRequest>) -> EngineResponse<serde_json::Value> {
    let pool = connect_db(&req.database_url).await?;
    let list = crate::state::migration_history::list_migrations(&pool)
        .await
        .map_err(engine_error)?;
    Ok(Json(serde_json::to_value(&list).unwrap()))
}

// ── Validate (DB) ───────────────────────────────────────────────────────────

pub async fn validate(Json(req): Json<ValidateRequest>) -> EngineResponse<serde_json::Value> {
    let diff: crate::differ::DiffOutput =
        serde_json::from_value(req.diff).map_err(|e| engine_error(e))?;
    let pool = connect_db(&req.database_url).await?;
    let report = crate::differ::risk_analyser::validate(&diff, &pool)
        .await
        .map_err(engine_error)?;
    Ok(Json(serde_json::to_value(&report).unwrap()))
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn engine_error(e: impl std::fmt::Display) -> (StatusCode, Json<ErrorResponse>) {
    let msg = e.to_string();
    error!(%msg, "engine error");
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(ErrorResponse { error: msg }),
    )
}

fn require_ast(
    ast: &Option<serde_json::Value>,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    match ast {
        Some(v) => Ok(serde_json::to_string(v).unwrap_or_default()),
        None => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Missing 'ast' field in request body".to_string(),
            }),
        )),
    }
}

fn parse_ast(
    input: &str,
) -> Result<crate::parser::ast::SchemaAst, (StatusCode, Json<ErrorResponse>)> {
    crate::parser::parse(input).map_err(engine_error)
}

async fn connect_db(
    url: &str,
) -> Result<PgPool, (StatusCode, Json<ErrorResponse>)> {
    PgPool::connect(url)
        .await
        .map_err(|e| engine_error(anyhow::anyhow!("Failed to connect to database: {e}")))
}

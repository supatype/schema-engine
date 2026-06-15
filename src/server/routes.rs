use axum::http::StatusCode;
use axum::Json;
use sqlx::{Column, Executor, PgPool, Row, TypeInfo};
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
    let url = resolve_db_request_url(&req)?;
    let pool = connect_db(&url).await?;
    match crate::introspector::introspect(&pool, &req.schema).await {
        Ok(state) => Ok(Json(serde_json::to_value(&state).unwrap())),
        Err(e) => Err(engine_error(e)),
    }
}

// ── Diff (DB) ───────────────────────────────────────────────────────────────

pub async fn diff(Json(req): Json<DbRequest>) -> EngineResponse<serde_json::Value> {
    let ast_json = require_ast(&req.ast)?;
    let ast = parse_ast(&ast_json)?;
    let url = resolve_db_request_url(&req)?;
    let pool = connect_db(&url).await?;
    let db_state = crate::introspector::introspect(&pool, &req.schema)
        .await
        .map_err(engine_error)?;
    let previous_ast = load_previous_schema(&pool).await;
    let diff = crate::differ::diff_with_previous(&ast, &db_state, previous_ast.as_ref())
        .map_err(engine_error)?;
    Ok(Json(serde_json::to_value(&diff).unwrap()))
}

// ── Migrate (DB — generate SQL only, does not apply) ────────────────────────

pub async fn migrate(Json(req): Json<DbRequest>) -> EngineResponse<SqlResponse> {
    let ast_json = require_ast(&req.ast)?;
    let ast = parse_ast(&ast_json)?;
    let url = resolve_db_request_url(&req)?;
    let pool = connect_db(&url).await?;
    let db_state = crate::introspector::introspect(&pool, &req.schema)
        .await
        .map_err(engine_error)?;
    let previous_ast = load_previous_schema(&pool).await;
    let diff = crate::differ::diff_with_previous(&ast, &db_state, previous_ast.as_ref())
        .map_err(engine_error)?;
    let sql = crate::generator::sql::migration::generate(&diff, req.force, &req.schema, &ast)
        .map_err(engine_error)?;
    Ok(Json(SqlResponse { sql }))
}

// ── Push (DB — diff + apply + record in history) ────────────────────────────

pub async fn push(Json(req): Json<DbRequest>) -> EngineResponse<serde_json::Value> {
    use crate::state::{migration_history, studio_state};

    let ast_json = require_ast(&req.ast)?;
    let ast = parse_ast(&ast_json)?;
    let storage_sql = crate::generator::sql::storage::generate(&ast).map_err(engine_error)?;
    let url = resolve_db_request_url(&req)?;
    let pool = connect_db(&url).await?;

    // Ensure _supatype schema and internal tables exist
    sqlx::raw_sql(migration_history::create_internal_schema_sql())
        .execute(&pool)
        .await
        .map_err(engine_error)?;
    sqlx::raw_sql(&migration_history::create_migrations_table_sql())
        .execute(&pool)
        .await
        .map_err(engine_error)?;
    sqlx::raw_sql(&migration_history::create_schema_state_table_sql())
        .execute(&pool)
        .await
        .map_err(engine_error)?;
    sqlx::raw_sql(&migration_history::ensure_migrations_admin_config_column_sql())
        .execute(&pool)
        .await
        .map_err(engine_error)?;
    sqlx::raw_sql(&migration_history::ensure_migrations_sql_up_column_sql())
        .execute(&pool)
        .await
        .map_err(engine_error)?;
    sqlx::raw_sql(&migration_history::ensure_migrations_status_columns_sql())
        .execute(&pool)
        .await
        .map_err(engine_error)?;
    sqlx::raw_sql(&migration_history::ensure_schema_state_studio_columns_sql())
        .execute(&pool)
        .await
        .map_err(engine_error)?;

    // Ensure supatype schema and studio tables exist
    sqlx::raw_sql(studio_state::create_studio_schema_sql())
        .execute(&pool)
        .await
        .map_err(engine_error)?;
    sqlx::raw_sql(studio_state::grant_studio_schema_sql())
        .execute(&pool)
        .await
        .map_err(engine_error)?;
    sqlx::raw_sql(&studio_state::create_dashboard_views_table_sql())
        .execute(&pool)
        .await
        .map_err(engine_error)?;
    sqlx::raw_sql(&studio_state::create_storage_stats_function_sql())
        .execute(&pool)
        .await
        .map_err(engine_error)?;
    sqlx::raw_sql(&studio_state::create_db_stats_function_sql())
        .execute(&pool)
        .await
        .map_err(engine_error)?;
    sqlx::raw_sql(&studio_state::create_daily_signups_function_sql())
        .execute(&pool)
        .await
        .map_err(engine_error)?;
    sqlx::raw_sql(&studio_state::create_daily_content_creates_function_sql())
        .execute(&pool)
        .await
        .map_err(engine_error)?;

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

    let previous_ast = if !req.no_cache {
        load_previous_schema(&pool).await
    } else {
        None
    };
    let diff = crate::differ::diff_with_previous(&ast, &db_state, previous_ast.as_ref())
        .map_err(engine_error)?;

    if diff.operations.is_empty() {
        sqlx::raw_sql(&storage_sql)
            .execute(&pool)
            .await
            .map_err(engine_error)?;
        info!("Schema is up to date — refreshing Studio metadata.");
        let admin_cfg =
            crate::generator::typescript::admin::generate(&ast).map_err(engine_error)?;
        let schema_snap = serde_json::to_value(&ast).map_err(engine_error)?;
        migration_history::refresh_metadata_on_up_to_date_push(&pool, &admin_cfg, &schema_snap)
            .await
            .map_err(engine_error)?;
        return Ok(Json(serde_json::json!({
            "status": "up_to_date",
            "operations": 0,
            "admin_refreshed": true
        })));
    }

    let migration_name = req
        .name
        .clone()
        .unwrap_or_else(|| format!("push_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S")));

    let migration_sql =
        crate::generator::sql::migration::generate(&diff, req.force, &req.schema, &ast)
            .map_err(engine_error)?;
    let hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(migration_sql.as_bytes());
        format!("sha256:{}", hex::encode(h.finalize()))
    };

    let apply_body = crate::generator::sql::migration::push_storage_and_model_apply_body(
        &storage_sql,
        &diff,
        req.force,
        &req.schema,
        &ast,
    )
    .map_err(engine_error)?;
    let apply_batch = crate::generator::sql::migration::push_storage_and_model_batch_sql(
        &storage_sql,
        &diff,
        req.force,
        &req.schema,
        &ast,
    )
    .map_err(engine_error)?;

    let mut tx = pool.begin().await.map_err(engine_error)?;

    if let Err(e) = (&mut *tx).execute(sqlx::raw_sql(apply_body.as_str())).await {
        migration_history::rollback_push_tx(
            tx,
            &pool,
            &migration_name,
            &hash,
            &apply_batch,
            &e.to_string(),
        )
        .await;
        let msg =
            crate::generator::sql::migration_errors::enrich_migration_error(&e.to_string());
        return Err(engine_error(anyhow::anyhow!(msg)));
    }

    let new_db_state = match crate::introspector::introspect_connection(&mut tx, &req.schema).await
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
            return Err(engine_error(e));
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
        return Err(engine_error(e));
    }

    let admin_cfg = crate::generator::typescript::admin::generate(&ast).ok();
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
        return Err(engine_error(e));
    }

    tx.commit().await.map_err(engine_error)?;

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
        other => crate::generator::sdk::generate(&ast, other).map_err(engine_error)?,
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
    let config = crate::generator::config::postgrest::generate(&ast).map_err(engine_error)?;
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
        Some(sso_cfg) => crate::generator::sql::sso::generate(sso_cfg).map_err(engine_error)?,
        None => "-- SSO not configured in this schema.".to_string(),
    };
    Ok(Json(SqlResponse { sql }))
}

// ── Admin (no DB) ───────────────────────────────────────────────────────────

pub async fn admin(Json(req): Json<AstRequest>) -> EngineResponse<serde_json::Value> {
    let input = serde_json::to_string(&req.ast).unwrap_or_default();
    let ast = parse_ast(&input)?;
    let config = crate::generator::typescript::admin::generate(&ast).map_err(engine_error)?;
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
    let url = resolve_db_request_url(&req)?;
    let pool = connect_db(&url).await?;
    let list = crate::state::migration_history::list_migrations(&pool)
        .await
        .map_err(engine_error)?;
    Ok(Json(serde_json::to_value(&list).unwrap()))
}

// ── Studio config (DB) — latest persisted AdminConfig ─────────────────────

/// Returns the AdminConfig JSON stored at last successful `push`.
/// Single-tenant: resolve `DATABASE_URL` from the engine environment (or optional body for CLI).
pub async fn studio_config(
    Json(req): Json<StudioConfigRequest>,
) -> EngineResponse<serde_json::Value> {
    let url = resolve_database_url(req.database_url)?;
    let pool = connect_db(&url).await?;

    match crate::state::migration_history::load_latest_admin_config(&pool).await {
        Some(config) => Ok(Json(config)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "No schema pushed yet. Run: supatype push".to_string(),
            }),
        )),
    }
}

// ── SQL execution (DB) — dev / self-host Studio only ────────────────────────
//
// Multi-tenant deployments should route SQL through the cloud control plane (org-scoped proxy with
// SET LOCAL ROLE), not this endpoint. Here, `DATABASE_URL` is the single project database.

pub async fn execute_sql(Json(req): Json<SqlExecRequest>) -> EngineResponse<SqlExecResponse> {
    let url = resolve_database_url(req.database_url)?;
    let pool = connect_db(&url).await?;
    let rows = sqlx::query(&req.query)
        .fetch_all(&pool)
        .await
        .map_err(engine_error)?;
    let json_rows: Vec<serde_json::Value> = rows.iter().map(pg_row_to_json).collect();
    let row_count = json_rows.len() as i64;
    Ok(Json(SqlExecResponse {
        rows: json_rows,
        row_count,
    }))
}

// ── Validate (DB) ───────────────────────────────────────────────────────────

pub async fn validate(Json(req): Json<ValidateRequest>) -> EngineResponse<serde_json::Value> {
    let diff: crate::differ::DiffOutput = serde_json::from_value(req.diff).map_err(engine_error)?;
    let url = resolve_database_url(req.database_url)?;
    let pool = connect_db(&url).await?;
    let report = crate::differ::risk_analyser::validate(&diff, &pool)
        .await
        .map_err(engine_error)?;
    Ok(Json(serde_json::to_value(&report).unwrap()))
}

// ── Helpers ─────────────────────────────────────────────────────────────────

async fn load_previous_schema(pool: &PgPool) -> Option<crate::parser::ast::SchemaAst> {
    use crate::state::migration_history;
    migration_history::load_latest_schema_snapshot(pool)
        .await
        .and_then(|v| serde_json::from_value(v).ok())
}

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

async fn connect_db(url: &str) -> Result<PgPool, (StatusCode, Json<ErrorResponse>)> {
    PgPool::connect(url)
        .await
        .map_err(|e| engine_error(anyhow::anyhow!("Failed to connect to database: {e}")))
}

fn resolve_db_request_url(
    req: &DbRequest,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    resolve_database_url(req.database_url.clone())
}

fn resolve_database_url(
    explicit: Option<String>,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let env_url = std::env::var("DATABASE_URL")
        .ok()
        .filter(|s| !s.is_empty());

    if let Some(env) = env_url {
        if let Some(body) = explicit {
            if !body.is_empty() && body != env {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "database_url in request body is not allowed when DATABASE_URL is configured on the engine"
                            .to_string(),
                    }),
                ));
            }
        }
        return Ok(env);
    }

    explicit.filter(|s| !s.is_empty()).ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "DATABASE_URL is not set on the schema engine. Configure it for the engine service (or pass database_url from a trusted proxy)."
                    .to_string(),
            }),
        )
    })
}

fn pg_row_to_json(row: &sqlx::postgres::PgRow) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for i in 0..row.len() {
        let col = row.column(i);
        let key = col.name().to_string();
        map.insert(key, pg_cell_to_json(row, i));
    }
    serde_json::Value::Object(map)
}

fn pg_cell_to_json(row: &sqlx::postgres::PgRow, i: usize) -> serde_json::Value {
    use serde_json::json;
    if let Ok(v) = row.try_get::<Option<serde_json::Value>, _>(i) {
        return v.unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<bool>, _>(i) {
        return v
            .map(serde_json::Value::Bool)
            .unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<i16>, _>(i) {
        return v.map(|n| json!(n)).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<i32>, _>(i) {
        return v.map(|n| json!(n)).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<i64>, _>(i) {
        return v
            .map(|n| serde_json::Value::Number(n.into()))
            .unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<f32>, _>(i) {
        return v
            .and_then(|f| serde_json::Number::from_f64(f as f64).map(serde_json::Value::Number))
            .unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<f64>, _>(i) {
        return v
            .and_then(|f| serde_json::Number::from_f64(f).map(serde_json::Value::Number))
            .unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<String>, _>(i) {
        return v
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<Vec<u8>>, _>(i) {
        return v
            .map(|b| serde_json::Value::String(hex::encode(b)))
            .unwrap_or(serde_json::Value::Null);
    }
    serde_json::Value::String(format!(
        "<unserializable:{}>",
        row.column(i).type_info().name()
    ))
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use axum::Json;

    use super::ErrorResponse;

    fn sanitize_schema_identifier(
        schema: &str,
    ) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
        if schema.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Schema must not be empty".to_string(),
                }),
            ));
        }

        let mut chars = schema.chars();
        let first = chars.next().unwrap_or('_');
        let valid_start = first.is_ascii_alphabetic() || first == '_';
        let valid_rest = chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid_start || !valid_rest {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid schema identifier".to_string(),
                }),
            ));
        }

        Ok(format!("\"{}\"", schema))
    }

    #[test]
    fn accepts_valid_schema_identifier() {
        let result = sanitize_schema_identifier("public_schema1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap_or_default(), "\"public_schema1\"");
    }

    #[test]
    fn rejects_invalid_schema_identifier() {
        assert!(sanitize_schema_identifier("").is_err());
        assert!(sanitize_schema_identifier("public;DROP").is_err());
        assert!(sanitize_schema_identifier("1public").is_err());
        assert!(sanitize_schema_identifier("public-schema").is_err());
    }
}

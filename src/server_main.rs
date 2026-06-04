use supatype_engine::server;

use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::{from_fn, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tracing::info;

async fn require_admin_token(req: Request, next: Next) -> Response {
    let expected = match std::env::var("ENGINE_ADMIN_TOKEN") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "ENGINE_ADMIN_TOKEN is not configured for protected endpoints",
            )
                .into_response()
        }
    };

    if has_valid_admin_token(req.headers(), &expected) {
        return next.run(req).await;
    }

    (
        StatusCode::UNAUTHORIZED,
        "Missing or invalid X-Engine-Admin-Token",
    )
        .into_response()
}

fn has_valid_admin_token(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get("X-Engine-Admin-Token")
        .and_then(|v| v.to_str().ok())
        .map(|provided| provided == expected)
        .unwrap_or(false)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let port: u16 = std::env::var("ENGINE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7500);

    let app = Router::new()
        // Health
        .route("/health", get(server::routes::health))
        // Compute-only (no DB)
        .route("/parse", post(server::routes::parse))
        .route("/generate", post(server::routes::generate))
        .route("/triggers", post(server::routes::triggers))
        .route("/rls", post(server::routes::rls))
        .route("/storage", post(server::routes::storage))
        .route("/postgrest", post(server::routes::postgrest))
        .route("/auth-functions", post(server::routes::auth_functions))
        .route("/sso", post(server::routes::sso))
        .route("/admin", post(server::routes::admin))
        .route("/studio", post(server::routes::studio))
        .route("/openapi", post(server::routes::openapi))
        // DB-dependent
        .route("/introspect", post(server::routes::introspect))
        .route("/diff", post(server::routes::diff))
        .route("/migrate", post(server::routes::migrate))
        .route("/push", post(server::routes::push))
        .route("/migrations", post(server::routes::migrations))
        .route("/validate", post(server::routes::validate))
        .route("/studio-config", post(server::routes::studio_config))
        .route("/sql", post(server::routes::execute_sql))
        .route_layer(from_fn(require_admin_token));

    let bind_host = std::env::var("ENGINE_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
    let bind_ip: std::net::IpAddr = bind_host.parse().unwrap_or(std::net::IpAddr::V4(
        std::net::Ipv4Addr::new(127, 0, 0, 1),
    ));
    let addr = SocketAddr::from((bind_ip, port));
    info!(%addr, version = env!("ENGINE_VERSION"), "Schema engine server starting");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::has_valid_admin_token;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn validates_expected_engine_admin_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Engine-Admin-Token",
            HeaderValue::from_static("expected-token"),
        );
        assert!(has_valid_admin_token(&headers, "expected-token"));
    }

    #[test]
    fn rejects_missing_or_mismatched_engine_admin_token() {
        let headers = HeaderMap::new();
        assert!(!has_valid_admin_token(&headers, "expected-token"));

        let mut wrong_headers = HeaderMap::new();
        wrong_headers.insert(
            "X-Engine-Admin-Token",
            HeaderValue::from_static("wrong-token"),
        );
        assert!(!has_valid_admin_token(&wrong_headers, "expected-token"));
    }
}

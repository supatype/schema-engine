use supatype_engine::server;

use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
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
        .route("/validate", post(server::routes::validate));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!(%addr, version = env!("ENGINE_VERSION"), "Schema engine server starting");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

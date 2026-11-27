use axum::{routing::get, Json, Router};
use serde::Serialize;
use std::{env, net::SocketAddr};
use tracing_subscriber::EnvFilter;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

async fn live() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "tomos-pos-api",
    })
}

async fn ready() -> Json<HealthResponse> {
    // Database connectivity will be added with the SQLx persistence milestone.
    Json(HealthResponse {
        status: "starting",
        service: "tomos-pos-api",
    })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let app = Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready));

    let host = env::var("API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("API_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(8080);
    let address: SocketAddr = format!("{host}:{port}")
        .parse()
        .expect("API_HOST and API_PORT must form a valid socket address");

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("failed to bind API listener");

    tracing::info!(%address, "TomOS POS API listening");
    axum::serve(listener, app)
        .await
        .expect("API server failed");
}

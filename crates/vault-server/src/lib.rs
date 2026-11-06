pub mod api;
pub mod config;
pub mod db;
pub mod error;

use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use sqlx::SqlitePool;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use config::Config;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<Config>,
}

pub fn build_router(state: AppState) -> Router {
    let max = state.config.max_body_bytes;
    Router::new()
        .route("/healthz", get(api::health::health))
        .layer(RequestBodyLimitLayer::new(max))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

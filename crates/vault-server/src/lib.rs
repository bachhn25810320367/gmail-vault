pub mod api;
pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod rate_limit;

use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use sqlx::SqlitePool;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use auth::AuthService;
use config::Config;
use rate_limit::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<Config>,
    pub auth: AuthService,
    pub rate: Arc<RateLimiter>,
}

impl AppState {
    pub fn new(pool: SqlitePool, config: Arc<Config>) -> Self {
        let auth = AuthService::new(pool.clone(), config.jwt_secret.clone());
        Self {
            pool,
            config,
            auth,
            rate: Arc::new(RateLimiter::default()),
        }
    }
}

pub fn build_router(state: AppState) -> Router {
    let max = state.config.max_body_bytes;
    Router::new()
        .route("/healthz", get(api::health::health))
        .nest("/v1", api::auth::routes())
        .layer(RequestBodyLimitLayer::new(max))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

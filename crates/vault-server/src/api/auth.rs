use std::net::SocketAddr;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::routing::post;

use crate::AppState;
use crate::api::dto::{
    AuthResponse, LoginRequest, RecoverLoginRequest, RefreshRequest, RegisterRequest,
};
use crate::error::AppError;

const LOGIN_LIMIT: usize = 5;
const LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);
const REGISTER_LIMIT: usize = 3;
const REGISTER_WINDOW: Duration = Duration::from_secs(60 * 60);

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/recover/login", post(recover_login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
}

struct ClientIp(String);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        Ok(ClientIp(ip))
    }
}

async fn register(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), AppError> {
    if !state
        .rate
        .check(&format!("register|{ip}"), REGISTER_LIMIT, REGISTER_WINDOW)
    {
        return Err(AppError::RateLimited);
    }
    let response = state
        .auth
        .register(req, state.config.allow_registration)
        .await?;
    Ok((StatusCode::CREATED, Json(response)))
}

async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let key = format!("login|{}|{ip}", req.email.trim().to_lowercase());
    if !state.rate.check(&key, LOGIN_LIMIT, LOGIN_WINDOW) {
        return Err(AppError::RateLimited);
    }
    Ok(Json(state.auth.login(req).await?))
}

async fn recover_login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<RecoverLoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let key = format!("recover|{}|{ip}", req.email.trim().to_lowercase());
    if !state.rate.check(&key, LOGIN_LIMIT, LOGIN_WINDOW) {
        return Err(AppError::RateLimited);
    }
    Ok(Json(state.auth.recover_login(req).await?))
}

async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    Ok(Json(state.auth.refresh(req.refresh_token).await?))
}

async fn logout(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<StatusCode, AppError> {
    state.auth.logout(req.refresh_token).await?;
    Ok(StatusCode::NO_CONTENT)
}

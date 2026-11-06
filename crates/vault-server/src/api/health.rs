use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};

use crate::{AppState, error::AppError};

pub async fn health(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    sqlx::query("SELECT 1")
        .execute(&state.pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(json!({"status": "ok"})))
}

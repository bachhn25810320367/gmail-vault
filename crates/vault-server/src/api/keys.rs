use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::api::dto::{KdfDto, WrappedKeyDto};
use crate::auth::{AuthUser, hash_secret};
use crate::error::AppError;

pub fn routes() -> Router<AppState> {
    Router::new().route("/keys", get(get_keys).put(put_keys))
}

#[derive(Deserialize)]
pub struct PutKeysRequest {
    pub kdf: KdfDto,
    pub wrapped_key: WrappedKeyDto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_wrapped_key: Option<WrappedKeyDto>,
    #[serde(
        default,
        with = "crate::api::dto::b64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub recovery_auth_key: Option<Vec<u8>>,
}

#[derive(Serialize)]
pub struct KeysResponse {
    pub kdf: KdfDto,
    pub wrapped_key: WrappedKeyDto,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_wrapped_key: Option<WrappedKeyDto>,
}

fn internal(e: impl std::fmt::Display) -> AppError {
    AppError::Internal(e.to_string())
}

async fn get_keys(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<KeysResponse>, AppError> {
    let row: Option<(String, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT kdf_params, wrapped_vault_key, wrapped_key_nonce,
                recovery_wrapped_key, recovery_nonce
         FROM users WHERE id = ?",
    )
    .bind(user.user_id.to_string())
    .fetch_optional(&state.pool)
    .await
    .map_err(internal)?;
    let Some((kdf_params, ciphertext, nonce, recovery_ciphertext, recovery_nonce)) = row else {
        return Err(AppError::Unauthorized);
    };
    let kdf: KdfDto = serde_json::from_str(&kdf_params).map_err(internal)?;
    let recovery_wrapped_key = match (recovery_ciphertext, recovery_nonce) {
        (Some(ciphertext), Some(nonce)) => Some(WrappedKeyDto { nonce, ciphertext }),
        _ => None,
    };
    Ok(Json(KeysResponse {
        kdf,
        wrapped_key: WrappedKeyDto { nonce, ciphertext },
        recovery_wrapped_key,
    }))
}

async fn put_keys(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<PutKeysRequest>,
) -> Result<StatusCode, AppError> {
    if req.kdf.salt.len() != 16 {
        return Err(AppError::BadRequest("kdf salt không hợp lệ".into()));
    }
    if req.wrapped_key.nonce.len() != 24 || req.wrapped_key.ciphertext.len() != 48 {
        return Err(AppError::BadRequest("wrapped_key không hợp lệ".into()));
    }
    match (&req.recovery_wrapped_key, &req.recovery_auth_key) {
        (Some(wrapped), Some(auth_key)) => {
            if wrapped.nonce.len() != 24 || wrapped.ciphertext.len() != 48 || auth_key.len() != 32 {
                return Err(AppError::BadRequest("recovery key không hợp lệ".into()));
            }
        }
        (None, None) => {}
        _ => {
            return Err(AppError::BadRequest(
                "recovery_wrapped_key và recovery_auth_key phải đi cùng nhau".into(),
            ));
        }
    }

    let user_id = user.user_id.to_string();
    let current: Option<(String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT kdf_params, wrapped_vault_key, wrapped_key_nonce FROM users WHERE id = ?",
    )
    .bind(&user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(internal)?;
    let Some((old_kdf, old_ciphertext, old_nonce)) = current else {
        return Err(AppError::Unauthorized);
    };
    let kdf_params = serde_json::to_string(&req.kdf).map_err(internal)?;
    let rotated = kdf_params != old_kdf
        || old_ciphertext != req.wrapped_key.ciphertext
        || old_nonce != req.wrapped_key.nonce;

    match (&req.recovery_wrapped_key, req.recovery_auth_key.as_deref()) {
        (Some(wrapped), Some(auth_key)) => {
            let recovery_hash = hash_secret(auth_key)?;
            sqlx::query(
                "UPDATE users SET kdf_salt = ?, kdf_params = ?, wrapped_vault_key = ?,
                        wrapped_key_nonce = ?, recovery_wrapped_key = ?, recovery_nonce = ?,
                        recovery_auth_hash = ?
                 WHERE id = ?",
            )
            .bind(&req.kdf.salt)
            .bind(&kdf_params)
            .bind(&req.wrapped_key.ciphertext)
            .bind(&req.wrapped_key.nonce)
            .bind(&wrapped.ciphertext)
            .bind(&wrapped.nonce)
            .bind(&recovery_hash)
            .bind(&user_id)
            .execute(&state.pool)
            .await
            .map_err(internal)?;
        }
        _ => {
            sqlx::query(
                "UPDATE users SET kdf_salt = ?, kdf_params = ?, wrapped_vault_key = ?,
                        wrapped_key_nonce = ?
                 WHERE id = ?",
            )
            .bind(&req.kdf.salt)
            .bind(&kdf_params)
            .bind(&req.wrapped_key.ciphertext)
            .bind(&req.wrapped_key.nonce)
            .bind(&user_id)
            .execute(&state.pool)
            .await
            .map_err(internal)?;
        }
    }

    if rotated {
        sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?")
            .bind(&user_id)
            .execute(&state.pool)
            .await
            .map_err(internal)?;
    }

    Ok(StatusCode::NO_CONTENT)
}

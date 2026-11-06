use std::sync::Arc;

use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng as PwOsRng,
};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{
    Algorithm as JwtAlgorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode,
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::AppState;
use crate::api::dto::{
    AuthResponse, KdfDto, LoginRequest, RecoverLoginRequest, RegisterRequest, WrappedKeyDto,
};
use crate::error::AppError;

pub const ACCESS_TTL_SECS: usize = 900;
const REFRESH_TTL_MS: i64 = 30 * 24 * 3600 * 1000;
const SERVER_ARGON2_M_KIB: u32 = 19_456;
const SERVER_ARGON2_T: u32 = 2;
const SERVER_ARGON2_P: u32 = 1;

#[derive(Clone)]
pub struct AuthService {
    pool: SqlitePool,
    jwt_secret: Arc<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
}

pub struct AuthUser {
    pub user_id: Uuid,
}

type LoginRow = (String, String, String, Vec<u8>, Vec<u8>);
type RecoverRow = (String, String, String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
type UserKeysRow = (String, Vec<u8>, Vec<u8>);

fn internal(e: impl std::fmt::Display) -> AppError {
    AppError::Internal(e.to_string())
}

fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

fn server_argon2() -> Result<Argon2<'static>, AppError> {
    let params = Params::new(
        SERVER_ARGON2_M_KIB,
        SERVER_ARGON2_T,
        SERVER_ARGON2_P,
        Some(32),
    )
    .map_err(internal)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

pub(crate) fn hash_secret(secret: &[u8]) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut PwOsRng);
    server_argon2()?
        .hash_password(secret, &salt)
        .map(|hash| hash.to_string())
        .map_err(internal)
}

pub fn verify_secret(stored: &str, secret: &[u8]) -> Result<bool, AppError> {
    let parsed = PasswordHash::new(stored).map_err(internal)?;
    Ok(server_argon2()?.verify_password(secret, &parsed).is_ok())
}

fn random_refresh() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

impl AuthService {
    pub fn new(pool: SqlitePool, jwt_secret: Arc<Vec<u8>>) -> Self {
        Self { pool, jwt_secret }
    }

    async fn store_refresh(&self, user_id: Uuid, token: &str) -> Result<(), AppError> {
        let now = now_ms();
        sqlx::query(
            "INSERT INTO refresh_tokens(id, user_id, token_hash, created_at, expires_at, revoked)
             VALUES(?, ?, ?, ?, ?, 0)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(user_id.to_string())
        .bind(token_hash(token))
        .bind(now)
        .bind(now + REFRESH_TTL_MS)
        .execute(&self.pool)
        .await
        .map_err(internal)?;
        Ok(())
    }

    fn access_token(&self, user_id: Uuid) -> Result<String, AppError> {
        let now = Utc::now().timestamp() as usize;
        let claims = Claims {
            sub: user_id.to_string(),
            exp: now + ACCESS_TTL_SECS,
            iat: now,
        };
        encode(
            &Header::new(JwtAlgorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_slice()),
        )
        .map_err(internal)
    }

    async fn issue(
        &self,
        user_id: Uuid,
        kdf: KdfDto,
        wrapped_key: WrappedKeyDto,
        recovery_wrapped_key: Option<WrappedKeyDto>,
    ) -> Result<AuthResponse, AppError> {
        let access_token = self.access_token(user_id)?;
        let refresh_token = random_refresh();
        self.store_refresh(user_id, &refresh_token).await?;
        Ok(AuthResponse {
            user_id,
            access_token,
            refresh_token,
            expires_in: ACCESS_TTL_SECS,
            kdf,
            wrapped_key,
            recovery_wrapped_key,
        })
    }

    pub async fn register(
        &self,
        req: RegisterRequest,
        allow_registration: bool,
    ) -> Result<AuthResponse, AppError> {
        if req.auth_key.len() != 32 || req.recovery_auth_key.len() != 32 {
            return Err(AppError::BadRequest("auth_key không hợp lệ".into()));
        }
        if req.wrapped_key.nonce.len() != 24 || req.wrapped_key.ciphertext.len() != 48 {
            return Err(AppError::BadRequest("wrapped_key không hợp lệ".into()));
        }
        if req.recovery_wrapped_key.nonce.len() != 24
            || req.recovery_wrapped_key.ciphertext.len() != 48
        {
            return Err(AppError::BadRequest(
                "recovery_wrapped_key không hợp lệ".into(),
            ));
        }
        if req.kdf.salt.len() != 16 {
            return Err(AppError::BadRequest("kdf salt không hợp lệ".into()));
        }
        let email = req.email.trim().to_lowercase();
        if email.is_empty() || !email.contains('@') {
            return Err(AppError::BadRequest("email không hợp lệ".into()));
        }
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await
            .map_err(internal)?;
        if count > 0 && !allow_registration {
            return Err(AppError::Forbidden);
        }
        let auth_hash = hash_secret(&req.auth_key)?;
        let recovery_auth_hash = hash_secret(&req.recovery_auth_key)?;
        let kdf_params = serde_json::to_string(&req.kdf).map_err(internal)?;
        let inserted = sqlx::query(
            "INSERT INTO users(id, email, auth_hash, kdf_salt, kdf_params, wrapped_vault_key,
                                wrapped_key_nonce, recovery_wrapped_key, recovery_nonce,
                                recovery_auth_hash, created_at)
             VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(req.user_id.to_string())
        .bind(&email)
        .bind(&auth_hash)
        .bind(&req.kdf.salt)
        .bind(&kdf_params)
        .bind(&req.wrapped_key.ciphertext)
        .bind(&req.wrapped_key.nonce)
        .bind(&req.recovery_wrapped_key.ciphertext)
        .bind(&req.recovery_wrapped_key.nonce)
        .bind(&recovery_auth_hash)
        .bind(now_ms())
        .execute(&self.pool)
        .await;
        match inserted {
            Ok(_) => {}
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                return Err(AppError::Conflict);
            }
            Err(e) => return Err(internal(e)),
        }
        self.issue(req.user_id, req.kdf, req.wrapped_key, None)
            .await
    }

    pub async fn login(&self, req: LoginRequest) -> Result<AuthResponse, AppError> {
        let email = req.email.trim().to_lowercase();
        let row: Option<LoginRow> = sqlx::query_as(
            "SELECT id, auth_hash, kdf_params, wrapped_vault_key, wrapped_key_nonce
             FROM users WHERE email = ?",
        )
        .bind(&email)
        .fetch_optional(&self.pool)
        .await
        .map_err(internal)?;
        let Some((id, auth_hash, kdf_params, wrapped_key, nonce)) = row else {
            return Err(AppError::Unauthorized);
        };
        if !verify_secret(&auth_hash, &req.auth_key)? {
            return Err(AppError::Unauthorized);
        }
        let kdf: KdfDto = serde_json::from_str(&kdf_params).map_err(internal)?;
        let user_id = Uuid::parse_str(&id).map_err(internal)?;
        self.issue(
            user_id,
            kdf,
            WrappedKeyDto {
                nonce,
                ciphertext: wrapped_key,
            },
            None,
        )
        .await
    }

    pub async fn recover_login(&self, req: RecoverLoginRequest) -> Result<AuthResponse, AppError> {
        let email = req.email.trim().to_lowercase();
        let row: Option<RecoverRow> = sqlx::query_as(
            "SELECT id, recovery_auth_hash, kdf_params, wrapped_vault_key, wrapped_key_nonce,
                    recovery_wrapped_key, recovery_nonce
             FROM users WHERE email = ? AND recovery_auth_hash IS NOT NULL",
        )
        .bind(&email)
        .fetch_optional(&self.pool)
        .await
        .map_err(internal)?;
        let Some((
            id,
            recovery_auth_hash,
            kdf_params,
            wrapped_key,
            nonce,
            recovery_key,
            recovery_nonce,
        )) = row
        else {
            return Err(AppError::Unauthorized);
        };
        if !verify_secret(&recovery_auth_hash, &req.recovery_auth_key)? {
            return Err(AppError::Unauthorized);
        }
        let kdf: KdfDto = serde_json::from_str(&kdf_params).map_err(internal)?;
        let user_id = Uuid::parse_str(&id).map_err(internal)?;
        self.issue(
            user_id,
            kdf,
            WrappedKeyDto {
                nonce,
                ciphertext: wrapped_key,
            },
            Some(WrappedKeyDto {
                nonce: recovery_nonce,
                ciphertext: recovery_key,
            }),
        )
        .await
    }

    async fn keys_for(&self, user_id: Uuid) -> Result<(KdfDto, WrappedKeyDto), AppError> {
        let row: UserKeysRow = sqlx::query_as(
            "SELECT kdf_params, wrapped_vault_key, wrapped_key_nonce FROM users WHERE id = ?",
        )
        .bind(user_id.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(|_| AppError::Unauthorized)?;
        let (kdf_params, wrapped_key, nonce) = row;
        let kdf: KdfDto = serde_json::from_str(&kdf_params).map_err(internal)?;
        Ok((
            kdf,
            WrappedKeyDto {
                nonce,
                ciphertext: wrapped_key,
            },
        ))
    }

    pub async fn refresh(&self, token: String) -> Result<AuthResponse, AppError> {
        let hash = token_hash(&token);
        let row: Option<(String, i64)> = sqlx::query_as(
            "SELECT user_id, expires_at FROM refresh_tokens WHERE token_hash = ? AND revoked = 0",
        )
        .bind(&hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(internal)?;
        let Some((user_id, expires_at)) = row else {
            return Err(AppError::Unauthorized);
        };
        if expires_at < now_ms() {
            return Err(AppError::Unauthorized);
        }
        sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?")
            .bind(&hash)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        let user_id = Uuid::parse_str(&user_id).map_err(|_| AppError::Unauthorized)?;
        let (kdf, wrapped_key) = self.keys_for(user_id).await?;
        self.issue(user_id, kdf, wrapped_key, None).await
    }

    pub async fn logout(&self, token: String) -> Result<(), AppError> {
        sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?")
            .bind(token_hash(&token))
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        Ok(())
    }

    pub async fn verify_access(&self, token: &str) -> Result<Uuid, AppError> {
        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_slice()),
            &Validation::new(JwtAlgorithm::HS256),
        )
        .map_err(|_| AppError::Unauthorized)?;
        Uuid::parse_str(&data.claims.sub).map_err(|_| AppError::Unauthorized)
    }
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(AppError::Unauthorized)?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or(AppError::Unauthorized)?;
        let user_id = state.auth.verify_access(token).await?;
        Ok(AuthUser { user_id })
    }
}

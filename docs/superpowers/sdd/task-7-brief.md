## Task 7: Server auth, recovery login, and rate limiting

**Files:**
- Create: `crates/vault-server/src/auth.rs`
- Create: `crates/vault-server/src/rate_limit.rs`
- Create: `crates/vault-server/src/api/dto.rs`
- Create: `crates/vault-server/src/api/auth.rs`
- Modify: `crates/vault-server/src/lib.rs`
- Modify: `crates/vault-server/src/api/mod.rs`
- Create: `crates/vault-server/tests/common/mod.rs`
- Create: `crates/vault-server/tests/auth.rs`

**Interfaces:**
- Consumes: `AppState`, `Config`, `AppError`, `SqlitePool`.
- Produces:
  - `AuthService::{register, login, recover_login, refresh, logout, verify_access}`.
  - `AuthUser` extractor.
  - `RateLimiter::check(key, limit, window) -> bool`.
  - DTOs `RegisterRequest`, `LoginRequest`, `RecoverLoginRequest`, `RefreshRequest`, `AuthResponse`, `KdfDto`, `WrappedKeyDto`.

- [ ] **Step 1: Write the failing auth integration tests**

`tests/common/mod.rs`:

```rust
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::SqlitePool;
use tower::ServiceExt;
use uuid::Uuid;
use vault_server::{build_router, config::Config, db, AppState};

pub struct TestApp {
    pub router: Router,
    pub pool: SqlitePool,
    pub config: Arc<Config>,
}

pub async fn spawn() -> TestApp {
    let pool = db::connect("sqlite::memory:").await.unwrap();
    db::migrate(&pool).await.unwrap();
    let config = Arc::new(Config::from_map(|k| match k {
        "DATABASE_URL" => Some("sqlite::memory:".into()),
        "JWT_SECRET" => Some("0123456789abcdef0123456789abcdef".into()),
        _ => None,
    }).unwrap());
    TestApp { router: build_router(AppState::new(pool.clone(), config.clone())), pool, config }
}

pub fn b64(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(bytes)
}

pub fn register_body(email: &str) -> Value {
    json!({
        "user_id": Uuid::new_v4(),
        "email": email,
        "auth_key": b64(&[7u8; 32]),
        "kdf": {"algo": "argon2id", "salt": b64(&[1u8; 16]), "m_kib": 65536, "t": 3, "p": 2},
        "wrapped_key": {"nonce": b64(&[2u8; 24]), "ciphertext": b64(&[3u8; 48])},
        "recovery_wrapped_key": {"nonce": b64(&[4u8; 24]), "ciphertext": b64(&[5u8; 48])},
        "recovery_auth_key": b64(&[6u8; 32])
    })
}

pub async fn request(app: &TestApp, method: &str, uri: &str, token: Option<&str>, body: Option<Value>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token { builder = builder.header("authorization", format!("Bearer {t}")); }
    let body = match body {
        Some(v) => {
            builder = builder.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let res = app.router.clone().oneshot(builder.body(body).unwrap()).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

pub async fn register(app: &TestApp, email: &str) -> (StatusCode, Value) {
    request(app, "POST", "/v1/auth/register", None, Some(register_body(email))).await
}

pub async fn login(app: &TestApp, email: &str) -> (StatusCode, Value) {
    request(app, "POST", "/v1/auth/login", None, Some(json!({"email": email, "auth_key": b64(&[7u8; 32])}))).await
}
```

`tests/auth.rs`:

```rust
mod common;

use common::*;
use serde_json::json;

#[tokio::test]
async fn first_user_registers_second_is_forbidden() {
    let app = spawn().await;
    let (status, body) = register(&app, "owner@example.com").await;
    assert_eq!(status, 201);
    assert!(body["access_token"].is_string());
    let (status, _) = register(&app, "second@example.com").await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn login_and_refresh_rotate() {
    let app = spawn().await;
    register(&app, "owner@example.com").await;
    let (status, body) = login(&app, "owner@example.com").await;
    assert_eq!(status, 200);
    let refresh = body["refresh_token"].as_str().unwrap().to_string();
    let (status, _) = request(&app, "POST", "/v1/auth/refresh", None, Some(json!({"refresh_token": refresh}))).await;
    assert_eq!(status, 200);
    let (status, _) = request(&app, "POST", "/v1/auth/refresh", None, Some(json!({"refresh_token": refresh}))).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn wrong_password_is_401_and_sixth_attempt_is_429() {
    let app = spawn().await;
    register(&app, "owner@example.com").await;
    for _ in 0..5 {
        let (status, _) = request(&app, "POST", "/v1/auth/login", None, Some(json!({
            "email": "owner@example.com", "auth_key": b64(&[9u8; 32])
        }))).await;
        assert_eq!(status, 401);
    }
    let (status, _) = request(&app, "POST", "/v1/auth/login", None, Some(json!({
        "email": "owner@example.com", "auth_key": b64(&[9u8; 32])
    }))).await;
    assert_eq!(status, 429);
}

#[tokio::test]
async fn recovery_login_works_and_logout_revokes() {
    let app = spawn().await;
    register(&app, "owner@example.com").await;
    let (status, body) = request(&app, "POST", "/v1/auth/recover/login", None, Some(json!({
        "email": "owner@example.com", "recovery_auth_key": b64(&[6u8; 32])
    }))).await;
    assert_eq!(status, 200);
    let refresh = body["refresh_token"].as_str().unwrap().to_string();
    let (status, _) = request(&app, "POST", "/v1/auth/logout", None, Some(json!({"refresh_token": refresh.clone()}))).await;
    assert_eq!(status, 204);
    let (status, _) = request(&app, "POST", "/v1/auth/refresh", None, Some(json!({"refresh_token": refresh}))).await;
    assert_eq!(status, 401);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p vault-server --test auth`
Expected: 404 responses or compile error for missing routes/modules.

- [ ] **Step 3: Implement rate limiter and auth service**

`rate_limit.rs`:

```rust
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct RateLimiter { inner: Mutex<HashMap<String, Vec<Instant>>> }

impl RateLimiter {
    pub fn check(&self, key: &str, limit: usize, window: Duration) -> bool {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap();
        let entries = map.entry(key.to_string()).or_default();
        entries.retain(|t| now.duration_since(*t) < window);
        if entries.len() >= limit { return false; }
        entries.push(now);
        true
    }
}
```

`api/dto.rs`:

```rust
use serde::{Deserialize, Serialize};

pub mod b64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

pub mod b64_opt {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => s.serialize_some(&STANDARD.encode(bytes)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let value: Option<String> = Option::deserialize(d)?;
        value.map(|s| STANDARD.decode(&s).map_err(serde::de::Error::custom)).transpose()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfDto {
    pub algo: String,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKeyDto {
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub user_id: Uuid,
    pub email: String,
    #[serde(with = "b64")]
    pub auth_key: Vec<u8>,
    pub kdf: KdfDto,
    pub wrapped_key: WrappedKeyDto,
    pub recovery_wrapped_key: WrappedKeyDto,
    #[serde(with = "b64")]
    pub recovery_auth_key: Vec<u8>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    #[serde(with = "b64")]
    pub auth_key: Vec<u8>,
}

#[derive(Deserialize)]
pub struct RecoverLoginRequest {
    pub email: String,
    #[serde(with = "b64")]
    pub recovery_auth_key: Vec<u8>,
}

#[derive(Deserialize)]
pub struct RefreshRequest { pub refresh_token: String }

#[derive(Serialize)]
pub struct AuthResponse {
    pub user_id: Uuid,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: usize,
    pub kdf: KdfDto,
    pub wrapped_key: WrappedKeyDto,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_wrapped_key: Option<WrappedKeyDto>,
}
```

Add `use uuid::Uuid;` at the top of `dto.rs`.

`auth.rs`:

```rust
use std::sync::Arc;

use argon2::{
    password_hash::{rand_core::OsRng as PwOsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm as JwtAlgorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::api::dto::{AuthResponse, KdfDto, LoginRequest, RecoverLoginRequest, RegisterRequest, WrappedKeyDto};
use crate::error::AppError;
use crate::AppState;

pub const ACCESS_TTL_SECS: usize = 900;
const REFRESH_TTL_MS: i64 = 30 * 24 * 3600 * 1000;

#[derive(Clone)]
pub struct AuthService {
    pool: SqlitePool,
    jwt_secret: Arc<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims { sub: String, exp: usize, iat: usize }

pub struct AuthUser { pub user_id: Uuid }
```

`AuthService::new`, `hash_secret`, `verify_secret`, `random_refresh`, `store_refresh`, `issue`, `register`, `login`, `recover_login`, `refresh`, `logout`, `verify_access`. Use `now_ms()`. `hash_secret` hashes the client-supplied `auth_key`/`recovery_auth_key` with server-side Argon2id `Params::new(19_456, 2, 1, Some(32))` and a fresh `SaltString`; `verify_secret` parses the stored `PasswordHash` and verifies constant-time.

`register` request validation:
```rust
if req.auth_key.len() != 32 || req.recovery_auth_key.len() != 32 { return Err(AppError::BadRequest(...)); }
if req.wrapped_key.nonce.len() != 24 || req.wrapped_key.ciphertext.len() != 48 { ... }
if req.recovery_wrapped_key.nonce.len() != 24 || req.recovery_wrapped_key.ciphertext.len() != 48 { ... }
```
`users` insert:
```sql
INSERT INTO users(id,email,auth_hash,kdf_salt,kdf_params,wrapped_vault_key,wrapped_key_nonce,recovery_wrapped_key,recovery_nonce,recovery_auth_hash,created_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?)
```
`kdf_salt` binds `req.kdf.salt`, `kdf_params` JSON, and the required recovery wrap/hash fields.

`login` selects `id, auth_hash, kdf_params, wrapped_vault_key, wrapped_key_nonce`.
`recover_login` selects `id, recovery_auth_hash, kdf_params, ..., recovery_wrapped_key, recovery_nonce`.
`issue` returns `AuthResponse`; takes optional recovery.

`refresh`:
```rust
let hash = Sha256::digest(token.as_bytes());
let row: Option<(String,i64,i64)> = sqlx::query_as("SELECT user_id, expires_at, revoked FROM refresh_tokens WHERE token_hash = ?")...
if row.is_none() || revoked != 0 || expires_at < now_ms() { return Err(Unauthorized); }
sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?")...
self.issue(user_id, None).await
```
`issue` inserts new refresh.

`logout`: update revoked; always Ok.

`verify_access`:
```rust
let data = decode::<Claims>(token, &DecodingKey::from_secret(&self.jwt_secret), &Validation::new(JwtAlgorithm::HS256))?;
Uuid::parse_str(&data.claims.sub).map_err(|_| AppError::Unauthorized)
```

Extractor uses `state.auth.verify_access(token).await?`.

`api/auth.rs` handlers:
- `register(State, Option<ConnectInfo>, Json<RegisterRequest>) -> Result<(StatusCode, Json<AuthResponse>), AppError>`.
- `login`, `recover_login`, `refresh`, `logout`.
- Rate limit helper `client_ip`.
- Routes function.

`lib.rs` update:
```rust
pub mod auth;
pub mod rate_limit;
...
pub struct AppState { pool, config, auth, rate }
impl AppState::new(...)
build_router: nest("/v1", api::auth::routes())
```

Update health test and common to `AppState::new`.

- [ ] **Step 4: Run tests and commit**

Run: `cargo test -p vault-server`
Expected: 7 tests pass (2 config + 1 health + 4 auth).

```bash
git add crates/vault-server
git commit -m "feat(server): add JWT auth, recovery login, and rate limiting"
```


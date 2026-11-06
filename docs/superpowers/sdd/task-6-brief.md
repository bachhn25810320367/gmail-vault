## Task 6: Server scaffold, config, migrations, health

**Files:**
- Modify: `Cargo.toml` (add server workspace dependencies)
- Modify: `crates/vault-server/Cargo.toml`
- Create: `crates/vault-server/src/lib.rs`
- Create: `crates/vault-server/src/config.rs`
- Create: `crates/vault-server/src/error.rs`
- Create: `crates/vault-server/src/db.rs`
- Create: `crates/vault-server/src/api/mod.rs`
- Create: `crates/vault-server/src/api/health.rs`
- Create: `crates/vault-server/src/main.rs`
- Create: `crates/vault-server/migrations/0001_init.sql`
- Create: `crates/vault-server/tests/health.rs`

**Interfaces:**
- Consumes: nothing from earlier crates (server is independent of `vault-core`).
- Produces:
  - `Config::{from_env, from_map}`
  - `AppState { pool, config }`
  - `build_router(state: AppState) -> axum::Router`
  - `db::{connect, migrate}`
  - `AppError` with `IntoResponse`.

- [ ] **Step 1: Add server dependencies**

Append to root `[workspace.dependencies]`:

```toml
axum = "0.8"
tokio = { version = "1", features = ["full"] }
sqlx = { version = "0.8", features = ["runtime-tokio-rustls", "sqlite", "migrate", "uuid", "chrono"] }
jsonwebtoken = "9"
tower = "0.5"
tower-http = { version = "0.6", features = ["limit", "trace"] }
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
dotenvy = "0.15"
http-body-util = "0.1"
```

Replace `crates/vault-server/Cargo.toml`:

```toml
[package]
name = "vault-server"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
axum.workspace = true
tokio.workspace = true
sqlx.workspace = true
serde.workspace = true
serde_json.workspace = true
jsonwebtoken.workspace = true
argon2.workspace = true
sha2.workspace = true
rand.workspace = true
uuid.workspace = true
chrono.workspace = true
base64.workspace = true
thiserror.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
dotenvy.workspace = true
tower-http.workspace = true

[dev-dependencies]
tower.workspace = true
http-body-util.workspace = true
```

- [ ] **Step 2: Write the failing config and health tests**

`crates/vault-server/src/config.rs` test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_required_values() {
        let env = |k: &str| match k {
            "DATABASE_URL" => Some("sqlite:///tmp/vault.db".to_string()),
            "JWT_SECRET" => Some("0123456789abcdef0123456789abcdef".to_string()),
            _ => None,
        };
        let cfg = Config::from_map(env).unwrap();
        assert_eq!(cfg.bind_addr.to_string(), "127.0.0.1:8080");
        assert_eq!(cfg.max_body_bytes, 2 * 1024 * 1024);
        assert!(!cfg.allow_registration);
    }

    #[test]
    fn rejects_short_jwt_secret() {
        let env = |k: &str| match k {
            "DATABASE_URL" => Some("sqlite::memory:".to_string()),
            "JWT_SECRET" => Some("short".to_string()),
            _ => None,
        };
        assert!(Config::from_map(env).is_err());
    }
}
```

`crates/vault-server/tests/health.rs`:

```rust
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use vault_server::{build_router, config::Config, db, AppState};

async fn test_app() -> axum::Router {
    let pool = db::connect("sqlite::memory:").await.unwrap();
    db::migrate(&pool).await.unwrap();
    let config = Config::from_map(|k| match k {
        "DATABASE_URL" => Some("sqlite::memory:".into()),
        "JWT_SECRET" => Some("0123456789abcdef0123456789abcdef".into()),
        _ => None,
    }).unwrap();
    build_router(AppState { pool, config })
}

#[tokio::test]
async fn health_ok() {
    let app = test_app().await;
    let res = app.oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p vault-server`
Expected: compile error because `Config` and `build_router` do not exist.

- [ ] **Step 4: Implement config, error, db, router**

`config.rs`:

```rust
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub jwt_secret: Arc<Vec<u8>>,
    pub allow_registration: bool,
    pub max_body_bytes: usize,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::from_map(|key| std::env::var(key).ok())
    }

    pub fn from_map(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let database_url = get("DATABASE_URL").ok_or("DATABASE_URL is required")?;
        let secret = get("JWT_SECRET").ok_or("JWT_SECRET is required")?;
        if secret.as_bytes().len() < 32 {
            return Err("JWT_SECRET must be at least 32 bytes".into());
        }
        let bind_addr = get("BIND_ADDR").unwrap_or_else(|| "127.0.0.1:8080".into())
            .parse().map_err(|e| format!("invalid BIND_ADDR: {e}"))?;
        let allow_registration = get("ALLOW_REGISTRATION").map(|v| v == "true").unwrap_or(false);
        let max_body_bytes = get("MAX_BODY_BYTES").and_then(|v| v.parse().ok()).unwrap_or(2 * 1024 * 1024);
        Ok(Self { bind_addr, database_url, jwt_secret: Arc::new(secret.into_bytes()), allow_registration, max_body_bytes })
    }
}
```

`error.rs`:

```rust
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("conflict")]
    Conflict,
    #[error("rate limited")]
    RateLimited,
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, "invalid_request", m),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", "Phiên đăng nhập không hợp lệ".into()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "forbidden", "Không có quyền".into()),
            AppError::Conflict => (StatusCode::CONFLICT, "conflict", "Dữ liệu đã thay đổi".into()),
            AppError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Thử lại sau".into()),
            AppError::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", "Dữ liệu quá lớn".into()),
            AppError::Internal(m) => {
                tracing::error!(error = %m, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal", "Lỗi server".into())
            }
        };
        (status, Json(json!({"error": {"code": code, "message": message}}))).into_response()
    }
}
```

`db.rs`:

```rust
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

pub async fn connect(url: &str) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .foreign_keys(true);
    SqlitePoolOptions::new().max_connections(5).connect_with(options).await
}

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}
```

`api/mod.rs`:

```rust
pub mod health;
```

`api/health.rs`:

```rust
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::{AppState, error::AppError};

pub async fn health(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    sqlx::query("SELECT 1").execute(&state.pool).await.map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(json!({"status": "ok"})))
}
```

`lib.rs`:

```rust
pub mod api;
pub mod config;
pub mod db;
pub mod error;

use std::sync::Arc;
use axum::routing::get;
use axum::Router;
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
```

`main.rs`:

```rust
use std::net::SocketAddr;

use tower_http::trace::TraceLayer;
use vault_server::{build_router, config::Config, db, AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = Config::from_env()?;
    let pool = db::connect(&config.database_url).await?;
    db::migrate(&pool).await?;
    let addr = config.bind_addr;
    let app = build_router(AppState { pool, config: std::sync::Arc::new(config) });
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "vault-server listening");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
```

Remove the unused `TraceLayer` import in `main.rs` (the router owns it).

`migrations/0001_init.sql` — copy the exact schema from spec section 5, including `recovery_auth_hash` and all indexes.

- [ ] **Step 5: Run tests and commit**

Run: `cargo test -p vault-server`
Expected: 3 tests pass (2 config + 1 health).

```bash
git add Cargo.toml crates/vault-server
git commit -m "feat(server): add config, SQLite migrations, and health endpoint"
```

---


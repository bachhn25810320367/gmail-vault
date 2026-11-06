use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::SqlitePool;
use tower::ServiceExt;
use uuid::Uuid;
use vault_server::{AppState, build_router, config::Config, db};

#[allow(dead_code)] // fields kept as shared test fixtures for later integration tests
pub struct TestApp {
    pub router: Router,
    pub pool: SqlitePool,
    pub config: Arc<Config>,
}

pub async fn spawn() -> TestApp {
    let pool = db::connect("sqlite::memory:").await.unwrap();
    db::migrate(&pool).await.unwrap();
    let config = Arc::new(
        Config::from_map(|k| match k {
            "DATABASE_URL" => Some("sqlite::memory:".into()),
            "JWT_SECRET" => Some("0123456789abcdef0123456789abcdef".into()),
            _ => None,
        })
        .unwrap(),
    );
    TestApp {
        router: build_router(AppState::new(pool.clone(), config.clone())),
        pool,
        config,
    }
}

pub fn b64(bytes: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
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

pub async fn request(
    app: &TestApp,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let body = match body {
        Some(v) => {
            builder = builder.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let res = app
        .router
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

pub async fn register(app: &TestApp, email: &str) -> (StatusCode, Value) {
    request(
        app,
        "POST",
        "/v1/auth/register",
        None,
        Some(register_body(email)),
    )
    .await
}

pub async fn login(app: &TestApp, email: &str) -> (StatusCode, Value) {
    request(
        app,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"email": email, "auth_key": b64(&[7u8; 32])})),
    )
    .await
}

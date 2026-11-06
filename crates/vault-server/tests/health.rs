use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;
use vault_server::{AppState, build_router, config::Config, db};

async fn test_app() -> axum::Router {
    let pool = db::connect("sqlite::memory:").await.unwrap();
    db::migrate(&pool).await.unwrap();
    let config = Config::from_map(|k| match k {
        "DATABASE_URL" => Some("sqlite::memory:".into()),
        "JWT_SECRET" => Some("0123456789abcdef0123456789abcdef".into()),
        _ => None,
    })
    .unwrap();
    build_router(AppState {
        pool,
        config: Arc::new(config),
    })
}

#[tokio::test]
async fn health_ok() {
    let app = test_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
}

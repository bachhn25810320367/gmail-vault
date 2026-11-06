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
    let (status, _) = request(
        &app,
        "POST",
        "/v1/auth/refresh",
        None,
        Some(json!({"refresh_token": refresh})),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = request(
        &app,
        "POST",
        "/v1/auth/refresh",
        None,
        Some(json!({"refresh_token": refresh})),
    )
    .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn wrong_password_is_401_and_sixth_attempt_is_429() {
    let app = spawn().await;
    register(&app, "owner@example.com").await;
    for _ in 0..5 {
        let (status, _) = request(
            &app,
            "POST",
            "/v1/auth/login",
            None,
            Some(json!({
                "email": "owner@example.com", "auth_key": b64(&[9u8; 32])
            })),
        )
        .await;
        assert_eq!(status, 401);
    }
    let (status, _) = request(
        &app,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({
            "email": "owner@example.com", "auth_key": b64(&[9u8; 32])
        })),
    )
    .await;
    assert_eq!(status, 429);
}

#[tokio::test]
async fn recovery_login_works_and_logout_revokes() {
    let app = spawn().await;
    register(&app, "owner@example.com").await;
    let (status, body) = request(
        &app,
        "POST",
        "/v1/auth/recover/login",
        None,
        Some(json!({
            "email": "owner@example.com", "recovery_auth_key": b64(&[6u8; 32])
        })),
    )
    .await;
    assert_eq!(status, 200);
    let refresh = body["refresh_token"].as_str().unwrap().to_string();
    let (status, _) = request(
        &app,
        "POST",
        "/v1/auth/logout",
        None,
        Some(json!({"refresh_token": refresh.clone()})),
    )
    .await;
    assert_eq!(status, 204);
    let (status, _) = request(
        &app,
        "POST",
        "/v1/auth/refresh",
        None,
        Some(json!({"refresh_token": refresh})),
    )
    .await;
    assert_eq!(status, 401);
}

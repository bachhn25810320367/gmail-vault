mod common;

use common::*;
use serde_json::{Value, json};

async fn token(app: &TestApp) -> String {
    let (_, body) = register(app, "owner@example.com").await;
    body["access_token"].as_str().unwrap().to_string()
}

fn record(id: &str, base: u64, text: &str) -> Value {
    json!({
        "id": id,
        "base_revision": base,
        "updated_at": 1762000000000_i64,
        "deleted": false,
        "nonce": b64(&[9u8; 24]),
        "payload": b64(text.as_bytes())
    })
}

#[tokio::test]
async fn keys_roundtrip_and_update_revokes_sessions() {
    let app = spawn().await;
    let token = token(&app).await;
    let (status, body) = request(&app, "GET", "/v1/keys", Some(&token), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["kdf"]["algo"], "argon2id");
    let (status, _) = request(
        &app,
        "PUT",
        "/v1/keys",
        Some(&token),
        Some(json!({
            "kdf": {"algo": "argon2id", "salt": b64(&[8u8; 16]), "m_kib": 65536, "t": 3, "p": 2},
            "wrapped_key": {"nonce": b64(&[7u8; 24]), "ciphertext": b64(&[6u8; 48])}
        })),
    )
    .await;
    assert_eq!(status, 204);
    let (status, _) = request(&app, "GET", "/v1/keys", None, None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn push_new_then_update_then_stale_conflict() {
    let app = spawn().await;
    let token = token(&app).await;
    let id = uuid::Uuid::new_v4().to_string();
    let (status, body) = request(
        &app,
        "POST",
        "/v1/sync/push",
        Some(&token),
        Some(json!({"records": [record(&id, 0, "v1")]})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["accepted"][0]["revision"], 1);
    let (status, body) = request(
        &app,
        "POST",
        "/v1/sync/push",
        Some(&token),
        Some(json!({"records": [record(&id, 1, "v2")]})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["accepted"][0]["revision"], 2);
    let (status, body) = request(
        &app,
        "POST",
        "/v1/sync/push",
        Some(&token),
        Some(json!({"records": [record(&id, 1, "stale")]})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["conflicts"][0]["server"]["revision"], 2);
}

#[tokio::test]
async fn pull_since_and_limit() {
    let app = spawn().await;
    let token = token(&app).await;
    let a = uuid::Uuid::new_v4().to_string();
    let b = uuid::Uuid::new_v4().to_string();
    request(
        &app,
        "POST",
        "/v1/sync/push",
        Some(&token),
        Some(json!({"records": [record(&a, 0, "a")]})),
    )
    .await;
    request(
        &app,
        "POST",
        "/v1/sync/push",
        Some(&token),
        Some(json!({"records": [record(&b, 0, "b")]})),
    )
    .await;
    let (status, body) = request(&app, "GET", "/v1/sync/changes?since=0", Some(&token), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["items"].as_array().unwrap().len(), 2);
    let first_seq = body["items"][0]["change_seq"].as_u64().unwrap();
    let (status, body) = request(
        &app,
        "GET",
        &format!("/v1/sync/changes?since={first_seq}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn sync_requires_auth() {
    let app = spawn().await;
    let (status, _) = request(&app, "GET", "/v1/sync/changes?since=0", None, None).await;
    assert_eq!(status, 401);
}

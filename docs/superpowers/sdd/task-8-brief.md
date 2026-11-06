## Task 8: Server keys and sync endpoints

**Files:**
- Create: `crates/vault-server/src/api/keys.rs`
- Create: `crates/vault-server/src/api/sync.rs`
- Modify: `crates/vault-server/src/api/mod.rs`
- Modify: `crates/vault-server/src/lib.rs`
- Create: `crates/vault-server/tests/sync.rs`

**Interfaces:**
- Consumes: `AuthUser`, `AppState`, `AppError`, `KdfDto`, `WrappedKeyDto`, `b64`.
- Produces:
  - `GET /v1/keys`, `PUT /v1/keys`
  - `GET /v1/sync/changes?since=&limit=`
  - `POST /v1/sync/push`
  - DTOs `RecordDto`, `PushItemDto`, `PushRequest`, `PushResponse`, `AcceptedDto`, `ConflictDto`, `PullResponse`, `PutKeysRequest`.

- [ ] **Step 1: Write the failing keys/sync tests**

`tests/sync.rs`:

```rust
mod common;

use common::*;
use serde_json::{json, Value};

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
    let (status, _) = request(&app, "PUT", "/v1/keys", Some(&token), Some(json!({
        "kdf": {"algo": "argon2id", "salt": b64(&[8u8; 16]), "m_kib": 65536, "t": 3, "p": 2},
        "wrapped_key": {"nonce": b64(&[7u8; 24]), "ciphertext": b64(&[6u8; 48])}
    }))).await;
    assert_eq!(status, 204);
    let (status, _) = request(&app, "GET", "/v1/keys", None, None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn push_new_then_update_then_stale_conflict() {
    let app = spawn().await;
    let token = token(&app).await;
    let id = uuid::Uuid::new_v4().to_string();
    let (status, body) = request(&app, "POST", "/v1/sync/push", Some(&token), Some(json!({"records": [record(&id, 0, "v1")]}))).await;
    assert_eq!(status, 200);
    assert_eq!(body["accepted"][0]["revision"], 1);
    let (status, body) = request(&app, "POST", "/v1/sync/push", Some(&token), Some(json!({"records": [record(&id, 1, "v2")]}))).await;
    assert_eq!(status, 200);
    assert_eq!(body["accepted"][0]["revision"], 2);
    let (status, body) = request(&app, "POST", "/v1/sync/push", Some(&token), Some(json!({"records": [record(&id, 1, "stale")]}))).await;
    assert_eq!(status, 200);
    assert_eq!(body["conflicts"][0]["server"]["revision"], 2);
}

#[tokio::test]
async fn pull_since_and_limit() {
    let app = spawn().await;
    let token = token(&app).await;
    let a = uuid::Uuid::new_v4().to_string();
    let b = uuid::Uuid::new_v4().to_string();
    request(&app, "POST", "/v1/sync/push", Some(&token), Some(json!({"records": [record(&a, 0, "a")]}))).await;
    request(&app, "POST", "/v1/sync/push", Some(&token), Some(json!({"records": [record(&b, 0, "b")]}))).await;
    let (status, body) = request(&app, "GET", "/v1/sync/changes?since=0", Some(&token), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["items"].as_array().unwrap().len(), 2);
    let first_seq = body["items"][0]["change_seq"].as_u64().unwrap();
    let (status, body) = request(&app, "GET", &format!("/v1/sync/changes?since={first_seq}"), Some(&token), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn sync_requires_auth() {
    let app = spawn().await;
    let (status, _) = request(&app, "GET", "/v1/sync/changes?since=0", None, None).await;
    assert_eq!(status, 401);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p vault-server --test sync`
Expected: 404 for missing routes.

- [ ] **Step 3: Implement keys and sync handlers**

`api/keys.rs`:

```rust
#[derive(Deserialize)]
pub struct PutKeysRequest {
    pub kdf: KdfDto,
    pub wrapped_key: WrappedKeyDto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_wrapped_key: Option<WrappedKeyDto>,
    #[serde(default, with = "crate::api::dto::b64_opt", skip_serializing_if = "Option::is_none")]
    pub recovery_auth_key: Option<Vec<u8>>,
}
```

- `get_keys`: query `kdf_params`, `wrapped_vault_key`, `wrapped_key_nonce`, recovery fields; parse; return JSON.
- `put_keys`: validate salt 16, nonce 24, ciphertext 48; read the old `kdf_params` and wrapped key; update user; if `recovery_auth_key` is present, require `recovery_wrapped_key` and hash the auth key with Argon2; revoke all refresh tokens **only when `kdf` or `wrapped_key` changed** (master-password rotation). A recovery-only update keeps the current session. Return `StatusCode::NO_CONTENT`.
- Reuse `auth::hash_secret` by making it `pub(crate)`.

`api/sync.rs`:

```rust
#[derive(Deserialize)]
pub struct ChangesQuery { pub since: Option<u64>, pub limit: Option<u32> }

#[derive(Serialize)]
pub struct RecordDto {
    pub id: Uuid,
    pub revision: u64,
    pub change_seq: u64,
    pub updated_at: i64,
    pub deleted: bool,
    #[serde(with = "crate::api::dto::b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "crate::api::dto::b64")]
    pub payload: Vec<u8>,
}

#[derive(Deserialize)]
pub struct PushItemDto {
    pub id: Uuid,
    pub base_revision: u64,
    pub updated_at: i64,
    pub deleted: bool,
    #[serde(with = "crate::api::dto::b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "crate::api::dto::b64")]
    pub payload: Vec<u8>,
}

#[derive(Deserialize)]
pub struct PushRequest { pub records: Vec<PushItemDto> }

#[derive(Serialize)]
pub struct AcceptedDto { pub id: Uuid, pub revision: u64, pub change_seq: u64 }

#[derive(Serialize)]
pub struct ConflictDto { pub id: Uuid, pub server: RecordDto }

#[derive(Serialize)]
pub struct PushResponse { pub accepted: Vec<AcceptedDto>, pub conflicts: Vec<ConflictDto> }

#[derive(Serialize)]
pub struct PullResponse { pub items: Vec<RecordDto>, pub next_since: u64, pub has_more: bool }
```

Handlers:
- `changes(AuthUser, State, Query<ChangesQuery>)`: limit default 500, clamp 1..=1000. Fetch `limit + 1`, trim, `has_more`.
- `push(AuthUser, State, Json<PushRequest>)`: validate count ≤ 200, each payload ≤ 64 KiB, nonce 24 unless deleted. Begin transaction. For each record:
  - `SELECT revision FROM records WHERE user_id=? AND id=?`.
  - none + base 0 → `next_seq`, `INSERT`.
  - some == base → `next_seq`, `UPDATE revision=revision+1`.
  - else → select full row and add conflict.
  - Commit.
- `next_seq` helper as described.
- `record_from_row` helper.

`lib.rs` nest:
```rust
.nest("/v1", api::auth::routes().merge(api::keys::routes()).merge(api::sync::routes()))
```

`api/mod.rs` add `pub mod keys; pub mod sync;`.

- [ ] **Step 4: Run tests and commit**

Run: `cargo test -p vault-server`
Expected: 11 tests pass.

```bash
git add crates/vault-server
git commit -m "feat(server): add key material and sync endpoints"
```


## Task 11: Client sync integration and status banner

**Files:**
- Modify: `crates/vault-core/src/sync.rs` (serde derives)
- Modify: `crates/vault-client/Cargo.toml` (add `async-trait`)
- Modify: `crates/vault-client/src/api.rs` (`SyncApi` impl)
- Modify: `crates/vault-client/src/state.rs` (`SyncStatus`)
- Modify: `crates/vault-client/src/workers/vault.rs` (sync loop)
- Modify: `crates/vault-client/src/app.rs` (spawn with API, handle status)
- Modify: `crates/vault-client/src/ui/main.rs` (sync banner + button)

**Interfaces:**
- Consumes: `vault_core::sync::{SyncApi, SyncEngine, PushItem, PullResponse, PushResponse}`.
- Produces:
  - `impl SyncApi for VaultApi`.
  - `SyncStatus { online, syncing, last_sync, pending, last_error, conflicts }`.
  - `VaultEvent::SyncStatus(SyncStatus)`.
  - `VaultCommand::SyncNow`.

- [ ] **Step 1: Write the failing serialization and status tests**

Add to `crates/vault-core/src/sync.rs`:

```rust
#[test]
fn push_item_serializes_base64_and_snake_case() {
    let item = PushItem {
        id: Uuid::new_v4(), base_revision: 2, updated_at: 5,
        deleted: false, nonce: vec![1; 24], payload: vec![2; 8],
    };
    let value = serde_json::to_value(&item).unwrap();
    assert_eq!(value["base_revision"], 2);
    assert!(value["nonce"].is_string());
    assert!(value["payload"].is_string());
}
```

Add to `crates/vault-client/src/state.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_label_is_vietnamese() {
        let status = SyncStatus { pending: 3, ..Default::default() };
        assert_eq!(status.pending_label(), "3 thay đổi chờ");
        let status = SyncStatus { pending: 0, online: true, ..Default::default() };
        assert_eq!(status.pending_label(), "Đã đồng bộ");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p vault-core push_item_serializes_base64_and_snake_case && cargo test -p vault-client pending_label_is_vietnamese`
Expected: compile error because `PushItem` has no serde and `SyncStatus` does not exist.

- [ ] **Step 3: Add serde derives to core sync types**

In `sync.rs`:

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PushItem {
    pub id: Uuid,
    pub base_revision: u64,
    pub updated_at: i64,
    pub deleted: bool,
    #[serde(with = "crate::codec::base64")]
    pub nonce: Vec<u8>,
    #[serde(with = "crate::codec::base64")]
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PullResponse {
    pub items: Vec<RecordRow>,
    pub next_since: u64,
    pub has_more: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PushResponse {
    pub accepted: Vec<Accepted>,
    pub conflicts: Vec<Conflict>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Accepted { pub id: Uuid, pub revision: u64, pub change_seq: u64 }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Conflict { pub id: Uuid, pub server: RecordRow }
```

`RecordRow` already has serde with base64 and `#[serde(default)] dirty`; verify.

- [ ] **Step 4: Implement `SyncApi` for `VaultApi`**

Add `async-trait.workspace = true` to client dependencies.

In `api.rs`:

```rust
use vault_core::sync::{PullResponse, PushItem, PushResponse, SyncApi};

#[async_trait::async_trait]
impl SyncApi for VaultApi {
    async fn pull(&self, since: u64, limit: u32) -> vault_core::Result<PullResponse> {
        let url = format!("{}/v1/sync/changes?since={since}&limit={limit}", self.base_url);
        let res = self.send_authorized(reqwest::Method::GET, &url, None).await
            .map_err(ApiError::into_core)?;
        res.json().await.map_err(|e| vault_core::CoreError::Network(e.to_string()))
    }

    async fn push(&self, items: Vec<PushItem>) -> vault_core::Result<PushResponse> {
        let url = format!("{}/v1/sync/push", self.base_url);
        let body = serde_json::json!({ "records": items });
        let res = self.send_authorized(reqwest::Method::POST, &url, Some(body)).await
            .map_err(ApiError::into_core)?;
        res.json().await.map_err(|e| vault_core::CoreError::Network(e.to_string()))
    }
}

impl ApiError {
    fn into_core(self) -> vault_core::CoreError {
        match self {
            ApiError::Unauthorized => vault_core::CoreError::Unauthorized,
            other => vault_core::CoreError::Network(other.to_string()),
        }
    }
}
```

`send_authorized`:
- Get access token; if none and email set → `refresh().await`.
- Send with Bearer.
- If 401 → refresh once, retry; if still 401 → `ApiError::Unauthorized`.
- Return response if success; else parse server error.
- `VaultApi::push` sends `{records: [...]}` because the server expects `PushRequest { records }`.

- `VaultApi::refresh()`:
  - email from `self.email`.
  - refresh token from keychain if not in memory; `platform::load_refresh`.
  - POST `/v1/auth/refresh`, store new refresh + access; return.
  - This is called by worker on first sync after restart.

- `VaultApi::new` has `email: Arc<Mutex<String>>`; add `pub fn set_email(&self, email: &str)`.

- `store_tokens` saves refresh and sets email.

- For setup, after register, `store_tokens` uses req.email.

- [ ] **Step 5: Extend worker with sync loop**

`state.rs`:

```rust
#[derive(Debug, Clone, Default)]
pub struct SyncStatus {
    pub online: bool,
    pub syncing: bool,
    pub last_sync: Option<chrono::DateTime<chrono::Utc>>,
    pub pending: usize,
    pub last_error: Option<String>,
    pub conflicts: usize,
}

impl SyncStatus {
    pub fn pending_label(&self) -> String {
        if self.pending > 0 { format!("{} thay đổi chờ", self.pending) }
        else if self.online { "Đã đồng bộ".into() }
        else { "Offline".into() }
    }
}
```

`workers/vault.rs`:
- Add `VaultEvent::SyncStatus(SyncStatus)` and `VaultCommand::SyncNow`.
- Change the worker API parameter to `sync_api: Arc<dyn SyncApi>` so tests can use a no-network mock while production passes `Arc<VaultApi>`. This is an intermediate 8-argument signature; Task 14 adds `auth_key` and `admin_api`.
- Worker state includes `sync_api`, `rt`, `sync_interval`, `last_sync: Option<Instant>`, `last_attempt: Option<Instant>`, `status`.
- On start: set `status.pending = store.count_dirty()?`, emit `Accounts` and `SyncStatus`, then try a sync only if `pending > 0`. Local reads must not wait for the network.
- Loop `recv_timeout(500ms)`:
  - `Ok(cmd)` handle. For Save/Delete/MarkUsed/SaveMany, after the local write call `state.sync_and_emit(&evt_tx)`.
  - `Err(RecvTimeoutError::Timeout)` → sync when the interval elapsed or `pending > 0`, but not more often than once every 5 seconds.
  - `Disconnected` break.
- `sync_now`:
```rust
fn sync_now(&mut self) -> SyncStatus {
    self.status.syncing = true;
    let rt = &self.rt;
    let api = &self.sync_api;
    let vault = &self.vault;
    let store = &mut self.store;
    let device = self.meta.device_label.clone();
    let mut engine = SyncEngine::new(api.as_ref(), store, vault, device);
    match rt.block_on(engine.sync_once()) {
        Ok(_) => {
            self.status.online = true;
            self.status.last_sync = Some(Utc::now());
            self.status.last_error = None;
            let _ = self.reload();
            self.status.conflicts = self.accounts.iter()
                .filter(|a| a.tags.iter().any(|t| t.eq_ignore_ascii_case("conflict")))
                .count();
        }
        Err(e) => {
            self.status.online = false;
            self.status.last_error = Some(e.to_string());
        }
    }
    self.status.pending = self.store.count_dirty().unwrap_or(0);
    self.status.syncing = false;
    self.status.clone()
}
```
Binding `rt`, `sync_api`, `vault`, and the mutable `store` to locals keeps the disjoint field borrows explicit for the borrow checker.
- `sync_and_emit` records `last_attempt`, emits `SyncStatus` before and after, calls `sync_now`, and emits `Accounts` + `SyncStatus`.
- On sync conflict, `reload` decrypts all accounts, including conflict copies.

Task 11 uses this intermediate 8-argument call:
```rust
let sync_api: Arc<dyn SyncApi> = api.clone();
let interval = Duration::from_secs(self.config.sync_interval_secs.clamp(15, 600));
let handle = spawn_vault(
    session.meta, session.vault, session.store, session.accounts,
    platform::db_path(), platform::backup_dir(), sync_api, interval,
);
```
Task 14 replaces it with the final 10-argument call. The Task 10 worker test becomes:
```rust
let handle = spawn_vault(
    meta, vault, store, Vec::new(), db.clone(), dir.path().join("backups"),
    Arc::new(NoopApi), Duration::from_secs(3600),
);
```
with a local `NoopApi` implementing `SyncApi` by returning empty pull/push responses. Use `handle.shutdown()`; `VaultHandle` has carried a join handle since Task 10, so the worker is fully stopped before the test reopens SQLite.

- [ ] **Step 6: Wire app status and banner**

`app.rs`:
- On unlock: create `let api = Arc::new(VaultApi::new(&meta.server_url)); api.set_email(&meta.email);` store `self.api = Some(api.clone())`; spawn with a clone coerced to `Arc<dyn SyncApi>`.
- Poll `VaultEvent::SyncStatus(s)` into `self.sync_status`.
- MainView `show` receives `&SyncStatus`; the top bar shows `pending_label()` and a `Sync now` button that sends `VaultCommand::SyncNow`.
- `VaultEvent::BackupDone` sets the toast.

- [ ] **Step 7: Run tests and commit**

Run: `cargo test -p vault-core && cargo test -p vault-client`
Expected: all pass. The worker test uses `NoopApi` and never touches the network.

Manual: run the server + client, add an account, and verify `change_seq` increments via `curl` or a second profile after Task 15.

```bash
git add crates/vault-core crates/vault-client
git commit -m "feat(client): sync encrypted records with status banner"
```


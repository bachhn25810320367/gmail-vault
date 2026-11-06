## Task 5: Sync engine with conflict copies

**Files:**
- Create: `crates/vault-core/src/sync.rs`
- Modify: `crates/vault-core/src/lib.rs`
- Modify: `crates/vault-core/Cargo.toml` (add `tokio` dev-dependency)

**Interfaces:**
- Consumes: `LocalStore`, `UnlockedVault`, `RecordRow`, `Account`.
- Produces:
  - `SyncApi` trait with `pull` and `push`.
  - `PushItem`, `PullResponse`, `PushResponse`, `Accepted`, `Conflict`.
  - `SyncEngine<'a>::new(api, store, vault, device_label)`.
  - `SyncEngine::sync_once(&mut self) -> Result<SyncReport>`.
  - `SyncReport { pushed, pulled, conflicts, cursor }`.

- [ ] **Step 1: Write the failing sync tests**

Add `tokio = { version = "1", features = ["rt", "macros"] }` to core `[dev-dependencies]`, then:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{create_vault, KdfParams, UnlockedVault, WrappedKey};
    use crate::store::{LocalMeta, LocalStore};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use uuid::Uuid;

    struct MockState { records: HashMap<Uuid, RecordRow>, seq: u64 }
    struct MockApi { state: Mutex<MockState> }

    impl MockApi {
        fn new() -> Self { Self { state: Mutex::new(MockState { records: HashMap::new(), seq: 0 }) } }
        fn put_server(&self, mut row: RecordRow) {
            let mut s = self.state.lock().unwrap();
            s.seq += 1;
            row.change_seq = s.seq;
            row.revision = row.revision.max(1);
            s.records.insert(row.id, row);
        }
    }

    #[async_trait::async_trait]
    impl SyncApi for MockApi {
        async fn pull(&self, since: u64, _limit: u32) -> Result<PullResponse> {
            let s = self.state.lock().unwrap();
            let mut items: Vec<_> = s.records.values().filter(|r| r.change_seq > since).cloned().collect();
            items.sort_by_key(|r| r.change_seq);
            let next_since = items.last().map(|r| r.change_seq).unwrap_or(since);
            Ok(PullResponse { items, next_since, has_more: false })
        }

        async fn push(&self, items: Vec<PushItem>) -> Result<PushResponse> {
            let mut s = self.state.lock().unwrap();
            let mut accepted = Vec::new();
            let mut conflicts = Vec::new();
            for item in items {
                let current = s.records.get(&item.id).cloned();
                let ok = match &current {
                    None => item.base_revision == 0,
                    Some(cur) => cur.revision == item.base_revision,
                };
                if ok {
                    s.seq += 1;
                    let revision = current.map(|c| c.revision + 1).unwrap_or(1);
                    let row = RecordRow {
                        id: item.id, revision, change_seq: s.seq, updated_at: item.updated_at,
                        deleted: item.deleted, dirty: false, nonce: item.nonce, payload: item.payload,
                    };
                    s.records.insert(item.id, row);
                    accepted.push(Accepted { id: item.id, revision, change_seq: s.seq });
                } else {
                    conflicts.push(Conflict { id: item.id, server: current.unwrap() });
                }
            }
            Ok(PushResponse { accepted, conflicts })
        }
    }

    struct Fixture {
        store: LocalStore,
        vault: UnlockedVault,
        meta: LocalMeta,
    }

    fn fixture() -> Fixture {
        let nv = create_vault("pw").unwrap();
        let mut store = LocalStore::open_in_memory().unwrap();
        let meta = LocalMeta {
            user_id: nv.user_id, email: "owner@example.com".into(),
            server_url: "http://test".into(), device_label: "PC-A".into(),
            kdf: nv.kdf.clone(), wrapped_key: nv.wrapped_key.clone(), last_change_seq: 0,
        };
        store.save_meta(&meta).unwrap();
        let vault = crate::crypto::unwrap_vault_key("pw", nv.user_id, &nv.kdf, &nv.wrapped_key).unwrap();
        Fixture { store, vault, meta }
    }

    fn save_dirty(store: &mut LocalStore, vault: &UnlockedVault, account: &Account) -> RecordRow {
        let enc = vault.encrypt_account(account).unwrap();
        let row = RecordRow {
            id: account.id, revision: 0, change_seq: 0, updated_at: account.updated_at.timestamp_millis(),
            deleted: false, dirty: true, nonce: enc.nonce.to_vec(), payload: enc.payload,
        };
        store.upsert_record(&row).unwrap();
        row
    }

    #[tokio::test]
    async fn push_then_pull_marks_clean() {
        let mut f = fixture();
        let api = MockApi::new();
        let account = Account::new("a@b.co", "pw");
        save_dirty(&mut f.store, &f.vault, &account);
        let report = SyncEngine::new(&api, &mut f.store, &f.vault, "PC-A").sync_once().await.unwrap();
        assert_eq!(report.pushed, 1);
        assert!(f.store.load_dirty(10).unwrap().is_empty());
        assert!(f.store.cursor().unwrap() > 0);
    }

    #[tokio::test]
    async fn conflict_copy_preserves_both_versions() {
        let mut f = fixture();
        let api = MockApi::new();
        let account = Account::new("a@b.co", "local-password");
        let row = save_dirty(&mut f.store, &f.vault, &account);
        let mut server_account = account.clone();
        server_account.password = "server-password".into();
        let enc = f.vault.encrypt_account(&server_account).unwrap();
        api.put_server(RecordRow {
            id: account.id, revision: 1, change_seq: 0, updated_at: 2,
            deleted: false, dirty: false, nonce: enc.nonce.to_vec(), payload: enc.payload,
        });
        f.store.upsert_record(&RecordRow { revision: 1, ..row }).unwrap();
        let report = SyncEngine::new(&api, &mut f.store, &f.vault, "PC-A").sync_once().await.unwrap();
        assert_eq!(report.conflicts, 1);
        let all = f.store.load_all_records().unwrap();
        assert_eq!(all.len(), 2);
        let copy = all.iter().find(|r| r.id != account.id).unwrap();
        let copy_account = f.vault.decrypt_account(copy.id, &copy.nonce, &copy.payload).unwrap();
        assert!(copy_account.tags.contains(&"conflict".to_string()));
        assert_eq!(copy_account.password, "local-password");
        let original = f.vault.decrypt_account(account.id, &all.iter().find(|r| r.id == account.id).unwrap().nonce, &all.iter().find(|r| r.id == account.id).unwrap().payload).unwrap();
        assert_eq!(original.password, "server-password");
    }

    #[tokio::test]
    async fn pull_newer_clean_applies() {
        let mut f = fixture();
        let api = MockApi::new();
        let account = Account::new("a@b.co", "server");
        let enc = f.vault.encrypt_account(&account).unwrap();
        api.put_server(RecordRow {
            id: account.id, revision: 1, change_seq: 0, updated_at: 1,
            deleted: false, dirty: false, nonce: enc.nonce.to_vec(), payload: enc.payload,
        });
        let report = SyncEngine::new(&api, &mut f.store, &f.vault, "PC-A").sync_once().await.unwrap();
        assert_eq!(report.pulled, 1);
        assert_eq!(f.store.load_all_records().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn tombstone_with_local_edit_creates_conflict_copy() {
        let mut f = fixture();
        let api = MockApi::new();
        let account = Account::new("a@b.co", "local-edit");
        let row = save_dirty(&mut f.store, &f.vault, &account);
        f.store.mark_clean(account.id, 1, 1).unwrap();
        f.store.upsert_record(&RecordRow { dirty: true, revision: 1, ..row }).unwrap();
        api.put_server(RecordRow {
            id: account.id, revision: 2, change_seq: 0, updated_at: 2,
            deleted: true, dirty: false, nonce: vec![], payload: vec![],
        });
        let report = SyncEngine::new(&api, &mut f.store, &f.vault, "PC-A").sync_once().await.unwrap();
        assert_eq!(report.conflicts, 1);
        let all = f.store.load_all_records().unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|r| r.id == account.id && r.deleted));
        assert!(all.iter().any(|r| r.id != account.id && !r.deleted));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p vault-core sync::tests`
Expected: compile error because `SyncEngine` does not exist.

- [ ] **Step 3: Implement sync types and engine**

Types:

```rust
#[derive(Debug, Clone)]
pub struct PushItem {
    pub id: Uuid,
    pub base_revision: u64,
    pub updated_at: i64,
    pub deleted: bool,
    pub nonce: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PullResponse {
    pub items: Vec<RecordRow>,
    pub next_since: u64,
    pub has_more: bool,
}

#[derive(Debug, Clone)]
pub struct PushResponse {
    pub accepted: Vec<Accepted>,
    pub conflicts: Vec<Conflict>,
}

#[derive(Debug, Clone)]
pub struct Accepted { pub id: Uuid, pub revision: u64, pub change_seq: u64 }

#[derive(Debug, Clone)]
pub struct Conflict { pub id: Uuid, pub server: RecordRow }

#[derive(Debug, Clone, Default)]
pub struct SyncReport { pub pushed: usize, pub pulled: usize, pub conflicts: usize, pub cursor: u64 }

#[async_trait::async_trait]
pub trait SyncApi: Send + Sync {
    async fn pull(&self, since: u64, limit: u32) -> Result<PullResponse>;
    async fn push(&self, items: Vec<PushItem>) -> Result<PushResponse>;
}
```

Engine:

```rust
pub struct SyncEngine<'a> {
    api: &'a dyn SyncApi,
    store: &'a mut LocalStore,
    vault: &'a UnlockedVault,
    device_label: String,
}

impl<'a> SyncEngine<'a> {
    pub fn new(api: &'a dyn SyncApi, store: &'a mut LocalStore, vault: &'a UnlockedVault, device_label: impl Into<String>) -> Self { ... }

    pub async fn sync_once(&mut self) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        let dirty = self.store.load_dirty(200)?;
        if !dirty.is_empty() {
            let items = dirty.iter().map(|r| PushItem { id: r.id, base_revision: r.revision, updated_at: r.updated_at, deleted: r.deleted, nonce: r.nonce.clone(), payload: r.payload.clone() }).collect();
            let response = self.api.push(items).await?;
            for a in response.accepted { self.store.mark_clean(a.id, a.revision, a.change_seq)?; report.pushed += 1; }
            for c in response.conflicts {
                self.store_conflict_copy(c.id)?;
                self.store.upsert_record(&RecordRow { dirty: false, ..c.server })?;
                report.conflicts += 1;
            }
        }
        loop {
            let since = self.store.cursor()?;
            let page = self.api.pull(since, 500).await?;
            for server in &page.items {
                match self.store.get_record(server.id)? {
                    None => self.store.upsert_record(&RecordRow { dirty: false, ..server.clone() })?,
                    Some(local) if server.revision > local.revision => {
                        if local.dirty && !local.deleted { self.store_conflict_copy(server.id)?; report.conflicts += 1; }
                        self.store.upsert_record(&RecordRow { dirty: false, ..server.clone() })?;
                    }
                    Some(_) => {}
                }
                report.pulled += 1;
            }
            self.store.set_cursor(page.next_since)?;
            report.cursor = page.next_since;
            if !page.has_more { break; }
        }
        Ok(report)
    }

    fn store_conflict_copy(&mut self, id: Uuid) -> Result<()> {
        let Some(local) = self.store.get_record(id)? else { return Ok(()); };
        if local.deleted || local.payload.is_empty() { return Ok(()); }
        let account = self.vault.decrypt_account(id, &local.nonce, &local.payload)?;
        let copy = make_conflict_copy(&account, &self.device_label, chrono::Utc::now());
        let enc = self.vault.encrypt_account(&copy)?;
        self.store.upsert_record(&RecordRow {
            id: copy.id, revision: 0, change_seq: 0, updated_at: copy.updated_at.timestamp_millis(),
            deleted: false, dirty: true, nonce: enc.nonce.to_vec(), payload: enc.payload,
        })?;
        Ok(())
    }
}
```

`make_conflict_copy`:

```rust
pub fn make_conflict_copy(account: &Account, device_label: &str, now: DateTime<Utc>) -> Account {
    let mut copy = account.clone();
    copy.id = Uuid::new_v4();
    if !copy.tags.iter().any(|t| t.eq_ignore_ascii_case("conflict")) {
        copy.tags.push("conflict".into());
    }
    let note = format!("Conflict copy từ {device_label} lúc {}", now.format("%d/%m/%Y %H:%M"));
    copy.notes = Some(match &account.notes {
        Some(existing) if !existing.is_empty() => format!("{existing}\n\n{note}"),
        _ => note,
    });
    copy.created_at = now;
    copy.updated_at = now;
    copy
}
```

- [ ] **Step 4: Run tests and commit**

Run: `cargo test -p vault-core sync::tests`
Expected: 5 tests pass.

```bash
git add crates/vault-core
git commit -m "feat(core): add revision-based sync with conflict copies"
```


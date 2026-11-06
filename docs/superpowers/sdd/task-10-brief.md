## Task 10: Vault service, main table, filters, and editor

**Files:**
- Create: `crates/vault-client/src/workers/mod.rs`
- Create: `crates/vault-client/src/workers/vault.rs`
- Create: `crates/vault-client/src/ui/main.rs`
- Create: `crates/vault-client/src/ui/editor.rs`
- Create: `crates/vault-client/src/ui/filters.rs`
- Modify: `crates/vault-client/src/state.rs`
- Modify: `crates/vault-client/src/app.rs`
- Modify: `crates/vault-client/src/ui/mod.rs`

**Interfaces:**
- Consumes: `LocalStore`, `UnlockedVault`, `LocalMeta`, `Account`, `RecordRow`, `backup_database`.
- Produces:
  - `VaultCommand { Save, SaveMany, Delete, MarkUsed, Reload, BackupNow, Shutdown }`.
  - `VaultEvent { Accounts, Error, BackupDone }`.
  - `VaultHandle { tx, rx, join }` with `shutdown()`, `spawn_vault(...)`.
  - `Filters::{matches, apply}`, `normalize_for_search`.
  - `SortKey`, `SortState`, `sort_accounts`.
  - `EditorDraft::{new, from_account, validate, into_account}`.
  - `MainView` with `show(ctx, accounts, handle) -> bool` (returns true when lock is requested). Task 11 adds a `&SyncStatus` argument before `handle`; Task 14 keeps that signature.

- [ ] **Step 1: Write the failing filter/editor/worker tests**

`ui/filters.rs` tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{Account, Plan};

    #[test]
    fn search_removes_vietnamese_diacritics() {
        assert_eq!(normalize_for_search("Đặng Văn"), "dang van");
        let mut a = Account::new("dang@example.com", "p");
        a.notes = Some("Tài khoản của Đặng".into());
        let f = Filters { text: "dang".into(), ..Default::default() };
        assert!(f.matches(&a));
        let f = Filters { text: "dang van".into(), ..Default::default() };
        assert!(!f.matches(&a));
    }

    #[test]
    fn filters_by_plan_status_and_tag() {
        let mut a = Account::new("a@b.co", "p");
        a.plan = Plan::Pro;
        a.tags = vec!["vip".into()];
        assert!(Filters { plan: Some(Plan::Pro), ..Default::default() }.matches(&a));
        assert!(!Filters { plan: Some(Plan::Ultra), ..Default::default() }.matches(&a));
        assert!(Filters { tag: Some("vip".into()), ..Default::default() }.matches(&a));
    }
}
```

`ui/editor.rs` tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::Account;

    #[test]
    fn draft_commits_changes() {
        let a = Account::new("a@b.co", "p");
        let mut d = EditorDraft::from_account(&a);
        d.account.notes = Some("ghi chú".into());
        let out = d.into_account();
        assert_eq!(out.notes.as_deref(), Some("ghi chú"));
        assert_eq!(out.id, a.id);
    }

    #[test]
    fn draft_rejects_empty_email() {
        let d = EditorDraft::new();
        assert!(d.validate().is_err());
    }
}
```

`workers/vault.rs` tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;
    use vault_core::{create_vault, unwrap_vault_key, LocalMeta, LocalStore};

    #[test]
    fn save_and_delete_roundtrip() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("vault.db");
        let nv = create_vault("pw").unwrap();
        let meta = LocalMeta {
            user_id: nv.user_id, email: "owner@example.com".into(),
            server_url: "http://test".into(), device_label: "PC".into(),
            kdf: nv.kdf.clone(), wrapped_key: nv.wrapped_key.clone(), last_change_seq: 0,
        };
        let mut store = LocalStore::open(&db).unwrap();
        store.save_meta(&meta).unwrap();
        let vault = unwrap_vault_key("pw", nv.user_id, &nv.kdf, &nv.wrapped_key).unwrap();
        let handle = spawn_vault(meta, vault, store, Vec::new(), db.clone(), dir.path().join("backups"));
        let account = Account::new("a@b.co", "p");
        let id = account.id;
        handle.tx.send(VaultCommand::Save(account)).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match handle.rx.recv_timeout(Duration::from_millis(100)) {
                Ok(VaultEvent::Accounts(accounts)) if accounts.len() == 1 => break,
                Ok(_) => {}
                Err(_) if std::time::Instant::now() > deadline => panic!("timeout"),
                Err(_) => {}
            }
        }
        handle.tx.send(VaultCommand::Delete(id)).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match handle.rx.recv_timeout(Duration::from_millis(100)) {
                Ok(VaultEvent::Accounts(accounts)) if accounts.is_empty() => break,
                Ok(_) => {}
                Err(_) if std::time::Instant::now() > deadline => panic!("timeout"),
                Err(_) => {}
            }
        }
        handle.shutdown();
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p vault-client`
Expected: compile errors for `Filters`, `EditorDraft`, `spawn_vault`.

- [ ] **Step 3: Implement filters and editor**

`ui/filters.rs`:

```rust
use unicode_normalization::UnicodeNormalization;
use vault_core::{Account, AccountStatus, Plan};

#[derive(Debug, Clone, Default)]
pub struct Filters {
    pub text: String,
    pub plan: Option<Plan>,
    pub status: Option<AccountStatus>,
    pub tag: Option<String>,
}

pub fn normalize_for_search(input: &str) -> String {
    input
        .to_lowercase()
        .replace('đ', "d")
        .nfd()
        .filter(|c| !unicode_normalization::char::is_combining_mark(*c))
        .collect()
}

impl Filters {
    pub fn matches(&self, account: &Account) -> bool {
        if let Some(plan) = &self.plan {
            if &account.plan != plan { return false; }
        }
        if let Some(status) = &self.status {
            if &account.status != status { return false; }
        }
        if let Some(tag) = &self.tag {
            if !account.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)) { return false; }
        }
        let text = normalize_for_search(self.text.trim());
        if text.is_empty() { return true; }
        let haystack = normalize_for_search(&format!(
            "{} {} {}", account.email, account.notes.clone().unwrap_or_default(), account.tags.join(" ")
        ));
        haystack.contains(&text)
    }

    pub fn apply<'a>(&self, accounts: &'a [Account]) -> Vec<&'a Account> {
        accounts.iter().filter(|a| self.matches(a)).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey { Email, CreatedOn, Plan, Status, ExpiresOn, LastUsedOn, UpdatedAt }

#[derive(Debug, Clone, Copy)]
pub struct SortState { pub key: SortKey, pub descending: bool }

impl Default for SortState {
    fn default() -> Self { Self { key: SortKey::Email, descending: false } }
}

pub fn sort_accounts(rows: &mut [&Account], sort: &SortState) {
    rows.sort_by(|a, b| {
        let ord = match sort.key {
            SortKey::Email => a.normalized_email().cmp(&b.normalized_email()),
            SortKey::CreatedOn => a.created_on.cmp(&b.created_on),
            SortKey::Plan => a.plan.as_str().cmp(b.plan.as_str()),
            SortKey::Status => a.status.as_str().cmp(b.status.as_str()),
            SortKey::ExpiresOn => a.expires_on.cmp(&b.expires_on),
            SortKey::LastUsedOn => a.last_used_on.cmp(&b.last_used_on),
            SortKey::UpdatedAt => a.updated_at.cmp(&b.updated_at),
        };
        if sort.descending { ord.reverse() } else { ord }
    });
}
```

`ui/editor.rs`:

```rust
use chrono::Utc;
use vault_core::Account;

#[derive(Debug, Clone)]
pub struct EditorDraft {
    pub account: Account,
    pub original_password: String,
    pub is_new: bool,
}

impl EditorDraft {
    pub fn new() -> Self {
        Self { account: Account::new("", ""), original_password: String::new(), is_new: true }
    }
    pub fn from_account(account: &Account) -> Self {
        Self { account: account.clone(), original_password: account.password.clone(), is_new: false }
    }

    pub fn validate(&self) -> Result<(), String> {
        self.account.validate().map_err(|e| e.to_string())
    }

    pub fn into_account(mut self) -> Account {
        self.account.updated_at = Utc::now();
        self.account
    }
}
```

- [ ] **Step 4: Implement the worker**

`workers/vault.rs`:

```rust
use std::path::PathBuf;
use std::time::Duration;

use chrono::{Local, Utc};
use crossbeam_channel::{unbounded, Receiver, Sender};
use uuid::Uuid;
use vault_core::{
    backup_database, Account, LocalMeta, LocalStore, RecordRow, UnlockedVault,
};

pub enum VaultCommand {
    Save(Account),
    SaveMany(Vec<Account>),
    Delete(Uuid),
    MarkUsed(Uuid),
    Reload,
    BackupNow,
    Shutdown,
}

pub enum VaultEvent {
    Accounts(Vec<Account>),
    Error(String),
    BackupDone(PathBuf),
}

pub struct VaultHandle {
    pub tx: Sender<VaultCommand>,
    pub rx: Receiver<VaultEvent>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl VaultHandle {
    pub fn shutdown(mut self) {
        let _ = self.tx.send(VaultCommand::Shutdown);
        if let Some(join) = self.join.take() { let _ = join.join(); }
    }
}

struct WorkerState {
    meta: LocalMeta,
    store: LocalStore,
    vault: UnlockedVault,
    accounts: Vec<Account>,
    db_path: PathBuf,
    backup_dir: PathBuf,
}

pub fn spawn_vault(
    meta: LocalMeta,
    vault: UnlockedVault,
    store: LocalStore,
    accounts: Vec<Account>,
    db_path: PathBuf,
    backup_dir: PathBuf,
) -> VaultHandle {
    let (tx, cmd_rx) = unbounded();
    let (evt_tx, rx) = unbounded();
    let worker = std::thread::spawn(move || {
        let mut state = WorkerState { meta, store, vault, accounts, db_path, backup_dir };
        state.accounts.sort_by(|a, b| a.normalized_email().cmp(&b.normalized_email()));
        let _ = evt_tx.send(VaultEvent::Accounts(state.accounts.clone()));
        while let Ok(cmd) = cmd_rx.recv_timeout(Duration::from_millis(500)) {
            match cmd {
                VaultCommand::Save(account) => {
                    if let Err(e) = state.save(account) { let _ = evt_tx.send(VaultEvent::Error(e.to_string())); }
                    let _ = evt_tx.send(VaultEvent::Accounts(state.accounts.clone()));
                }
                VaultCommand::SaveMany(accounts) => {
                    for account in accounts { if let Err(e) = state.save(account) { let _ = evt_tx.send(VaultEvent::Error(e.to_string())); } }
                    let _ = evt_tx.send(VaultEvent::Accounts(state.accounts.clone()));
                }
                VaultCommand::Delete(id) => {
                    if let Err(e) = state.delete(id) { let _ = evt_tx.send(VaultEvent::Error(e.to_string())); }
                    let _ = evt_tx.send(VaultEvent::Accounts(state.accounts.clone()));
                }
                VaultCommand::MarkUsed(id) => {
                    if let Err(e) = state.mark_used(id) { let _ = evt_tx.send(VaultEvent::Error(e.to_string())); }
                    let _ = evt_tx.send(VaultEvent::Accounts(state.accounts.clone()));
                }
                VaultCommand::Reload => {
                    match state.reload() {
                        Ok(()) => { let _ = evt_tx.send(VaultEvent::Accounts(state.accounts.clone())); }
                        Err(e) => { let _ = evt_tx.send(VaultEvent::Error(e.to_string())); }
                    }
                }
                VaultCommand::BackupNow => {
                    match backup_database(&state.db_path, &state.backup_dir, 10) {
                        Ok(path) => { let _ = evt_tx.send(VaultEvent::BackupDone(path)); }
                        Err(e) => { let _ = evt_tx.send(VaultEvent::Error(e.to_string())); }
                    }
                }
                VaultCommand::Shutdown => break,
            }
        }
    });
    VaultHandle { tx, rx, join: Some(worker) }
}

impl WorkerState {
    fn save(&mut self, mut account: Account) -> vault_core::Result<()> {
        account.updated_at = Utc::now();
        account.validate()?;
        let existing = self.store.get_record(account.id)?;
        let enc = self.vault.encrypt_account(&account)?;
        self.store.upsert_record(&RecordRow {
            id: account.id,
            revision: existing.as_ref().map(|r| r.revision).unwrap_or(0),
            change_seq: existing.as_ref().map(|r| r.change_seq).unwrap_or(0),
            updated_at: account.updated_at.timestamp_millis(),
            deleted: false,
            dirty: true,
            nonce: enc.nonce.to_vec(),
            payload: enc.payload,
        })?;
        if let Some(slot) = self.accounts.iter_mut().find(|a| a.id == account.id) {
            *slot = account;
        } else {
            self.accounts.push(account);
        }
        self.accounts.sort_by(|a, b| a.normalized_email().cmp(&b.normalized_email()));
        Ok(())
    }

    fn delete(&mut self, id: Uuid) -> vault_core::Result<()> {
        let existing = self.store.get_record(id)?;
        self.store.upsert_record(&RecordRow {
            id,
            revision: existing.as_ref().map(|r| r.revision).unwrap_or(0),
            change_seq: existing.as_ref().map(|r| r.change_seq).unwrap_or(0),
            updated_at: Utc::now().timestamp_millis(),
            deleted: true,
            dirty: true,
            nonce: Vec::new(),
            payload: Vec::new(),
        })?;
        self.accounts.retain(|a| a.id != id);
        Ok(())
    }

    fn mark_used(&mut self, id: Uuid) -> vault_core::Result<()> {
        let account = self.accounts.iter().find(|a| a.id == id).cloned().ok_or(vault_core::CoreError::NotFound)?;
        let mut account = account;
        account.mark_used(Local::now().date_naive());
        self.save(account)
    }

    fn reload(&mut self) -> vault_core::Result<()> {
        let mut accounts = Vec::new();
        for row in self.store.load_all_records()? {
            if row.deleted { continue; }
            accounts.push(self.vault.decrypt_account(row.id, &row.nonce, &row.payload)?);
        }
        self.accounts = accounts;
        self.accounts.sort_by(|a, b| a.normalized_email().cmp(&b.normalized_email()));
        Ok(())
    }
}
```

`mark_used` must use today's date via `chrono::Local::now().date_naive()`, not a hardcoded date. Use `chrono::Local::now().date_naive()`. Add `chrono::Local` import.

- [ ] **Step 5: Implement the main view and wire the app**

`ui/main.rs`:
- `MainView { filters, sort, selected, draft, confirm_delete }`.
- `show` draws:
  - top toolbar: search field bound to `filters.text`, plan combo, status combo, sort combo, "Sync now" button (sends nothing until Task 11; keep disabled or omitted), "Lock" button returns true.
  - left `SidePanel`: All/Free/Pro/Ultra counts, tags list.
  - right `SidePanel` if `draft` Some: editor fields. Save sends `VaultCommand::Save(draft.clone().into_account())`; Delete toggles `confirm_delete`, then a second "Xác nhận xóa" button sends `Delete`; Mark used sends `MarkUsed`.
  - central `TableBuilder` with columns from spec; row click sets selected and loads draft. When `accounts` is empty, show a centered empty state with a "Tạo tài khoản" button and a hint to import.
  - "New" button sets `draft = Some(EditorDraft::new())`.
- Use `egui_extras::{Column, TableBuilder}`.
- Handle keyboard shortcuts with `ctx.input_mut(|i| i.consume_shortcut(&shortcut))`: `Ctrl+F` focuses the search field, `Ctrl+N` starts a new draft, `Ctrl+L` requests lock, `Esc` closes the editor, and `Ctrl+S` saves the current draft. `Ctrl+Shift+C` copies the selected account password via `security::copy_password`.
- Editor fields bind to `draft.account`; plan/status combos; tags as comma text (temporary string field).
- On save, keep panel open until Accounts event; simple.

`app.rs`:
- Add fields `vault: Option<VaultHandle>`, `accounts: Vec<Account>`, `main_view: MainView`, `last_activity: Instant`.
- On unlock Done: `let handle = spawn_vault(session.meta, session.vault, session.store, session.accounts.clone(), platform::db_path(), platform::backup_dir());` set accounts, screen Main.
- `update`: poll `handle.rx.try_recv()` in a loop; on Accounts set accounts; on Error set error; on BackupDone set toast.
- If screen Main: `if self.main_view.show(ctx, &self.accounts, handle) { self.lock(); }`.
- `lock()`: send Shutdown, drop handle, clear accounts, screen Unlock.
- Auto-lock wiring comes in Task 12.

- [ ] **Step 6: Run tests and commit**

Run: `cargo test -p vault-client`
Expected: 8 tests pass (4 existing + 4 new).

Run: `cargo run -p vault-client` and create a test vault against a local server (Task 15 E2E).
Expected: table appears, can add/edit/delete/search.

```bash
git add crates/vault-client
git commit -m "feat(client): add vault worker, table, filters, and editor"
```


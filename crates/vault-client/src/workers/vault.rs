use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{Local, Utc};
use crossbeam_channel::{Receiver, Sender, unbounded};
use uuid::Uuid;
use vault_core::sync::{SyncApi, SyncEngine};
use vault_core::{Account, LocalMeta, LocalStore, RecordRow, UnlockedVault, backup_database};

use crate::state::SyncStatus;

#[allow(dead_code)]
#[allow(clippy::large_enum_variant)]
pub enum VaultCommand {
    Save(Account),
    SaveMany(Vec<Account>),
    Delete(Uuid),
    MarkUsed(Uuid),
    Reload,
    BackupNow,
    SyncNow,
    Shutdown,
}

#[allow(dead_code)]
#[allow(clippy::large_enum_variant)]
pub enum VaultEvent {
    Accounts(Vec<Account>),
    Error(String),
    BackupDone(PathBuf),
    SyncStatus(SyncStatus),
}

pub struct VaultHandle {
    pub tx: Sender<VaultCommand>,
    pub rx: Receiver<VaultEvent>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl VaultHandle {
    pub fn shutdown(mut self) {
        let _ = self.tx.send(VaultCommand::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for VaultHandle {
    fn drop(&mut self) {
        let _ = self.tx.send(VaultCommand::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[allow(dead_code)]
struct WorkerState {
    meta: LocalMeta,
    store: LocalStore,
    vault: UnlockedVault,
    accounts: Vec<Account>,
    db_path: PathBuf,
    backup_dir: PathBuf,
    sync_api: Arc<dyn SyncApi>,
    sync_interval: Duration,
    rt: tokio::runtime::Runtime,
    last_sync: Option<Instant>,
    last_attempt: Option<Instant>,
    status: SyncStatus,
}

// Worker constructor needs its whole context; a struct for it would have exactly one caller.
#[allow(clippy::too_many_arguments)]
pub fn spawn_vault(
    meta: LocalMeta,
    vault: UnlockedVault,
    store: LocalStore,
    accounts: Vec<Account>,
    db_path: PathBuf,
    backup_dir: PathBuf,
    sync_api: Arc<dyn SyncApi>,
    sync_interval: Duration,
) -> VaultHandle {
    let (tx, cmd_rx) = unbounded();
    let (evt_tx, rx) = unbounded();
    let worker = std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = evt_tx.send(VaultEvent::Error(format!(
                    "Failed to create async runtime: {e}"
                )));
                return;
            }
        };

        let mut state = WorkerState {
            meta,
            store,
            vault,
            accounts,
            db_path,
            backup_dir,
            sync_api,
            sync_interval,
            rt,
            last_sync: None,
            last_attempt: None,
            status: SyncStatus::default(),
        };

        let pending = state.store.count_dirty().unwrap_or(0);
        state.status.pending = pending;
        state.accounts.sort_by_key(|a| a.normalized_email());
        let _ = evt_tx.send(VaultEvent::Accounts(state.accounts.clone()));
        let _ = evt_tx.send(VaultEvent::SyncStatus(state.status.clone()));

        if state.status.pending > 0 {
            state.sync_and_emit(&evt_tx);
        }

        loop {
            match cmd_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(cmd) => match cmd {
                    VaultCommand::Save(account) => {
                        if let Err(e) = state.save(account) {
                            let _ = evt_tx.send(VaultEvent::Error(e.to_string()));
                        }
                        let _ = evt_tx.send(VaultEvent::Accounts(state.accounts.clone()));
                        state.sync_and_emit(&evt_tx);
                    }
                    VaultCommand::SaveMany(accounts) => {
                        for account in accounts {
                            if let Err(e) = state.save(account) {
                                let _ = evt_tx.send(VaultEvent::Error(e.to_string()));
                            }
                        }
                        let _ = evt_tx.send(VaultEvent::Accounts(state.accounts.clone()));
                        state.sync_and_emit(&evt_tx);
                    }
                    VaultCommand::Delete(id) => {
                        if let Err(e) = state.delete(id) {
                            let _ = evt_tx.send(VaultEvent::Error(e.to_string()));
                        }
                        let _ = evt_tx.send(VaultEvent::Accounts(state.accounts.clone()));
                        state.sync_and_emit(&evt_tx);
                    }
                    VaultCommand::MarkUsed(id) => {
                        if let Err(e) = state.mark_used(id) {
                            let _ = evt_tx.send(VaultEvent::Error(e.to_string()));
                        }
                        let _ = evt_tx.send(VaultEvent::Accounts(state.accounts.clone()));
                        state.sync_and_emit(&evt_tx);
                    }
                    VaultCommand::Reload => match state.reload() {
                        Ok(()) => {
                            let _ = evt_tx.send(VaultEvent::Accounts(state.accounts.clone()));
                        }
                        Err(e) => {
                            let _ = evt_tx.send(VaultEvent::Error(e.to_string()));
                        }
                    },
                    VaultCommand::BackupNow => {
                        match backup_database(&state.db_path, &state.backup_dir, 10) {
                            Ok(path) => {
                                let _ = evt_tx.send(VaultEvent::BackupDone(path));
                            }
                            Err(e) => {
                                let _ = evt_tx.send(VaultEvent::Error(e.to_string()));
                            }
                        }
                    }
                    VaultCommand::SyncNow => {
                        state.sync_and_emit(&evt_tx);
                    }
                    VaultCommand::Shutdown => break,
                },
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    let throttled = state
                        .last_attempt
                        .map(|t| t.elapsed() < Duration::from_secs(5))
                        .unwrap_or(false);
                    let interval_elapsed = state
                        .last_sync
                        .map(|t| t.elapsed() >= state.sync_interval)
                        .unwrap_or(true);
                    if !throttled && (interval_elapsed || state.status.pending > 0) {
                        state.sync_and_emit(&evt_tx);
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            }
        }
    });
    VaultHandle {
        tx,
        rx,
        join: Some(worker),
    }
}

impl WorkerState {
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
                self.last_sync = Some(Instant::now());
                self.status.last_error = None;
                let _ = self.reload();
                self.status.conflicts = self
                    .accounts
                    .iter()
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

    fn sync_and_emit(&mut self, evt_tx: &Sender<VaultEvent>) {
        self.last_attempt = Some(Instant::now());
        self.last_sync = Some(Instant::now());
        self.status.syncing = true;
        let _ = evt_tx.send(VaultEvent::SyncStatus(self.status.clone()));
        let status = self.sync_now();
        let _ = evt_tx.send(VaultEvent::Accounts(self.accounts.clone()));
        let _ = evt_tx.send(VaultEvent::SyncStatus(status));
    }

    fn save(&mut self, mut account: Account) -> vault_core::Result<()> {
        account.updated_at = Utc::now();
        account.validate()?;
        let existing = self.store.get_record(account.id)?;
        let (revision, change_seq) = match existing {
            Some(r) => (r.revision, r.change_seq),
            None => (0, 0),
        };
        let enc = self.vault.encrypt_account(&account)?;
        self.store.upsert_record(&RecordRow {
            id: account.id,
            revision,
            change_seq,
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
        self.accounts.sort_by_key(|a| a.normalized_email());
        Ok(())
    }

    fn delete(&mut self, id: Uuid) -> vault_core::Result<()> {
        let existing = self.store.get_record(id)?;
        let (revision, change_seq) = match existing {
            Some(r) => (r.revision, r.change_seq),
            None => (0, 0),
        };
        self.store.upsert_record(&RecordRow {
            id,
            revision,
            change_seq,
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
        let mut account = self
            .accounts
            .iter()
            .find(|a| a.id == id)
            .cloned()
            .ok_or(vault_core::CoreError::NotFound)?;
        account.mark_used(Local::now().date_naive());
        self.save(account)
    }

    fn reload(&mut self) -> vault_core::Result<()> {
        let mut accounts = Vec::new();
        for row in self.store.load_all_records()? {
            if row.deleted {
                continue;
            }
            accounts.push(
                self.vault
                    .decrypt_account(row.id, &row.nonce, &row.payload)?,
            );
        }
        self.accounts = accounts;
        self.accounts.sort_by_key(|a| a.normalized_email());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;
    use vault_core::{LocalMeta, LocalStore, create_vault, unwrap_vault_key};

    struct NoopApi;

    #[async_trait::async_trait]
    impl SyncApi for NoopApi {
        async fn pull(
            &self,
            since: u64,
            _limit: u32,
        ) -> vault_core::Result<vault_core::sync::PullResponse> {
            Ok(vault_core::sync::PullResponse {
                items: Vec::new(),
                next_since: since,
                has_more: false,
            })
        }

        async fn push(
            &self,
            _items: Vec<vault_core::sync::PushItem>,
        ) -> vault_core::Result<vault_core::sync::PushResponse> {
            Ok(vault_core::sync::PushResponse {
                accepted: Vec::new(),
                conflicts: Vec::new(),
            })
        }
    }

    #[test]
    fn save_and_delete_roundtrip() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("vault.db");
        let nv = create_vault("pw").unwrap();
        let meta = LocalMeta {
            user_id: nv.user_id,
            email: "owner@example.com".into(),
            server_url: "http://test".into(),
            device_label: "PC".into(),
            kdf: nv.kdf.clone(),
            wrapped_key: nv.wrapped_key.clone(),
            last_change_seq: 0,
        };
        let mut store = LocalStore::open(&db).unwrap();
        store.save_meta(&meta).unwrap();
        let vault = unwrap_vault_key("pw", nv.user_id, &nv.kdf, &nv.wrapped_key).unwrap();
        let handle = spawn_vault(
            meta,
            vault,
            store,
            Vec::new(),
            db.clone(),
            dir.path().join("backups"),
            Arc::new(NoopApi),
            Duration::from_secs(3600),
        );
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
        assert!(db.exists());
    }
}

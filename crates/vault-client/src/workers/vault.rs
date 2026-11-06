use std::path::PathBuf;
use std::time::Duration;

use chrono::{Local, Utc};
use crossbeam_channel::{Receiver, Sender, unbounded};
use uuid::Uuid;
use vault_core::{Account, LocalMeta, LocalStore, RecordRow, UnlockedVault, backup_database};

#[allow(dead_code)]
#[allow(clippy::large_enum_variant)]
pub enum VaultCommand {
    Save(Account),
    SaveMany(Vec<Account>),
    Delete(Uuid),
    MarkUsed(Uuid),
    Reload,
    BackupNow,
    Shutdown,
}

#[allow(dead_code)]
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
        let mut state = WorkerState {
            meta,
            store,
            vault,
            accounts,
            db_path,
            backup_dir,
        };
        state
            .accounts
            .sort_by(|a, b| a.normalized_email().cmp(&b.normalized_email()));
        let _ = evt_tx.send(VaultEvent::Accounts(state.accounts.clone()));
        loop {
            match cmd_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(cmd) => match cmd {
                    VaultCommand::Save(account) => {
                        if let Err(e) = state.save(account) {
                            let _ = evt_tx.send(VaultEvent::Error(e.to_string()));
                        }
                        let _ = evt_tx.send(VaultEvent::Accounts(state.accounts.clone()));
                    }
                    VaultCommand::SaveMany(accounts) => {
                        for account in accounts {
                            if let Err(e) = state.save(account) {
                                let _ = evt_tx.send(VaultEvent::Error(e.to_string()));
                            }
                        }
                        let _ = evt_tx.send(VaultEvent::Accounts(state.accounts.clone()));
                    }
                    VaultCommand::Delete(id) => {
                        if let Err(e) = state.delete(id) {
                            let _ = evt_tx.send(VaultEvent::Error(e.to_string()));
                        }
                        let _ = evt_tx.send(VaultEvent::Accounts(state.accounts.clone()));
                    }
                    VaultCommand::MarkUsed(id) => {
                        if let Err(e) = state.mark_used(id) {
                            let _ = evt_tx.send(VaultEvent::Error(e.to_string()));
                        }
                        let _ = evt_tx.send(VaultEvent::Accounts(state.accounts.clone()));
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
                    VaultCommand::Shutdown => break,
                },
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
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
        self.accounts
            .sort_by(|a, b| a.normalized_email().cmp(&b.normalized_email()));
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
        self.accounts
            .sort_by(|a, b| a.normalized_email().cmp(&b.normalized_email()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;
    use vault_core::{LocalMeta, LocalStore, create_vault, unwrap_vault_key};

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

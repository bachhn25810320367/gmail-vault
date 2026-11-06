use std::path::PathBuf;

use crossbeam_channel::{Receiver, bounded};
use vault_core::{Account, LocalMeta, LocalStore, UnlockedVault, unwrap_vault_key};

use crate::state::UnlockedSession;

pub enum UnlockEvent {
    Done(Box<UnlockedSession>),
    Failed(String),
}

pub fn start_unlock(meta: LocalMeta, password: String, db_path: PathBuf) -> Receiver<UnlockEvent> {
    let (tx, rx) = bounded(1);
    std::thread::spawn(move || {
        let result = (|| -> Result<UnlockedSession, String> {
            let store = LocalStore::open(&db_path).map_err(|e| e.to_string())?;
            let vault: UnlockedVault =
                unwrap_vault_key(&password, meta.user_id, &meta.kdf, &meta.wrapped_key)
                    .map_err(|e| e.to_string())?;
            let mut accounts: Vec<Account> = Vec::new();
            for row in store.load_all_records().map_err(|e| e.to_string())? {
                if row.deleted {
                    continue;
                }
                let account = vault
                    .decrypt_account(row.id, &row.nonce, &row.payload)
                    .map_err(|e| e.to_string())?;
                accounts.push(account);
            }
            Ok(UnlockedSession {
                meta,
                store,
                vault,
                accounts,
            })
        })();
        let _ = tx.send(match result {
            Ok(s) => UnlockEvent::Done(Box::new(s)),
            Err(e) => UnlockEvent::Failed(e),
        });
    });
    rx
}

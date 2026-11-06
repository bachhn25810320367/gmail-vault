use chrono::{DateTime, Utc};
use vault_core::{Account, LocalMeta, LocalStore, UnlockedVault};

use crate::config::ClientConfig;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Setup,
    ShowRecovery,
    Unlock,
    Main,
    Fatal,
}

#[derive(Debug, Clone, Default)]
pub struct SetupForm {
    pub server_url: String,
    pub email: String,
    pub password: String,
    pub confirm: String,
}

impl SetupForm {
    pub fn from_config(config: &ClientConfig) -> Self {
        Self {
            server_url: config.server_url.clone(),
            email: config.email.clone().unwrap_or_default(),
            password: String::new(),
            confirm: String::new(),
        }
    }
}

pub struct UnlockedSession {
    pub meta: LocalMeta,
    pub store: LocalStore,
    pub vault: UnlockedVault,
    pub accounts: Vec<Account>,
}

#[derive(Debug, Clone, Default)]
pub struct SyncStatus {
    pub online: bool,
    pub syncing: bool,
    pub last_sync: Option<DateTime<Utc>>,
    pub pending: usize,
    pub last_error: Option<String>,
    pub conflicts: usize,
}

impl SyncStatus {
    pub fn pending_label(&self) -> String {
        if self.pending > 0 {
            format!("{} thay đổi chờ", self.pending)
        } else if self.online {
            "Đã đồng bộ".into()
        } else {
            "Offline".into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_label_is_vietnamese() {
        let status = SyncStatus {
            pending: 3,
            ..Default::default()
        };
        assert_eq!(status.pending_label(), "3 thay đổi chờ");
        let status = SyncStatus {
            pending: 0,
            online: true,
            ..Default::default()
        };
        assert_eq!(status.pending_label(), "Đã đồng bộ");
    }
}

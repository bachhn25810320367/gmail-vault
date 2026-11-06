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

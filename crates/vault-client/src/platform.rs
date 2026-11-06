use std::path::PathBuf;

use directories::ProjectDirs;

pub fn app_data_dir() -> PathBuf {
    ProjectDirs::from("com", "gmailvault", "GmailVault")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn config_path() -> PathBuf {
    app_data_dir().join("config.json")
}

pub fn db_path() -> PathBuf {
    app_data_dir().join("vault.db")
}

#[allow(dead_code)]
pub fn backup_dir() -> PathBuf {
    app_data_dir().join("backups")
}

fn entry(server: &str, email: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new("gmail-vault", &format!("{server}|{email}")).map_err(|e| e.to_string())
}

pub fn save_refresh(server: &str, email: &str, token: &str) -> Result<(), String> {
    entry(server, email)?
        .set_password(token)
        .map_err(|e| e.to_string())
}

pub fn load_refresh(server: &str, email: &str) -> Result<Option<String>, String> {
    match entry(server, email)?.get_password() {
        Ok(v) => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

#[allow(dead_code)]
pub fn delete_refresh(server: &str, email: &str) -> Result<(), String> {
    match entry(server, email)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

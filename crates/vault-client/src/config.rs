use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThemePref {
    System,
    Light,
    Dark,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientConfig {
    pub server_url: String,
    pub email: Option<String>,
    pub device_label: String,
    pub sync_interval_secs: u64,
    pub auto_lock_minutes: u64,
    pub clipboard_secs: u64,
    pub theme: ThemePref,
}

impl Default for ClientConfig {
    fn default() -> Self {
        let device_label = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "My PC".into());
        Self {
            server_url: "https://vault.example.com".into(),
            email: None,
            device_label,
            sync_interval_secs: 60,
            auto_lock_minutes: 5,
            clipboard_secs: 30,
            theme: ThemePref::System,
        }
    }
}

impl ClientConfig {
    pub fn load(path: &Path) -> Self {
        let mut cfg: Self = std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        cfg.sync_interval_secs = cfg.sync_interval_secs.clamp(15, 600);
        cfg.auto_lock_minutes = cfg.auto_lock_minutes.clamp(1, 30);
        cfg.clipboard_secs = cfg.clipboard_secs.clamp(10, 120);
        cfg
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let raw = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, raw).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn config_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");
        let mut cfg = ClientConfig::default();
        cfg.email = Some("owner@example.com".into());
        cfg.sync_interval_secs = 120;
        cfg.save(&path).unwrap();
        let loaded = ClientConfig::load(&path);
        assert_eq!(loaded.email, cfg.email);
        assert_eq!(loaded.sync_interval_secs, 120);
    }

    #[test]
    fn missing_file_uses_defaults() {
        let dir = tempdir().unwrap();
        let cfg = ClientConfig::load(&dir.path().join("missing.json"));
        assert_eq!(cfg.auto_lock_minutes, 5);
        assert_eq!(cfg.clipboard_secs, 30);
    }

    #[test]
    fn load_clamps_settings_to_supported_ranges() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");
        let mut cfg = ClientConfig::default();
        cfg.sync_interval_secs = 1;
        cfg.auto_lock_minutes = 0;
        cfg.clipboard_secs = 999;
        cfg.save(&path).unwrap();
        let loaded = ClientConfig::load(&path);
        assert_eq!(loaded.sync_interval_secs, 15);
        assert_eq!(loaded.auto_lock_minutes, 1);
        assert_eq!(loaded.clipboard_secs, 120);
    }
}

## Task 9: Client scaffold, setup, and unlock

**Files:**
- Modify: `Cargo.toml` (add client workspace dependencies)
- Modify: `crates/vault-client/Cargo.toml`
- Create: `crates/vault-client/src/main.rs`
- Create: `crates/vault-client/src/app.rs`
- Create: `crates/vault-client/src/config.rs`
- Create: `crates/vault-client/src/platform.rs`
- Create: `crates/vault-client/src/api.rs`
- Create: `crates/vault-client/src/state.rs`
- Create: `crates/vault-client/src/ui/mod.rs`
- Create: `crates/vault-client/src/ui/setup.rs`
- Create: `crates/vault-client/src/ui/unlock.rs`

**Interfaces:**
- Consumes: `vault_core::{create_vault, unwrap_vault_key, LocalStore, LocalMeta, Account, KdfParams, WrappedKey}`.
- Produces:
  - `ClientConfig::{load, save}`.
  - `VaultApi::{new, prelogin, register, login, recover_login, refresh, get_keys, put_keys}`.
  - `Screen`, `SetupForm`, `UnlockedSession`.
  - `validate_setup`, `start_setup`, `start_unlock`.
  - `VaultApp` implementing `eframe::App`.

- [ ] **Step 1: Add client dependencies**

Append to root `[workspace.dependencies]`:

```toml
eframe = "0.32"
egui = "0.32"
egui_extras = "0.32"
rfd = "0.15"
arboard = "3"
keyring = "3"
crossbeam-channel = "0.5"
```

Replace `crates/vault-client/Cargo.toml`:

```toml
[package]
name = "vault-client"
version.workspace = true
edition.workspace = true
license.workspace = true

[[bin]]
name = "gmail-vault"
path = "src/main.rs"

[dependencies]
vault-core = { path = "../vault-core" }
eframe.workspace = true
egui.workspace = true
egui_extras.workspace = true
serde.workspace = true
serde_json.workspace = true
chrono.workspace = true
uuid.workspace = true
tokio.workspace = true
crossbeam-channel.workspace = true
rfd.workspace = true
arboard.workspace = true
keyring.workspace = true
reqwest.workspace = true
thiserror.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
directories.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

- [ ] **Step 2: Write the failing client tests**

`config.rs`:

```rust
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
```

`ui/setup.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_setup_rejects_bad_input() {
        assert!(validate_setup("https://vault.example.com", "a@b.co", "long-enough-pass", "long-enough-pass").is_ok());
        assert!(validate_setup("vault.example.com", "a@b.co", "long-enough-pass", "long-enough-pass").is_err());
        assert!(validate_setup("https://vault.example.com", "bad", "long-enough-pass", "long-enough-pass").is_err());
        assert!(validate_setup("https://vault.example.com", "a@b.co", "short", "short").is_err());
        assert!(validate_setup("https://vault.example.com", "a@b.co", "long-enough-pass", "different-pass").is_err());
    }
}
```

`api.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::create_vault;

    #[test]
    fn register_request_uses_base64_strings() {
        let nv = create_vault("password-123").unwrap();
        let req = RegisterRequest {
            user_id: nv.user_id,
            email: "owner@example.com".into(),
            auth_key: nv.auth_key.to_vec(),
            kdf: nv.kdf.clone(),
            wrapped_key: nv.wrapped_key.clone(),
            recovery_wrapped_key: nv.recovery.wrapped_key.clone(),
            recovery_auth_key: nv.recovery.auth_key.to_vec(),
        };
        let value = serde_json::to_value(&req).unwrap();
        assert!(value["auth_key"].is_string());
        assert!(value["kdf"]["salt"].is_string());
        assert!(value["wrapped_key"]["nonce"].is_string());
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p vault-client`
Expected: compile error because the modules do not exist.

- [ ] **Step 4: Implement config, platform, and API client**

`config.rs`:

```rust
use std::path::Path;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThemePref { System, Light, Dark }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
        let device_label = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "My PC".into());
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
        let mut cfg: Self = std::fs::read(path).ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        cfg.sync_interval_secs = cfg.sync_interval_secs.clamp(15, 600);
        cfg.auto_lock_minutes = cfg.auto_lock_minutes.clamp(1, 30);
        cfg.clipboard_secs = cfg.clipboard_secs.clamp(10, 120);
        cfg
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
        let raw = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, raw).map_err(|e| e.to_string())
    }
}
```

`platform.rs`:

```rust
use std::path::PathBuf;
use directories::ProjectDirs;

pub fn app_data_dir() -> PathBuf {
    ProjectDirs::from("com", "gmailvault", "GmailVault")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn config_path() -> PathBuf { app_data_dir().join("config.json") }
pub fn db_path() -> PathBuf { app_data_dir().join("vault.db") }
pub fn backup_dir() -> PathBuf { app_data_dir().join("backups") }

fn entry(server: &str, email: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new("gmail-vault", &format!("{server}|{email}")).map_err(|e| e.to_string())
}

pub fn save_refresh(server: &str, email: &str, token: &str) -> Result<(), String> {
    entry(server, email)?.set_password(token).map_err(|e| e.to_string())
}

pub fn load_refresh(server: &str, email: &str) -> Result<Option<String>, String> {
    match entry(server, email)?.get_password() {
        Ok(v) => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

pub fn delete_refresh(server: &str, email: &str) -> Result<(), String> {
    match entry(server, email)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}
```

`api.rs`:

```rust
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vault_core::{KdfParams, WrappedKey};

use crate::platform;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("network error: {0}")]
    Network(String),
    #[error("{message}")]
    Server { status: u16, code: String, message: String },
    #[error("unauthorized")]
    Unauthorized,
}

#[derive(Serialize)]
pub struct RegisterRequest {
    pub user_id: Uuid,
    pub email: String,
    #[serde(with = "vault_core::codec::base64")]
    pub auth_key: Vec<u8>,
    pub kdf: KdfParams,
    pub wrapped_key: WrappedKey,
    pub recovery_wrapped_key: WrappedKey,
    #[serde(with = "vault_core::codec::base64")]
    pub recovery_auth_key: Vec<u8>,
}

#[derive(Deserialize, Clone)]
pub struct AuthResponse {
    pub user_id: Uuid,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: usize,
    pub kdf: KdfParams,
    pub wrapped_key: WrappedKey,
    #[serde(default)]
    pub recovery_wrapped_key: Option<WrappedKey>,
}

#[derive(Debug, Deserialize)]
pub struct PreloginResponse {
    pub kdf: KdfParams,
}

#[derive(Debug, Deserialize, Clone)]
pub struct KeysResponse {
    pub kdf: KdfParams,
    pub wrapped_key: WrappedKey,
    #[serde(default)]
    pub recovery_wrapped_key: Option<WrappedKey>,
}

#[derive(Serialize)]
pub struct PutKeysRequest {
    pub kdf: KdfParams,
    pub wrapped_key: WrappedKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_wrapped_key: Option<WrappedKey>,
    #[serde(skip_serializing_if = "Option::is_none", with = "vault_core::codec::base64_option")]
    pub recovery_auth_key: Option<Vec<u8>>,
}

#[derive(Clone)]
pub struct VaultApi {
    base_url: String,
    http: reqwest::Client,
    access: Arc<Mutex<Option<String>>>,
    server_url: String,
    email: Arc<Mutex<String>>,
}
```

Methods:
- `new(server_url)` trims trailing `/`, builds `reqwest::Client::builder().timeout(Duration::from_secs(30))`.
- `prelogin(&self, email)` GET `/v1/auth/kdf?email=<urlencoded>` → `PreloginResponse`; used by a new device before it can derive `auth_key`.
- `register(&self, req)` POST `/v1/auth/register`, status 201/200, parse AuthResponse, call `store_tokens`. Registration doesn't know the refresh keychain email? It has req.email; store `server_url` + email.
- `login(&self, email, auth_key: &[u8])` POST, store tokens.
- `recover_login(&self, email, recovery_auth_key: &[u8])`.
- `refresh()` gets token from keychain via `self.email`, POST `/v1/auth/refresh`, store new.
- `get_keys()` GET authorized, on 401 refresh once and retry.
- `put_keys(req)` PUT authorized, expect 204, same refresh retry.
- `store_tokens(&self, email, response)` sets access, saves refresh via platform, sets email.
- `set_email(&self, email: &str)` sets the keychain lookup email without touching tokens; used after loading local meta and before the first login/refresh.
- `authorized_get`/`authorized_put` helper with `send_with_retry`.

Error mapping: parse body `{error:{code,message}}`; status 401 → Unauthorized.

Simplify: `async fn send(&self, method, path, body: Option<Value>, auth: bool) -> Result<reqwest::Response, ApiError>`.

`state.rs`:

```rust
use vault_core::{Account, LocalMeta, LocalStore, UnlockedVault};
use crate::config::ClientConfig;

pub enum Screen { Setup, ShowRecovery, Unlock, Main, Fatal }

pub struct SetupForm {
    pub server_url: String,
    pub email: String,
    pub password: String,
    pub confirm: String,
}

pub struct UnlockedSession {
    pub meta: LocalMeta,
    pub store: LocalStore,
    pub vault: UnlockedVault,
    pub accounts: Vec<Account>,
}
```

`VaultApp` stores `recovery_code: Option<String>` and `error: Option<String>`; `Screen` remains data-free. Task 14 replaces `recovery_code` with `RecoveryDisplay` when recovery login is added.

`ui/setup.rs`:

```rust
use crossbeam_channel::{bounded, Receiver};
use vault_core::{create_vault, LocalMeta, LocalStore};

use crate::api::{RegisterRequest, VaultApi};
use crate::config::ClientConfig;
use crate::platform;

pub enum SetupEvent { Done { recovery_code: String }, Failed(String) }

pub fn validate_setup(server_url: &str, email: &str, password: &str, confirm: &str) -> Result<(), String> {
    if !(server_url.starts_with("https://") || server_url.starts_with("http://")) {
        return Err("Server URL phải bắt đầu bằng https:// hoặc http://".into());
    }
    if !email.contains('@') || !email.split('@').nth(1).map(|d| d.contains('.')).unwrap_or(false) {
        return Err("Email không hợp lệ".into());
    }
    if password.chars().count() < 12 {
        return Err("Master password phải dài ít nhất 12 ký tự".into());
    }
    if password != confirm {
        return Err("Mật khẩu xác nhận không khớp".into());
    }
    Ok(())
}

pub fn start_setup(config: ClientConfig, email: String, password: String) -> Receiver<SetupEvent> {
    let (tx, rx) = bounded(1);
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => { let _ = tx.send(SetupEvent::Failed(e.to_string())); return; }
        };
        let result = rt.block_on(async {
            let nv = create_vault(&password).map_err(|e| e.to_string())?;
            let api = VaultApi::new(&config.server_url);
            let req = RegisterRequest {
                user_id: nv.user_id,
                email: email.clone(),
                auth_key: nv.auth_key.to_vec(),
                kdf: nv.kdf.clone(),
                wrapped_key: nv.wrapped_key.clone(),
                recovery_wrapped_key: nv.recovery.wrapped_key.clone(),
                recovery_auth_key: nv.recovery.auth_key.to_vec(),
            };
            api.register(&req).await.map_err(|e| e.to_string())?;
            let mut store = LocalStore::open(&platform::db_path()).map_err(|e| e.to_string())?;
            let meta = LocalMeta {
                user_id: nv.user_id,
                email: email.clone(),
                server_url: config.server_url.clone(),
                device_label: config.device_label.clone(),
                kdf: nv.kdf.clone(),
                wrapped_key: nv.wrapped_key.clone(),
                last_change_seq: 0,
            };
            store.save_meta(&meta).map_err(|e| e.to_string())?;
            Ok::<_, String>(nv.recovery.display.clone())
        });
        let _ = tx.send(match result {
            Ok(code) => SetupEvent::Done { recovery_code: code },
            Err(e) => SetupEvent::Failed(e),
        });
    });
    rx
}
```

`ui/unlock.rs`:

```rust
use std::path::PathBuf;

use crossbeam_channel::{bounded, Receiver};
use vault_core::{unwrap_vault_key, Account, LocalMeta, LocalStore, UnlockedVault};

use crate::state::UnlockedSession;

pub enum UnlockEvent { Done(UnlockedSession), Failed(String) }

pub fn start_unlock(meta: LocalMeta, password: String, db_path: PathBuf) -> Receiver<UnlockEvent> {
    let (tx, rx) = bounded(1);
    std::thread::spawn(move || {
        let result = (|| -> Result<UnlockedSession, String> {
            let store = LocalStore::open(&db_path).map_err(|e| e.to_string())?;
            let vault = unwrap_vault_key(&password, meta.user_id, &meta.kdf, &meta.wrapped_key)
                .map_err(|e| e.to_string())?;
            let mut accounts = Vec::new();
            for row in store.load_all_records().map_err(|e| e.to_string())? {
                if row.deleted { continue; }
                let account = vault.decrypt_account(row.id, &row.nonce, &row.payload).map_err(|e| e.to_string())?;
                accounts.push(account);
            }
            Ok(UnlockedSession { meta, store, vault, accounts })
        })();
        let _ = tx.send(match result {
            Ok(s) => UnlockEvent::Done(s),
            Err(e) => UnlockEvent::Failed(e),
        });
    });
    rx
}
```

`app.rs`: define `VaultApp` with the fields above; store `recovery_code` and `error` as app fields, not inside `Screen`. Implement `new`, `update`, `render_setup`, `render_recovery`, `render_unlock`, `render_placeholder_main`. Use `egui::CentralPanel`, `TextEdit::singleline().password(true)`. `Screen` transitions.

`main.rs`: initialize tracing, run eframe.

- [ ] **Step 5: Run tests and commit**

Run: `cargo test -p vault-client`
Expected: 4 tests pass.

Run: `cargo run -p vault-client`
Expected: app window opens with Setup screen (server may not exist; entering data fails gracefully).

```bash
git add Cargo.toml crates/vault-client
git commit -m "feat(client): add setup, unlock, config, and API client"
```


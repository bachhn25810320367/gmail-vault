use crossbeam_channel::{Receiver, bounded};
use vault_core::{LocalMeta, LocalStore, create_vault};

use crate::api::{RegisterRequest, VaultApi};
use crate::config::ClientConfig;
use crate::platform;

pub enum SetupEvent {
    Done { recovery_code: String },
    Failed(String),
}

pub fn validate_setup(
    server_url: &str,
    email: &str,
    password: &str,
    confirm: &str,
) -> Result<(), String> {
    if !(server_url.starts_with("https://") || server_url.starts_with("http://")) {
        return Err("Server URL phải bắt đầu bằng https:// hoặc http://".into());
    }
    if !email.contains('@')
        || !email
            .split('@')
            .nth(1)
            .map(|d| d.contains('.'))
            .unwrap_or(false)
    {
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
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = tx.send(SetupEvent::Failed(e.to_string()));
                return;
            }
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
            Ok(code) => SetupEvent::Done {
                recovery_code: code,
            },
            Err(e) => SetupEvent::Failed(e),
        });
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_setup_rejects_bad_input() {
        assert!(
            validate_setup(
                "https://vault.example.com",
                "a@b.co",
                "long-enough-pass",
                "long-enough-pass"
            )
            .is_ok()
        );
        assert!(
            validate_setup(
                "vault.example.com",
                "a@b.co",
                "long-enough-pass",
                "long-enough-pass"
            )
            .is_err()
        );
        assert!(
            validate_setup(
                "https://vault.example.com",
                "bad",
                "long-enough-pass",
                "long-enough-pass"
            )
            .is_err()
        );
        assert!(validate_setup("https://vault.example.com", "a@b.co", "short", "short").is_err());
        assert!(
            validate_setup(
                "https://vault.example.com",
                "a@b.co",
                "long-enough-pass",
                "different-pass"
            )
            .is_err()
        );
    }
}

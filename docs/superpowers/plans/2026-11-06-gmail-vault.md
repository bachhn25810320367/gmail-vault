# Gmail Vault Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local-first, end-to-end encrypted Rust desktop app that manages Gmail accounts and syncs ciphertext records to a self-hosted server.

**Architecture:** Cargo workspace with `vault-core` (model, crypto, local SQLite, sync engine, import/export), `vault-server` (axum + SQLite WAL + JWT auth), and `vault-client` (eframe/egui). The client owns a background `VaultService` that holds the decrypted vault key, SQLite connection, and sync loop; the UI never touches keys or disks directly. Records sync by revision and per-user `change_seq`; conflicts are preserved as conflict copies.

**Tech Stack:** Rust 2024, eframe/egui, rusqlite, sqlx (SQLite), axum, Argon2id, XChaCha20-Poly1305, reqwest, tokio.

**Spec:** `docs/superpowers/specs/2026-11-06-gmail-vault-design.md`

## Global Constraints

- Rust edition 2024, stable toolchain 1.99 or newer.
- Argon2id: `m=65536 KiB`, `t=3`, `p=2`, output 32 bytes, salt 16 bytes.
- AEAD: XChaCha20-Poly1305, 24-byte random nonce per record.
- Access token 15 minutes; refresh token 30 days, rotated and hashed with SHA-256 in the server DB.
- Sync push batch max 200 records, request body max 2 MiB, one record payload max 64 KiB after CBOR serialization.
- Record AAD: `gmail-vault:v1:record:<user_id>:<record_id>`; wrap AAD: `gmail-vault:v1:user:<user_id>`; recovery wrap AAD: `gmail-vault:v1:recovery:<user_id>`.
- UI copy is Vietnamese; dates display as `dd/MM/yyyy`; default currencies VND and USD.
- Auto-lock default 5 minutes; clipboard clear default 30 seconds.
- Server binds `127.0.0.1:8080`; Caddy terminates TLS; systemd runs the binary as user `vault`.
- Never log passwords, `auth_key`, tokens, recovery keys, or record payloads.
- Only the first server user may register unless `ALLOW_REGISTRATION=true`.
- All timestamps stored as Unix milliseconds UTC; all calendar dates stored as `YYYY-MM-DD`.
- Every task ends with `cargo test` for the touched crates and a git commit.

## Review Focus

1. **Wrong password vs corrupt ciphertext.** A mistyped master password must return `WrongPassword`; tampered ciphertext must return `Crypto`. Tested in Task 2 (`wrong_password_is_distinct_error`, `tampered_payload_fails`).
2. **Concurrent offline edits.** Two machines editing the same account must both survive as original + conflict copy. Tested in Task 5 (`conflict_copy_preserves_both_versions`).
3. **Offline edits across restart.** A dirty record written before shutdown must still push after reopen, exactly once. Tested in Task 3 (`dirty_records_survive_reopen`) and Task 5 (`push_then_pull_marks_clean`).
4. **Tombstone vs local edit.** A delete on machine A must not silently destroy an offline edit from machine B; the edit becomes a conflict copy. Tested in Task 5 (`tombstone_with_local_edit_creates_conflict_copy`).
5. **Password and recovery rotation.** After changing the master password or recovery key, the old credential must no longer decrypt or authenticate. Tested in Task 2 (`password_rewrap_invalidates_old_password`, `recovery_key_rotation_invalidates_old_key`) and Task 14 (`change_password_revokes_old_sessions`).

---

## Task 1: Workspace, model, and validation

**Files:**
- Create: `Cargo.toml`
- Create: `crates/vault-core/Cargo.toml`
- Create: `crates/vault-core/src/lib.rs`
- Create: `crates/vault-core/src/error.rs`
- Create: `crates/vault-core/src/model.rs`
- Create: `crates/vault-server/Cargo.toml`
- Create: `crates/vault-server/src/main.rs`
- Create: `crates/vault-client/Cargo.toml`
- Create: `crates/vault-client/src/main.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `vault_core::{Account, AccountStatus, Plan, Money, PasswordHistoryEntry, CoreError, Result}`; workspace dependencies reusable by all later tasks.

- [ ] **Step 1: Create the workspace and crate skeletons**

Root `Cargo.toml`:

```toml
[workspace]
members = ["crates/vault-core", "crates/vault-server", "crates/vault-client"]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT"

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
ciborium = "0.2"
uuid = { version = "1", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
rust_decimal = { version = "1", features = ["serde-with-str"] }
argon2 = "0.5"
hkdf = "0.12"
sha2 = "0.10"
chacha20poly1305 = "0.10"
zeroize = { version = "1", features = ["derive"] }
rand = "0.8"
rusqlite = { version = "0.32", features = ["bundled"] }
base64 = "0.22"
thiserror = "2"
tracing = "0.1"
async-trait = "0.1"
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
directories = "5"
totp-rs = { version = "5", features = ["otpauth"] }
zxcvbn = "3"
csv = "1"
unicode-normalization = "0.1"
tempfile = "3"
```

`crates/vault-core/Cargo.toml`:

```toml
[package]
name = "vault-core"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
serde.workspace = true
serde_json.workspace = true
ciborium.workspace = true
uuid.workspace = true
chrono.workspace = true
rust_decimal.workspace = true
argon2.workspace = true
hkdf.workspace = true
sha2.workspace = true
chacha20poly1305.workspace = true
zeroize.workspace = true
rand.workspace = true
rusqlite.workspace = true
base64.workspace = true
thiserror.workspace = true
tracing.workspace = true
async-trait.workspace = true
reqwest.workspace = true
totp-rs.workspace = true
zxcvbn.workspace = true
csv.workspace = true
unicode-normalization.workspace = true
directories.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

`crates/vault-server/Cargo.toml` and `crates/vault-client/Cargo.toml` are minimal for now:

```toml
[package]
name = "vault-server"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
```

```toml
[package]
name = "vault-client"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
```

`crates/vault-core/src/lib.rs`:

```rust
pub mod error;
pub mod model;

pub use error::{CoreError, Result};
pub use model::{Account, AccountStatus, Money, PasswordHistoryEntry, Plan};
```

`crates/vault-server/src/main.rs` and `crates/vault-client/src/main.rs` each start as `fn main() {}`.

- [ ] **Step 2: Write the failing model tests**

Add to `crates/vault-core/src/model.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Days;

    #[test]
    fn new_account_has_defaults() {
        let a = Account::new(" User@Example.com ", "secret");
        assert_eq!(a.email, " User@Example.com ");
        assert_eq!(a.normalized_email(), "user@example.com");
        assert_eq!(a.plan, Plan::Free);
        assert_eq!(a.status, AccountStatus::Active);
        assert_eq!(a.schema_version, 1);
        assert_eq!(a.use_count, 0);
        assert!(a.password_history.is_empty());
        assert!(a.validate().is_ok());
    }

    #[test]
    fn validate_rejects_bad_email() {
        let a = Account::new("not-an-email", "x");
        assert!(matches!(a.validate(), Err(CoreError::Validation(_))));
    }

    #[test]
    fn set_password_keeps_last_five() {
        let mut a = Account::new("a@b.co", "p0");
        for i in 1..=7 {
            a.set_password(format!("p{i}"), Utc::now());
        }
        assert_eq!(a.password_history.len(), 5);
        assert_eq!(a.password_history[0].password, "p6");
        assert_eq!(a.password_history[4].password, "p2");
        assert!(a.password_changed_on.is_some());
    }

    #[test]
    fn mark_used_updates_count_and_date() {
        let mut a = Account::new("a@b.co", "p");
        let today = NaiveDate::from_ymd_opt(2026, 11, 6).unwrap();
        a.mark_used(today);
        a.mark_used(today);
        assert_eq!(a.use_count, 2);
        assert_eq!(a.last_used_on, Some(today));
    }

    #[test]
    fn age_days_uses_created_on() {
        let mut a = Account::new("a@b.co", "p");
        let today = NaiveDate::from_ymd_opt(2026, 11, 6).unwrap();
        a.created_on = Some(today - Days::new(10));
        assert_eq!(a.age_days(today), Some(10));
        a.created_on = None;
        assert_eq!(a.age_days(today), None);
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p vault-core model::tests`
Expected: compile error because `Account` does not exist.

- [ ] **Step 4: Implement `error.rs` and `model.rs`**

`error.rs`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid input: {0}")]
    Validation(String),
    #[error("wrong password")]
    WrongPassword,
    #[error("crypto failure")]
    Crypto,
    #[error("record not found")]
    NotFound,
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("network error: {0}")]
    Network(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;
```

`model.rs` imports:

```rust
use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};

pub const SCHEMA_VERSION: u16 = 1;
```

Add the types exactly as the spec section 5 defines them. Derive `Debug, Clone, PartialEq, Eq, Serialize, Deserialize` on `Plan`, `AccountStatus`, `Money`, and `PasswordHistoryEntry`; derive `Debug, Clone, PartialEq, Serialize, Deserialize` on `Account`. Implement:

```rust
impl Plan {
    pub fn as_str(&self) -> &'static str {
        match self { Plan::Free => "Free", Plan::Pro => "Pro", Plan::Ultra => "Ultra" }
    }
}

impl Default for Plan { fn default() -> Self { Plan::Free } }

impl AccountStatus {
    pub fn as_str(&self) -> &str {
        match self {
            AccountStatus::Active => "Active",
            AccountStatus::Banned => "Banned",
            AccountStatus::Sold => "Sold",
            AccountStatus::Deleted => "Deleted",
            AccountStatus::Other(s) => s,
        }
    }
}

impl Default for AccountStatus { fn default() -> Self { AccountStatus::Active } }

impl Money {
    pub fn new(amount: Decimal, currency: impl Into<String>) -> Self {
        Self { amount, currency: currency.into().to_uppercase() }
    }
}

impl Account {
    pub fn new(email: impl Into<String>, password: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            schema_version: SCHEMA_VERSION,
            id: Uuid::new_v4(),
            email: email.into(),
            password: password.into(),
            created_on: None,
            plan: Plan::Free,
            status: AccountStatus::Active,
            tags: Vec::new(),
            notes: None,
            recovery_email: None,
            recovery_phone: None,
            totp_secret: None,
            expires_on: None,
            price: None,
            last_used_on: None,
            use_count: 0,
            password_changed_on: None,
            password_history: Vec::new(),
            custom_fields: BTreeMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn normalized_email(&self) -> String {
        self.email.trim().to_lowercase()
    }

    pub fn age_days(&self, today: NaiveDate) -> Option<i64> {
        self.created_on.map(|d| (today - d).num_days())
    }

    pub fn set_password(&mut self, new_password: String, now: DateTime<Utc>) {
        if new_password == self.password {
            return;
        }
        self.password_history.insert(0, PasswordHistoryEntry {
            changed_at: now,
            password: std::mem::replace(&mut self.password, new_password),
        });
        self.password_history.truncate(5);
        self.password_changed_on = Some(now.date_naive());
        self.updated_at = now;
    }

    pub fn mark_used(&mut self, today: NaiveDate) {
        self.last_used_on = Some(today);
        self.use_count = self.use_count.saturating_add(1);
        self.updated_at = Utc::now();
    }

    pub fn validate(&self) -> Result<()> {
        let email = self.normalized_email();
        let mut parts = email.split('@');
        let local = parts.next().unwrap_or_default();
        let domain = parts.next().unwrap_or_default();
        if local.is_empty() || domain.is_empty() || parts.next().is_some() || !domain.contains('.') {
            return Err(CoreError::Validation("email không hợp lệ".into()));
        }
        if self.password.is_empty() {
            return Err(CoreError::Validation("mật khẩu không được rỗng".into()));
        }
        if self.tags.len() > 50 {
            return Err(CoreError::Validation("tối đa 50 tag".into()));
        }
        if self.tags.iter().any(|t| t.trim().is_empty() || t.len() > 40) {
            return Err(CoreError::Validation("tag không hợp lệ".into()));
        }
        if let Some(price) = &self.price {
            if price.amount < Decimal::ZERO {
                return Err(CoreError::Validation("giá không được âm".into()));
            }
            if price.currency.len() != 3 || !price.currency.chars().all(|c| c.is_ascii_uppercase()) {
                return Err(CoreError::Validation("currency phải là 3 chữ in hoa".into()));
            }
        }
        if let (Some(created), Some(expires)) = (self.created_on, self.expires_on) {
            if expires < created {
                return Err(CoreError::Validation("ngày hết hạn trước ngày tạo".into()));
            }
        }
        if self.custom_fields.len() > 50 {
            return Err(CoreError::Validation("tối đa 50 custom field".into()));
        }
        if self.custom_fields.keys().any(|key| key.trim().is_empty()) {
            return Err(CoreError::Validation("custom field key không được rỗng".into()));
        }
        Ok(())
    }
}
```

- [ ] **Step 5: Run tests and commit**

Run: `cargo test -p vault-core model::tests`
Expected: 5 tests pass.

```bash
git add Cargo.toml crates
git commit -m "feat(core): scaffold workspace and account model"
```

---

## Task 2: Crypto primitives

**Files:**
- Create: `crates/vault-core/src/codec.rs`
- Create: `crates/vault-core/src/crypto.rs`
- Modify: `crates/vault-core/src/lib.rs`

**Interfaces:**
- Consumes: `Account`, `CoreError`, `Result`, `KdfParams`, `WrappedKey` (defined here).
- Produces:
  - `create_vault(password: &str) -> Result<NewVault>`
  - `unwrap_vault_key(password: &str, user_id: Uuid, kdf: &KdfParams, wrapped: &WrappedKey) -> Result<UnlockedVault>`
  - `recover_vault(recovery_code: &str, user_id: Uuid, wrapped: &WrappedKey) -> Result<UnlockedVault>`
  - `UnlockedVault::{user_id, encrypt_account, decrypt_account, rewrap_with_password, new_recovery}`
  - `KdfParams`, `WrappedKey`, `RecoveryMaterial`, `NewVault`
  - `codec::{base64, base64_option}` serde modules.

- [ ] **Step 1: Write the failing crypto tests**

Add to `crates/vault-core/src/crypto.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Account;

    #[test]
    fn vault_roundtrip_with_password() {
        let nv = create_vault("correct horse battery staple").unwrap();
        let unlocked = unwrap_vault_key(
            "correct horse battery staple", nv.user_id, &nv.kdf, &nv.wrapped_key,
        ).unwrap();
        let account = Account::new("a@b.co", "secret");
        let enc = unlocked.encrypt_account(&account).unwrap();
        let back = unlocked.decrypt_account(account.id, &enc.nonce, &enc.payload).unwrap();
        assert_eq!(back, account);
    }

    #[test]
    fn wrong_password_is_distinct_error() {
        let nv = create_vault("right").unwrap();
        let err = unwrap_vault_key("wrong", nv.user_id, &nv.kdf, &nv.wrapped_key).unwrap_err();
        assert!(matches!(err, CoreError::WrongPassword));
    }

    #[test]
    fn tampered_payload_fails() {
        let nv = create_vault("pw").unwrap();
        let unlocked = unwrap_vault_key("pw", nv.user_id, &nv.kdf, &nv.wrapped_key).unwrap();
        let account = Account::new("a@b.co", "secret");
        let mut enc = unlocked.encrypt_account(&account).unwrap();
        enc.payload[0] ^= 0xff;
        let err = unlocked.decrypt_account(account.id, &enc.nonce, &enc.payload).unwrap_err();
        assert!(matches!(err, CoreError::Crypto));
    }

    #[test]
    fn record_aad_binds_id() {
        let nv = create_vault("pw").unwrap();
        let unlocked = unwrap_vault_key("pw", nv.user_id, &nv.kdf, &nv.wrapped_key).unwrap();
        let account = Account::new("a@b.co", "secret");
        let enc = unlocked.encrypt_account(&account).unwrap();
        let err = unlocked.decrypt_account(Uuid::new_v4(), &enc.nonce, &enc.payload).unwrap_err();
        assert!(matches!(err, CoreError::Crypto));
    }

    #[test]
    fn password_rewrap_invalidates_old_password() {
        let nv = create_vault("old-password").unwrap();
        let unlocked = unwrap_vault_key("old-password", nv.user_id, &nv.kdf, &nv.wrapped_key).unwrap();
        let (kdf, wrapped, _auth) = unlocked.rewrap_with_password("new-password").unwrap();
        assert!(unwrap_vault_key("old-password", nv.user_id, &kdf, &wrapped).is_err());
        assert!(unwrap_vault_key("new-password", nv.user_id, &kdf, &wrapped).is_ok());
    }

    #[test]
    fn recovery_key_roundtrip_and_checksum() {
        let nv = create_vault("pw").unwrap();
        let code = nv.recovery.display.clone();
        let key = parse_recovery_code(&code).unwrap();
        assert_eq!(&key[..], &nv.recovery.key[..]);
        let mut broken = code.clone();
        broken.replace_range(0..1, if broken.starts_with('0') { "1" } else { "0" });
        assert!(parse_recovery_code(&broken).is_err());
    }

    #[test]
    fn recovery_key_rotation_invalidates_old_key() {
        let nv = create_vault("pw").unwrap();
        let unlocked = unwrap_vault_key("pw", nv.user_id, &nv.kdf, &nv.wrapped_key).unwrap();
        let first = unlocked.new_recovery().unwrap();
        let second = unlocked.new_recovery().unwrap();
        assert!(recover_vault(&first.display, nv.user_id, &first.wrapped_key).is_ok());
        assert!(recover_vault(&first.display, nv.user_id, &second.wrapped_key).is_err());
        assert!(recover_vault(&second.display, nv.user_id, &second.wrapped_key).is_ok());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p vault-core crypto::tests`
Expected: compile error because `create_vault` does not exist.

- [ ] **Step 3: Implement codec and crypto**

`codec.rs`:

```rust
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Deserializer, Serializer};

pub fn encode(bytes: &[u8]) -> String { STANDARD.encode(bytes) }

pub fn decode(value: &str) -> crate::Result<Vec<u8>> {
    STANDARD.decode(value).map_err(|e| crate::CoreError::Serialization(e.to_string()))
}

pub mod base64 {
    use super::*;
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        super::decode(&s).map_err(serde::de::Error::custom)
    }
}

pub mod base64_option {
    use super::*;
    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(v) => s.serialize_some(&encode(v)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let s: Option<String> = Option::deserialize(d)?;
        s.map(|v| super::decode(&v).map_err(serde::de::Error::custom)).transpose()
    }
}
```

`crypto.rs` core types and constants:

```rust
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};
use crate::model::Account;

pub const KDF_M_KIB: u32 = 65_536;
pub const KDF_T: u32 = 3;
pub const KDF_P: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub algo: String,
    #[serde(with = "crate::codec::base64")]
    pub salt: Vec<u8>,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrappedKey {
    #[serde(with = "crate::codec::base64")]
    pub nonce: Vec<u8>,
    #[serde(with = "crate::codec::base64")]
    pub ciphertext: Vec<u8>,
}

pub struct NewVault {
    pub user_id: Uuid,
    pub kdf: KdfParams,
    pub wrapped_key: WrappedKey,
    pub auth_key: Zeroizing<[u8; 32]>,
    pub vault_key: Zeroizing<[u8; 32]>,
    pub recovery: RecoveryMaterial,
}

pub struct RecoveryMaterial {
    pub key: Zeroizing<[u8; 32]>,
    pub auth_key: Zeroizing<[u8; 32]>,
    pub wrapped_key: WrappedKey,
    pub display: String,
}

pub struct UnlockedVault {
    user_id: Uuid,
    key: Zeroizing<[u8; 32]>,
}
```

Do not derive `Debug` on `NewVault`, `RecoveryMaterial`, or `UnlockedVault`; their fields contain raw keys and a debug print would leak them into logs.

Implement helpers:

```rust
fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

fn derive_master(password: &str, kdf: &KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    if kdf.algo != "argon2id" || kdf.salt.len() != 16 {
        return Err(CoreError::Validation("KDF params không hợp lệ".into()));
    }
    let params = Params::new(kdf.m_kib, kdf.t, kdf.p, Some(32)).map_err(|_| CoreError::Crypto)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon.hash_password_into(password.as_bytes(), &kdf.salt, &mut out[..])
        .map_err(|_| CoreError::Crypto)?;
    Ok(out)
}

fn hkdf32(master: &[u8; 32], salt: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut out[..]).map_err(|_| CoreError::Crypto)?;
    Ok(out)
}

fn wrap_aad(user_id: Uuid) -> String { format!("gmail-vault:v1:user:{user_id}") }
fn recovery_aad(user_id: Uuid) -> String { format!("gmail-vault:v1:recovery:{user_id}") }
fn record_aad(user_id: Uuid, record_id: Uuid) -> String {
    format!("gmail-vault:v1:record:{user_id}:{record_id}")
}

fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CoreError::Crypto)?;
    let nonce = random_array::<24>();
    let ciphertext = cipher.encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CoreError::Crypto)?;
    Ok((nonce.to_vec(), ciphertext))
}

fn open(key: &[u8; 32], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != 24 {
        return Err(CoreError::Crypto);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CoreError::Crypto)?;
    cipher.decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| CoreError::Crypto)
}
```

Public functions:

```rust
impl KdfParams {
    pub fn generate() -> Self {
        Self { algo: "argon2id".into(), salt: random_array::<16>().to_vec(), m_kib: KDF_M_KIB, t: KDF_T, p: KDF_P }
    }
}

pub fn create_vault(password: &str) -> Result<NewVault> {
    let user_id = Uuid::new_v4();
    let kdf = KdfParams::generate();
    let master = derive_master(password, &kdf)?;
    let auth_key = hkdf32(&master, &kdf.salt, b"gmail-vault/auth/v1")?;
    let kek = hkdf32(&master, &kdf.salt, b"gmail-vault/kek/v1")?;
    let vault_key = Zeroizing::new(random_array::<32>());
    let (nonce, ciphertext) = seal(&kek, wrap_aad(user_id).as_bytes(), &vault_key[..])?;
    let wrapped_key = WrappedKey { nonce, ciphertext };
    let unlocked = UnlockedVault { user_id, key: Zeroizing::new(*vault_key) };
    let recovery = unlocked.new_recovery()?;
    Ok(NewVault { user_id, kdf, wrapped_key, auth_key, vault_key, recovery })
}

pub fn unwrap_vault_key(password: &str, user_id: Uuid, kdf: &KdfParams, wrapped: &WrappedKey) -> Result<UnlockedVault> {
    let master = derive_master(password, kdf)?;
    let kek = hkdf32(&master, &kdf.salt, b"gmail-vault/kek/v1")?;
    let plaintext = open(&kek, &wrapped.nonce, wrap_aad(user_id).as_bytes(), &wrapped.ciphertext)
        .map_err(|_| CoreError::WrongPassword)?;
    if plaintext.len() != 32 { return Err(CoreError::WrongPassword); }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    Ok(UnlockedVault { user_id, key: Zeroizing::new(key) })
}

impl UnlockedVault {
    pub fn user_id(&self) -> Uuid { self.user_id }

    pub fn encrypt_account(&self, account: &Account) -> Result<EncryptedRecord> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(account, &mut buf).map_err(|e| CoreError::Serialization(e.to_string()))?;
        if buf.len() > 64 * 1024 { return Err(CoreError::Validation("record quá lớn".into())); }
        let aad = record_aad(self.user_id, account.id);
        let (nonce, payload) = seal(&self.key, aad.as_bytes(), &buf)?;
        let mut nonce_arr = [0u8; 24];
        nonce_arr.copy_from_slice(&nonce);
        Ok(EncryptedRecord { nonce: nonce_arr, payload })
    }

    pub fn decrypt_account(&self, id: Uuid, nonce: &[u8], payload: &[u8]) -> Result<Account> {
        let aad = record_aad(self.user_id, id);
        let plaintext = open(&self.key, nonce, aad.as_bytes(), payload)?;
        ciborium::de::from_reader(&plaintext[..]).map_err(|e| CoreError::Serialization(e.to_string()))
    }

    pub fn rewrap_with_password(&self, password: &str) -> Result<(KdfParams, WrappedKey, Zeroizing<[u8; 32]>)> {
        let kdf = KdfParams::generate();
        let master = derive_master(password, &kdf)?;
        let auth_key = hkdf32(&master, &kdf.salt, b"gmail-vault/auth/v1")?;
        let kek = hkdf32(&master, &kdf.salt, b"gmail-vault/kek/v1")?;
        let (nonce, ciphertext) = seal(&kek, wrap_aad(self.user_id).as_bytes(), &self.key[..])?;
        Ok((kdf, WrappedKey { nonce, ciphertext }, auth_key))
    }

    pub fn new_recovery(&self) -> Result<RecoveryMaterial> {
        let key = Zeroizing::new(random_array::<32>());
        let recovery_kek = hkdf32(&key, &[], b"gmail-vault/recovery/v1")?;
        let (nonce, ciphertext) = seal(&recovery_kek, recovery_aad(self.user_id).as_bytes(), &self.key[..])?;
        let auth_key = hkdf32(&key, &[], b"gmail-vault/recovery-auth/v1")?;
        Ok(RecoveryMaterial {
            display: format_recovery_code(&key),
            key,
            auth_key,
            wrapped_key: WrappedKey { nonce, ciphertext },
        })
    }
}

pub struct EncryptedRecord { pub nonce: [u8; 24], pub payload: Vec<u8> }
```

Recovery code encoding in the same file:

```rust
const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn recovery_checksum(key: &[u8; 32]) -> String {
    let checksum = Sha256::digest(key);
    let value = u32::from_be_bytes([checksum[0], checksum[1], checksum[2], checksum[3]]);
    let mut out = String::new();
    for i in 0..4 {
        out.push(CROCKFORD[((value >> (25 - i * 5)) & 31) as usize] as char);
    }
    out
}

pub fn format_recovery_code(key: &[u8; 32]) -> String {
    let mut body = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in key {
        buffer = (buffer << 8) | *byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            body.push(CROCKFORD[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 { body.push(CROCKFORD[((buffer << (5 - bits)) & 31) as usize] as char); }
    let grouped = body.as_bytes().chunks(5)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-");
    format!("{grouped}-{}", recovery_checksum(key))
}

pub fn parse_recovery_code(input: &str) -> Result<Zeroizing<[u8; 32]>> {
    let clean: String = input.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_uppercase();
    if clean.len() != 56 { return Err(CoreError::Validation("recovery key sai độ dài".into())); }
    let (body, check) = clean.split_at(52);
    let mut bytes = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for ch in body.bytes() {
        let v = CROCKFORD.iter().position(|c| *c == ch).ok_or(CoreError::Validation("recovery key sai ký tự".into()))? as u32;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 { bits -= 8; bytes.push(((buffer >> bits) & 0xff) as u8); }
    }
    if bytes.len() != 32 { return Err(CoreError::Validation("recovery key sai".into())); }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    if recovery_checksum(&key) != check {
        return Err(CoreError::Validation("recovery key checksum sai".into()));
    }
    Ok(Zeroizing::new(key))
}

pub fn recover_vault(code: &str, user_id: Uuid, wrapped: &WrappedKey) -> Result<UnlockedVault> {
    let key = parse_recovery_code(code)?;
    let recovery_kek = hkdf32(&key, &[], b"gmail-vault/recovery/v1")?;
    let plaintext = open(&recovery_kek, &wrapped.nonce, recovery_aad(user_id).as_bytes(), &wrapped.ciphertext)
        .map_err(|_| CoreError::Crypto)?;
    if plaintext.len() != 32 { return Err(CoreError::Crypto); }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    Ok(UnlockedVault { user_id, key: Zeroizing::new(key) })
}
```

Add `pub mod codec; pub mod crypto;` to `lib.rs`, and re-export `crypto::{KdfParams, WrappedKey, UnlockedVault, NewVault, RecoveryMaterial, create_vault, unwrap_vault_key, recover_vault, parse_recovery_code, format_recovery_code}`.

- [ ] **Step 4: Run tests and commit**

Run: `cargo test -p vault-core crypto::tests`
Expected: 7 tests pass.

```bash
git add crates/vault-core
git commit -m "feat(core): add E2E crypto and recovery keys"
```

---

## Task 3: Local SQLite store

**Files:**
- Create: `crates/vault-core/src/store.rs`
- Modify: `crates/vault-core/src/lib.rs`
- Modify: `crates/vault-core/src/crypto.rs` (`RecordRow` lives here)

**Interfaces:**
- Consumes: `LocalMeta`, `KdfParams`, `WrappedKey`.
- Produces:
  - `RecordRow { id, revision, change_seq, updated_at, deleted, nonce, payload }` with serde.
  - `LocalStore::{open, open_in_memory, load_meta, save_meta, upsert_record, get_record, load_all_records, load_dirty, mark_clean, set_cursor, cursor, remove_record, count_dirty}`.

- [ ] **Step 1: Write the failing store tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::WrappedKey;
    use tempfile::tempdir;
    use uuid::Uuid;

    fn meta() -> LocalMeta {
        LocalMeta {
            user_id: Uuid::new_v4(),
            email: "owner@example.com".into(),
            server_url: "https://vault.example.com".into(),
            device_label: "PC".into(),
            kdf: KdfParams::generate(),
            wrapped_key: WrappedKey { nonce: vec![0; 24], ciphertext: vec![1; 48] },
            last_change_seq: 0,
        }
    }

    fn row(id: Uuid, revision: u64) -> RecordRow {
        RecordRow {
            id, revision, change_seq: revision, updated_at: 1_762_000_000_000,
            deleted: false, dirty: true, nonce: vec![0; 24], payload: vec![2; 32],
        }
    }

    #[test]
    fn meta_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let mut store = LocalStore::open(&path).unwrap();
        let m = meta();
        store.save_meta(&m).unwrap();
        drop(store);
        let store = LocalStore::open(&path).unwrap();
        assert_eq!(store.load_meta().unwrap().unwrap(), m);
    }

    #[test]
    fn dirty_records_survive_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let mut store = LocalStore::open(&path).unwrap();
        let id = Uuid::new_v4();
        store.upsert_record(&row(id, 0)).unwrap();
        drop(store);
        let store = LocalStore::open(&path).unwrap();
        let dirty = store.load_dirty(10).unwrap();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].id, id);
    }

    #[test]
    fn mark_clean_and_cursor() {
        let mut store = LocalStore::open_in_memory().unwrap();
        let id = Uuid::new_v4();
        store.upsert_record(&row(id, 0)).unwrap();
        store.mark_clean(id, 3, 7).unwrap();
        assert!(store.load_dirty(10).unwrap().is_empty());
        store.set_cursor(7).unwrap();
        assert_eq!(store.cursor().unwrap(), 7);
        let got = store.get_record(id).unwrap().unwrap();
        assert_eq!(got.revision, 3);
        assert_eq!(got.change_seq, 7);
        assert!(!got.dirty);
    }

    #[test]
    fn tombstone_roundtrip() {
        let mut store = LocalStore::open_in_memory().unwrap();
        let id = Uuid::new_v4();
        let mut r = row(id, 2);
        r.deleted = true;
        r.nonce.clear();
        r.payload.clear();
        store.upsert_record(&r).unwrap();
        let got = store.get_record(id).unwrap().unwrap();
        assert!(got.deleted);
        assert!(got.payload.is_empty());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p vault-core store::tests`
Expected: compile error because `LocalStore` does not exist.

- [ ] **Step 3: Implement `RecordRow`, `LocalMeta`, and `LocalStore`**

Add to `crypto.rs`:

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RecordRow {
    pub id: Uuid,
    pub revision: u64,
    pub change_seq: u64,
    pub updated_at: i64,
    pub deleted: bool,
    #[serde(default)]
    pub dirty: bool,
    #[serde(with = "crate::codec::base64")]
    pub nonce: Vec<u8>,
    #[serde(with = "crate::codec::base64")]
    pub payload: Vec<u8>,
}
```

`store.rs`:

```rust
use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{KdfParams, RecordRow, WrappedKey};
use crate::error::{CoreError, Result};

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
    id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL DEFAULT 0,
    change_seq INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    dirty INTEGER NOT NULL DEFAULT 1,
    nonce BLOB,
    payload BLOB
);
CREATE INDEX IF NOT EXISTS idx_records_dirty ON records(dirty) WHERE dirty = 1;
"#;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocalMeta {
    pub user_id: Uuid,
    pub email: String,
    pub server_url: String,
    pub device_label: String,
    pub kdf: KdfParams,
    pub wrapped_key: WrappedKey,
    pub last_change_seq: u64,
}

pub struct LocalStore { conn: Connection }

impl LocalStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn load_meta(&self) -> Result<Option<LocalMeta>> {
        let raw: Option<Vec<u8>> = self.conn.query_row(
            "SELECT value FROM meta WHERE key = 'state'", [], |r| r.get(0)
        ).optional()?;
        raw.map(|b| serde_json::from_slice(&b).map_err(|e| CoreError::Serialization(e.to_string()))).transpose()
    }

    pub fn save_meta(&mut self, meta: &LocalMeta) -> Result<()> {
        let raw = serde_json::to_vec(meta).map_err(|e| CoreError::Serialization(e.to_string()))?;
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES('state', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value", params![raw],
        )?;
        Ok(())
    }

    pub fn upsert_record(&mut self, row: &RecordRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO records(id, revision, change_seq, updated_at, deleted, dirty, nonce, payload)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
               revision = excluded.revision, change_seq = excluded.change_seq,
               updated_at = excluded.updated_at, deleted = excluded.deleted,
               dirty = excluded.dirty, nonce = excluded.nonce, payload = excluded.payload",
            params![
                row.id.to_string(), row.revision as i64, row.change_seq as i64,
                row.updated_at, row.deleted as i64, row.dirty as i64,
                if row.nonce.is_empty() { None } else { Some(&row.nonce) },
                if row.payload.is_empty() { None } else { Some(&row.payload) },
            ],
        )?;
        Ok(())
    }

    pub fn get_record(&self, id: Uuid) -> Result<Option<RecordRow>> {
        self.conn.query_row(
            "SELECT id, revision, change_seq, updated_at, deleted, dirty, nonce, payload
             FROM records WHERE id = ?1", params![id.to_string()], map_row,
        ).optional().map_err(Into::into)
    }

    pub fn load_all_records(&self) -> Result<Vec<RecordRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, revision, change_seq, updated_at, deleted, dirty, nonce, payload FROM records"
        )?;
        let rows = stmt.query_map([], map_row)?.collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn load_dirty(&self, limit: usize) -> Result<Vec<RecordRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, revision, change_seq, updated_at, deleted, dirty, nonce, payload
             FROM records WHERE dirty = 1 ORDER BY updated_at ASC LIMIT ?1"
        )?;
        let rows = stmt.query_map(params![limit as i64], map_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn mark_clean(&mut self, id: Uuid, revision: u64, change_seq: u64) -> Result<()> {
        self.conn.execute(
            "UPDATE records SET revision = ?2, change_seq = ?3, dirty = 0 WHERE id = ?1",
            params![id.to_string(), revision as i64, change_seq as i64],
        )?;
        Ok(())
    }

    pub fn set_cursor(&mut self, seq: u64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES('cursor', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![seq.to_string().into_bytes()],
        )?;
        Ok(())
    }

    pub fn cursor(&self) -> Result<u64> {
        let raw: Option<Vec<u8>> = self.conn.query_row(
            "SELECT value FROM meta WHERE key = 'cursor'", [], |r| r.get(0)
        ).optional()?;
        Ok(raw.and_then(|b| String::from_utf8(b).ok()).and_then(|s| s.parse().ok()).unwrap_or(0))
    }

    pub fn remove_record(&mut self, id: Uuid) -> Result<()> {
        self.conn.execute("DELETE FROM records WHERE id = ?1", params![id.to_string()])?;
        Ok(())
    }

    pub fn count_dirty(&self) -> Result<usize> {
        let count: i64 = self.conn.query_row("SELECT COUNT(*) FROM records WHERE dirty = 1", [], |r| r.get(0))?;
        Ok(count as usize)
    }
}

fn map_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RecordRow> {
    let id: String = row.get(0)?;
    Ok(RecordRow {
        id: Uuid::parse_str(&id).map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?,
        revision: row.get::<_, i64>(1)? as u64,
        change_seq: row.get::<_, i64>(2)? as u64,
        updated_at: row.get(3)?,
        deleted: row.get::<_, i64>(4)? != 0,
        dirty: row.get::<_, i64>(5)? != 0,
        nonce: row.get::<_, Option<Vec<u8>>>(6)?.unwrap_or_default(),
        payload: row.get::<_, Option<Vec<u8>>>(7)?.unwrap_or_default(),
    })
}
```

Add `pub mod store;` and re-export `store::{LocalMeta, LocalStore}`, `crypto::RecordRow`.

- [ ] **Step 4: Run tests and commit**

Run: `cargo test -p vault-core store::tests`
Expected: 4 tests pass.

```bash
git add crates/vault-core
git commit -m "feat(core): add encrypted local record store"
```

## Task 4: CSV/JSON import-export and encrypted backup

**Files:**
- Create: `crates/vault-core/src/portability.rs`
- Modify: `crates/vault-core/src/lib.rs`

**Interfaces:**
- Consumes: `Account`, `Plan`, `AccountStatus`, `Money`, `RecordRow`, `KdfParams`, `WrappedKey`, `LocalStore`.
- Produces:
  - `DuplicatePolicy { Skip, Replace, CreateNew }`
  - `ImportResult { accounts: Vec<Account>, skipped: usize, errors: Vec<ImportRowError> }`
  - `ImportRowError { row: usize, message: String }`
  - `export_csv<W: Write>(accounts: &[Account], include_password: bool, include_totp: bool, writer: W) -> Result<()>`
  - `import_csv<R: Read>(reader: R, existing: &HashMap<String, Uuid>, policy: DuplicatePolicy) -> Result<ImportResult>`
  - `export_json<W: Write>(accounts: &[Account], writer: W) -> Result<()>`
  - `import_json<R: Read>(reader: R, existing: &HashMap<String, Uuid>, policy: DuplicatePolicy) -> Result<ImportResult>`
  - `VaultExport { format, version, user_id, kdf, wrapped_key, records }`
  - `write_gvault(path: &Path, export: &VaultExport) -> Result<()>`
  - `read_gvault(path: &Path) -> Result<VaultExport>`
  - `backup_database(db_path: &Path, backup_dir: &Path, keep: usize) -> Result<PathBuf>`
  - `list_backups(dir: &Path) -> Result<Vec<PathBuf>>`

- [ ] **Step 1: Write the failing portability tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{create_vault, RecordRow};
    use tempfile::tempdir;

    fn sample() -> Account {
        let mut a = Account::new("User@Example.com", "p,w\"ord");
        a.plan = Plan::Pro;
        a.status = AccountStatus::Active;
        a.tags = vec!["vip".into(), "2024".into()];
        a.notes = Some("hello, \"world\"".into());
        a.created_on = Some(chrono::NaiveDate::from_ymd_opt(2025, 1, 2).unwrap());
        a.price = Some(Money::new("199000".parse().unwrap(), "vnd"));
        a.custom_fields.insert("proxy".into(), "1.2.3.4:8080".into());
        a
    }

    #[test]
    fn csv_handles_quoted_commas_bom_and_tags() {
        let mut buf = Vec::new();
        export_csv(&[sample()], true, true, &mut buf).unwrap();
        assert!(buf.starts_with(&[0xEF, 0xBB, 0xBF]));
        let text = String::from_utf8(buf).unwrap();
        let mut result = import_csv(text.as_bytes(), &HashMap::new(), DuplicatePolicy::Skip).unwrap();
        assert_eq!(result.errors.len(), 0);
        let a = result.accounts.remove(0);
        assert_eq!(a.email, "User@Example.com");
        assert_eq!(a.password, "p,w\"ord");
        assert_eq!(a.tags, vec!["vip", "2024"]);
        assert_eq!(a.notes.as_deref(), Some("hello, \"world\""));
        assert_eq!(a.price.unwrap().currency, "VND");
    }

    #[test]
    fn duplicate_policy_skip_replace_create() {
        let mut existing = HashMap::new();
        let id = Uuid::new_v4();
        existing.insert("user@example.com".to_string(), id);
        let csv = "email,password\nuser@example.com,new\n";
        let skip = import_csv(csv.as_bytes(), &existing, DuplicatePolicy::Skip).unwrap();
        assert_eq!(skip.accounts.len(), 0);
        assert_eq!(skip.skipped, 1);
        let replace = import_csv(csv.as_bytes(), &existing, DuplicatePolicy::Replace).unwrap();
        assert_eq!(replace.accounts[0].id, id);
        let create = import_csv(csv.as_bytes(), &existing, DuplicatePolicy::CreateNew).unwrap();
        assert_ne!(create.accounts[0].id, id);
    }

    #[test]
    fn json_roundtrip() {
        let accounts = vec![sample()];
        let mut buf = Vec::new();
        export_json(&accounts, &mut buf).unwrap();
        let result = import_json(&buf[..], &HashMap::new(), DuplicatePolicy::Skip).unwrap();
        assert_eq!(result.accounts, accounts);
    }

    #[test]
    fn gvault_roundtrip_contains_no_plaintext() {
        let nv = create_vault("pw").unwrap();
        let account = sample();
        let enc = nv.vault_key.len();
        assert_eq!(enc, 32);
        let record = RecordRow {
            id: account.id, revision: 1, change_seq: 1, updated_at: 1,
            deleted: false, dirty: false, nonce: vec![9; 24], payload: b"ciphertext-only".to_vec(),
        };
        let export = VaultExport {
            format: "gmail-vault-export".into(), version: 1, user_id: nv.user_id,
            kdf: nv.kdf.clone(), wrapped_key: nv.wrapped_key.clone(), records: vec![record],
        };
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.gvault");
        write_gvault(&path, &export).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("User@Example.com"));
        let back = read_gvault(&path).unwrap();
        assert_eq!(back.records.len(), 1);
        assert_eq!(back.format, "gmail-vault-export");
    }

    #[test]
    fn backup_rotates_old_files() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("vault.db");
        let _store = crate::store::LocalStore::open(&db).unwrap();
        drop(_store);
        let backup_dir = dir.path().join("backups");
        for _ in 0..3 {
            backup_database(&db, &backup_dir, 2).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(list_backups(&backup_dir).unwrap().len(), 2);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p vault-core portability::tests`
Expected: compile error because `export_csv` does not exist.

- [ ] **Step 3: Implement portability functions**

Key implementation decisions:

- CSV header order: `email,password,created_on,plan,status,tags,notes,recovery_email,recovery_phone,totp_secret,expires_on,price,currency,last_used_on,use_count,custom_fields`.
- `export_csv` writes UTF-8 BOM first, then `csv::Writer::from_writer`.
- `include_password=false` writes an empty password column; `include_totp=false` writes an empty secret.
- `tags` joined with `;`; `custom_fields` serialized with `serde_json::to_string`.
- `import_csv` strips a leading `\u{feff}`, lowercases headers, maps aliases:
  - email: `email`, `user`, `username`, `login`
  - password: `password`, `pass`
  - created_on: `created_on`, `created`, `date`, `ngay_tao`
  - plan: `plan`, `tier`, `goi`
  - status: `status`, `trang_thai`
  - tags: `tags`, `label`, `labels`
  - notes: `notes`, `note`, `ghi_chu`
  - recovery_email: `recovery_email`
  - recovery_phone: `recovery_phone`
  - totp_secret: `totp_secret`, `totp`, `2fa`
  - expires_on: `expires_on`, `expires`, `het_han`
  - price: `price`, `gia`
  - currency: `currency`
  - last_used_on: `last_used_on`, `last_used`
  - use_count: `use_count`, `uses`
  - custom_fields: `custom_fields`, `custom`
- Header matching is case-insensitive and trims whitespace.
- Date parser tries `%Y-%m-%d` then `%d/%m/%Y`.
- Plan parser: `free`/`pro`/`ultra`, case-insensitive; unknown → `Free` plus row error.
- Status parser: `active`, `banned`, `sold`, `deleted`, otherwise `Other(raw)`.
- Empty password row → error, skip, increment `errors`.
- Duplicate detection uses `account.normalized_email()` against the `existing` map keys (already normalized by caller).
- `Replace` sets the new account id to the existing id.
- `CreateNew` keeps the freshly generated id.
- `import_json` accepts either a top-level array of `Account` or an object `{ "accounts": [...] }`.
- Both importers reject more than 50,000 rows/accounts with `CoreError::Validation("tối đa 50.000 dòng mỗi lần import")` before building the result.

`VaultExport`:

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VaultExport {
    pub format: String,
    pub version: u32,
    pub user_id: Uuid,
    pub kdf: KdfParams,
    pub wrapped_key: WrappedKey,
    pub records: Vec<RecordRow>,
}
```

`write_gvault` uses `serde_json::to_writer_pretty`; `read_gvault` validates `format == "gmail-vault-export"` and `version == 1`, otherwise `CoreError::Validation`.

`backup_database`:

```rust
pub fn backup_database(db_path: &Path, backup_dir: &Path, keep: usize) -> Result<PathBuf> {
    std::fs::create_dir_all(backup_dir)?;
    let mut target = backup_dir.join(format!("vault-{}.db", chrono::Utc::now().format("%Y%m%d-%H%M%S-%3f")));
    let mut n = 1;
    while target.exists() {
        target = backup_dir.join(format!("vault-{}-{n}.db", chrono::Utc::now().format("%Y%m%d-%H%M%S-%3f")));
        n += 1;
    }
    let src = rusqlite::Connection::open(db_path)?;
    let mut dst = rusqlite::Connection::open(&target)?;
    let backup = rusqlite::backup::Backup::new(&src, &mut dst)?;
    backup.run_to_completion(100, std::time::Duration::from_millis(10), None)?;
    let mut files = list_backups(backup_dir)?;
    files.sort();
    while files.len() > keep {
        if let Some(old) = files.first().cloned() { std::fs::remove_file(old)?; files.remove(0); }
    }
    Ok(target)
}

pub fn list_backups(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.exists() { return Ok(Vec::new()); }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("db") {
            if path.file_name().and_then(|n| n.to_str()).map(|n| n.starts_with("vault-")).unwrap_or(false) {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}
```

- [ ] **Step 4: Run tests and commit**

Run: `cargo test -p vault-core portability::tests`
Expected: 5 tests pass.

```bash
git add crates/vault-core
git commit -m "feat(core): add import, export, gvault, and backup"
```

---

## Task 5: Sync engine with conflict copies

**Files:**
- Create: `crates/vault-core/src/sync.rs`
- Modify: `crates/vault-core/src/lib.rs`
- Modify: `crates/vault-core/Cargo.toml` (add `tokio` dev-dependency)

**Interfaces:**
- Consumes: `LocalStore`, `UnlockedVault`, `RecordRow`, `Account`.
- Produces:
  - `SyncApi` trait with `pull` and `push`.
  - `PushItem`, `PullResponse`, `PushResponse`, `Accepted`, `Conflict`.
  - `SyncEngine<'a>::new(api, store, vault, device_label)`.
  - `SyncEngine::sync_once(&mut self) -> Result<SyncReport>`.
  - `SyncReport { pushed, pulled, conflicts, cursor }`.

- [ ] **Step 1: Write the failing sync tests**

Add `tokio = { version = "1", features = ["rt", "macros"] }` to core `[dev-dependencies]`, then:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{create_vault, KdfParams, UnlockedVault, WrappedKey};
    use crate::store::{LocalMeta, LocalStore};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use uuid::Uuid;

    struct MockState { records: HashMap<Uuid, RecordRow>, seq: u64 }
    struct MockApi { state: Mutex<MockState> }

    impl MockApi {
        fn new() -> Self { Self { state: Mutex::new(MockState { records: HashMap::new(), seq: 0 }) } }
        fn put_server(&self, mut row: RecordRow) {
            let mut s = self.state.lock().unwrap();
            s.seq += 1;
            row.change_seq = s.seq;
            row.revision = row.revision.max(1);
            s.records.insert(row.id, row);
        }
    }

    #[async_trait::async_trait]
    impl SyncApi for MockApi {
        async fn pull(&self, since: u64, _limit: u32) -> Result<PullResponse> {
            let s = self.state.lock().unwrap();
            let mut items: Vec<_> = s.records.values().filter(|r| r.change_seq > since).cloned().collect();
            items.sort_by_key(|r| r.change_seq);
            let next_since = items.last().map(|r| r.change_seq).unwrap_or(since);
            Ok(PullResponse { items, next_since, has_more: false })
        }

        async fn push(&self, items: Vec<PushItem>) -> Result<PushResponse> {
            let mut s = self.state.lock().unwrap();
            let mut accepted = Vec::new();
            let mut conflicts = Vec::new();
            for item in items {
                let current = s.records.get(&item.id).cloned();
                let ok = match &current {
                    None => item.base_revision == 0,
                    Some(cur) => cur.revision == item.base_revision,
                };
                if ok {
                    s.seq += 1;
                    let revision = current.map(|c| c.revision + 1).unwrap_or(1);
                    let row = RecordRow {
                        id: item.id, revision, change_seq: s.seq, updated_at: item.updated_at,
                        deleted: item.deleted, dirty: false, nonce: item.nonce, payload: item.payload,
                    };
                    s.records.insert(item.id, row);
                    accepted.push(Accepted { id: item.id, revision, change_seq: s.seq });
                } else {
                    conflicts.push(Conflict { id: item.id, server: current.unwrap() });
                }
            }
            Ok(PushResponse { accepted, conflicts })
        }
    }

    struct Fixture {
        store: LocalStore,
        vault: UnlockedVault,
        meta: LocalMeta,
    }

    fn fixture() -> Fixture {
        let nv = create_vault("pw").unwrap();
        let mut store = LocalStore::open_in_memory().unwrap();
        let meta = LocalMeta {
            user_id: nv.user_id, email: "owner@example.com".into(),
            server_url: "http://test".into(), device_label: "PC-A".into(),
            kdf: nv.kdf.clone(), wrapped_key: nv.wrapped_key.clone(), last_change_seq: 0,
        };
        store.save_meta(&meta).unwrap();
        let vault = crate::crypto::unwrap_vault_key("pw", nv.user_id, &nv.kdf, &nv.wrapped_key).unwrap();
        Fixture { store, vault, meta }
    }

    fn save_dirty(store: &mut LocalStore, vault: &UnlockedVault, account: &Account) -> RecordRow {
        let enc = vault.encrypt_account(account).unwrap();
        let row = RecordRow {
            id: account.id, revision: 0, change_seq: 0, updated_at: account.updated_at.timestamp_millis(),
            deleted: false, dirty: true, nonce: enc.nonce.to_vec(), payload: enc.payload,
        };
        store.upsert_record(&row).unwrap();
        row
    }

    #[tokio::test]
    async fn push_then_pull_marks_clean() {
        let mut f = fixture();
        let api = MockApi::new();
        let account = Account::new("a@b.co", "pw");
        save_dirty(&mut f.store, &f.vault, &account);
        let report = SyncEngine::new(&api, &mut f.store, &f.vault, "PC-A").sync_once().await.unwrap();
        assert_eq!(report.pushed, 1);
        assert!(f.store.load_dirty(10).unwrap().is_empty());
        assert!(f.store.cursor().unwrap() > 0);
    }

    #[tokio::test]
    async fn conflict_copy_preserves_both_versions() {
        let mut f = fixture();
        let api = MockApi::new();
        let account = Account::new("a@b.co", "local-password");
        let row = save_dirty(&mut f.store, &f.vault, &account);
        let mut server_account = account.clone();
        server_account.password = "server-password".into();
        let enc = f.vault.encrypt_account(&server_account).unwrap();
        api.put_server(RecordRow {
            id: account.id, revision: 1, change_seq: 0, updated_at: 2,
            deleted: false, dirty: false, nonce: enc.nonce.to_vec(), payload: enc.payload,
        });
        f.store.upsert_record(&RecordRow { revision: 1, ..row }).unwrap();
        let report = SyncEngine::new(&api, &mut f.store, &f.vault, "PC-A").sync_once().await.unwrap();
        assert_eq!(report.conflicts, 1);
        let all = f.store.load_all_records().unwrap();
        assert_eq!(all.len(), 2);
        let copy = all.iter().find(|r| r.id != account.id).unwrap();
        let copy_account = f.vault.decrypt_account(copy.id, &copy.nonce, &copy.payload).unwrap();
        assert!(copy_account.tags.contains(&"conflict".to_string()));
        assert_eq!(copy_account.password, "local-password");
        let original = f.vault.decrypt_account(account.id, &all.iter().find(|r| r.id == account.id).unwrap().nonce, &all.iter().find(|r| r.id == account.id).unwrap().payload).unwrap();
        assert_eq!(original.password, "server-password");
    }

    #[tokio::test]
    async fn pull_newer_clean_applies() {
        let mut f = fixture();
        let api = MockApi::new();
        let account = Account::new("a@b.co", "server");
        let enc = f.vault.encrypt_account(&account).unwrap();
        api.put_server(RecordRow {
            id: account.id, revision: 1, change_seq: 0, updated_at: 1,
            deleted: false, dirty: false, nonce: enc.nonce.to_vec(), payload: enc.payload,
        });
        let report = SyncEngine::new(&api, &mut f.store, &f.vault, "PC-A").sync_once().await.unwrap();
        assert_eq!(report.pulled, 1);
        assert_eq!(f.store.load_all_records().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn tombstone_with_local_edit_creates_conflict_copy() {
        let mut f = fixture();
        let api = MockApi::new();
        let account = Account::new("a@b.co", "local-edit");
        let row = save_dirty(&mut f.store, &f.vault, &account);
        f.store.mark_clean(account.id, 1, 1).unwrap();
        f.store.upsert_record(&RecordRow { dirty: true, revision: 1, ..row }).unwrap();
        api.put_server(RecordRow {
            id: account.id, revision: 2, change_seq: 0, updated_at: 2,
            deleted: true, dirty: false, nonce: vec![], payload: vec![],
        });
        let report = SyncEngine::new(&api, &mut f.store, &f.vault, "PC-A").sync_once().await.unwrap();
        assert_eq!(report.conflicts, 1);
        let all = f.store.load_all_records().unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|r| r.id == account.id && r.deleted));
        assert!(all.iter().any(|r| r.id != account.id && !r.deleted));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p vault-core sync::tests`
Expected: compile error because `SyncEngine` does not exist.

- [ ] **Step 3: Implement sync types and engine**

Types:

```rust
#[derive(Debug, Clone)]
pub struct PushItem {
    pub id: Uuid,
    pub base_revision: u64,
    pub updated_at: i64,
    pub deleted: bool,
    pub nonce: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PullResponse {
    pub items: Vec<RecordRow>,
    pub next_since: u64,
    pub has_more: bool,
}

#[derive(Debug, Clone)]
pub struct PushResponse {
    pub accepted: Vec<Accepted>,
    pub conflicts: Vec<Conflict>,
}

#[derive(Debug, Clone)]
pub struct Accepted { pub id: Uuid, pub revision: u64, pub change_seq: u64 }

#[derive(Debug, Clone)]
pub struct Conflict { pub id: Uuid, pub server: RecordRow }

#[derive(Debug, Clone, Default)]
pub struct SyncReport { pub pushed: usize, pub pulled: usize, pub conflicts: usize, pub cursor: u64 }

#[async_trait::async_trait]
pub trait SyncApi: Send + Sync {
    async fn pull(&self, since: u64, limit: u32) -> Result<PullResponse>;
    async fn push(&self, items: Vec<PushItem>) -> Result<PushResponse>;
}
```

Engine:

```rust
pub struct SyncEngine<'a> {
    api: &'a dyn SyncApi,
    store: &'a mut LocalStore,
    vault: &'a UnlockedVault,
    device_label: String,
}

impl<'a> SyncEngine<'a> {
    pub fn new(api: &'a dyn SyncApi, store: &'a mut LocalStore, vault: &'a UnlockedVault, device_label: impl Into<String>) -> Self { ... }

    pub async fn sync_once(&mut self) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        let dirty = self.store.load_dirty(200)?;
        if !dirty.is_empty() {
            let items = dirty.iter().map(|r| PushItem { id: r.id, base_revision: r.revision, updated_at: r.updated_at, deleted: r.deleted, nonce: r.nonce.clone(), payload: r.payload.clone() }).collect();
            let response = self.api.push(items).await?;
            for a in response.accepted { self.store.mark_clean(a.id, a.revision, a.change_seq)?; report.pushed += 1; }
            for c in response.conflicts {
                self.store_conflict_copy(c.id)?;
                self.store.upsert_record(&RecordRow { dirty: false, ..c.server })?;
                report.conflicts += 1;
            }
        }
        loop {
            let since = self.store.cursor()?;
            let page = self.api.pull(since, 500).await?;
            for server in &page.items {
                match self.store.get_record(server.id)? {
                    None => self.store.upsert_record(&RecordRow { dirty: false, ..server.clone() })?,
                    Some(local) if server.revision > local.revision => {
                        if local.dirty && !local.deleted { self.store_conflict_copy(server.id)?; report.conflicts += 1; }
                        self.store.upsert_record(&RecordRow { dirty: false, ..server.clone() })?;
                    }
                    Some(_) => {}
                }
                report.pulled += 1;
            }
            self.store.set_cursor(page.next_since)?;
            report.cursor = page.next_since;
            if !page.has_more { break; }
        }
        Ok(report)
    }

    fn store_conflict_copy(&mut self, id: Uuid) -> Result<()> {
        let Some(local) = self.store.get_record(id)? else { return Ok(()); };
        if local.deleted || local.payload.is_empty() { return Ok(()); }
        let account = self.vault.decrypt_account(id, &local.nonce, &local.payload)?;
        let copy = make_conflict_copy(&account, &self.device_label, chrono::Utc::now());
        let enc = self.vault.encrypt_account(&copy)?;
        self.store.upsert_record(&RecordRow {
            id: copy.id, revision: 0, change_seq: 0, updated_at: copy.updated_at.timestamp_millis(),
            deleted: false, dirty: true, nonce: enc.nonce.to_vec(), payload: enc.payload,
        })?;
        Ok(())
    }
}
```

`make_conflict_copy`:

```rust
pub fn make_conflict_copy(account: &Account, device_label: &str, now: DateTime<Utc>) -> Account {
    let mut copy = account.clone();
    copy.id = Uuid::new_v4();
    if !copy.tags.iter().any(|t| t.eq_ignore_ascii_case("conflict")) {
        copy.tags.push("conflict".into());
    }
    let note = format!("Conflict copy từ {device_label} lúc {}", now.format("%d/%m/%Y %H:%M"));
    copy.notes = Some(match &account.notes {
        Some(existing) if !existing.is_empty() => format!("{existing}\n\n{note}"),
        _ => note,
    });
    copy.created_at = now;
    copy.updated_at = now;
    copy
}
```

- [ ] **Step 4: Run tests and commit**

Run: `cargo test -p vault-core sync::tests`
Expected: 5 tests pass.

```bash
git add crates/vault-core
git commit -m "feat(core): add revision-based sync with conflict copies"
```

## Task 6: Server scaffold, config, migrations, health

**Files:**
- Modify: `Cargo.toml` (add server workspace dependencies)
- Modify: `crates/vault-server/Cargo.toml`
- Create: `crates/vault-server/src/lib.rs`
- Create: `crates/vault-server/src/config.rs`
- Create: `crates/vault-server/src/error.rs`
- Create: `crates/vault-server/src/db.rs`
- Create: `crates/vault-server/src/api/mod.rs`
- Create: `crates/vault-server/src/api/health.rs`
- Create: `crates/vault-server/src/main.rs`
- Create: `crates/vault-server/migrations/0001_init.sql`
- Create: `crates/vault-server/tests/health.rs`

**Interfaces:**
- Consumes: nothing from earlier crates (server is independent of `vault-core`).
- Produces:
  - `Config::{from_env, from_map}`
  - `AppState { pool, config }`
  - `build_router(state: AppState) -> axum::Router`
  - `db::{connect, migrate}`
  - `AppError` with `IntoResponse`.

- [ ] **Step 1: Add server dependencies**

Append to root `[workspace.dependencies]`:

```toml
axum = "0.8"
tokio = { version = "1", features = ["full"] }
sqlx = { version = "0.8", features = ["runtime-tokio-rustls", "sqlite", "migrate", "uuid", "chrono"] }
jsonwebtoken = "9"
tower = "0.5"
tower-http = { version = "0.6", features = ["limit", "trace"] }
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
dotenvy = "0.15"
http-body-util = "0.1"
```

Replace `crates/vault-server/Cargo.toml`:

```toml
[package]
name = "vault-server"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
axum.workspace = true
tokio.workspace = true
sqlx.workspace = true
serde.workspace = true
serde_json.workspace = true
jsonwebtoken.workspace = true
argon2.workspace = true
sha2.workspace = true
rand.workspace = true
uuid.workspace = true
chrono.workspace = true
base64.workspace = true
thiserror.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
dotenvy.workspace = true
tower-http.workspace = true

[dev-dependencies]
tower.workspace = true
http-body-util.workspace = true
```

- [ ] **Step 2: Write the failing config and health tests**

`crates/vault-server/src/config.rs` test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_required_values() {
        let env = |k: &str| match k {
            "DATABASE_URL" => Some("sqlite:///tmp/vault.db".to_string()),
            "JWT_SECRET" => Some("0123456789abcdef0123456789abcdef".to_string()),
            _ => None,
        };
        let cfg = Config::from_map(env).unwrap();
        assert_eq!(cfg.bind_addr.to_string(), "127.0.0.1:8080");
        assert_eq!(cfg.max_body_bytes, 2 * 1024 * 1024);
        assert!(!cfg.allow_registration);
    }

    #[test]
    fn rejects_short_jwt_secret() {
        let env = |k: &str| match k {
            "DATABASE_URL" => Some("sqlite::memory:".to_string()),
            "JWT_SECRET" => Some("short".to_string()),
            _ => None,
        };
        assert!(Config::from_map(env).is_err());
    }
}
```

`crates/vault-server/tests/health.rs`:

```rust
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use vault_server::{build_router, config::Config, db, AppState};

async fn test_app() -> axum::Router {
    let pool = db::connect("sqlite::memory:").await.unwrap();
    db::migrate(&pool).await.unwrap();
    let config = Config::from_map(|k| match k {
        "DATABASE_URL" => Some("sqlite::memory:".into()),
        "JWT_SECRET" => Some("0123456789abcdef0123456789abcdef".into()),
        _ => None,
    }).unwrap();
    build_router(AppState { pool, config })
}

#[tokio::test]
async fn health_ok() {
    let app = test_app().await;
    let res = app.oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p vault-server`
Expected: compile error because `Config` and `build_router` do not exist.

- [ ] **Step 4: Implement config, error, db, router**

`config.rs`:

```rust
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub jwt_secret: Arc<Vec<u8>>,
    pub allow_registration: bool,
    pub max_body_bytes: usize,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::from_map(|key| std::env::var(key).ok())
    }

    pub fn from_map(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let database_url = get("DATABASE_URL").ok_or("DATABASE_URL is required")?;
        let secret = get("JWT_SECRET").ok_or("JWT_SECRET is required")?;
        if secret.as_bytes().len() < 32 {
            return Err("JWT_SECRET must be at least 32 bytes".into());
        }
        let bind_addr = get("BIND_ADDR").unwrap_or_else(|| "127.0.0.1:8080".into())
            .parse().map_err(|e| format!("invalid BIND_ADDR: {e}"))?;
        let allow_registration = get("ALLOW_REGISTRATION").map(|v| v == "true").unwrap_or(false);
        let max_body_bytes = get("MAX_BODY_BYTES").and_then(|v| v.parse().ok()).unwrap_or(2 * 1024 * 1024);
        Ok(Self { bind_addr, database_url, jwt_secret: Arc::new(secret.into_bytes()), allow_registration, max_body_bytes })
    }
}
```

`error.rs`:

```rust
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("conflict")]
    Conflict,
    #[error("rate limited")]
    RateLimited,
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, "invalid_request", m),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", "Phiên đăng nhập không hợp lệ".into()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "forbidden", "Không có quyền".into()),
            AppError::Conflict => (StatusCode::CONFLICT, "conflict", "Dữ liệu đã thay đổi".into()),
            AppError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Thử lại sau".into()),
            AppError::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", "Dữ liệu quá lớn".into()),
            AppError::Internal(m) => {
                tracing::error!(error = %m, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal", "Lỗi server".into())
            }
        };
        (status, Json(json!({"error": {"code": code, "message": message}}))).into_response()
    }
}
```

`db.rs`:

```rust
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

pub async fn connect(url: &str) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .foreign_keys(true);
    SqlitePoolOptions::new().max_connections(5).connect_with(options).await
}

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}
```

`api/mod.rs`:

```rust
pub mod health;
```

`api/health.rs`:

```rust
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::{AppState, error::AppError};

pub async fn health(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    sqlx::query("SELECT 1").execute(&state.pool).await.map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(json!({"status": "ok"})))
}
```

`lib.rs`:

```rust
pub mod api;
pub mod config;
pub mod db;
pub mod error;

use std::sync::Arc;
use axum::routing::get;
use axum::Router;
use sqlx::SqlitePool;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use config::Config;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<Config>,
}

pub fn build_router(state: AppState) -> Router {
    let max = state.config.max_body_bytes;
    Router::new()
        .route("/healthz", get(api::health::health))
        .layer(RequestBodyLimitLayer::new(max))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
```

`main.rs`:

```rust
use std::net::SocketAddr;

use tower_http::trace::TraceLayer;
use vault_server::{build_router, config::Config, db, AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = Config::from_env()?;
    let pool = db::connect(&config.database_url).await?;
    db::migrate(&pool).await?;
    let addr = config.bind_addr;
    let app = build_router(AppState { pool, config: std::sync::Arc::new(config) });
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "vault-server listening");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
```

Remove the unused `TraceLayer` import in `main.rs` (the router owns it).

`migrations/0001_init.sql` — copy the exact schema from spec section 5, including `recovery_auth_hash` and all indexes.

- [ ] **Step 5: Run tests and commit**

Run: `cargo test -p vault-server`
Expected: 3 tests pass (2 config + 1 health).

```bash
git add Cargo.toml crates/vault-server
git commit -m "feat(server): add config, SQLite migrations, and health endpoint"
```

---

## Task 7: Server auth, recovery login, and rate limiting

**Files:**
- Create: `crates/vault-server/src/auth.rs`
- Create: `crates/vault-server/src/rate_limit.rs`
- Create: `crates/vault-server/src/api/dto.rs`
- Create: `crates/vault-server/src/api/auth.rs`
- Modify: `crates/vault-server/src/lib.rs`
- Modify: `crates/vault-server/src/api/mod.rs`
- Create: `crates/vault-server/tests/common/mod.rs`
- Create: `crates/vault-server/tests/auth.rs`

**Interfaces:**
- Consumes: `AppState`, `Config`, `AppError`, `SqlitePool`.
- Produces:
  - `AuthService::{register, login, recover_login, refresh, logout, verify_access}`.
  - `AuthUser` extractor.
  - `RateLimiter::check(key, limit, window) -> bool`.
  - DTOs `RegisterRequest`, `LoginRequest`, `RecoverLoginRequest`, `RefreshRequest`, `AuthResponse`, `KdfDto`, `WrappedKeyDto`.

- [ ] **Step 1: Write the failing auth integration tests**

`tests/common/mod.rs`:

```rust
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::SqlitePool;
use tower::ServiceExt;
use uuid::Uuid;
use vault_server::{build_router, config::Config, db, AppState};

pub struct TestApp {
    pub router: Router,
    pub pool: SqlitePool,
    pub config: Arc<Config>,
}

pub async fn spawn() -> TestApp {
    let pool = db::connect("sqlite::memory:").await.unwrap();
    db::migrate(&pool).await.unwrap();
    let config = Arc::new(Config::from_map(|k| match k {
        "DATABASE_URL" => Some("sqlite::memory:".into()),
        "JWT_SECRET" => Some("0123456789abcdef0123456789abcdef".into()),
        _ => None,
    }).unwrap());
    TestApp { router: build_router(AppState::new(pool.clone(), config.clone())), pool, config }
}

pub fn b64(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(bytes)
}

pub fn register_body(email: &str) -> Value {
    json!({
        "user_id": Uuid::new_v4(),
        "email": email,
        "auth_key": b64(&[7u8; 32]),
        "kdf": {"algo": "argon2id", "salt": b64(&[1u8; 16]), "m_kib": 65536, "t": 3, "p": 2},
        "wrapped_key": {"nonce": b64(&[2u8; 24]), "ciphertext": b64(&[3u8; 48])},
        "recovery_wrapped_key": {"nonce": b64(&[4u8; 24]), "ciphertext": b64(&[5u8; 48])},
        "recovery_auth_key": b64(&[6u8; 32])
    })
}

pub async fn request(app: &TestApp, method: &str, uri: &str, token: Option<&str>, body: Option<Value>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token { builder = builder.header("authorization", format!("Bearer {t}")); }
    let body = match body {
        Some(v) => {
            builder = builder.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let res = app.router.clone().oneshot(builder.body(body).unwrap()).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

pub async fn register(app: &TestApp, email: &str) -> (StatusCode, Value) {
    request(app, "POST", "/v1/auth/register", None, Some(register_body(email))).await
}

pub async fn login(app: &TestApp, email: &str) -> (StatusCode, Value) {
    request(app, "POST", "/v1/auth/login", None, Some(json!({"email": email, "auth_key": b64(&[7u8; 32])}))).await
}
```

`tests/auth.rs`:

```rust
mod common;

use common::*;
use serde_json::json;

#[tokio::test]
async fn first_user_registers_second_is_forbidden() {
    let app = spawn().await;
    let (status, body) = register(&app, "owner@example.com").await;
    assert_eq!(status, 201);
    assert!(body["access_token"].is_string());
    let (status, _) = register(&app, "second@example.com").await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn login_and_refresh_rotate() {
    let app = spawn().await;
    register(&app, "owner@example.com").await;
    let (status, body) = login(&app, "owner@example.com").await;
    assert_eq!(status, 200);
    let refresh = body["refresh_token"].as_str().unwrap().to_string();
    let (status, _) = request(&app, "POST", "/v1/auth/refresh", None, Some(json!({"refresh_token": refresh}))).await;
    assert_eq!(status, 200);
    let (status, _) = request(&app, "POST", "/v1/auth/refresh", None, Some(json!({"refresh_token": refresh}))).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn wrong_password_is_401_and_sixth_attempt_is_429() {
    let app = spawn().await;
    register(&app, "owner@example.com").await;
    for _ in 0..5 {
        let (status, _) = request(&app, "POST", "/v1/auth/login", None, Some(json!({
            "email": "owner@example.com", "auth_key": b64(&[9u8; 32])
        }))).await;
        assert_eq!(status, 401);
    }
    let (status, _) = request(&app, "POST", "/v1/auth/login", None, Some(json!({
        "email": "owner@example.com", "auth_key": b64(&[9u8; 32])
    }))).await;
    assert_eq!(status, 429);
}

#[tokio::test]
async fn recovery_login_works_and_logout_revokes() {
    let app = spawn().await;
    register(&app, "owner@example.com").await;
    let (status, body) = request(&app, "POST", "/v1/auth/recover/login", None, Some(json!({
        "email": "owner@example.com", "recovery_auth_key": b64(&[6u8; 32])
    }))).await;
    assert_eq!(status, 200);
    let refresh = body["refresh_token"].as_str().unwrap().to_string();
    let (status, _) = request(&app, "POST", "/v1/auth/logout", None, Some(json!({"refresh_token": refresh.clone()}))).await;
    assert_eq!(status, 204);
    let (status, _) = request(&app, "POST", "/v1/auth/refresh", None, Some(json!({"refresh_token": refresh}))).await;
    assert_eq!(status, 401);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p vault-server --test auth`
Expected: 404 responses or compile error for missing routes/modules.

- [ ] **Step 3: Implement rate limiter and auth service**

`rate_limit.rs`:

```rust
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct RateLimiter { inner: Mutex<HashMap<String, Vec<Instant>>> }

impl RateLimiter {
    pub fn check(&self, key: &str, limit: usize, window: Duration) -> bool {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap();
        let entries = map.entry(key.to_string()).or_default();
        entries.retain(|t| now.duration_since(*t) < window);
        if entries.len() >= limit { return false; }
        entries.push(now);
        true
    }
}
```

`api/dto.rs`:

```rust
use serde::{Deserialize, Serialize};

pub mod b64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

pub mod b64_opt {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => s.serialize_some(&STANDARD.encode(bytes)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let value: Option<String> = Option::deserialize(d)?;
        value.map(|s| STANDARD.decode(&s).map_err(serde::de::Error::custom)).transpose()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfDto {
    pub algo: String,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKeyDto {
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub user_id: Uuid,
    pub email: String,
    #[serde(with = "b64")]
    pub auth_key: Vec<u8>,
    pub kdf: KdfDto,
    pub wrapped_key: WrappedKeyDto,
    pub recovery_wrapped_key: WrappedKeyDto,
    #[serde(with = "b64")]
    pub recovery_auth_key: Vec<u8>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    #[serde(with = "b64")]
    pub auth_key: Vec<u8>,
}

#[derive(Deserialize)]
pub struct RecoverLoginRequest {
    pub email: String,
    #[serde(with = "b64")]
    pub recovery_auth_key: Vec<u8>,
}

#[derive(Deserialize)]
pub struct RefreshRequest { pub refresh_token: String }

#[derive(Serialize)]
pub struct AuthResponse {
    pub user_id: Uuid,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: usize,
    pub kdf: KdfDto,
    pub wrapped_key: WrappedKeyDto,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_wrapped_key: Option<WrappedKeyDto>,
}
```

Add `use uuid::Uuid;` at the top of `dto.rs`.

`auth.rs`:

```rust
use std::sync::Arc;

use argon2::{
    password_hash::{rand_core::OsRng as PwOsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm as JwtAlgorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::api::dto::{AuthResponse, KdfDto, LoginRequest, RecoverLoginRequest, RegisterRequest, WrappedKeyDto};
use crate::error::AppError;
use crate::AppState;

pub const ACCESS_TTL_SECS: usize = 900;
const REFRESH_TTL_MS: i64 = 30 * 24 * 3600 * 1000;

#[derive(Clone)]
pub struct AuthService {
    pool: SqlitePool,
    jwt_secret: Arc<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims { sub: String, exp: usize, iat: usize }

pub struct AuthUser { pub user_id: Uuid }
```

`AuthService::new`, `hash_secret`, `verify_secret`, `random_refresh`, `store_refresh`, `issue`, `register`, `login`, `recover_login`, `refresh`, `logout`, `verify_access`. Use `now_ms()`. `hash_secret` hashes the client-supplied `auth_key`/`recovery_auth_key` with server-side Argon2id `Params::new(19_456, 2, 1, Some(32))` and a fresh `SaltString`; `verify_secret` parses the stored `PasswordHash` and verifies constant-time.

`register` request validation:
```rust
if req.auth_key.len() != 32 || req.recovery_auth_key.len() != 32 { return Err(AppError::BadRequest(...)); }
if req.wrapped_key.nonce.len() != 24 || req.wrapped_key.ciphertext.len() != 48 { ... }
if req.recovery_wrapped_key.nonce.len() != 24 || req.recovery_wrapped_key.ciphertext.len() != 48 { ... }
```
`users` insert:
```sql
INSERT INTO users(id,email,auth_hash,kdf_salt,kdf_params,wrapped_vault_key,wrapped_key_nonce,recovery_wrapped_key,recovery_nonce,recovery_auth_hash,created_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?)
```
`kdf_salt` binds `req.kdf.salt`, `kdf_params` JSON, and the required recovery wrap/hash fields.

`login` selects `id, auth_hash, kdf_params, wrapped_vault_key, wrapped_key_nonce`.
`recover_login` selects `id, recovery_auth_hash, kdf_params, ..., recovery_wrapped_key, recovery_nonce`.
`issue` returns `AuthResponse`; takes optional recovery.

`refresh`:
```rust
let hash = Sha256::digest(token.as_bytes());
let row: Option<(String,i64,i64)> = sqlx::query_as("SELECT user_id, expires_at, revoked FROM refresh_tokens WHERE token_hash = ?")...
if row.is_none() || revoked != 0 || expires_at < now_ms() { return Err(Unauthorized); }
sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?")...
self.issue(user_id, None).await
```
`issue` inserts new refresh.

`logout`: update revoked; always Ok.

`verify_access`:
```rust
let data = decode::<Claims>(token, &DecodingKey::from_secret(&self.jwt_secret), &Validation::new(JwtAlgorithm::HS256))?;
Uuid::parse_str(&data.claims.sub).map_err(|_| AppError::Unauthorized)
```

Extractor uses `state.auth.verify_access(token).await?`.

`api/auth.rs` handlers:
- `register(State, Option<ConnectInfo>, Json<RegisterRequest>) -> Result<(StatusCode, Json<AuthResponse>), AppError>`.
- `login`, `recover_login`, `refresh`, `logout`.
- Rate limit helper `client_ip`.
- Routes function.

`lib.rs` update:
```rust
pub mod auth;
pub mod rate_limit;
...
pub struct AppState { pool, config, auth, rate }
impl AppState::new(...)
build_router: nest("/v1", api::auth::routes())
```

Update health test and common to `AppState::new`.

- [ ] **Step 4: Run tests and commit**

Run: `cargo test -p vault-server`
Expected: 7 tests pass (2 config + 1 health + 4 auth).

```bash
git add crates/vault-server
git commit -m "feat(server): add JWT auth, recovery login, and rate limiting"
```

## Task 8: Server keys and sync endpoints

**Files:**
- Create: `crates/vault-server/src/api/keys.rs`
- Create: `crates/vault-server/src/api/sync.rs`
- Modify: `crates/vault-server/src/api/mod.rs`
- Modify: `crates/vault-server/src/lib.rs`
- Create: `crates/vault-server/tests/sync.rs`

**Interfaces:**
- Consumes: `AuthUser`, `AppState`, `AppError`, `KdfDto`, `WrappedKeyDto`, `b64`.
- Produces:
  - `GET /v1/keys`, `PUT /v1/keys`
  - `GET /v1/sync/changes?since=&limit=`
  - `POST /v1/sync/push`
  - DTOs `RecordDto`, `PushItemDto`, `PushRequest`, `PushResponse`, `AcceptedDto`, `ConflictDto`, `PullResponse`, `PutKeysRequest`.

- [ ] **Step 1: Write the failing keys/sync tests**

`tests/sync.rs`:

```rust
mod common;

use common::*;
use serde_json::{json, Value};

async fn token(app: &TestApp) -> String {
    let (_, body) = register(app, "owner@example.com").await;
    body["access_token"].as_str().unwrap().to_string()
}

fn record(id: &str, base: u64, text: &str) -> Value {
    json!({
        "id": id,
        "base_revision": base,
        "updated_at": 1762000000000_i64,
        "deleted": false,
        "nonce": b64(&[9u8; 24]),
        "payload": b64(text.as_bytes())
    })
}

#[tokio::test]
async fn keys_roundtrip_and_update_revokes_sessions() {
    let app = spawn().await;
    let token = token(&app).await;
    let (status, body) = request(&app, "GET", "/v1/keys", Some(&token), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["kdf"]["algo"], "argon2id");
    let (status, _) = request(&app, "PUT", "/v1/keys", Some(&token), Some(json!({
        "kdf": {"algo": "argon2id", "salt": b64(&[8u8; 16]), "m_kib": 65536, "t": 3, "p": 2},
        "wrapped_key": {"nonce": b64(&[7u8; 24]), "ciphertext": b64(&[6u8; 48])}
    }))).await;
    assert_eq!(status, 204);
    let (status, _) = request(&app, "GET", "/v1/keys", None, None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn push_new_then_update_then_stale_conflict() {
    let app = spawn().await;
    let token = token(&app).await;
    let id = uuid::Uuid::new_v4().to_string();
    let (status, body) = request(&app, "POST", "/v1/sync/push", Some(&token), Some(json!({"records": [record(&id, 0, "v1")]}))).await;
    assert_eq!(status, 200);
    assert_eq!(body["accepted"][0]["revision"], 1);
    let (status, body) = request(&app, "POST", "/v1/sync/push", Some(&token), Some(json!({"records": [record(&id, 1, "v2")]}))).await;
    assert_eq!(status, 200);
    assert_eq!(body["accepted"][0]["revision"], 2);
    let (status, body) = request(&app, "POST", "/v1/sync/push", Some(&token), Some(json!({"records": [record(&id, 1, "stale")]}))).await;
    assert_eq!(status, 200);
    assert_eq!(body["conflicts"][0]["server"]["revision"], 2);
}

#[tokio::test]
async fn pull_since_and_limit() {
    let app = spawn().await;
    let token = token(&app).await;
    let a = uuid::Uuid::new_v4().to_string();
    let b = uuid::Uuid::new_v4().to_string();
    request(&app, "POST", "/v1/sync/push", Some(&token), Some(json!({"records": [record(&a, 0, "a")]}))).await;
    request(&app, "POST", "/v1/sync/push", Some(&token), Some(json!({"records": [record(&b, 0, "b")]}))).await;
    let (status, body) = request(&app, "GET", "/v1/sync/changes?since=0", Some(&token), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["items"].as_array().unwrap().len(), 2);
    let first_seq = body["items"][0]["change_seq"].as_u64().unwrap();
    let (status, body) = request(&app, "GET", &format!("/v1/sync/changes?since={first_seq}"), Some(&token), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn sync_requires_auth() {
    let app = spawn().await;
    let (status, _) = request(&app, "GET", "/v1/sync/changes?since=0", None, None).await;
    assert_eq!(status, 401);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p vault-server --test sync`
Expected: 404 for missing routes.

- [ ] **Step 3: Implement keys and sync handlers**

`api/keys.rs`:

```rust
#[derive(Deserialize)]
pub struct PutKeysRequest {
    pub kdf: KdfDto,
    pub wrapped_key: WrappedKeyDto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_wrapped_key: Option<WrappedKeyDto>,
    #[serde(default, with = "crate::api::dto::b64_opt", skip_serializing_if = "Option::is_none")]
    pub recovery_auth_key: Option<Vec<u8>>,
}
```

- `get_keys`: query `kdf_params`, `wrapped_vault_key`, `wrapped_key_nonce`, recovery fields; parse; return JSON.
- `put_keys`: validate salt 16, nonce 24, ciphertext 48; read the old `kdf_params` and wrapped key; update user; if `recovery_auth_key` is present, require `recovery_wrapped_key` and hash the auth key with Argon2; revoke all refresh tokens **only when `kdf` or `wrapped_key` changed** (master-password rotation). A recovery-only update keeps the current session. Return `StatusCode::NO_CONTENT`.
- Reuse `auth::hash_secret` by making it `pub(crate)`.

`api/sync.rs`:

```rust
#[derive(Deserialize)]
pub struct ChangesQuery { pub since: Option<u64>, pub limit: Option<u32> }

#[derive(Serialize)]
pub struct RecordDto {
    pub id: Uuid,
    pub revision: u64,
    pub change_seq: u64,
    pub updated_at: i64,
    pub deleted: bool,
    #[serde(with = "crate::api::dto::b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "crate::api::dto::b64")]
    pub payload: Vec<u8>,
}

#[derive(Deserialize)]
pub struct PushItemDto {
    pub id: Uuid,
    pub base_revision: u64,
    pub updated_at: i64,
    pub deleted: bool,
    #[serde(with = "crate::api::dto::b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "crate::api::dto::b64")]
    pub payload: Vec<u8>,
}

#[derive(Deserialize)]
pub struct PushRequest { pub records: Vec<PushItemDto> }

#[derive(Serialize)]
pub struct AcceptedDto { pub id: Uuid, pub revision: u64, pub change_seq: u64 }

#[derive(Serialize)]
pub struct ConflictDto { pub id: Uuid, pub server: RecordDto }

#[derive(Serialize)]
pub struct PushResponse { pub accepted: Vec<AcceptedDto>, pub conflicts: Vec<ConflictDto> }

#[derive(Serialize)]
pub struct PullResponse { pub items: Vec<RecordDto>, pub next_since: u64, pub has_more: bool }
```

Handlers:
- `changes(AuthUser, State, Query<ChangesQuery>)`: limit default 500, clamp 1..=1000. Fetch `limit + 1`, trim, `has_more`.
- `push(AuthUser, State, Json<PushRequest>)`: validate count ≤ 200, each payload ≤ 64 KiB, nonce 24 unless deleted. Begin transaction. For each record:
  - `SELECT revision FROM records WHERE user_id=? AND id=?`.
  - none + base 0 → `next_seq`, `INSERT`.
  - some == base → `next_seq`, `UPDATE revision=revision+1`.
  - else → select full row and add conflict.
  - Commit.
- `next_seq` helper as described.
- `record_from_row` helper.

`lib.rs` nest:
```rust
.nest("/v1", api::auth::routes().merge(api::keys::routes()).merge(api::sync::routes()))
```

`api/mod.rs` add `pub mod keys; pub mod sync;`.

- [ ] **Step 4: Run tests and commit**

Run: `cargo test -p vault-server`
Expected: 11 tests pass.

```bash
git add crates/vault-server
git commit -m "feat(server): add key material and sync endpoints"
```

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
  - `VaultHandle { tx, rx }`, `spawn_vault(...)`.
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
            match handle.rx.recv_timeout(Duration::from_millis(100)).unwrap() {
                VaultEvent::Accounts(accounts) if accounts.len() == 1 => break,
                _ if std::time::Instant::now() > deadline => panic!("timeout"),
                _ => {}
            }
        }
        handle.tx.send(VaultCommand::Delete(id)).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match handle.rx.recv_timeout(Duration::from_millis(100)).unwrap() {
                VaultEvent::Accounts(accounts) if accounts.is_empty() => break,
                _ if std::time::Instant::now() > deadline => panic!("timeout"),
                _ => {}
            }
        }
        handle.tx.send(VaultCommand::Shutdown).unwrap();
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
    std::thread::spawn(move || {
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
    VaultHandle { tx, rx }
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

## Task 11: Client sync integration and status banner

**Files:**
- Modify: `crates/vault-core/src/sync.rs` (serde derives)
- Modify: `crates/vault-client/Cargo.toml` (add `async-trait`)
- Modify: `crates/vault-client/src/api.rs` (`SyncApi` impl)
- Modify: `crates/vault-client/src/state.rs` (`SyncStatus`)
- Modify: `crates/vault-client/src/workers/vault.rs` (sync loop)
- Modify: `crates/vault-client/src/app.rs` (spawn with API, handle status)
- Modify: `crates/vault-client/src/ui/main.rs` (sync banner + button)

**Interfaces:**
- Consumes: `vault_core::sync::{SyncApi, SyncEngine, PushItem, PullResponse, PushResponse}`.
- Produces:
  - `impl SyncApi for VaultApi`.
  - `SyncStatus { online, syncing, last_sync, pending, last_error, conflicts }`.
  - `VaultEvent::SyncStatus(SyncStatus)`.
  - `VaultCommand::SyncNow`.

- [ ] **Step 1: Write the failing serialization and status tests**

Add to `crates/vault-core/src/sync.rs`:

```rust
#[test]
fn push_item_serializes_base64_and_snake_case() {
    let item = PushItem {
        id: Uuid::new_v4(), base_revision: 2, updated_at: 5,
        deleted: false, nonce: vec![1; 24], payload: vec![2; 8],
    };
    let value = serde_json::to_value(&item).unwrap();
    assert_eq!(value["base_revision"], 2);
    assert!(value["nonce"].is_string());
    assert!(value["payload"].is_string());
}
```

Add to `crates/vault-client/src/state.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_label_is_vietnamese() {
        let status = SyncStatus { pending: 3, ..Default::default() };
        assert_eq!(status.pending_label(), "3 thay đổi chờ");
        let status = SyncStatus { pending: 0, online: true, ..Default::default() };
        assert_eq!(status.pending_label(), "Đã đồng bộ");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p vault-core push_item_serializes_base64_and_snake_case && cargo test -p vault-client pending_label_is_vietnamese`
Expected: compile error because `PushItem` has no serde and `SyncStatus` does not exist.

- [ ] **Step 3: Add serde derives to core sync types**

In `sync.rs`:

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PushItem {
    pub id: Uuid,
    pub base_revision: u64,
    pub updated_at: i64,
    pub deleted: bool,
    #[serde(with = "crate::codec::base64")]
    pub nonce: Vec<u8>,
    #[serde(with = "crate::codec::base64")]
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PullResponse {
    pub items: Vec<RecordRow>,
    pub next_since: u64,
    pub has_more: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PushResponse {
    pub accepted: Vec<Accepted>,
    pub conflicts: Vec<Conflict>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Accepted { pub id: Uuid, pub revision: u64, pub change_seq: u64 }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Conflict { pub id: Uuid, pub server: RecordRow }
```

`RecordRow` already has serde with base64 and `#[serde(default)] dirty`; verify.

- [ ] **Step 4: Implement `SyncApi` for `VaultApi`**

Add `async-trait.workspace = true` to client dependencies.

In `api.rs`:

```rust
use vault_core::sync::{PullResponse, PushItem, PushResponse, SyncApi};

#[async_trait::async_trait]
impl SyncApi for VaultApi {
    async fn pull(&self, since: u64, limit: u32) -> vault_core::Result<PullResponse> {
        let url = format!("{}/v1/sync/changes?since={since}&limit={limit}", self.base_url);
        let res = self.send_authorized(reqwest::Method::GET, &url, None).await
            .map_err(ApiError::into_core)?;
        res.json().await.map_err(|e| vault_core::CoreError::Network(e.to_string()))
    }

    async fn push(&self, items: Vec<PushItem>) -> vault_core::Result<PushResponse> {
        let url = format!("{}/v1/sync/push", self.base_url);
        let body = serde_json::json!({ "records": items });
        let res = self.send_authorized(reqwest::Method::POST, &url, Some(body)).await
            .map_err(ApiError::into_core)?;
        res.json().await.map_err(|e| vault_core::CoreError::Network(e.to_string()))
    }
}

impl ApiError {
    fn into_core(self) -> vault_core::CoreError {
        match self {
            ApiError::Unauthorized => vault_core::CoreError::Unauthorized,
            other => vault_core::CoreError::Network(other.to_string()),
        }
    }
}
```

`send_authorized`:
- Get access token; if none and email set → `refresh().await`.
- Send with Bearer.
- If 401 → refresh once, retry; if still 401 → `ApiError::Unauthorized`.
- Return response if success; else parse server error.
- `VaultApi::push` sends `{records: [...]}` because the server expects `PushRequest { records }`.

- `VaultApi::refresh()`:
  - email from `self.email`.
  - refresh token from keychain if not in memory; `platform::load_refresh`.
  - POST `/v1/auth/refresh`, store new refresh + access; return.
  - This is called by worker on first sync after restart.

- `VaultApi::new` has `email: Arc<Mutex<String>>`; add `pub fn set_email(&self, email: &str)`.

- `store_tokens` saves refresh and sets email.

- For setup, after register, `store_tokens` uses req.email.

- [ ] **Step 5: Extend worker with sync loop**

`state.rs`:

```rust
#[derive(Debug, Clone, Default)]
pub struct SyncStatus {
    pub online: bool,
    pub syncing: bool,
    pub last_sync: Option<chrono::DateTime<chrono::Utc>>,
    pub pending: usize,
    pub last_error: Option<String>,
    pub conflicts: usize,
}

impl SyncStatus {
    pub fn pending_label(&self) -> String {
        if self.pending > 0 { format!("{} thay đổi chờ", self.pending) }
        else if self.online { "Đã đồng bộ".into() }
        else { "Offline".into() }
    }
}
```

`workers/vault.rs`:
- Add `VaultEvent::SyncStatus(SyncStatus)` and `VaultCommand::SyncNow`.
- Change the worker API parameter to `sync_api: Arc<dyn SyncApi>` so tests can use a no-network mock while production passes `Arc<VaultApi>`. This is an intermediate 8-argument signature; Task 14 adds `auth_key` and `admin_api`.
- Worker state includes `sync_api`, `rt`, `sync_interval`, `last_sync: Option<Instant>`, `last_attempt: Option<Instant>`, `status`.
- On start: set `status.pending = store.count_dirty()?`, emit `Accounts` and `SyncStatus`, then try a sync only if `pending > 0`. Local reads must not wait for the network.
- Loop `recv_timeout(500ms)`:
  - `Ok(cmd)` handle. For Save/Delete/MarkUsed/SaveMany, after the local write call `state.sync_and_emit(&evt_tx)`.
  - `Err(RecvTimeoutError::Timeout)` → sync when the interval elapsed or `pending > 0`, but not more often than once every 5 seconds.
  - `Disconnected` break.
- `sync_now`:
```rust
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
            self.status.last_error = None;
            let _ = self.reload();
            self.status.conflicts = self.accounts.iter()
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
```
Binding `rt`, `sync_api`, `vault`, and the mutable `store` to locals keeps the disjoint field borrows explicit for the borrow checker.
- `sync_and_emit` records `last_attempt`, emits `SyncStatus` before and after, calls `sync_now`, and emits `Accounts` + `SyncStatus`.
- On sync conflict, `reload` decrypts all accounts, including conflict copies.

Task 11 uses this intermediate 8-argument call:
```rust
let sync_api: Arc<dyn SyncApi> = api.clone();
let interval = Duration::from_secs(self.config.sync_interval_secs.clamp(15, 600));
let handle = spawn_vault(
    session.meta, session.vault, session.store, session.accounts,
    platform::db_path(), platform::backup_dir(), sync_api, interval,
);
```
Task 14 replaces it with the final 10-argument call. The Task 10 worker test becomes:
```rust
let handle = spawn_vault(
    meta, vault, store, Vec::new(), db.clone(), dir.path().join("backups"),
    Arc::new(NoopApi), Duration::from_secs(3600),
);
```
with a local `NoopApi` implementing `SyncApi` by returning empty pull/push responses. Use `handle.shutdown()` after Task 14 adds the join handle; until then the test can send `Shutdown`.

- [ ] **Step 6: Wire app status and banner**

`app.rs`:
- On unlock: create `let api = Arc::new(VaultApi::new(&meta.server_url)); api.set_email(&meta.email);` store `self.api = Some(api.clone())`; spawn with a clone coerced to `Arc<dyn SyncApi>`.
- Poll `VaultEvent::SyncStatus(s)` into `self.sync_status`.
- MainView `show` receives `&SyncStatus`; the top bar shows `pending_label()` and a `Sync now` button that sends `VaultCommand::SyncNow`.
- `VaultEvent::BackupDone` sets the toast.

- [ ] **Step 7: Run tests and commit**

Run: `cargo test -p vault-core && cargo test -p vault-client`
Expected: all pass. The worker test uses `NoopApi` and never touches the network.

Manual: run the server + client, add an account, and verify `change_seq` increments via `curl` or a second profile after Task 15.

```bash
git add crates/vault-core crates/vault-client
git commit -m "feat(client): sync encrypted records with status banner"
```

## Task 12: TOTP, password generator, clipboard, and auto-lock

**Files:**
- Create: `crates/vault-core/src/totp.rs`
- Create: `crates/vault-core/src/password.rs`
- Modify: `crates/vault-core/src/lib.rs`
- Create: `crates/vault-client/src/security.rs`
- Modify: `crates/vault-client/src/main.rs` (add `mod security;`)
- Modify: `crates/vault-client/src/ui/editor.rs` (TOTP + copy + generator)
- Modify: `crates/vault-client/src/ui/main.rs` (copy, auto-lock touch)
- Modify: `crates/vault-client/src/app.rs` (auto-lock timer)

**Interfaces:**
- Consumes: `Account`, `zxcvbn`, `totp-rs`, `arboard`.
- Produces:
  - `totp::current_code(secret: &str, unix_secs: u64) -> Result<(String, u32)>`.
  - `password::{PasswordOptions, generate_password, strength_score}`.
  - `security::{AutoLock, copy_password}`.

- [ ] **Step 1: Write the failing core tests**

`totp.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1_vector() {
        // RFC 6238 test secret "12345678901234567890" in base32.
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let (code, remaining) = current_code(secret, 59).unwrap();
        assert_eq!(code, "287082");
        assert_eq!(remaining, 1);
    }

    #[test]
    fn accepts_otpauth_uri() {
        let uri = "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6&period=30";
        let (code, _) = current_code(uri, 59).unwrap();
        assert_eq!(code, "287082");
    }
}
```

`password.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn generated_password_has_requested_length_and_classes() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let opts = PasswordOptions { length: 24, upper: true, lower: true, digits: true, symbols: true, exclude_ambiguous: true };
        let pw = generate_password(&opts, &mut rng).unwrap();
        assert_eq!(pw.chars().count(), 24);
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw.chars().any(|c| !c.is_ascii_alphanumeric()));
        assert!(!pw.chars().any(|c| "Il1O0".contains(c)));
    }

    #[test]
    fn rejects_impossible_options() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let opts = PasswordOptions { length: 2, upper: true, lower: true, digits: true, symbols: true, exclude_ambiguous: false };
        assert!(generate_password(&opts, &mut rng).is_err());
    }

    #[test]
    fn strength_orders_weak_and_strong() {
        assert!(strength_score("123456") <= 1);
        assert!(strength_score("Correct-Horse-Battery-Staple-2026!") >= 3);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p vault-core totp::tests password::tests`
Expected: compile error for missing modules.

- [ ] **Step 3: Implement TOTP and password generation**

`totp.rs`:

```rust
use totp_rs::{Algorithm, Secret, TOTP};

use crate::error::{CoreError, Result};

pub fn current_code(secret: &str, unix_secs: u64) -> Result<(String, u32)> {
    let (secret, digits, period, algorithm) = parse_secret(secret)?;
    let bytes = Secret::Encoded(secret).to_bytes().map_err(|_| CoreError::Validation("TOTP secret không hợp lệ".into()))?;
    let totp = TOTP::new(algorithm, digits, 1, period, bytes).map_err(|e| CoreError::Validation(e.to_string()))?;
    let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(unix_secs);
    let code = totp.generate(time);
    let remaining = period - (unix_secs % period as u64);
    Ok((code, remaining as u32))
}

fn parse_secret(input: &str) -> Result<(String, usize, u64, Algorithm)> {
    let input = input.trim();
    if !input.starts_with("otpauth://") {
        return Ok((input.to_string(), 6, 30, Algorithm::SHA1));
    }
    let url = url::Url::parse(input).map_err(|_| CoreError::Validation("otpauth URI không hợp lệ".into()))?;
    let mut secret = None;
    let mut digits = 6usize;
    let mut period = 30u64;
    let mut algorithm = Algorithm::SHA1;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "secret" => secret = Some(v.to_string()),
            "digits" => digits = v.parse().map_err(|_| CoreError::Validation("digits không hợp lệ".into()))?,
            "period" => period = v.parse().map_err(|_| CoreError::Validation("period không hợp lệ".into()))?,
            "algorithm" => algorithm = match v.to_uppercase().as_str() {
                "SHA1" => Algorithm::SHA1,
                "SHA256" => Algorithm::SHA256,
                "SHA512" => Algorithm::SHA512,
                _ => return Err(CoreError::Validation("algorithm không hỗ trợ".into())),
            },
            _ => {}
        }
    }
    let secret = secret.ok_or(CoreError::Validation("otpauth thiếu secret".into()))?;
    Ok((secret, digits, period, algorithm))
}
```

Add `url.workspace = true` to core and workspace `url = "2"`.

`password.rs`:

```rust
use rand::RngCore;

use crate::error::{CoreError, Result};

#[derive(Debug, Clone, Copy)]
pub struct PasswordOptions {
    pub length: usize,
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self { length: 20, upper: true, lower: true, digits: true, symbols: true, exclude_ambiguous: false }
    }
}

pub fn generate_password(opts: &PasswordOptions, rng: &mut impl RngCore) -> Result<String> {
    let mut sets: Vec<&[u8]> = Vec::new();
    if opts.upper { sets.push(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"); }
    if opts.lower { sets.push(b"abcdefghijklmnopqrstuvwxyz"); }
    if opts.digits { sets.push(b"0123456789"); }
    if opts.symbols { sets.push(b"!@#$%^&*()-_=+[]{};:,.?/"); }
    if sets.is_empty() { return Err(CoreError::Validation("chọn ít nhất một loại ký tự".into())); }
    if opts.length < sets.len() { return Err(CoreError::Validation("độ dài quá ngắn".into())); }

    let allowed = |set: &[u8]| -> Vec<u8> {
        if opts.exclude_ambiguous { set.iter().copied().filter(|c| !b"Il1O0".contains(c)).collect() } else { set.to_vec() }
    };
    let sets: Vec<Vec<u8>> = sets.into_iter().map(allowed).collect();

    let mut chars = Vec::with_capacity(opts.length);
    for set in &sets {
        let idx = (rng.next_u32() as usize) % set.len();
        chars.push(set[idx]);
    }
    let all: Vec<u8> = sets.iter().flatten().copied().collect();
    while chars.len() < opts.length {
        let idx = (rng.next_u32() as usize) % all.len();
        chars.push(all[idx]);
    }
    for i in (1..chars.len()).rev() {
        let j = (rng.next_u32() as usize) % (i + 1);
        chars.swap(i, j);
    }
    String::from_utf8(chars).map_err(|_| CoreError::Internal("invalid charset".into()))
}

pub fn strength_score(password: &str) -> u8 {
    zxcvbn::zxcvbn(password, &[]).map(|e| e.score()).unwrap_or(0)
}
```

`zxcvbn::zxcvbn` signature may return `Result<Entropy, Error>` with `score()`; API in zxcvbn 3: `zxcvbn(password, user_inputs) -> Result<Entropy, Error>`, `entropy.score()` returns `u8`. Fine.

Add `pub mod password; pub mod totp;` to lib.

- [ ] **Step 4: Write the failing client auto-lock test**

`security.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn auto_lock_fires_after_timeout() {
        let start = Instant::now();
        let lock = AutoLock::with_timeout(Duration::from_secs(300), start);
        assert!(!lock.should_lock(start + Duration::from_secs(299)));
        assert!(lock.should_lock(start + Duration::from_secs(300)));
    }
}
```

- [ ] **Step 5: Implement client security and UI wiring**

`security.rs`:

```rust
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct AutoLock { timeout: Duration, last_activity: Instant }

impl AutoLock {
    pub fn with_timeout(timeout: Duration, now: Instant) -> Self { Self { timeout, last_activity: now } }
    pub fn new(timeout: Duration) -> Self { Self::with_timeout(timeout, Instant::now()) }
    pub fn touch(&mut self) { self.last_activity = Instant::now(); }
    pub fn should_lock(&self, now: Instant) -> bool { now.duration_since(self.last_activity) >= self.timeout }
    pub fn timeout(&self) -> Duration { self.timeout }
    pub fn set_timeout(&mut self, timeout: Duration) { self.timeout = timeout; }
}

pub fn copy_password(text: &str, clear_after: Duration) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    clipboard.set_text(text.to_string()).map_err(|e| e.to_string())?;
    let original = text.to_string();
    std::thread::spawn(move || {
        std::thread::sleep(clear_after);
        if let Ok(mut cb) = arboard::Clipboard::new() {
            if cb.get_text().ok().as_deref() == Some(original.as_str()) {
                let _ = cb.clear();
            }
        }
    });
    Ok(())
}
```

`app.rs`:
- `auto_lock: AutoLock` initialized from `config.auto_lock_minutes`.
- In `update` when Main: if any input event, `self.auto_lock.touch()`; then if `should_lock(Instant::now())` → lock.
- On lock, `self.auto_lock.touch()`.

`ui/editor.rs`:
- Add fields `show_secret: bool`, `gen: PasswordOptions`, `gen_value: Option<String>`, `totp_code: Option<(String,u32)>`.
- Password row: `TextEdit::singleline(&mut account.password).password(!show_secret)`, eye toggle, copy button, generate button.
- TOTP row: input + optional code refresh each second using `ctx.input(|i| i.time)`? Use `Utc::now().timestamp() as u64`.
- `generate` window: length slider, checkboxes; button calls core `generate_password` with `rand::thread_rng()`, sets `account.password`.
- `EditorDraft::into_account` records history when the password changed in the editor:
```rust
if self.account.password != self.original_password {
    let new = self.account.password.clone();
    self.account.password = self.original_password.clone();
    self.account.set_password(new, Utc::now());
}
self.account.updated_at = Utc::now();
self.account
```
Restoring the old password before calling `set_password` is required; otherwise `set_password` records the empty string (or the new password) in `password_history`.
- Add test `changing_password_adds_history`:
```rust
let account = Account::new("a@b.co", "old-password");
let mut draft = EditorDraft::from_account(&account);
draft.account.password = "new-password".into();
let saved = draft.into_account();
assert_eq!(saved.password, "new-password");
assert_eq!(saved.password_history[0].password, "old-password");
```

`ui/main.rs`:
- Copy password button in row or editor; use `copy_password`.
- Toast: `app.toast = Some((msg, Instant))`.
- Pass clipboard timeout to editor.

- [ ] **Step 6: Run tests and commit**

Run: `cargo test -p vault-core && cargo test -p vault-client`
Expected: all pass.

```bash
git add crates/vault-core crates/vault-client
git commit -m "feat: add TOTP, password generator, clipboard, and auto-lock"
```

## Task 13: Dashboard, import/export, and backup UI

**Files:**
- Create: `crates/vault-core/src/stats.rs`
- Modify: `crates/vault-core/src/lib.rs`
- Create: `crates/vault-client/src/ui/dashboard.rs`
- Create: `crates/vault-client/src/ui/import.rs`
- Create: `crates/vault-client/src/ui/backup.rs`
- Modify: `crates/vault-client/src/app.rs` (tabs and routing)
- Modify: `crates/vault-client/src/ui/mod.rs`

**Interfaces:**
- Consumes: `Account`, `password::strength_score`, `portability::{import_csv, import_json, export_csv, export_json, list_backups, backup_database, DuplicatePolicy, ImportResult}`.
- Produces:
  - `stats::DashboardStats`, `stats::compute(accounts, today)`.
  - `ui::dashboard::show(ui, &DashboardStats)`.
  - `ui::import::{ImportState, preview, apply}`.
  - `ui::backup::{BackupState, restore_backup}`.
  - `AppTab { Accounts, Dashboard, Import, Backup, Settings }`.

- [ ] **Step 1: Write the failing stats and backup tests**

`stats.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn date() -> NaiveDate { NaiveDate::from_ymd_opt(2026, 11, 6).unwrap() }

    #[test]
    fn counts_plans_statuses_and_expiring() {
        let mut a = Account::new("a@b.co", "123456");
        a.plan = Plan::Pro;
        a.expires_on = Some(date() + chrono::Days::new(10));
        let mut b = Account::new("c@d.co", "Correct-Horse-Battery-Staple-2026!");
        b.plan = Plan::Ultra;
        b.status = AccountStatus::Banned;
        b.expires_on = Some(date() + chrono::Days::new(40));
        let stats = compute(&[a, b], date());
        assert_eq!(stats.total, 2);
        assert_eq!(stats.by_plan, [0, 1, 1]);
        assert_eq!(stats.expiring_30d.len(), 1);
        assert_eq!(stats.by_status.get("Banned"), Some(&1));
    }

    #[test]
    fn finds_weak_and_duplicate_passwords() {
        let a = Account::new("a@b.co", "same-password");
        let b = Account::new("c@d.co", "same-password");
        let c = Account::new("e@f.co", "123456");
        let stats = compute(&[a, b, c], date());
        assert_eq!(stats.duplicates.len(), 2);
        assert!(stats.weak.contains(&c.id));
    }
}
```

`ui/backup.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn restore_copies_backup_and_preserves_current() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("vault.db");
        let backup = dir.path().join("vault-20260101-000000.db");
        std::fs::write(&db, b"current").unwrap();
        std::fs::write(dir.path().join("vault.db-wal"), b"wal").unwrap();
        std::fs::write(dir.path().join("vault.db-shm"), b"shm").unwrap();
        std::fs::write(&backup, b"old").unwrap();
        let backup_dir = dir.path().join("backups");
        restore_backup(&db, &backup, &backup_dir).unwrap();
        assert_eq!(std::fs::read(&db).unwrap(), b"old");
        assert!(!dir.path().join("vault.db-wal").exists());
        assert!(!dir.path().join("vault.db-shm").exists());
        let preserved = std::fs::read_dir(&backup_dir).unwrap().count();
        assert_eq!(preserved, 1);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p vault-core stats::tests && cargo test -p vault-client restore_copies_backup_and_preserves_current`
Expected: compile errors for missing modules.

- [ ] **Step 3: Implement dashboard stats**

`stats.rs`:

```rust
use std::collections::{BTreeMap, HashMap};

use chrono::{Days, NaiveDate};
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::model::{Account, AccountStatus, Plan};

#[derive(Debug, Clone, Default)]
pub struct DashboardStats {
    pub total: usize,
    pub by_plan: [usize; 3],
    pub by_status: BTreeMap<String, usize>,
    pub expiring_30d: Vec<Uuid>,
    pub totals: BTreeMap<String, Decimal>,
    pub weak: Vec<Uuid>,
    pub duplicates: Vec<Uuid>,
    pub stale_90d: Vec<Uuid>,
}

pub fn compute(accounts: &[Account], today: NaiveDate) -> DashboardStats {
    let mut stats = DashboardStats::default();
    let mut password_counts: HashMap<&str, Vec<Uuid>> = HashMap::new();
    for account in accounts {
        stats.total += 1;
        stats.by_plan[match account.plan { Plan::Free => 0, Plan::Pro => 1, Plan::Ultra => 2 }] += 1;
        *stats.by_status.entry(account.status.as_str().to_string()).or_default() += 1;
        if let Some(expires) = account.expires_on {
            if expires <= today + Days::new(30) && expires >= today { stats.expiring_30d.push(account.id); }
        }
        if let Some(price) = &account.price {
            *stats.totals.entry(price.currency.clone()).or_insert(Decimal::ZERO) += price.amount;
        }
        if crate::password::strength_score(&account.password) <= 2 { stats.weak.push(account.id); }
        password_counts.entry(account.password.as_str()).or_default().push(account.id);
        let stale = match account.last_used_on {
            Some(d) => d < today - Days::new(90),
            None => account.created_on.map(|d| d < today - Days::new(90)).unwrap_or(false),
        };
        if stale { stats.stale_90d.push(account.id); }
    }
    for ids in password_counts.values().filter(|ids| ids.len() > 1) {
        stats.duplicates.extend(ids.iter().copied());
    }
    stats
}
```

Add `pub mod stats;` and re-export.

- [ ] **Step 4: Implement import, export, and backup UI**

`ui/import.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat { Csv, Json }

pub struct ImportState {
    pub path: Option<PathBuf>,
    pub format: ImportFormat,
    pub policy: DuplicatePolicy,
    pub preview: Option<ImportResult>,
    pub error: Option<String>,
}

pub fn preview(path: &Path, format: ImportFormat, existing: &HashMap<String, Uuid>, policy: DuplicatePolicy) -> Result<ImportResult, String>
```

- `preview` opens the file, calls `import_csv` or `import_json`.
- UI: `Chọn file` via `rfd::FileDialog`, combo format/policy, show counts + first 10 rows, `Import` button sends `VaultCommand::SaveMany(preview.accounts.clone())`.
- After import, reset.

`ui/backup.rs`:

```rust
pub fn restore_backup(db_path: &Path, backup_path: &Path, backup_dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(backup_dir).map_err(|e| e.to_string())?;
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S-%3f");
    let preserved = backup_dir.join(format!("pre-restore-{stamp}.db"));
    std::fs::copy(db_path, &preserved).map_err(|e| e.to_string())?;
    std::fs::copy(backup_path, db_path).map_err(|e| e.to_string())?;
    for suffix in ["-wal", "-shm"] {
        let path = PathBuf::from(format!("{}{suffix}", db_path.display()));
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
```

- The caller must stop the worker and join it **before** calling `restore_backup`; otherwise the open SQLite handle can keep Windows from replacing the file. On success, reload `LocalMeta` and go to `Screen::Unlock`.
- UI lists `list_backups(backup_dir)` with size/time, `Backup now` sends `VaultCommand::BackupNow`, `Restore` confirms, calls `handle.shutdown()`, then `restore_backup`, then goes to Unlock. Warn that restore uses the backup's master password.
- Export: `Export CSV` and `Export JSON` buttons use `rfd::FileDialog::save_file`, call core `export_csv`/`export_json`. UI warnings/checkboxes for include password/TOTP.

- [ ] **Step 5: Wire tabs into the app**

`state.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppTab { Accounts, Dashboard, Import, Backup, Settings }
```

`app.rs`:
- Top bar with selectable labels for tabs.
- `Accounts` renders `MainView`.
- `Dashboard` computes `stats::compute(&self.accounts, Local::now().date_naive())` and renders cards/lists.
- `Import`/`Backup` render their panels.
- `Settings` is a placeholder until Task 14.
- Keep tables/panels inside `CentralPanel` to avoid nested panel issues.

- [ ] **Step 6: Run tests and commit**

Run: `cargo test -p vault-core && cargo test -p vault-client`
Expected: all pass.

Manual: import the sample CSV from Task 4, verify rows; export CSV and check BOM; backup then restore into a copy.

```bash
git add crates/vault-core crates/vault-client
git commit -m "feat: add dashboard, import/export, and backup restore"
```

## Task 14: Multi-device login, bulk actions, settings, conflicts, rotation, and recovery

**Files:**
- Modify: `crates/vault-server/src/api/dto.rs`
- Modify: `crates/vault-server/src/api/auth.rs`
- Modify: `crates/vault-server/src/api/keys.rs`
- Modify: `crates/vault-server/tests/auth.rs`
- Modify: `crates/vault-server/tests/sync.rs`
- Modify: `crates/vault-core/src/crypto.rs`
- Modify: `crates/vault-core/src/lib.rs`
- Modify: `crates/vault-core/src/model.rs`
- Modify: `crates/vault-client/src/api.rs`
- Modify: `crates/vault-client/src/state.rs`
- Modify: `crates/vault-client/src/platform.rs`
- Modify: `crates/vault-client/src/ui/setup.rs`
- Modify: `crates/vault-client/src/ui/unlock.rs`
- Modify: `crates/vault-client/src/ui/main.rs`
- Modify: `crates/vault-client/src/ui/editor.rs`
- Modify: `crates/vault-client/src/ui/backup.rs`
- Modify: `crates/vault-client/src/workers/vault.rs`
- Modify: `crates/vault-client/src/app.rs`
- Create: `crates/vault-client/src/ui/settings.rs`
- Create: `crates/vault-client/src/ui/conflicts.rs`
- Modify: `crates/vault-client/src/ui/mod.rs`

**Interfaces:**
- Consumes: `VaultApi`, `AdminApi`, `Interval`, `SyncEngine`, `LocalStore`, `UnlockedVault`, `LocalMeta`, `derive_auth_key`, `derive_recovery_auth_key`, `recover_vault`, `write_gvault`, `VaultExport`, `ClientConfig`, `ThemePref`, `list_backups`, `Zeroizing`.
- Produces:
  - `VaultApi::{prelogin, login, recover_login, get_keys, put_keys, logout}` and `AdminApi`.
  - `derive_auth_key(password, kdf)` and `derive_recovery_auth_key(code)`.
  - `Screen::{Setup(SetupMode), ShowRecovery, Unlock, ResetPassword, Main, Fatal}`.
  - `start_device_login`, `start_recovery_login`, `start_unlock`.
  - `VaultCommand::{DeleteMany, ChangeMasterPassword, RegenerateRecovery, Logout, LogoutAndShutdown, SetSyncInterval, ExportGvault}` and `VaultHandle::shutdown_with_logout`.
  - `VaultEvent::{AdminDone, RecoveryRegenerated, LoggedOut, ExportDone}`.
  - `SettingsState`, `SettingsAction`, `ConflictsView`.
  - `Account::duplicate(now)`.
  - `platform::wipe_local_data(db_path, backup_dir)`.

- [ ] **Step 1: Write failing server tests for prelogin, user id, and revocation**

Add to `crates/vault-server/tests/auth.rs`:

```rust
#[tokio::test]
async fn prelogin_returns_kdf_and_login_returns_user_id() {
    let app = spawn().await;
    let body = register_body("owner@example.com");
    let user_id = body["user_id"].clone();
    let (status, _) = request(&app, "POST", "/v1/auth/register", None, Some(body)).await;
    assert_eq!(status, 201);

    let (status, prelogin) = request(
        &app, "GET", "/v1/auth/kdf?email=owner@example.com", None, None,
    ).await;
    assert_eq!(status, 200);
    assert_eq!(prelogin["kdf"]["algo"], "argon2id");
    assert_eq!(prelogin["kdf"]["salt"], b64(&[1u8; 16]));

    let (status, login) = login(&app, "owner@example.com").await;
    assert_eq!(status, 200);
    assert_eq!(login["user_id"], user_id);

    let (status, unknown) = request(
        &app, "GET", "/v1/auth/kdf?email=unknown@example.com", None, None,
    ).await;
    assert_eq!(status, 200);
    assert_ne!(unknown["kdf"]["salt"], prelogin["kdf"]["salt"]);
}
```

Add to `crates/vault-server/tests/sync.rs`:

```rust
#[tokio::test]
async fn change_password_revokes_old_sessions() {
    let app = spawn().await;
    register(&app, "owner@example.com").await;
    let (status, body) = login(&app, "owner@example.com").await;
    assert_eq!(status, 200);
    let access = body["access_token"].as_str().unwrap().to_string();
    let refresh = body["refresh_token"].as_str().unwrap().to_string();

    let (status, _) = request(&app, "PUT", "/v1/keys", Some(&access), Some(json!({
        "kdf": {"algo": "argon2id", "salt": b64(&[8u8; 16]), "m_kib": 65536, "t": 3, "p": 2},
        "wrapped_key": {"nonce": b64(&[7u8; 24]), "ciphertext": b64(&[6u8; 48])}
    }))).await;
    assert_eq!(status, 204);

    let (status, _) = request(
        &app, "POST", "/v1/auth/refresh", None, Some(json!({"refresh_token": refresh})),
    ).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn recovery_only_update_keeps_current_sessions() {
    let app = spawn().await;
    register(&app, "owner@example.com").await;
    let (_, body) = login(&app, "owner@example.com").await;
    let access = body["access_token"].as_str().unwrap().to_string();
    let refresh = body["refresh_token"].as_str().unwrap().to_string();

    let (status, _) = request(&app, "PUT", "/v1/keys", Some(&access), Some(json!({
        "kdf": body["kdf"].clone(),
        "wrapped_key": body["wrapped_key"].clone(),
        "recovery_wrapped_key": {"nonce": b64(&[8u8; 24]), "ciphertext": b64(&[9u8; 48])},
        "recovery_auth_key": b64(&[10u8; 32])
    }))).await;
    assert_eq!(status, 204);

    let (status, _) = request(
        &app, "POST", "/v1/auth/refresh", None, Some(json!({"refresh_token": refresh})),
    ).await;
    assert_eq!(status, 200);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p vault-server --test auth --test sync`
Expected: `prelogin_returns_kdf_and_login_returns_user_id` fails because `/v1/auth/kdf` is 404; the two rotation tests fail because `PUT /v1/keys` does not yet compare key material. `user_id` is already present in the Task 7 `AuthResponse`, so that assertion should already pass.

- [ ] **Step 3: Implement prelogin, user id in auth responses, and conditional revocation**

In `crates/vault-server/src/api/dto.rs`, add:

```rust
#[derive(Debug, Deserialize)]
pub struct PreloginQuery { pub email: String }

#[derive(Debug, Serialize)]
pub struct PreloginResponse { pub kdf: KdfDto }
```

`AuthResponse.user_id` already exists from Task 7. Ensure the Task 7 handlers populate it from the stored user row (do not issue a random or omitted id).

In `crates/vault-server/src/api/auth.rs`:
- Keep `issue(&self, user_id: Uuid, recovery: Option<WrappedKeyDto>) -> Result<AuthResponse, AppError>` and populate `user_id`.
- `register` calls `issue(req.user_id, Some(req.recovery_wrapped_key))`.
- `login` selects `id` and calls `issue(Uuid::parse_str(&id)?, None)`.
- `recover_login` selects `id` and calls `issue(id, Some(recovery))`.
- Add the public prelogin handler:

```rust
pub async fn prelogin(
    State(state): State<AppState>,
    Query(params): Query<PreloginQuery>,
) -> Result<Json<PreloginResponse>, AppError> {
    let email = params.email.trim().to_lowercase();
    let raw: Option<(String,)> = sqlx::query_as(
        "SELECT kdf_params FROM users WHERE email = ?1",
    ).bind(&email).fetch_optional(&state.pool).await.map_err(internal)?;

    let kdf = match raw {
        Some((json,)) => serde_json::from_str::<KdfDto>(&json).map_err(internal)?,
        None => fake_kdf(&email, &state.config.jwt_secret),
    };
    Ok(Json(PreloginResponse { kdf }))
}

fn fake_kdf(email: &str, secret: &[u8]) -> KdfDto {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(email.as_bytes());
    let digest = hasher.finalize();
    KdfDto {
        algo: "argon2id".into(),
        salt: digest[..16].to_vec(),
        m_kib: 65_536,
        t: 3,
        p: 2,
    }
}
```

Add `.route("/auth/kdf", get(prelogin))` to the auth router and import `Query`, `get`, `Sha256`, `Digest`, `PreloginQuery`, and `PreloginResponse`.

In `crates/vault-server/src/api/keys.rs`, implement conditional revocation inside one transaction:

```rust
struct ExistingKeys {
    kdf_params: String,
    wrapped_vault_key: Vec<u8>,
    wrapped_key_nonce: Vec<u8>,
}

if req.recovery_auth_key.is_some() != req.recovery_wrapped_key.is_some() {
    return Err(AppError::BadRequest(
        "recovery_wrapped_key và recovery_auth_key phải đi cùng nhau".into(),
    ));
}
if let Some(auth_key) = &req.recovery_auth_key {
    if auth_key.len() != 32 { return Err(AppError::BadRequest("recovery_auth_key sai".into())); }
}

let new_kdf = serde_json::to_string(&req.kdf).map_err(internal)?;
let mut tx = state.pool.begin().await.map_err(internal)?;
let old: ExistingKeys = sqlx::query_as(
    "SELECT kdf_params, wrapped_vault_key, wrapped_key_nonce FROM users WHERE id = ?1",
).bind(user.user_id).fetch_one(&mut *tx).await.map_err(internal)?;

let auth_material_changed = old.kdf_params != new_kdf
    || old.wrapped_vault_key != req.wrapped_key.ciphertext
    || old.wrapped_key_nonce != req.wrapped_key.nonce;

sqlx::query(
    "UPDATE users SET kdf_params = ?1, kdf_salt = ?2, wrapped_vault_key = ?3, wrapped_key_nonce = ?4 WHERE id = ?5",
)
.bind(&new_kdf)
.bind(&req.kdf.salt)
.bind(&req.wrapped_key.ciphertext)
.bind(&req.wrapped_key.nonce)
.bind(user.user_id)
.execute(&mut *tx).await.map_err(internal)?;

if let Some(wrapped) = &req.recovery_wrapped_key {
    sqlx::query("UPDATE users SET recovery_wrapped_key = ?1, recovery_nonce = ?2 WHERE id = ?3")
        .bind(&wrapped.ciphertext).bind(&wrapped.nonce).bind(user.user_id)
        .execute(&mut *tx).await.map_err(internal)?;
}
if let Some(auth_key) = &req.recovery_auth_key {
    let hash = crate::auth::hash_secret(auth_key)?;
    sqlx::query("UPDATE users SET recovery_auth_hash = ?1 WHERE id = ?2")
        .bind(hash).bind(user.user_id).execute(&mut *tx).await.map_err(internal)?;
}
if auth_material_changed {
    sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?1")
        .bind(user.user_id).execute(&mut *tx).await.map_err(internal)?;
}
tx.commit().await.map_err(internal)?;
```

When recovery fields are absent, leave the existing recovery columns and hash untouched. Keep the existing `kdf_salt` column in sync with `req.kdf.salt`.

- [ ] **Step 4: Add core auth-key derivation helpers**

Add to `crates/vault-core/src/crypto.rs`:

```rust
pub fn derive_auth_key(password: &str, kdf: &KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let master = derive_master(password, kdf)?;
    hkdf32(&master, &kdf.salt, b"gmail-vault/auth/v1")
}

pub fn derive_recovery_auth_key(code: &str) -> Result<Zeroizing<[u8; 32]>> {
    let key = parse_recovery_code(code)?;
    hkdf32(&key, &[], b"gmail-vault/recovery-auth/v1")
}
```

Add tests:

```rust
#[test]
fn auth_key_matches_created_vault() {
    let nv = create_vault("correct horse battery staple").unwrap();
    let derived = derive_auth_key("correct horse battery staple", &nv.kdf).unwrap();
    assert_eq!(&derived[..], &nv.auth_key[..]);
}

#[test]
fn recovery_auth_key_matches_recovery_material() {
    let nv = create_vault("pw").unwrap();
    let derived = derive_recovery_auth_key(&nv.recovery.display).unwrap();
    assert_eq!(&derived[..], &nv.recovery.auth_key[..]);
}
```

Re-export both functions from `lib.rs`.

- [ ] **Step 5: Run core and server tests**

Run: `cargo test -p vault-core crypto::tests && cargo test -p vault-server`
Expected: all server tests pass, including `change_password_revokes_old_sessions` and `recovery_only_update_keeps_current_sessions`.

- [ ] **Step 6: Add client API request tests, then implement admin API methods**

Add to `crates/vault-client/src/api.rs` tests:

```rust
#[test]
fn login_and_recover_requests_use_base64_auth_keys() {
    let login = LoginRequest { email: "a@b.co".into(), auth_key: vec![7u8; 32] };
    let value = serde_json::to_value(&login).unwrap();
    assert!(value["auth_key"].is_string());

    let recover = RecoverLoginRequest {
        email: "a@b.co".into(),
        recovery_auth_key: vec![8u8; 32],
    };
    let value = serde_json::to_value(&recover).unwrap();
    assert!(value["recovery_auth_key"].is_string());
}

#[test]
fn put_keys_omits_absent_recovery_fields() {
    let req = PutKeysRequest {
        kdf: KdfParams::generate(),
        wrapped_key: WrappedKey { nonce: vec![0u8; 24], ciphertext: vec![0u8; 48] },
        recovery_wrapped_key: None,
        recovery_auth_key: None,
    };
    let value = serde_json::to_value(&req).unwrap();
    assert!(value.get("recovery_wrapped_key").is_none());
    assert!(value.get("recovery_auth_key").is_none());
}
```

Run: `cargo test -p vault-client login_and_recover_requests_use_base64_auth_keys`
Expected: compile error because `LoginRequest` and `RecoverLoginRequest` do not exist.

Add the DTOs:

```rust
#[derive(Serialize)]
pub struct LoginRequest {
    pub email: String,
    #[serde(with = "vault_core::codec::base64")]
    pub auth_key: Vec<u8>,
}

#[derive(Serialize)]
pub struct RecoverLoginRequest {
    pub email: String,
    #[serde(with = "vault_core::codec::base64")]
    pub recovery_auth_key: Vec<u8>,
}
```

Add a trait next to `VaultApi`:

```rust
#[async_trait::async_trait]
pub trait AdminApi: Send + Sync {
    async fn login(&self, email: &str, auth_key: &[u8]) -> Result<AuthResponse, ApiError>;
    async fn get_keys(&self) -> Result<KeysResponse, ApiError>;
    async fn put_keys(&self, req: PutKeysRequest) -> Result<(), ApiError>;
    async fn logout(&self) -> Result<(), ApiError>;
}
```

Implement the methods on `VaultApi`:

- `prelogin(&self, email: &str) -> Result<PreloginResponse, ApiError>`:
  `GET {base}/v1/auth/kdf` with `.query(&[("email", email)])`; parse JSON.
- `login(&self, email: &str, auth_key: &[u8]) -> Result<AuthResponse, ApiError>`:
  POST `/v1/auth/login` with `LoginRequest`; on success call `store_tokens(email, &auth)`.
- `recover_login(&self, email: &str, recovery_auth_key: &[u8]) -> Result<AuthResponse, ApiError>`:
  POST `/v1/auth/recover/login` with `RecoverLoginRequest`; store tokens under `email`.
- `get_keys(&self) -> Result<KeysResponse, ApiError>`: GET `/v1/keys` with `send_authorized` (refresh once on 401).
- `put_keys(&self, req: PutKeysRequest) -> Result<(), ApiError>`:
  PUT `/v1/keys` with `send_authorized`; require 204.
- `logout(&self) -> Result<(), ApiError>`:
  read the refresh token from the keychain using the stored server URL and email; if present POST `/v1/auth/logout` with `{refresh_token}` (best effort); delete the keychain entry; clear `self.access`; return `Ok(())` even if the network call fails.
- Make `store_tokens(&self, email: &str, auth: &AuthResponse)` the single place that stores the refresh token and sets `self.email`.
- Keep one private helper for error parsing:
  ```rust
  async fn parse_json<T: serde::de::DeserializeOwned>(res: reqwest::Response) -> Result<T, ApiError> {
      if res.status().is_success() {
          res.json().await.map_err(|e| ApiError::Network(e.to_string()))
      } else {
          Err(Self::parse_error(res).await)
      }
  }
  ```

Trait impl:

```rust
#[async_trait::async_trait]
impl AdminApi for VaultApi {
    async fn login(&self, email: &str, auth_key: &[u8]) -> Result<AuthResponse, ApiError> {
        VaultApi::login(self, email, auth_key).await
    }
    async fn get_keys(&self) -> Result<KeysResponse, ApiError> {
        VaultApi::get_keys(self).await
    }
    async fn put_keys(&self, req: PutKeysRequest) -> Result<(), ApiError> {
        VaultApi::put_keys(self, req).await
    }
    async fn logout(&self) -> Result<(), ApiError> {
        VaultApi::logout(self).await
    }
}
```

Run: `cargo test -p vault-client`
Expected: the two new serialization tests pass.

- [ ] **Step 7: Add device login and recovery login flows**

Add tests to `ui/setup.rs`:

```rust
#[test]
fn validate_device_login_requires_https_and_email() {
    assert!(validate_device_login("https://vault.example.com", "a@b.co", "long-enough-pass").is_ok());
    assert!(validate_device_login("vault.example.com", "a@b.co", "long-enough-pass").is_err());
    assert!(validate_device_login("https://vault.example.com", "bad", "long-enough-pass").is_err());
    assert!(validate_device_login("https://vault.example.com", "a@b.co", "short").is_err());
}

#[test]
fn validate_recovery_requires_new_password_and_confirmation() {
    assert!(validate_recovery("https://vault.example.com", "a@b.co", "ABCDE-FGHJK", "long-enough-pass", "long-enough-pass").is_ok());
    assert!(validate_recovery("https://vault.example.com", "a@b.co", "", "long-enough-pass", "long-enough-pass").is_err());
    assert!(validate_recovery("https://vault.example.com", "a@b.co", "ABCDE-FGHJK", "long-enough-pass", "different-pass").is_err());
}
```

Run: `cargo test -p vault-client validate_device_login_requires_https_and_email`
Expected: compile error for missing `validate_device_login` / `validate_recovery`.

Implement in `state.rs`:

```rust
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupMode { Create, DeviceLogin, Recovery }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Setup(SetupMode),
    ShowRecovery,
    Unlock,
    ResetPassword,
    Main,
    Fatal,
}

// Replaces the Task 9 data-free enum and updates every match arm. `Setup`
// now carries the selected tab; `ResetPassword` is the online recovery flow.
pub struct UnlockedSession {
    pub meta: LocalMeta,
    pub store: LocalStore,
    pub vault: UnlockedVault,
    pub accounts: Vec<Account>,
    pub auth_key: Zeroizing<[u8; 32]>,
}
```

Keep the recovery code and optional session in the app, not in `Screen`:

```rust
pub struct RecoveryDisplay {
    pub code: String,
    pub session: Option<UnlockedSession>,
}
```

In `ui/setup.rs` add validation:

```rust
pub fn validate_device_login(server_url: &str, email: &str, password: &str) -> Result<(), String> {
    validate_server_and_email(server_url, email)?;
    if password.chars().count() < 12 {
        return Err("Master password phải dài ít nhất 12 ký tự".into());
    }
    Ok(())
}

pub fn validate_recovery(
    server_url: &str,
    email: &str,
    code: &str,
    password: &str,
    confirm: &str,
) -> Result<(), String> {
    validate_server_and_email(server_url, email)?;
    if code.trim().is_empty() {
        return Err("Nhập recovery key".into());
    }
    if password.chars().count() < 12 {
        return Err("Master password mới phải dài ít nhất 12 ký tự".into());
    }
    if password != confirm {
        return Err("Mật khẩu xác nhận không khớp".into());
    }
    Ok(())
}

fn validate_server_and_email(server_url: &str, email: &str) -> Result<(), String> {
    if !(server_url.starts_with("https://") || server_url.starts_with("http://")) {
        return Err("Server URL phải bắt đầu bằng https:// hoặc http://".into());
    }
    if !email.contains('@') || !email.split('@').nth(1).map(|d| d.contains('.')).unwrap_or(false) {
        return Err("Email không hợp lệ".into());
    }
    Ok(())
}
```

Refactor `validate_setup` to call `validate_server_and_email` and keep its existing behavior.

Add events:

```rust
pub enum DeviceLoginEvent { Done(UnlockedSession), Failed(String) }
pub enum RecoveryLoginEvent {
    Done { session: UnlockedSession, recovery_code: String },
    Failed(String),
}
```

`start_device_login(config: ClientConfig, email: String, password: String) -> Receiver<DeviceLoginEvent>`:

1. Build a current-thread Tokio runtime.
2. `let api = VaultApi::new(&config.server_url);`
3. `let pre = api.prelogin(&email).await?;`
4. `let auth_key = derive_auth_key(&password, &pre.kdf)?;`
5. `let auth = api.login(&email, &auth_key).await?;`
6. `let vault = unwrap_vault_key(&password, auth.user_id, &auth.kdf, &auth.wrapped_key)?;`
7. Open `LocalStore::open(&platform::db_path())`; if `load_meta()?.is_some()` return the error `"Thiết bị này đã có vault. Hãy mở khóa thay vì đăng nhập mới."`.
8. Save `LocalMeta { user_id: auth.user_id, email, server_url: config.server_url, device_label: config.device_label, kdf: auth.kdf, wrapped_key: auth.wrapped_key, last_change_seq: 0 }`.
9. Return `UnlockedSession { meta, store, vault, accounts: Vec::new(), auth_key }`.

`start_recovery_login(config, email, code, new_password, existing_meta: Option<LocalMeta>) -> Receiver<RecoveryLoginEvent>`:

1. `let api = VaultApi::new(&config.server_url);`
2. `let recovery_auth_key = derive_recovery_auth_key(&code)?;`
3. `let auth = api.recover_login(&email, &recovery_auth_key).await?;`
4. `let wrapped = auth.recovery_wrapped_key.clone().ok_or("Server không có recovery key")?;`
5. `let vault = recover_vault(&code, auth.user_id, &wrapped)?;`
6. If `existing_meta` is `Some` and its `user_id != auth.user_id`, return `"Tài khoản recovery không khớp với vault cục bộ."`.
7. `let (kdf, wrapped_key, auth_key) = vault.rewrap_with_password(&new_password)?;`
8. `let recovery = vault.new_recovery()?;`
9. `api.put_keys(PutKeysRequest { kdf: kdf.clone(), wrapped_key: wrapped_key.clone(), recovery_wrapped_key: Some(recovery.wrapped_key), recovery_auth_key: Some(recovery.auth_key.to_vec()) }).await?;`
10. Try `api.login(&email, &auth_key).await`; ignore a failure here because the worker re-authenticates on its first sync.
11. Open the store and save `LocalMeta` with the new `kdf`/`wrapped_key`; preserve `last_change_seq` from `existing_meta` or use 0.
12. Load and decrypt all non-deleted records; return the session and `recovery.display`.

`start_unlock` in `ui/unlock.rs` must derive the auth key after unwrapping:

```rust
let auth_key = derive_auth_key(&password, &meta.kdf).map_err(|e| e.to_string())?;
let vault = unwrap_vault_key(&password, meta.user_id, &meta.kdf, &meta.wrapped_key)
    .map_err(|e| e.to_string())?;
```

Include `auth_key` in `UnlockedSession`.

Run: `cargo test -p vault-client`
Expected: all client tests pass.

- [ ] **Step 8: Write failing worker admin tests**

In `workers/vault.rs` tests, extend the imports with `use crate::api::{AdminApi, ApiError, AuthResponse, KeysResponse, PutKeysRequest};` and `KdfParams, WrappedKey` from `vault_core`, then add helper types:

```rust
struct NoopApi;

#[async_trait::async_trait]
impl SyncApi for NoopApi {
    async fn pull(&self, _since: u64, _limit: u32) -> vault_core::Result<PullResponse> {
        Ok(PullResponse { items: Vec::new(), next_since: 0, has_more: false })
    }
    async fn push(&self, _items: Vec<PushItem>) -> vault_core::Result<PushResponse> {
        Ok(PushResponse { accepted: Vec::new(), conflicts: Vec::new() })
    }
}

struct MockAdmin {
    fail: bool,
    keys: std::sync::Mutex<KeysResponse>,
    puts: std::sync::Mutex<Vec<PutKeysRequest>>,
}

impl MockAdmin {
    fn new(fail: bool, meta: &LocalMeta) -> Self {
        Self {
            fail,
            keys: std::sync::Mutex::new(KeysResponse {
                kdf: meta.kdf.clone(),
                wrapped_key: meta.wrapped_key.clone(),
                recovery_wrapped_key: None,
            }),
            puts: Default::default(),
        }
    }
}

fn sample_auth(user_id: Uuid) -> AuthResponse {
    AuthResponse {
        user_id,
        access_token: "access".into(),
        refresh_token: "refresh".into(),
        expires_in: 900,
        kdf: KdfParams::generate(),
        wrapped_key: WrappedKey { nonce: vec![0u8; 24], ciphertext: vec![0u8; 48] },
        recovery_wrapped_key: None,
    }
}

#[async_trait::async_trait]
impl AdminApi for MockAdmin {
    async fn login(&self, _email: &str, _auth_key: &[u8]) -> Result<AuthResponse, ApiError> {
        Ok(sample_auth(Uuid::new_v4()))
    }
    async fn get_keys(&self) -> Result<KeysResponse, ApiError> {
        if self.fail { return Err(ApiError::Network("offline".into())); }
        Ok(self.keys.lock().unwrap().clone())
    }
    async fn put_keys(&self, req: PutKeysRequest) -> Result<(), ApiError> {
        if self.fail { return Err(ApiError::Network("offline".into())); }
        {
            let mut keys = self.keys.lock().unwrap();
            keys.kdf = req.kdf.clone();
            keys.wrapped_key = req.wrapped_key.clone();
            if req.recovery_wrapped_key.is_some() {
                keys.recovery_wrapped_key = req.recovery_wrapped_key.clone();
            }
        }
        self.puts.lock().unwrap().push(req);
        Ok(())
    }
    async fn logout(&self) -> Result<(), ApiError> { Ok(()) }
}

fn fixture(dir: &tempfile::TempDir) -> (LocalMeta, UnlockedVault, LocalStore, zeroize::Zeroizing<[u8; 32]>, PathBuf) {
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
    (meta, vault, store, nv.auth_key.clone(), db)
}

fn wait_for(handle: &VaultHandle, pred: impl Fn(&VaultEvent) -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        match handle.rx.recv_timeout(Duration::from_millis(100)) {
            Ok(evt) if pred(&evt) => return,
            Ok(_) => {}
            Err(_) if std::time::Instant::now() > deadline => panic!("timeout"),
            Err(_) => {}
        }
    }
}
```

Add tests:

```rust
#[test]
fn change_password_rewrites_meta_after_server_accepts() {
    let dir = tempfile::tempdir().unwrap();
    let (meta, vault, store, auth_key, db) = fixture(&dir);
    let admin = std::sync::Arc::new(MockAdmin::new(false, &meta));
    let handle = spawn_vault(
        meta.clone(), vault, store, Vec::new(), auth_key, db.clone(),
        dir.path().join("backups"), std::sync::Arc::new(NoopApi),
        admin.clone() as std::sync::Arc<dyn AdminApi>, Duration::from_secs(3600),
    );
    handle.tx.send(VaultCommand::ChangeMasterPassword("new-password-123".into())).unwrap();
    wait_for(&handle, |e| matches!(e, VaultEvent::AdminDone(_)));
    handle.shutdown();

    let store = LocalStore::open(&db).unwrap();
    let meta = store.load_meta().unwrap().unwrap();
    assert!(unwrap_vault_key("new-password-123", meta.user_id, &meta.kdf, &meta.wrapped_key).is_ok());
    assert!(unwrap_vault_key("pw", meta.user_id, &meta.kdf, &meta.wrapped_key).is_err());
}

#[test]
fn change_password_keeps_meta_when_server_rejects() {
    let dir = tempfile::tempdir().unwrap();
    let (meta, vault, store, auth_key, db) = fixture(&dir);
    let admin = std::sync::Arc::new(MockAdmin::new(true, &meta));
    let handle = spawn_vault(
        meta.clone(), vault, store, Vec::new(), auth_key, db.clone(),
        dir.path().join("backups"), std::sync::Arc::new(NoopApi),
        admin.clone() as std::sync::Arc<dyn AdminApi>, Duration::from_secs(3600),
    );
    handle.tx.send(VaultCommand::ChangeMasterPassword("new-password-123".into())).unwrap();
    wait_for(&handle, |e| matches!(e, VaultEvent::Error(_)));
    handle.shutdown();

    let store = LocalStore::open(&db).unwrap();
    let meta = store.load_meta().unwrap().unwrap();
    assert!(unwrap_vault_key("pw", meta.user_id, &meta.kdf, &meta.wrapped_key).is_ok());
}

#[test]
fn regenerate_recovery_sends_new_material() {
    let dir = tempfile::tempdir().unwrap();
    let (meta, vault, store, auth_key, db) = fixture(&dir);
    let admin = std::sync::Arc::new(MockAdmin::new(false, &meta));
    let handle = spawn_vault(
        meta.clone(), vault, store, Vec::new(), auth_key, db,
        dir.path().join("backups"), std::sync::Arc::new(NoopApi),
        admin.clone() as std::sync::Arc<dyn AdminApi>, Duration::from_secs(3600),
    );
    handle.tx.send(VaultCommand::RegenerateRecovery).unwrap();
    let mut code = None;
    wait_for(&handle, |e| {
        if let VaultEvent::RecoveryRegenerated(c) = e { code = Some(c.clone()); true } else { false }
    });
    handle.shutdown();

    let puts = admin.puts.lock().unwrap();
    let req = puts.last().expect("put_keys request");
    let wrapped = req.recovery_wrapped_key.as_ref().expect("recovery wrap");
    assert!(req.recovery_auth_key.is_some());
    assert!(recover_vault(code.as_deref().unwrap(), meta.user_id, wrapped).is_ok());
}

#[test]
fn regenerate_recovery_rejects_stale_server_keys() {
    let dir = tempfile::tempdir().unwrap();
    let (meta, vault, store, auth_key, db) = fixture(&dir);
    let mut server_meta = meta.clone();
    server_meta.kdf = KdfParams::generate();
    let admin = std::sync::Arc::new(MockAdmin::new(false, &server_meta));
    let handle = spawn_vault(
        meta, vault, store, Vec::new(), auth_key, db,
        dir.path().join("backups"), std::sync::Arc::new(NoopApi),
        admin.clone() as std::sync::Arc<dyn AdminApi>, Duration::from_secs(3600),
    );
    handle.tx.send(VaultCommand::RegenerateRecovery).unwrap();
    wait_for(&handle, |e| matches!(e, VaultEvent::Error(_)));
    handle.shutdown();

    assert!(admin.puts.lock().unwrap().is_empty());
}

#[test]
fn delete_many_removes_all_selected_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let (meta, vault, store, auth_key, db) = fixture(&dir);
    let admin = std::sync::Arc::new(MockAdmin::new(false, &meta));
    let handle = spawn_vault(
        meta, vault, store, Vec::new(), auth_key, db.clone(),
        dir.path().join("backups"), std::sync::Arc::new(NoopApi),
        admin as std::sync::Arc<dyn AdminApi>, Duration::from_secs(3600),
    );
    let a = Account::new("a@b.co", "p");
    let b = Account::new("c@d.co", "p");
    let ids = vec![a.id, b.id];
    handle.tx.send(VaultCommand::SaveMany(vec![a, b])).unwrap();
    wait_for(&handle, |e| matches!(e, VaultEvent::Accounts(rows) if rows.len() == 2));
    handle.tx.send(VaultCommand::DeleteMany(ids)).unwrap();
    wait_for(&handle, |e| matches!(e, VaultEvent::Accounts(rows) if rows.is_empty()));
    handle.shutdown();

    let store = LocalStore::open(&db).unwrap();
    let rows = store.load_all_records().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.deleted));
}
```

Run: `cargo test -p vault-client change_password_rewrites_meta_after_server_accepts`
Expected: compile errors for `AdminApi`, `VaultCommand::ChangeMasterPassword`, `DeleteMany`, `VaultHandle::shutdown`.

- [ ] **Step 9: Implement worker admin commands and session bootstrap**

Final signature (replace the Task 11 signature and update every call site):

```rust
pub fn spawn_vault(
    meta: LocalMeta,
    vault: UnlockedVault,
    store: LocalStore,
    accounts: Vec<Account>,
    auth_key: Zeroizing<[u8; 32]>,
    db_path: PathBuf,
    backup_dir: PathBuf,
    sync_api: Arc<dyn SyncApi>,
    admin_api: Arc<dyn AdminApi>,
    sync_interval: Duration,
) -> VaultHandle
```

`VaultHandle` gains a join handle:

```rust
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

    pub fn shutdown_with_logout(mut self) {
        let _ = self.tx.send(VaultCommand::LogoutAndShutdown);
        if let Some(join) = self.join.take() { let _ = join.join(); }
    }
}
```

`spawn_vault` must keep the `JoinHandle` returned by `thread::spawn` and return `VaultHandle { tx, rx, join: Some(worker) }`. Update every call site — the Task 10 worker test (6 → 10), the Task 11 worker test, and `start_vault` (8 → 10) — inserting `auth_key` after `accounts` and `admin_api` after `sync_api`, with the `Duration` interval last. In the Task 10 worker test replace `handle.tx.send(VaultCommand::Shutdown).unwrap()` with `handle.shutdown()` so SQLite is closed before the test reopens the database.

Extend the enums:

```rust
pub enum VaultCommand {
    Save(Account),
    SaveMany(Vec<Account>),
    Delete(Uuid),
    DeleteMany(Vec<Uuid>),
    MarkUsed(Uuid),
    Reload,
    BackupNow,
    ExportGvault(PathBuf),
    SyncNow,
    ChangeMasterPassword(String),
    RegenerateRecovery,
    SetSyncInterval(Duration),
    Logout,
    LogoutAndShutdown,
    Shutdown,
}

pub enum VaultEvent {
    Accounts(Vec<Account>),
    Error(String),
    BackupDone(PathBuf),
    ExportDone(PathBuf),
    AdminDone(String),
    RecoveryRegenerated(String),
    LoggedOut,
    SyncStatus(SyncStatus),
}
```

Worker fields:

```rust
struct WorkerState {
    meta: LocalMeta,
    store: LocalStore,
    vault: UnlockedVault,
    accounts: Vec<Account>,
    auth_key: Zeroizing<[u8; 32]>,
    db_path: PathBuf,
    backup_dir: PathBuf,
    sync_api: Arc<dyn SyncApi>,
    admin_api: Arc<dyn AdminApi>,
    rt: tokio::runtime::Runtime,
    sync_interval: Duration,
    last_sync: Option<Instant>,
    last_attempt: Option<Instant>,
    last_backup_check: Instant,
    logged_in: bool,
    status: SyncStatus,
}
```

Session bootstrap:

```rust
fn ensure_session(&mut self) -> bool {
    if self.logged_in { return true; }
    match self.rt.block_on(self.admin_api.login(&self.meta.email, &self.auth_key[..])) {
        Ok(_) => { self.logged_in = true; true }
        Err(e) => {
            self.status.online = false;
            self.status.last_error = Some(e.to_string());
            false
        }
    }
}
```

At worker start: compute `status.pending`, emit `Accounts` and `SyncStatus` immediately so the UI renders decrypted local data without waiting for the network; then run `maybe_auto_backup`, then call `ensure_session` (best effort) and start the first sync if it succeeded. Do not abort local operation when offline.

`sync_now` starts with `if !self.ensure_session() { ... return status; }`. On `vault_core::CoreError::Unauthorized`, set `self.logged_in = false` so the next tick retries login.

Admin command handlers:

```rust
VaultCommand::ChangeMasterPassword(new_password) => {
    match state.change_master_password(&new_password) {
        Ok(()) => { let _ = evt_tx.send(VaultEvent::AdminDone("Đã đổi master password".into())); }
        Err(e) => { let _ = evt_tx.send(VaultEvent::Error(e.to_string())); }
    }
}
VaultCommand::RegenerateRecovery => {
    match state.regenerate_recovery() {
        Ok(code) => { let _ = evt_tx.send(VaultEvent::RecoveryRegenerated(code)); }
        Err(e) => { let _ = evt_tx.send(VaultEvent::Error(e.to_string())); }
    }
}
VaultCommand::Logout => {
    let _ = state.rt.block_on(state.admin_api.logout());
    state.logged_in = false;
    let _ = evt_tx.send(VaultEvent::LoggedOut);
    break;
}
VaultCommand::LogoutAndShutdown => {
    // Best effort: revoke the refresh token and delete the keychain entry,
    // then exit so the caller can safely delete the local database.
    let _ = state.rt.block_on(state.admin_api.logout());
    state.logged_in = false;
    break;
}
VaultCommand::SetSyncInterval(d) => {
    state.sync_interval = d.clamp(Duration::from_secs(15), Duration::from_secs(600));
}
VaultCommand::ExportGvault(path) => {
    match state.export_gvault(&path) {
        Ok(()) => { let _ = evt_tx.send(VaultEvent::ExportDone(path)); }
        Err(e) => { let _ = evt_tx.send(VaultEvent::Error(e.to_string())); }
    }
}
```

Implement:

```rust
impl WorkerState {
    fn change_master_password(&mut self, new_password: &str) -> vault_core::Result<()> {
        if new_password.chars().count() < 12 {
            return Err(vault_core::CoreError::Validation("Master password phải dài ít nhất 12 ký tự".into()));
        }
        let (kdf, wrapped_key, auth_key) = self.vault.rewrap_with_password(new_password)?;
        let req = PutKeysRequest {
            kdf: kdf.clone(),
            wrapped_key: wrapped_key.clone(),
            recovery_wrapped_key: None,
            recovery_auth_key: None,
        };
        self.rt.block_on(self.admin_api.put_keys(req))
            .map_err(|e| vault_core::CoreError::Network(e.to_string()))?;

        self.meta.kdf = kdf;
        self.meta.wrapped_key = wrapped_key;
        self.store.save_meta(&self.meta)?;
        self.auth_key = auth_key;
        self.rt.block_on(self.admin_api.login(&self.meta.email, &self.auth_key[..]))
            .map_err(|e| vault_core::CoreError::Network(e.to_string()))?;
        self.logged_in = true;
        Ok(())
    }

    fn regenerate_recovery(&mut self) -> vault_core::Result<String> {
        let server = self.rt.block_on(self.admin_api.get_keys())
            .map_err(|e| vault_core::CoreError::Network(e.to_string()))?;
        if server.kdf != self.meta.kdf || server.wrapped_key != self.meta.wrapped_key {
            return Err(vault_core::CoreError::Validation(
                "Master password đã thay đổi trên thiết bị khác. Hãy khóa rồi mở khóa lại trước khi tạo lại recovery key.".into(),
            ));
        }
        let recovery = self.vault.new_recovery()?;
        let display = recovery.display.clone();
        let req = PutKeysRequest {
            kdf: self.meta.kdf.clone(),
            wrapped_key: self.meta.wrapped_key.clone(),
            recovery_wrapped_key: Some(recovery.wrapped_key),
            recovery_auth_key: Some(recovery.auth_key.to_vec()),
        };
        self.rt.block_on(self.admin_api.put_keys(req))
            .map_err(|e| vault_core::CoreError::Network(e.to_string()))?;
        Ok(display)
    }

    fn export_gvault(&mut self, path: &Path) -> vault_core::Result<()> {
        let export = VaultExport {
            format: "gmail-vault-export".into(),
            version: 1,
            user_id: self.meta.user_id,
            kdf: self.meta.kdf.clone(),
            wrapped_key: self.meta.wrapped_key.clone(),
            records: self.store.load_all_records()?,
        };
        write_gvault(path, &export)
    }

    fn maybe_auto_backup(&mut self, evt_tx: &Sender<VaultEvent>) {
        let due = list_backups(&self.backup_dir).ok()
            .and_then(|mut files| { files.sort(); files.pop() })
            .and_then(|p| std::fs::metadata(p).ok())
            .and_then(|m| m.modified().ok())
            .map(|t| t.elapsed().map(|d| d.as_secs() >= 86_400).unwrap_or(true))
            .unwrap_or(true);
        if due {
            if let Ok(path) = backup_database(&self.db_path, &self.backup_dir, 10) {
                let _ = evt_tx.send(VaultEvent::BackupDone(path));
            }
        }
        self.last_backup_check = Instant::now();
    }
}
```

`DeleteMany` loops `self.delete(id)` and emits one `Accounts` event. Keep `Delete` unchanged.

In the command loop, call `maybe_auto_backup` when `last_backup_check.elapsed() >= Duration::from_secs(3600)`. Before a periodic sync, use `last_attempt` to avoid retrying offline every 500 ms:

```rust
let due = self.last_attempt.map(|t| t.elapsed() >= Duration::from_secs(5)).unwrap_or(true);
if due && (self.status.pending > 0 || self.last_sync.map(|t| t.elapsed() >= self.sync_interval).unwrap_or(true)) {
    self.sync_and_emit(&evt_tx);
}
```

`sync_and_emit` sets `last_attempt`, emits `SyncStatus` before and after, and reloads accounts on success.

Run: `cargo test -p vault-client`
Expected: all worker admin tests pass.

- [ ] **Step 10: Add settings, conflicts, bulk actions, and local wipe**

**Settings and local wipe**

Add to `crates/vault-client/src/platform.rs`:

```rust
pub fn wipe_local_data(db_path: &Path, backup_dir: &Path) -> Result<(), String> {
    for suffix in ["", "-wal", "-shm"] {
        let path = PathBuf::from(format!("{}{suffix}", db_path.display()));
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| e.to_string())?;
        }
    }
    if backup_dir.exists() {
        std::fs::remove_dir_all(backup_dir).map_err(|e| e.to_string())?;
    }
    Ok(())
}
```

Test:

```rust
#[test]
fn wipe_local_data_removes_db_wal_and_backups() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    let backups = dir.path().join("backups");
    std::fs::write(&db, b"x").unwrap();
    std::fs::write(dir.path().join("vault.db-wal"), b"x").unwrap();
    std::fs::create_dir_all(&backups).unwrap();
    std::fs::write(backups.join("vault-1.db"), b"x").unwrap();
    wipe_local_data(&db, &backups).unwrap();
    assert!(!db.exists());
    assert!(!backups.exists());
}
```

Create `ui/settings.rs`:

```rust
use std::time::Duration;

use egui::Ui;
use vault_core::LocalMeta;

use crate::config::{ClientConfig, ThemePref};
use crate::state::SyncStatus;

#[derive(Default)]
pub struct SettingsState {
    pub new_password: String,
    pub confirm_password: String,
    pub password_error: Option<String>,
    pub password_busy: bool,
    pub new_recovery: Option<String>,
    pub recovery_confirmed: bool,
    pub confirm_logout: bool,
    pub confirm_wipe: bool,
    pub wipe_text: String,
}

pub enum SettingsAction {
    ChangePassword(String),
    RegenerateRecovery,
    SetSyncInterval(u64),
    Logout,
    WipeLocal,
}

pub fn last_sync_label(status: &SyncStatus) -> String {
    status.last_sync
        .map(|t| format_sync_time(t.with_timezone(&chrono::Local)))
        .unwrap_or_else(|| "Chưa đồng bộ".into())
}

pub fn show(
    ui: &mut Ui,
    meta: &LocalMeta,
    status: &SyncStatus,
    state: &mut SettingsState,
    config: &mut ClientConfig,
) -> Option<SettingsAction> {
    let mut action = None;
    ui.heading("Cài đặt");

    ui.group(|ui| {
        ui.label(format!("Email: {}", meta.email));
        ui.label(format!("Server: {}", meta.server_url));
        ui.label(format!("Thiết bị: {}", meta.device_label));
        ui.label(format!("Đồng bộ lần cuối: {}", last_sync_label(status)));
    });

    ui.separator();
    ui.heading("Giao diện và bảo mật");
    egui::Grid::new("settings_grid").num_columns(2).show(ui, |ui| {
        ui.label("Giao diện");
        egui::ComboBox::from_id_salt("theme")
            .selected_text(match config.theme {
                ThemePref::System => "Theo hệ thống",
                ThemePref::Light => "Sáng",
                ThemePref::Dark => "Tối",
            })
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut config.theme, ThemePref::System, "Theo hệ thống");
                ui.selectable_value(&mut config.theme, ThemePref::Light, "Sáng");
                ui.selectable_value(&mut config.theme, ThemePref::Dark, "Tối");
            });
        ui.end_row();

        ui.label("Tự khóa sau (phút)");
        ui.add(egui::DragValue::new(&mut config.auto_lock_minutes).range(1..=30));
        ui.end_row();

        ui.label("Xóa clipboard sau (giây)");
        ui.add(egui::DragValue::new(&mut config.clipboard_secs).range(10..=120));
        ui.end_row();

        ui.label("Đồng bộ mỗi (giây)");
        let changed = ui.add(egui::DragValue::new(&mut config.sync_interval_secs).range(15..=600))
            .changed();
        if changed {
            config.sync_interval_secs = config.sync_interval_secs.clamp(15, 600);
            action = Some(SettingsAction::SetSyncInterval(config.sync_interval_secs));
        }
        ui.end_row();
    });

    ui.separator();
    ui.heading("Đổi master password");
    ui.label("Cần kết nối server. Các thiết bị khác sẽ phải đăng nhập lại.");
    ui.add(egui::TextEdit::singleline(&mut state.new_password).password(true).hint_text("Mật khẩu mới"));
    ui.add(egui::TextEdit::singleline(&mut state.confirm_password).password(true).hint_text("Xác nhận mật khẩu mới"));
    if let Some(err) = &state.password_error {
        ui.colored_label(egui::Color32::RED, err);
    }
    if ui.add_enabled(!state.password_busy, egui::Button::new("Đổi mật khẩu")).clicked() {
        if state.new_password.chars().count() < 12 {
            state.password_error = Some("Mật khẩu mới phải dài ít nhất 12 ký tự".into());
        } else if state.new_password != state.confirm_password {
            state.password_error = Some("Mật khẩu xác nhận không khớp".into());
        } else {
            state.password_error = None;
            action = Some(SettingsAction::ChangePassword(state.new_password.clone()));
        }
    }

    ui.separator();
    ui.heading("Recovery key");
    if ui.button("Tạo lại recovery key").clicked() {
        action = Some(SettingsAction::RegenerateRecovery);
    }
    if let Some(code) = state.new_recovery.clone() {
        ui.label("Mã mới chỉ hiển thị một lần:");
        ui.add(egui::Label::new(egui::RichText::new(&code).monospace()).selectable(true));
        if ui.button("Copy mã").clicked() {
            ui.ctx().copy_text(code);
        }
        if ui.checkbox(&mut state.recovery_confirmed, "Tôi đã lưu mã mới").changed()
            && state.recovery_confirmed
        {
            state.new_recovery = None;
            state.recovery_confirmed = false;
        }
    }

    ui.separator();
    ui.heading("Đăng xuất");
    ui.label("Xóa token trên máy này, giữ dữ liệu local.");
    if !state.confirm_logout {
        if ui.button("Đăng xuất").clicked() { state.confirm_logout = true; }
    } else {
        ui.label("Bạn chắc chắn?");
        ui.horizontal(|ui| {
            if ui.button("Xác nhận đăng xuất").clicked() {
                state.confirm_logout = false;
                action = Some(SettingsAction::Logout);
            }
            if ui.button("Hủy").clicked() { state.confirm_logout = false; }
        });
    }

    ui.separator();
    ui.heading("Xóa dữ liệu local");
    ui.colored_label(
        egui::Color32::RED,
        "Xóa vault.db và toàn bộ backup trên máy này. Dữ liệu trên server vẫn còn.",
    );
    if !state.confirm_wipe {
        if ui.button("Xóa dữ liệu local").clicked() { state.confirm_wipe = true; }
    } else {
        ui.label("Nhập XOA để xác nhận:");
        ui.text_edit_singleline(&mut state.wipe_text);
        ui.horizontal(|ui| {
            if ui.add_enabled(state.wipe_text == "XOA", egui::Button::new("Xác nhận xóa")).clicked() {
                action = Some(SettingsAction::WipeLocal);
            }
            if ui.button("Hủy").clicked() {
                state.confirm_wipe = false;
                state.wipe_text.clear();
            }
        });
    }

    action
}
```

Extract the formatting so the test is independent of the machine timezone:

```rust
pub fn format_sync_time<T: chrono::TimeZone>(dt: chrono::DateTime<T>) -> String
where T::Offset: std::fmt::Display {
    dt.format("%d/%m/%Y %H:%M:%S").to_string()
}

#[test]
fn formats_last_sync_with_dd_mm_yyyy() {
    let dt = chrono::DateTime::parse_from_rfc3339("2026-11-06T10:20:30+07:00").unwrap();
    assert_eq!(format_sync_time(dt), "06/11/2026 10:20:30");
}
```

`last_sync_label` calls `format_sync_time(t.with_timezone(&chrono::Local))`.

**Conflicts view**

Create `ui/conflicts.rs`:

```rust
use std::time::Duration;

use egui::Ui;
use uuid::Uuid;
use vault_core::Account;

use crate::security::copy_password;
use crate::ui::editor::EditorDraft;
use crate::workers::vault::{VaultCommand, VaultHandle};

pub fn is_conflict(account: &Account) -> bool {
    account.tags.iter().any(|t| t.eq_ignore_ascii_case("conflict"))
}

pub struct ConflictsView {
    pub selected: Option<Uuid>,
    pub draft: Option<EditorDraft>,
    pub show_password: bool,
    pub confirm_delete: bool,
}

impl Default for ConflictsView {
    fn default() -> Self {
        Self { selected: None, draft: None, show_password: false, confirm_delete: false }
    }
}

impl ConflictsView {
    pub fn clear_sensitive(&mut self) {
        self.selected = None;
        self.draft = None;
        self.show_password = false;
        self.confirm_delete = false;
    }

    pub fn show(
        &mut self,
        ui: &mut Ui,
        accounts: &[Account],
        handle: &VaultHandle,
        clipboard_secs: u64,
    ) -> Option<String> {
        let conflicts: Vec<&Account> = accounts.iter().filter(|a| is_conflict(a)).collect();
        if conflicts.is_empty() {
            ui.label("Không có conflict nào.");
            return None;
        }

        let mut message = None;
        ui.columns(2, |cols| {
            cols[0].heading("Bản conflict");
            for account in &conflicts {
                let selected = self.selected == Some(account.id);
                if cols[0].selectable_label(selected, format!("{} — {}", account.email, account.updated_at.format("%d/%m/%Y %H:%M"))).clicked() {
                    self.selected = Some(account.id);
                    self.draft = Some(EditorDraft::from_account(account));
                    self.confirm_delete = false;
                }
            }

            if let (Some(id), Some(draft)) = (self.selected, self.draft.as_mut()) {
                let conflict = conflicts.iter().find(|a| a.id == id).copied();
                if let Some(conflict) = conflict {
                    cols[1].heading("Chi tiết");
                    let original = accounts.iter().find(|a| {
                        a.id != conflict.id
                            && !is_conflict(a)
                            && a.normalized_email() == conflict.normalized_email()
                    });
                    if let Some(original) = original {
                        cols[1].label("Bản gốc trên server:");
                        cols[1].label(format!("Email: {}", original.email));
                        cols[1].label(format!("Cập nhật: {}", original.updated_at.format("%d/%m/%Y %H:%M")));
                    } else {
                        cols[1].label("Không tìm thấy bản gốc cùng email.");
                    }

                    crate::ui::editor::show_fields(&mut cols[1], &mut draft.account, &mut self.show_password);
                    cols[1].horizontal(|ui| {
                        if ui.button("Lưu bản conflict").clicked() {
                            let account = draft.clone().into_account();
                            let _ = handle.tx.send(VaultCommand::Save(account));
                            message = Some("Đã lưu bản conflict".into());
                        }
                        if ui.button("Copy mật khẩu").clicked() {
                            let _ = copy_password(&draft.account.password, Duration::from_secs(clipboard_secs));
                            message = Some("Đã copy mật khẩu".into());
                        }
                    });

                    let mut fixed = draft.account.clone();
                    fixed.tags.retain(|t| !t.eq_ignore_ascii_case("conflict"));
                    if cols[1].button("Đánh dấu đã xử lý (bỏ tag conflict)").clicked() {
                        let _ = handle.tx.send(VaultCommand::Save(fixed));
                        message = Some("Đã bỏ tag conflict".into());
                    }

                    if !self.confirm_delete {
                        if cols[1].button("Xóa bản conflict").clicked() { self.confirm_delete = true; }
                    } else {
                        cols[1].label("Xóa bản conflict này?");
                        cols[1].horizontal(|ui| {
                            if ui.button("Xác nhận xóa").clicked() {
                                let _ = handle.tx.send(VaultCommand::Delete(id));
                                self.selected = None;
                                self.draft = None;
                                self.confirm_delete = false;
                                message = Some("Đã xóa bản conflict".into());
                            }
                            if ui.button("Hủy").clicked() { self.confirm_delete = false; }
                        });
                    }
                }
            }
        });
        message
    }
}
```

Test:

```rust
#[test]
fn detects_conflict_tag_case_insensitively() {
    let mut a = Account::new("a@b.co", "p");
    a.tags.push("Conflict".into());
    assert!(is_conflict(&a));
    a.tags.clear();
    assert!(!is_conflict(&a));
}
```

Extract `pub fn show_fields(ui: &mut Ui, account: &mut Account, show_password: &mut bool)` from `ui/editor.rs` and call it from both the normal editor and the conflicts view.

**Bulk delete and duplicate**

Add to `model.rs`:

```rust
pub fn duplicate(&self, now: DateTime<Utc>) -> Self {
    let mut copy = self.clone();
    copy.id = Uuid::new_v4();
    copy.created_on = Some(now.date_naive());
    copy.created_at = now;
    copy.updated_at = now;
    copy.last_used_on = None;
    copy.use_count = 0;
    copy.password_history.clear();
    copy.password_changed_on = None;
    copy.notes = Some(match self.notes.as_deref() {
        Some(note) if !note.is_empty() => {
            format!("{note}\n\nBản sao tạo lúc {}", now.format("%d/%m/%Y %H:%M"))
        }
        _ => format!("Bản sao tạo lúc {}", now.format("%d/%m/%Y %H:%M")),
    });
    copy
}
```

Test:

```rust
#[test]
fn duplicate_gets_new_id_and_resets_usage() {
    let mut a = Account::new("a@b.co", "p");
    a.mark_used(NaiveDate::from_ymd_opt(2026, 11, 6).unwrap());
    let b = a.duplicate(Utc::now());
    assert_ne!(a.id, b.id);
    assert_eq!(a.email, b.email);
    assert_eq!(a.password, b.password);
    assert_eq!(b.use_count, 0);
    assert!(b.notes.as_deref().unwrap_or_default().contains("Bản sao"));
}
```

`MainView` changes in `ui/main.rs`:

- Add `checked: std::collections::BTreeSet<Uuid>` and `bulk_confirm: bool`.
- Add a checkbox column as the first table column. Store `checked` per session; prune ids that no longer exist after each Accounts event.
- Toolbar shows `Xóa đã chọn ({checked.len()})`; clicking opens a confirmation window; confirm sends `VaultCommand::DeleteMany(ids)` and clears `checked`.
- Toolbar shows `Nhân bản đã chọn ({checked.len()})`; it builds `SaveMany` from every checked account via `account.duplicate(Utc::now())` and clears `checked`. Disable both bulk buttons when nothing is checked.
- Toolbar shows `Bỏ chọn`.
- Editor panel gets a `Nhân bản` button that sends `VaultCommand::Save(draft.account.duplicate(Utc::now()))`.
- Add `MainView::retain_ids(&[Account])`: keep only ids that still exist in `checked`, and clear `selected`/`draft` if the selected account disappeared.
- Add `MainView::clear_sensitive()`: clear `draft`, `confirm_delete`, `bulk_confirm`, and `checked`.
- `DeleteMany` worker handler:

```rust
VaultCommand::DeleteMany(ids) => {
    for id in ids {
        if let Err(e) = state.delete(id) {
            let _ = evt_tx.send(VaultEvent::Error(e.to_string()));
        }
    }
    let _ = evt_tx.send(VaultEvent::Accounts(state.accounts.clone()));
}
```

Run: `cargo test -p vault-core model::tests duplicate_gets_new_id_and_resets_usage && cargo test -p vault-client`
Expected: duplicate, wipe, conflict, and worker tests pass.

- [ ] **Step 11: Wire screens, tabs, settings, conflicts, logout, and wipe into the app**

`state.rs`:

- Add `AppTab { Accounts, Dashboard, Import, Backup, Conflicts, Settings }`.
- Add `SetupMode` and `Screen` as defined in Step 7.
- Add `RecoveryDisplay { code, session: Option<UnlockedSession> }`.

`app.rs` fields (`recovery_display` replaces the Task 9 `recovery_code`; `error` stays a plain field for `Screen::Fatal`):

```rust
screen: Screen,
setup_form: SetupForm,
recovery_display: Option<RecoveryDisplay>,
unlock_password: String,
reset_code: String,
reset_password: String,
reset_confirm: String,
pending_setup: Option<Receiver<SetupEvent>>,
pending_device: Option<Receiver<DeviceLoginEvent>>,
pending_recovery: Option<Receiver<RecoveryLoginEvent>>,
pending_unlock: Option<Receiver<UnlockEvent>>,
api: Option<Arc<VaultApi>>,
vault: Option<VaultHandle>,
meta: Option<LocalMeta>,
accounts: Vec<Account>,
sync_status: SyncStatus,
tab: AppTab,
main_view: MainView,
settings: SettingsState,
conflicts: ConflictsView,
auto_lock: AutoLock,
config: ClientConfig,
toast: Option<(String, Instant)>,
error: Option<String>,
```

Startup:

- Load `ClientConfig` and `LocalStore::open(db_path).load_meta()`. Keep the loaded `LocalMeta` in `self.meta` while locked so the Unlock and Settings screens can show email/server/KDF; it contains no plaintext secrets.
- If meta exists → `Screen::Unlock`; else → `Screen::Setup(SetupMode::Create)`.

Event polling in `update`:

- `ctx.request_repaint_after(Duration::from_millis(250))`.
- Poll each pending receiver with `try_recv()` in a loop; clear the receiver when the worker finishes or errors.
- `SetupEvent::Done { recovery_code }` → `recovery_display = Some(RecoveryDisplay { code, session: None })`; `screen = Screen::ShowRecovery`.
- `DeviceLoginEvent::Done(session)` → `start_vault(session)`.
- `RecoveryLoginEvent::Done { session, recovery_code }` → `recovery_display = Some(RecoveryDisplay { code: recovery_code, session: Some(session) })`; `screen = Screen::ShowRecovery`.
- `UnlockEvent::Done(session)` → `start_vault(session)`.
- `VaultEvent::Accounts(rows)` → `accounts = rows`; `main_view.retain_ids(&accounts)`; `conflicts` selection cleanup.
- `VaultEvent::SyncStatus(s)` → `sync_status = s`.
- `VaultEvent::Error(e)` → `error = Some(e)`; `settings.password_busy = false`.
- `VaultEvent::AdminDone(msg)` → clear password fields, `settings.password_busy = false`, toast msg.
- `VaultEvent::RecoveryRegenerated(code)` → `settings.new_recovery = Some(code)`, `settings.recovery_confirmed = false`.
- `VaultEvent::LoggedOut` → `self.lock(); self.toast = Some(("Đã đăng xuất".into(), Instant::now()));`.
- `VaultEvent::BackupDone(path)` → toast `"Đã backup: {path}"`.
- `VaultEvent::ExportDone(path)` → toast `"Đã xuất: {path}"`.

`start_vault`:

```rust
fn start_vault(&mut self, session: UnlockedSession) {
    let api = Arc::new(VaultApi::new(&session.meta.server_url));
    api.set_email(&session.meta.email);
    let sync_api: Arc<dyn SyncApi> = api.clone();
    let admin_api: Arc<dyn AdminApi> = api.clone();
    let interval = Duration::from_secs(self.config.sync_interval_secs.clamp(15, 600));
    let accounts = session.accounts.clone();
    let meta = session.meta.clone();
    let handle = spawn_vault(
        session.meta,
        session.vault,
        session.store,
        session.accounts,
        session.auth_key,
        platform::db_path(),
        platform::backup_dir(),
        sync_api,
        admin_api,
        interval,
    );
    self.api = Some(api);
    self.vault = Some(handle);
    self.meta = Some(meta);
    self.accounts = accounts;
    self.sync_status = SyncStatus::default();
    self.screen = Screen::Main;
}
```

Screens:

- `Setup(mode)` renders three tabs: "Tạo vault mới", "Đăng nhập thiết bị", "Khôi phục bằng mã".
  - Create uses the existing `start_setup`.
  - Device login uses `start_device_login`.
  - Recovery uses `start_recovery_login` with `existing_meta: None`.
- `ShowRecovery` shows `recovery_display.code` (selectable, copy button), warning that it is shown once, checkbox "Tôi đã lưu recovery key"; on continue:
  - if `session.is_some()` → `start_vault(session.take().unwrap())`.
  - else → `screen = Screen::Unlock` (setup path; the vault is already registered).
- `Unlock`: email/server label, password, "Mở khóa" sends `start_unlock`; "Quên mật khẩu?" switches to `Screen::ResetPassword`.
- `ResetPassword`: recovery code, new password, confirm, validation, warning; sends `start_recovery_login` with `existing_meta: store.load_meta().flatten()`. On Done, show new recovery code.
- `Main`: top bar tabs; body:
  - `Accounts` → `main_view.show(ctx, &self.accounts, self.vault.as_ref().expect("vault is running"), &self.sync_status)`.
  - `Dashboard` → `stats::compute` + `dashboard::show`.
  - `Import`/`Backup` → existing views; add a "Xuất .gvault" button that uses `rfd::FileDialog::save_file` and sends `VaultCommand::ExportGvault(path)`.
  - `Conflicts` → `conflicts.show(ui, &self.accounts, self.vault.as_ref().expect("vault is running"), self.config.clipboard_secs)`; set toast from returned message.
  - `Settings` → clone `self.meta` and call `settings::show(ui, &meta, &self.sync_status, &mut self.settings, &mut self.config)`; handle the returned `SettingsAction`.

Settings handling:

```rust
match action {
    SettingsAction::ChangePassword(pw) => {
        self.settings.password_busy = true;
        if let Some(handle) = &self.vault { let _ = handle.tx.send(VaultCommand::ChangeMasterPassword(pw)); }
    }
    SettingsAction::RegenerateRecovery => {
        if let Some(handle) = &self.vault { let _ = handle.tx.send(VaultCommand::RegenerateRecovery); }
    }
    SettingsAction::SetSyncInterval(secs) => {
        if let Some(handle) = &self.vault {
            let _ = handle.tx.send(VaultCommand::SetSyncInterval(Duration::from_secs(secs)));
        }
    }
    SettingsAction::Logout => {
        if let Some(handle) = &self.vault { let _ = handle.tx.send(VaultCommand::Logout); }
    }
    SettingsAction::WipeLocal => self.wipe_local(),
}
```

After rendering settings, apply config changes:

```rust
let before = self.config.clone();
// settings::show mutates self.config
if self.config != before {
    let _ = self.config.save(&platform::config_path());
    self.auto_lock.set_timeout(Duration::from_secs(self.config.auto_lock_minutes * 60));
    match self.config.theme {
        ThemePref::Light => ctx.set_visuals(egui::Visuals::light()),
        ThemePref::Dark => ctx.set_visuals(egui::Visuals::dark()),
        ThemePref::System => {}
    }
}
```

For `ThemePref::System`, apply the platform default once at startup; switching back can call `ctx.set_theme(egui::Theme::System)` if the egui version supports it, otherwise leave the current visuals.

Auto-lock:

- In `Screen::Main`, if any input event (`ctx.input(|i| !i.events.is_empty())`), `self.auto_lock.touch()`.
- After drawing, if `self.auto_lock.should_lock(Instant::now())` → `self.lock()`.

`lock()`:

```rust
fn lock(&mut self) {
    if let Some(handle) = self.vault.take() { handle.shutdown(); }
    self.api = None;
    self.accounts.clear();
    self.sync_status = SyncStatus::default();
    self.recovery_display = None;
    self.clear_sensitive_view_state();
    self.auto_lock.touch();
    self.screen = Screen::Unlock;
}
```

`wipe_local()`:

```rust
fn wipe_local(&mut self) {
    // Revoke/delete the refresh token, then join the worker so SQLite has
    // released vault.db, vault.db-wal, and vault.db-shm before deletion.
    if let Some(handle) = self.vault.take() { handle.shutdown_with_logout(); }
    self.api = None;
    if let Err(e) = platform::wipe_local_data(&platform::db_path(), &platform::backup_dir()) {
        self.error = Some(e);
        return;
    }
    self.config.email = None;
    let _ = self.config.save(&platform::config_path());
    self.meta = None;
    self.accounts.clear();
    self.sync_status = SyncStatus::default();
    self.recovery_display = None;
    self.clear_sensitive_view_state();
    self.screen = Screen::Setup(SetupMode::Create);
}
```

```rust
fn clear_sensitive_view_state(&mut self) {
    self.main_view.clear_sensitive();
    self.conflicts.clear_sensitive();
    self.settings = SettingsState::default();
}
```

Call the same helper from `lock()` so locking never leaves passwords or a recovery code in UI memory. `Drop for VaultApp` sends `VaultCommand::Shutdown` without joining, so closing the window lets the worker exit.

Add a `Conflicts` badge in the tab label using `sync_status.conflicts` or a live count of `is_conflict` accounts.

Run: `cargo test -p vault-client`
Expected: all client tests pass.

- [ ] **Step 12: Run the manual multi-device check and commit**

Run: `cargo test -p vault-core && cargo test -p vault-client`
Expected: all pass.

Manual (uses the server from Tasks 7–8; run it with `cargo run -p vault-server`):

1. Start the server on `http://127.0.0.1:8080` with `ALLOW_REGISTRATION=true`.
2. Run the client with a fresh app-data directory and create a vault.
3. Add an account, change its password, and verify the password history grows.
4. Run a second client instance with a different `APPDATA` directory, choose "Đăng nhập thiết bị", and verify the account appears after sync.
5. Stop the server; edit the account in both clients; restart the server; sync both; verify a conflict copy appears and the Conflicts tab can resolve it.
6. Change the master password on client A; verify client B can no longer refresh and must log in with the new password.
7. Regenerate the recovery key; verify the old code fails and the new code works in the recovery flow.
8. Logout; verify local unlock still works and sync re-authenticates. Then wipe local data and verify the Setup screen appears.

```bash
git add crates/vault-core crates/vault-server crates/vault-client
git commit -m "feat: add multi-device auth, settings, conflicts, and recovery"
```

## Task 15: Deployment, documentation, and end-to-end verification

**Files:**
- Create: `deploy/Caddyfile`
- Create: `deploy/gmail-vault.service`
- Create: `deploy/gmail-vault-backup.service`
- Create: `deploy/gmail-vault-backup.timer`
- Create: `deploy/backup.sh`
- Create: `deploy/server.env.example`
- Create: `README.md`
- Create: `docs/e2e-checklist.md`
- Create: `scripts/dev-server.ps1`
- Create: `scripts/dev-server.sh`

- [ ] **Step 1: Add deployment files**

`deploy/server.env.example`:

```dotenv
BIND_ADDR=127.0.0.1:8080
DATABASE_URL=sqlite:///var/lib/gmail-vault/vault.db?mode=rwc
JWT_SECRET=replace-with-at-least-32-random-bytes
ALLOW_REGISTRATION=false
MAX_BODY_BYTES=2097152
RUST_LOG=gmail_vault_server=info,tower_http=warn
```

`deploy/Caddyfile`:

```caddyfile
vault.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8080
}
```

`deploy/gmail-vault.service`:

```ini
[Unit]
Description=Gmail Vault sync server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=gmail-vault
Group=gmail-vault
EnvironmentFile=/etc/gmail-vault/server.env
ExecStart=/opt/gmail-vault/bin/gmail-vault-server
WorkingDirectory=/var/lib/gmail-vault
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/gmail-vault

[Install]
WantedBy=multi-user.target
```

`deploy/backup.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

DB="/var/lib/gmail-vault/vault.db"
DEST="/var/lib/gmail-vault/backups"
mkdir -p "$DEST"

stamp="$(date +%Y%m%d-%H%M%S)"
sqlite3 "$DB" ".backup '$DEST/vault-$stamp.db'"
find "$DEST" -maxdepth 1 -type f -name 'vault-*.db' -mtime +14 -delete
```

`deploy/gmail-vault-backup.service`:

```ini
[Unit]
Description=Backup Gmail Vault server database

[Service]
Type=oneshot
User=gmail-vault
Group=gmail-vault
ExecStart=/opt/gmail-vault/bin/backup.sh
```

`deploy/gmail-vault-backup.timer`:

```ini
[Unit]
Description=Daily Gmail Vault backup

[Timer]
OnCalendar=*-*-* 03:30:00
RandomizedDelaySec=300
Persistent=true

[Install]
WantedBy=timers.target
```

Deployment commands to document in README:

```bash
cargo build --release -p vault-server
sudo useradd --system --home /var/lib/gmail-vault --shell /usr/sbin/nologin gmail-vault
sudo mkdir -p /opt/gmail-vault/bin /etc/gmail-vault /var/lib/gmail-vault/backups
sudo install -m 755 target/release/vault-server /opt/gmail-vault/bin/gmail-vault-server
sudo install -m 755 deploy/backup.sh /opt/gmail-vault/bin/backup.sh
sudo cp deploy/server.env.example /etc/gmail-vault/server.env
sudo chmod 600 /etc/gmail-vault/server.env
sudo chown -R gmail-vault:gmail-vault /var/lib/gmail-vault
sudo cp deploy/gmail-vault.service /etc/systemd/system/
sudo cp deploy/gmail-vault-backup.service deploy/gmail-vault-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gmail-vault
sudo systemctl enable --now gmail-vault-backup.timer
```

Caddy:

```bash
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Generate a secret:

```bash
openssl rand -hex 32
```

Firewall: allow 80/443 only; keep `127.0.0.1:8080` private. Install `sqlite3` for the backup timer.

- [ ] **Step 2: Write the README**

Cover:

- What the app is and the zero-knowledge model.
- Requirements: Rust 1.99+, a Linux VPS for the server, Caddy, systemd, `sqlite3` for backups.
- Local development:
  ```bash
  cp deploy/server.env.example server.env
  # set DATABASE_URL=sqlite:///absolute/path/vault.db?mode=rwc and JWT_SECRET
  cargo run -p vault-server
  cargo run -p vault-client
  ```
- Build:
  ```bash
  cargo build --release -p vault-server
  cargo build --release -p vault-client
  ```
- VPS deployment, DNS, TLS, systemd, backup/restore, upgrade and rollback.
- First-run flow: register, save recovery code, optionally set `ALLOW_REGISTRATION=false`.
- Multi-device flow: create on device A, then "Đăng nhập thiết bị" on device B.
- Recovery: recovery code replaces the master password; data cannot be recovered if both are lost.
- Import/export formats and warnings about plaintext CSV.
- Security limitations: server sees metadata and ciphertext; no audit log; single user; no mobile.
- Troubleshooting: `journalctl -u gmail-vault`, `curl https://vault.example.com/healthz`, SQLite lock, keychain errors.

- [ ] **Step 3: Write the E2E checklist**

Create `docs/e2e-checklist.md` with sections:

1. **Server**: health, TLS, first-user registration, second registration rejected unless `ALLOW_REGISTRATION=true`, rate limiting, restart persistence, backup timer.
2. **Setup**: create vault, recovery code displayed once, confirmation required, local meta created, no plaintext email in server DB (inspect with `sqlite3`).
3. **Unlock**: correct/wrong password, offline unlock, auto-lock after 5 minutes.
4. **Accounts**: CRUD, search with Vietnamese diacritics, filters, sort, duplicate, bulk delete, conflict tag.
5. **Security tools**: TOTP RFC vector and real account, generator length/classes, strength warnings, clipboard clears after 30 seconds.
6. **Import/export**: CSV with BOM, JSON, duplicate policies, error rows, 50k limit; plaintext warnings.
7. **Backup/restore**: backup now, rotation to 10 files, restore creates a pre-restore copy, encrypted `.gvault` export.
8. **Sync**: two app-data directories, initial pull, offline edit, conflict copy, resolution, tombstone behavior.
9. **Auth**: device login via prelogin, production KDF salt, change password revokes old sessions, regenerate recovery invalidates old code, recovery login resets password, logout and local wipe.
10. **Deployment**: reboot server, service auto-start, Caddy renewal, backup restore on a copy.

Each item has `- [ ]` and a short expected result.

- [ ] **Step 4: Add development scripts**

`scripts/dev-server.ps1`:

```powershell
$env:DATABASE_URL = "sqlite:///$PWD/dev-vault.db?mode=rwc"
$env:JWT_SECRET = "dev-only-secret-0123456789abcdef"
$env:ALLOW_REGISTRATION = "true"
$env:RUST_LOG = "gmail_vault_server=debug,tower_http=warn"
cargo run -p vault-server
```

`scripts/dev-server.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
export DATABASE_URL="sqlite:///$PWD/dev-vault.db?mode=rwc"
export JWT_SECRET="dev-only-secret-0123456789abcdef"
export ALLOW_REGISTRATION=true
export RUST_LOG="gmail_vault_server=debug,tower_http=warn"
cargo run -p vault-server
```

- [ ] **Step 5: Run the full verification**

```bash
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release
```

Expected:

- Formatting check passes.
- Clippy has no warnings.
- All workspace tests pass.
- Release binaries exist at `target/release/vault-server` and `target/release/gmail-vault`.

Manual: run `cargo run -p vault-client` against the dev server and complete the E2E checklist.

```bash
git add deploy README.md docs/e2e-checklist.md scripts
git commit -m "docs: add deployment, backups, and E2E checklist"
```

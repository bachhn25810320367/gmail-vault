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


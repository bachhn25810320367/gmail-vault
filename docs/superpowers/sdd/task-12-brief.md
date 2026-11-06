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


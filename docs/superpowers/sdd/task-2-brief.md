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


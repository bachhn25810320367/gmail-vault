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


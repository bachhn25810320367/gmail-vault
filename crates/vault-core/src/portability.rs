use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chrono::NaiveDate;
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::crypto::{KdfParams, RecordRow, WrappedKey};
use crate::error::{CoreError, Result};
use crate::model::{Account, AccountStatus, Money, Plan};

const MAX_ROWS: usize = 50_000;

const CSV_HEADERS: [&str; 16] = [
    "email",
    "password",
    "created_on",
    "plan",
    "status",
    "tags",
    "notes",
    "recovery_email",
    "recovery_phone",
    "totp_secret",
    "expires_on",
    "price",
    "currency",
    "last_used_on",
    "use_count",
    "custom_fields",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicatePolicy {
    Skip,
    Replace,
    CreateNew,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportRowError {
    pub row: usize,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct ImportResult {
    pub accounts: Vec<Account>,
    pub skipped: usize,
    pub errors: Vec<ImportRowError>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VaultExport {
    pub format: String,
    pub version: u32,
    pub user_id: Uuid,
    pub kdf: KdfParams,
    pub wrapped_key: WrappedKey,
    pub records: Vec<RecordRow>,
}

fn csv_err(e: csv::Error) -> CoreError {
    CoreError::Serialization(e.to_string())
}

pub fn export_csv<W: Write>(
    accounts: &[Account],
    include_password: bool,
    include_totp: bool,
    writer: W,
) -> Result<()> {
    let mut out = writer;
    out.write_all(&[0xEF, 0xBB, 0xBF])?;
    let mut csv = csv::Writer::from_writer(out);
    csv.write_record(CSV_HEADERS).map_err(csv_err)?;
    for a in accounts {
        let password = if include_password {
            a.password.as_str()
        } else {
            ""
        };
        let totp = match (include_totp, a.totp_secret.as_deref()) {
            (true, Some(t)) => t,
            _ => "",
        };
        let tags = a.tags.join(";");
        let custom = serde_json::to_string(&a.custom_fields)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let row = [
            a.email.clone(),
            password.to_string(),
            date_str(a.created_on),
            a.plan.as_str().to_string(),
            a.status.as_str().to_string(),
            tags,
            a.notes.clone().unwrap_or_default(),
            a.recovery_email.clone().unwrap_or_default(),
            a.recovery_phone.clone().unwrap_or_default(),
            totp.to_string(),
            date_str(a.expires_on),
            a.price
                .as_ref()
                .map(|m| m.amount.to_string())
                .unwrap_or_default(),
            a.price
                .as_ref()
                .map(|m| m.currency.clone())
                .unwrap_or_default(),
            date_str(a.last_used_on),
            a.use_count.to_string(),
            custom,
        ];
        csv.write_record(row).map_err(csv_err)?;
    }
    csv.flush()?;
    Ok(())
}

fn date_str(value: Option<NaiveDate>) -> String {
    value
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

fn parse_date(raw: &str) -> Option<NaiveDate> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    NaiveDate::parse_from_str(raw, "%Y-%m-%d")
        .or_else(|_| NaiveDate::parse_from_str(raw, "%d/%m/%Y"))
        .ok()
}

fn parse_plan(raw: &str) -> Option<Plan> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "free" => Some(Plan::Free),
        "pro" => Some(Plan::Pro),
        "ultra" => Some(Plan::Ultra),
        "" => Some(Plan::Free),
        _ => None,
    }
}

fn parse_status(raw: &str) -> AccountStatus {
    match raw.trim().to_ascii_lowercase().as_str() {
        "active" | "" => AccountStatus::Active,
        "banned" => AccountStatus::Banned,
        "sold" => AccountStatus::Sold,
        "deleted" => AccountStatus::Deleted,
        _ => AccountStatus::Other(raw.trim().to_string()),
    }
}

struct HeaderIndex(HashMap<String, usize>);

impl HeaderIndex {
    fn new(headers: &csv::StringRecord) -> Self {
        let mut map = HashMap::new();
        for (i, h) in headers.iter().enumerate() {
            let key = h.trim_start_matches('\u{feff}').trim().to_ascii_lowercase();
            map.entry(key).or_insert(i);
        }
        Self(map)
    }

    fn get<'a>(&self, rec: &'a csv::StringRecord, aliases: &[&str]) -> Option<&'a str> {
        aliases
            .iter()
            .find_map(|a| self.0.get(*a))
            .and_then(|i| rec.get(*i))
    }
}

fn alias_index() -> &'static [(&'static [&'static str], &'static str)] {
    &[
        (&["email", "user", "username", "login"], "email"),
        (&["password", "pass"], "password"),
        (&["created_on", "created", "date", "ngay_tao"], "created_on"),
        (&["plan", "tier", "goi"], "plan"),
        (&["status", "trang_thai"], "status"),
        (&["tags", "label", "labels"], "tags"),
        (&["notes", "note", "ghi_chu"], "notes"),
        (&["recovery_email"], "recovery_email"),
        (&["recovery_phone"], "recovery_phone"),
        (&["totp_secret", "totp", "2fa"], "totp_secret"),
        (&["expires_on", "expires", "het_han"], "expires_on"),
        (&["price", "gia"], "price"),
        (&["currency"], "currency"),
        (&["last_used_on", "last_used"], "last_used_on"),
        (&["use_count", "uses"], "use_count"),
        (&["custom_fields", "custom"], "custom_fields"),
    ]
}

fn get<'a>(idx: &HeaderIndex, rec: &'a csv::StringRecord, name: &str) -> &'a str {
    let aliases = alias_index()
        .iter()
        .find(|(_, canonical)| *canonical == name)
        .map(|(aliases, _)| *aliases)
        .unwrap_or(&[]);
    idx.get(rec, aliases).unwrap_or_default()
}

fn apply_duplicate(
    account: Account,
    seen: &mut HashMap<String, Uuid>,
    policy: DuplicatePolicy,
    skipped: &mut usize,
) -> Option<Account> {
    let key = account.normalized_email();
    match seen.get(&key).copied() {
        Some(existing_id) => match policy {
            DuplicatePolicy::Skip => {
                *skipped += 1;
                None
            }
            DuplicatePolicy::Replace => {
                seen.insert(key, existing_id);
                Some(Account {
                    id: existing_id,
                    ..account
                })
            }
            DuplicatePolicy::CreateNew => {
                seen.insert(key, account.id);
                Some(account)
            }
        },
        None => {
            seen.insert(key, account.id);
            Some(account)
        }
    }
}

pub fn import_csv<R: Read>(
    reader: R,
    existing: &HashMap<String, Uuid>,
    policy: DuplicatePolicy,
) -> Result<ImportResult> {
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(reader);
    let headers = rdr.headers().map_err(csv_err)?.clone();
    let idx = HeaderIndex::new(&headers);
    let mut result = ImportResult::default();
    let mut seen = existing.clone();
    for (i, record) in rdr.records().enumerate() {
        if i >= MAX_ROWS {
            return Err(CoreError::Validation(
                "tối đa 50.000 dòng mỗi lần import".into(),
            ));
        }
        let row_number = i + 2;
        let record = match record {
            Ok(r) => r,
            Err(e) => {
                result.errors.push(ImportRowError {
                    row: row_number,
                    message: e.to_string(),
                });
                continue;
            }
        };
        let email = get(&idx, &record, "email").trim().to_string();
        let password = get(&idx, &record, "password").to_string();
        if email.is_empty() || !email.contains('@') {
            result.errors.push(ImportRowError {
                row: row_number,
                message: "email không hợp lệ".into(),
            });
            continue;
        }
        if password.is_empty() {
            result.errors.push(ImportRowError {
                row: row_number,
                message: "mật khẩu không được rỗng".into(),
            });
            continue;
        }

        let mut account = Account::new(email, password);
        let mut row_errors: Vec<String> = Vec::new();

        let plan_raw = get(&idx, &record, "plan");
        match parse_plan(plan_raw) {
            Some(plan) => account.plan = plan,
            None => {
                account.plan = Plan::Free;
                row_errors.push(format!("gói không hợp lệ: {plan_raw}"));
            }
        }
        account.status = parse_status(get(&idx, &record, "status"));

        let tags_raw = get(&idx, &record, "tags");
        account.tags = tags_raw
            .split(';')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();

        let notes = get(&idx, &record, "notes").trim();
        account.notes = (!notes.is_empty()).then(|| notes.to_string());

        let recovery_email = get(&idx, &record, "recovery_email").trim();
        account.recovery_email = (!recovery_email.is_empty()).then(|| recovery_email.to_string());
        let recovery_phone = get(&idx, &record, "recovery_phone").trim();
        account.recovery_phone = (!recovery_phone.is_empty()).then(|| recovery_phone.to_string());

        let totp = get(&idx, &record, "totp_secret").trim();
        account.totp_secret = (!totp.is_empty()).then(|| totp.to_string());

        for (field, value) in [
            ("created_on", get(&idx, &record, "created_on")),
            ("expires_on", get(&idx, &record, "expires_on")),
            ("last_used_on", get(&idx, &record, "last_used_on")),
        ] {
            let parsed = parse_date(value);
            if parsed.is_none() && !value.trim().is_empty() {
                row_errors.push(format!("{field} không hợp lệ: {value}"));
            }
            match field {
                "created_on" => account.created_on = parsed,
                "expires_on" => account.expires_on = parsed,
                _ => account.last_used_on = parsed,
            }
        }

        let price_raw = get(&idx, &record, "price").trim();
        if !price_raw.is_empty() {
            match price_raw.parse::<Decimal>() {
                Ok(amount) => {
                    let currency = get(&idx, &record, "currency").trim();
                    let currency = if currency.is_empty() { "VND" } else { currency };
                    account.price = Some(Money::new(amount, currency));
                }
                Err(_) => row_errors.push(format!("giá không hợp lệ: {price_raw}")),
            }
        }

        let uses = get(&idx, &record, "use_count").trim();
        if !uses.is_empty() {
            match uses.parse::<u32>() {
                Ok(n) => account.use_count = n,
                Err(_) => row_errors.push(format!("use_count không hợp lệ: {uses}")),
            }
        }

        let custom = get(&idx, &record, "custom_fields").trim();
        if !custom.is_empty() {
            match serde_json::from_str::<std::collections::BTreeMap<String, String>>(custom) {
                Ok(map) => account.custom_fields = map,
                Err(_) => row_errors.push("custom_fields không phải JSON object".into()),
            }
        }

        for message in row_errors {
            result.errors.push(ImportRowError {
                row: row_number,
                message,
            });
        }

        if let Some(account) = apply_duplicate(account, &mut seen, policy, &mut result.skipped) {
            result.accounts.push(account);
        }
    }
    Ok(result)
}

pub fn export_json<W: Write>(accounts: &[Account], writer: W) -> Result<()> {
    serde_json::to_writer_pretty(writer, accounts)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;
    Ok(())
}

pub fn import_json<R: Read>(
    reader: R,
    existing: &HashMap<String, Uuid>,
    policy: DuplicatePolicy,
) -> Result<ImportResult> {
    let mut text = String::new();
    let mut reader = reader;
    reader.read_to_string(&mut text)?;
    let accounts: Vec<Account> = match serde_json::from_str::<Vec<Account>>(&text) {
        Ok(v) => v,
        Err(_) => {
            #[derive(serde::Deserialize)]
            struct Wrapper {
                accounts: Vec<Account>,
            }
            serde_json::from_str::<Wrapper>(&text)
                .map_err(|e| CoreError::Serialization(e.to_string()))?
                .accounts
        }
    };
    if accounts.len() > MAX_ROWS {
        return Err(CoreError::Validation(
            "tối đa 50.000 dòng mỗi lần import".into(),
        ));
    }
    let mut result = ImportResult::default();
    let mut seen = existing.clone();
    for account in accounts {
        if let Some(account) = apply_duplicate(account, &mut seen, policy, &mut result.skipped) {
            result.accounts.push(account);
        }
    }
    Ok(result)
}

pub fn write_gvault(path: &Path, export: &VaultExport) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::File::create(path)?;
    serde_json::to_writer_pretty(file, export)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;
    Ok(())
}

pub fn read_gvault(path: &Path) -> Result<VaultExport> {
    let file = std::fs::File::open(path)?;
    let export: VaultExport =
        serde_json::from_reader(file).map_err(|e| CoreError::Serialization(e.to_string()))?;
    if export.format != "gmail-vault-export" || export.version != 1 {
        return Err(CoreError::Validation("file .gvault không hợp lệ".into()));
    }
    Ok(export)
}

pub fn backup_database(db_path: &Path, backup_dir: &Path, keep: usize) -> Result<PathBuf> {
    std::fs::create_dir_all(backup_dir)?;
    let stamp = || chrono::Utc::now().format("%Y%m%d-%H%M%S-%3f").to_string();
    let mut target = backup_dir.join(format!("vault-{}.db", stamp()));
    let mut n = 1;
    while target.exists() {
        target = backup_dir.join(format!("vault-{}-{n}.db", stamp()));
        n += 1;
    }
    let src = rusqlite::Connection::open(db_path)?;
    let mut dst = rusqlite::Connection::open(&target)?;
    let backup = rusqlite::backup::Backup::new(&src, &mut dst)?;
    backup.run_to_completion(100, std::time::Duration::from_millis(10), None)?;
    drop(backup);
    drop(dst);
    drop(src);
    let mut files = list_backups(backup_dir)?;
    files.sort();
    while files.len() > keep {
        if let Some(old) = files.first().cloned() {
            std::fs::remove_file(old)?;
            files.remove(0);
        }
    }
    Ok(target)
}

pub fn list_backups(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("db") {
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("vault-"))
                .unwrap_or(false)
            {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{RecordRow, create_vault};
    use tempfile::tempdir;

    fn sample() -> Account {
        let mut a = Account::new("User@Example.com", "p,w\"ord");
        a.plan = Plan::Pro;
        a.status = AccountStatus::Active;
        a.tags = vec!["vip".into(), "2024".into()];
        a.notes = Some("hello, \"world\"".into());
        a.created_on = Some(chrono::NaiveDate::from_ymd_opt(2025, 1, 2).unwrap());
        a.price = Some(Money::new("199000".parse().unwrap(), "vnd"));
        a.custom_fields
            .insert("proxy".into(), "1.2.3.4:8080".into());
        a
    }

    #[test]
    fn csv_handles_quoted_commas_bom_and_tags() {
        let mut buf = Vec::new();
        export_csv(&[sample()], true, true, &mut buf).unwrap();
        assert!(buf.starts_with(&[0xEF, 0xBB, 0xBF]));
        let text = String::from_utf8(buf).unwrap();
        let mut result =
            import_csv(text.as_bytes(), &HashMap::new(), DuplicatePolicy::Skip).unwrap();
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
            id: account.id,
            revision: 1,
            change_seq: 1,
            updated_at: 1,
            deleted: false,
            dirty: false,
            nonce: vec![9; 24],
            payload: b"ciphertext-only".to_vec(),
        };
        let export = VaultExport {
            format: "gmail-vault-export".into(),
            version: 1,
            user_id: nv.user_id,
            kdf: nv.kdf.clone(),
            wrapped_key: nv.wrapped_key.clone(),
            records: vec![record],
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

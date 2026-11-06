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


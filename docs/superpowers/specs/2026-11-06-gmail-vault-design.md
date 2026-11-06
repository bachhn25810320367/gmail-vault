# Gmail Vault — Thiết kế hệ thống

- **Ngày:** 2026-11-06
- **Trạng thái:** Design đã được duyệt trong hội thoại; spec chờ người dùng review
- **Người dùng:** cá nhân, quản lý tài khoản Gmail trên nhiều máy
- **Nền tảng client:** Windows (chính), egui cross-platform
- **Nền tảng server:** VPS Linux, binary Rust + systemd + Caddy

---

## 1. Tóm tắt

Gmail Vault là ứng dụng desktop viết bằng Rust để lưu trữ và quản lý tài khoản Gmail: email, mật khẩu, ngày tạo, gói dịch vụ (Free/Pro/Ultra), trạng thái, tags, ghi chú, thông tin khôi phục, 2FA, ngày hết hạn, giá tiền, lịch sử dùng và các trường tuỳ chỉnh.

Dữ liệu được mã hoá đầu-cuối (E2E) ngay trên máy người dùng. Server VPS chỉ lưu ciphertext và metadata đồng bộ, không bao giờ thấy email hay mật khẩu. Client hoạt động local-first: mở app và sửa dữ liệu được khi offline, tự đồng bộ khi có mạng.

### Tiêu chí thành công

1. Mở app bằng master password, xem/sửa/thêm tài khoản khi không có mạng.
2. Thêm một tài khoản trong dưới 5 giây; tìm kiếm dưới 100 ms với 5.000 tài khoản.
3. Lấy được file database trên VPS hoặc file local mà không đọc được email/mật khẩu.
4. Hai máy sửa offline cùng lúc, sau khi sync không mất bất kỳ thay đổi nào (bản thua được giữ thành conflict copy).
5. Triển khai server từ đầu trên VPS trống trong dưới 15 phút, chỉ cần binary + systemd + Caddy.

---

## 2. Phạm vi

### Trong phạm vi MVP

- CRUD tài khoản, tìm kiếm, lọc, sắp xếp, xoá hàng loạt, nhân bản.
- Mã hoá E2E, master password, recovery key.
- Local-first, sync nhiều máy qua server riêng.
- Copy mật khẩu, tự xoá clipboard, auto-lock.
- Sinh mã TOTP 2FA.
- Password generator + đo độ mạnh, cảnh báo mật khẩu yếu/trùng.
- Import/Export CSV + JSON.
- Dashboard thống kê.
- Backup tự động, restore.
- Xử lý xung đột bằng conflict copy.
- Server auth, sync, rate limit, systemd + Caddy.

### Ngoài phạm vi MVP

- Nhiều người dùng chung một vault, phân quyền, chia sẻ.
- Mobile app, browser extension.
- Tự động đăng nhập Gmail hoặc kiểm tra tài khoản còn sống.
- CRDT/merge tự động từng trường.
- Đồng bộ realtime qua WebSocket (MVP dùng polling định kỳ + sync khi có thay đổi).
- Code signing, auto-update.
- Audit log đầy đủ, versioning nhiều phiên bản.

---

## 3. Kiến trúc

```
┌─────────────────── Máy người dùng ───────────────────┐
│  vault-client (egui)                                 │
│    ├─ UI state (accounts đã giải mã, chỉ trong RAM)  │
│    ├─ store worker (SQLite local, ciphertext)        │
│    ├─ crypto worker (Argon2id, AEAD, zeroize)        │
│    └─ sync worker (tokio, HTTP client)               │
│                                                      │
│  vault-core                                          │
│    ├─ model + validation                             │
│    ├─ crypto                                         │
│    ├─ local store (rusqlite)                         │
│    ├─ sync engine + trait SyncApi                    │
│    └─ import/export/backup                           │
└──────────────────────┬───────────────────────────────┘
                       │ HTTPS + JSON (reqwest)
┌──────────────────────▼───────────────────────────────┐
│  Caddy (TLS, reverse proxy)                          │
│  vault-server (axum, 127.0.0.1:8080)                 │
│    ├─ /v1/auth/*                                     │
│    ├─ /v1/keys                                       │
│    ├─ /v1/sync/*                                     │
│    └─ SQLite WAL (ciphertext + metadata)             │
└──────────────────────────────────────────────────────┘
```

### Thành phần

**`vault-core`** — thư viện thuần logic, không phụ thuộc UI:

- `model`: struct `Account`, enum `Plan`, `AccountStatus`, `Money`, validation.
- `crypto`: KDF, HKDF, wrap/unwrap vault key, mã hoá/giải mã record.
- `store`: SQLite local, schema, migration, đọc/ghi record ciphertext, meta.
- `sync`: trait `SyncApi`, sync engine push/pull, conflict copy, cursor, retry.
- `portability`: import/export CSV/JSON, backup snapshot, encrypted vault export.

**`vault-server`** — binary axum:

- `auth`: register, login, refresh, logout, rate limit.
- `keys`: lưu và cập nhật KDF params + wrapped vault key.
- `sync`: changes/push, revision, change_seq, conflict response.
- `db`: SQLite WAL, migration nhúng, transaction.
- `config`: đọc env, kiểm tra bắt buộc.

**`vault-client`** — binary egui:

- `app`: vòng đời app, routing màn hình, session state.
- `ui`: unlock/setup, main table, detail panel, dashboard, import, conflicts, settings, backup.
- `workers`: store worker, crypto worker, sync worker; giao tiếp bằng channel.
- `platform`: đường dẫn app data, keychain, clipboard, file dialog.

### Mô hình luồng (threading)

- UI chạy trên main thread của egui; không làm I/O nặng trên UI thread.
- **Crypto worker** chạy Argon2id, wrap/unwrap, mã hoá/giải mã record. Giữ `vault_key` trong bộ nhớ `Zeroizing`; drop khi lock.
- **Store worker** sở hữu `rusqlite::Connection`, nhận lệnh qua channel, trả kết quả qua channel. UI không mở DB trực tiếp.
- **Sync worker** sở hữu tokio runtime riêng, nhận lệnh `SyncNow`/`PushNow`, phát event trạng thái. Không block UI.
- UI giữ `Vec<Account>` đã giải mã để tìm/lọc/sort; khi có event từ worker thì cập nhật lại.
- Khi lock: UI xoá state, crypto worker zeroize key, store worker đóng kết nối; plaintext không còn trong RAM.

### Luồng mở app

1. Đọc config + meta local (server URL, email, KDF params, wrapped key).
2. Hiện màn hình Unlock. Nếu chưa có meta → màn hình Setup.
3. Người dùng nhập master password.
4. Crypto worker chạy Argon2id → KEK → unwrap `vault_key`.
5. Store worker đọc toàn bộ record, crypto worker giải mã, gửi `Vec<Account>` cho UI.
6. UI hiện bảng; sync worker chạy nền (pull/push nếu online).
7. Auto-lock hết thời gian idle → quay lại bước 2.

### Luồng ghi

1. UI gửi `Account` đã sửa cho crypto worker.
2. Crypto worker serialize CBOR + mã hoá, gửi record ciphertext cho store worker.
3. Store worker ghi `dirty=1`, cập nhật cache, thông báo UI.
4. Sync worker được đánh thức sau 2 giây debounce; push khi online.

---

## 4. Bảo mật

### Threat model

| Chống được | Không chống được |
|---|---|
| VPS bị hack, lấy file DB server | Malware/keylogger trên máy đang unlock |
| Nghe lén traffic mạng | Người biết master password |
| File DB local bị copy | Dump RAM khi app đang mở khoá |
| Backup bị lộ | Tấn công vật lý vào máy đang mở |
| Server admin tò mò đọc dữ liệu | Mất master password + recovery key (mất dữ liệu) |

Server được tin tưởng về **thứ tự và tính sẵn sàng** của bản ghi, không được tin về **bí mật**. Server có thể từ chối phục vụ hoặc rollback dữ liệu, nhưng không đọc được nội dung.

### Cây khoá

```
master password (không rời máy)
  └─ Argon2id(salt 16B, m=64 MiB, t=3, p=2, out=32) → master_key
       ├─ HKDF-SHA256(info="gmail-vault/auth/v1") → auth_key  (gửi server)
       └─ HKDF-SHA256(info="gmail-vault/kek/v1")  → KEK       (ở lại máy)

vault_key: 32 byte random, sinh một lần khi tạo vault
  └─ XChaCha20-Poly1305(key=KEK, nonce 24B random,
                        AAD="gmail-vault:v1:user:<user_id>")
     → wrapped_vault_key  (lưu server + cache local)

record:
  └─ XChaCha20-Poly1305(key=vault_key, nonce 24B random,
                        AAD="gmail-vault:v1:record:<user_id>:<record_id>")
     → payload ciphertext
```

- HKDF dùng salt = KDF salt, output 32 byte cho mỗi mục đích.
- `auth_key` là khoá suy ra từ master password nhưng không thể dùng để giải mã vault.
- Server lưu `argon2id(auth_key, salt_server)`; không lưu `auth_key` thô.
- Record dùng chung `vault_key` với nonce ngẫu nhiên 24 byte cho mỗi lần mã hoá. AAD gắn record với user + id, chống di chuyển ciphertext giữa các record.
- Revision và `change_seq` do server quản lý, không nằm trong AAD; thay đổi các trường này không làm lộ nội dung nhưng có thể gây lỗi đồng bộ — chấp nhận vì server đã nằm trong trust boundary về ordering.

### Tham số

| Tham số | Giá trị |
|---|---|
| KDF | Argon2id v=19, m=65536 KiB, t=3, p=2 |
| Salt KDF | 16 byte random, mỗi user một salt |
| AEAD | XChaCha20-Poly1305, nonce 24 byte random |
| Vault key | 32 byte random từ `OsRng` |
| Auth hash server | Argon2id, salt 16 byte riêng, m=19456 KiB, t=2, p=1 |
| Access token | JWT HS256, hạn 15 phút |
| Refresh token | 32 byte opaque, hash SHA-256 trong DB, hạn 30 ngày, rotate mỗi lần refresh |
| Recovery key | 32 byte random, hiển thị Base32 Crockford có checksum |

### Xác thực

- Đăng ký chỉ cho user đầu tiên. Sau đó server trả 403 trừ khi `ALLOW_REGISTRATION=true`.
- `POST /v1/auth/register` nhận `email`, `auth_key`, `kdf` (salt + params), `wrapped_key` (ciphertext + nonce), `recovery_wrapped_key` (tuỳ chọn).
- `POST /v1/auth/login` nhận `email` + `auth_key`; server verify Argon2id, trả access token, refresh token, KDF material và wrapped key.
- Refresh token lưu trong OS keychain qua crate `keyring`, service `gmail-vault`, account `<server_url>|<email>`.
- Logout: revoke refresh token trên server + xoá keychain.
- Rate limit login: 5 lần / 15 phút theo cặp email + IP; vượt trả 429. So sánh hash constant-time.
- Sau 5 lần sai master password liên tiếp trên client, UI tăng delay 1s, 2s, 4s… tối đa 30s (không khoá vĩnh viễn để tránh tự DoS).

### Recovery key

- Sinh lúc setup, hiển thị một lần, yêu cầu người dùng xác nhận đã lưu.
- `recovery_key` (32 byte) derive hai nhánh:
  - `HKDF(info="gmail-vault/recovery/v1")` → recovery KEK → wrap `vault_key`, AAD `"gmail-vault:v1:recovery:<user_id>"`.
  - `HKDF(info="gmail-vault/recovery-auth/v1")` → `recovery_auth_key`, gửi server (qua TLS) để server lưu `argon2id(recovery_auth_key)`. Khoá này **không** giải mã được vault.
- Server lưu bản wrap + hash recovery auth; không lưu recovery key.
- Quên master password:
  1. `POST /v1/auth/recover/login` với `{email, recovery_auth_key}` → server verify hash, trả token tạm + KDF material + wrapped key + recovery_wrapped_key.
  2. Client unwrap `vault_key` bằng recovery key.
  3. Đặt master password mới → `PUT /v1/keys` với wrap mới, recovery wrap mới (nếu tạo lại recovery key) và `recovery_auth_key` mới.
  4. Server revoke toàn bộ refresh token cũ.
- Nếu không tạo lại recovery key, giữ nguyên recovery wrap/hash cũ.
- Mất cả master password và recovery key: dữ liệu không thể khôi phục. UI phải cảnh báo rõ.

### Auto-lock và clipboard

- Auto-lock mặc định 5 phút không có thao tác; chỉnh 1–30 phút trong Settings; tuỳ chọn khoá khi minimize.
- Khi lock: zeroize `vault_key`, KEK, plaintext; clear UI cache; đóng detail panel.
- Copy mật khẩu: ghi clipboard, hiện toast; sau 30 giây nếu clipboard vẫn đúng giá trị đã copy thì xoá.
- Không log mật khẩu, `auth_key`, token, payload, recovery key. Tracing chỉ log metadata.

### Lưu trữ local

- DB local chỉ chứa ciphertext + metadata (`id`, `revision`, `updated_at`, `deleted`, `dirty`, `change_seq`).
- File config (`config.json`) chứa server URL, email, device label, đường dẫn backup; không chứa secret.
- Meta trong DB chứa KDF salt/params, wrapped key (ciphertext), `last_change_seq`.
- Email đăng nhập vault được lưu plaintext để hiển thị màn hình Unlock; đây là email của chủ vault, **không phải** email tài khoản Gmail đang quản lý.
- Thư mục dữ liệu: `%APPDATA%\GmailVault\` trên Windows; dùng crate `directories` cho nền tảng khác.

---

## 5. Data model

### Account

```rust
pub struct Account {
    pub schema_version: u16,                 // = 1
    pub id: Uuid,
    pub email: String,
    pub password: String,
    pub created_on: Option<NaiveDate>,       // ngày tạo tài khoản
    pub plan: Plan,
    pub status: AccountStatus,
    pub tags: Vec<String>,
    pub notes: Option<String>,
    pub recovery_email: Option<String>,
    pub recovery_phone: Option<String>,
    pub totp_secret: Option<String>,         // base32 hoặc otpauth:// URI
    pub expires_on: Option<NaiveDate>,
    pub price: Option<Money>,
    pub last_used_on: Option<NaiveDate>,
    pub use_count: u32,
    pub password_changed_on: Option<NaiveDate>,
    pub password_history: Vec<PasswordHistoryEntry>, // tối đa 5, cũ nhất bị đẩy ra
    pub custom_fields: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub enum Plan { Free, Pro, Ultra }

pub enum AccountStatus {
    Active,
    Banned,
    Sold,
    Deleted,
    Other(String),
}

pub struct Money {
    pub amount: Decimal,   // serialize dạng string
    pub currency: String,  // "VND", "USD", ...
}

pub struct PasswordHistoryEntry {
    pub changed_at: DateTime<Utc>,
    pub password: String,
}
```

- `schema_version` cho phép migrate payload CBOR sau này.
- Tuổi tài khoản ("đã tạo X ngày") tính runtime từ `created_on`, không lưu.
- Khi đổi password trong editor: append password cũ vào `password_history`, cập nhật `password_changed_on`, giới hạn 5 mục.
- "Đánh dấu đã dùng": `last_used_on = hôm nay`, `use_count += 1`.

### Validation

- `email`: không rỗng, chứa đúng một `@`, phần domain có dấu chấm; chuẩn hoá lowercase + trim khi so trùng.
- `password`: không rỗng.
- `tags`: trim, bỏ rỗng, không trùng (case-insensitive), tối đa 50 tag, mỗi tag ≤ 40 ký tự.
- `notes`, `custom_fields`: giới hạn tổng payload 64 KiB/record (sau serialize, trước mã hoá).
- `price.amount >= 0`, currency 3 chữ cái in hoa.
- `expires_on >= created_on` nếu cả hai có.
- `totp_secret`: chấp nhận base32 hoặc `otpauth://`; parse và lưu base32 chuẩn hoá.
- `custom_fields`: key không rỗng, không trùng (case-sensitive), tối đa 50 cặp.

### Record đồng bộ

```rust
pub struct RecordRow {
    pub id: Uuid,
    pub revision: u64,       // server cấp, tăng mỗi lần ghi
    pub change_seq: u64,     // cursor pull, tăng đơn điệu theo user
    pub updated_at: i64,     // Unix millis, client set
    pub deleted: bool,
    pub nonce: [u8; 24],
    pub payload: Vec<u8>,    // CBOR(Account) đã mã hoá; rỗng nếu tombstone
}
```

### Schema SQLite local

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE records (
    id         TEXT PRIMARY KEY,
    revision   INTEGER NOT NULL DEFAULT 0,
    change_seq INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    deleted    INTEGER NOT NULL DEFAULT 0,
    dirty      INTEGER NOT NULL DEFAULT 1,
    nonce      BLOB,
    payload    BLOB
);

CREATE INDEX idx_records_dirty ON records(dirty) WHERE dirty = 1;
```

Meta keys: `schema_version`, `user_id`, `email`, `server_url`, `device_label`, `kdf_salt`, `kdf_params`, `wrapped_vault_key`, `wrapped_key_nonce`, `last_change_seq`, `last_sync_at`.

### Schema SQLite server

```sql
PRAGMA journal_mode = WAL;

CREATE TABLE users (
    id                  TEXT PRIMARY KEY,
    email               TEXT NOT NULL UNIQUE,
    auth_hash           TEXT NOT NULL,
    kdf_salt            BLOB NOT NULL,
    kdf_params          TEXT NOT NULL,
    wrapped_vault_key   BLOB NOT NULL,
    wrapped_key_nonce   BLOB NOT NULL,
    recovery_wrapped_key BLOB,
    recovery_nonce      BLOB,
    recovery_auth_hash  TEXT,
    created_at          INTEGER NOT NULL
);

CREATE TABLE refresh_tokens (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE records (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id         TEXT NOT NULL,
    revision   INTEGER NOT NULL,
    change_seq INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted    INTEGER NOT NULL,
    nonce      BLOB,
    payload    BLOB,
    PRIMARY KEY (user_id, id)
);

CREATE UNIQUE INDEX idx_records_user_seq ON records(user_id, change_seq);

CREATE TABLE user_seq (
    user_id  TEXT PRIMARY KEY,
    next_seq INTEGER NOT NULL DEFAULT 1
);
```

- `change_seq` cấp trong transaction khi accept write; dùng `user_seq.next_seq` rồi tăng.
- Không lưu email plaintext của tài khoản Gmail trên server; email đăng nhập (chủ vault) là plaintext để định danh user — chấp nhận được và ghi rõ trong threat model.

---

## 6. Sync protocol

### Endpoints

**Pull**

```
GET /v1/sync/changes?since=<change_seq>&limit=500
Authorization: Bearer <access_token>

200 {
  "items": [
    {"id": "...", "revision": 3, "change_seq": 12, "updated_at": 1762..,
     "deleted": false, "nonce": "<base64>", "payload": "<base64>"}
  ],
  "next_since": 12,
  "has_more": false
}
```

- Trả record có `change_seq > since`, sort tăng dần, tối đa `limit` (mặc định 500, tối đa 1000).
- `next_since` = `change_seq` lớn nhất trả về, hoặc `since` nếu rỗng.

**Push**

```
POST /v1/sync/push
Authorization: Bearer <access_token>

{
  "records": [
    {"id": "...", "base_revision": 2, "updated_at": 1762..,
     "deleted": false, "nonce": "<base64>", "payload": "<base64>"}
  ]
}

200 {
  "accepted": [{"id": "...", "revision": 3, "change_seq": 13}],
  "conflicts": [
    {"id": "...", "server": {"id": "...", "revision": 4, "change_seq": 14,
      "updated_at": 1762.., "deleted": false,
      "nonce": "<base64>", "payload": "<base64>"}}
  ]
}
```

- `base_revision = 0` nghĩa là record mới.
- Server accept khi `base_revision` bằng revision hiện tại (hoặc record chưa tồn tại với base 0).
- Mỗi batch tối đa 200 record, body tối đa 2 MiB. Vượt → 413.
- Transaction: hoặc toàn bộ batch được xử lý, hoặc rollback. Conflict không làm fail cả batch; record khác vẫn accept.

### Thuật toán client

1. Nếu có record `dirty`, gom batch (tối đa 200) và push.
2. Với mỗi record:
   - `accepted`: cập nhật `revision`, `change_seq`, `dirty=0`.
   - `conflict`: chuyển sang xử lý xung đột (mục dưới).
3. Pull từ `last_change_seq` đến hết (`has_more`), áp dụng từng trang trong transaction.
4. Lưu `last_change_seq` sau khi commit trang thành công.
5. Lặp lại nếu trong lúc pull có thay đổi local mới (tối đa 3 vòng mỗi lần sync).

### Áp dụng record từ server

- Nếu record local không tồn tại → insert, `dirty=0`.
- Nếu `incoming.revision > local.revision`:
  - Local `dirty=0` → ghi đè.
  - Local `dirty=1` → conflict: giữ bản local thành conflict copy, ghi đè bằng bản server.
- Nếu `incoming.revision <= local.revision` → bỏ qua.

### Xử lý xung đột (conflict copy)

Khi push trả conflict hoặc pull phát hiện local dirty bị server ghi đè:

1. Lấy bản local đang sửa, tạo `Account` mới với `id` mới.
2. Gắn tag `conflict`, thêm note `"Conflict copy từ <device_label> lúc <timestamp>"`.
3. Ghi bản copy vào local với `dirty=1` để push như record mới.
4. Ghi đè record gốc bằng bản server (giữ nguyên id/revision).
5. UI hiện banner "Có N bản conflict cần xem lại"; màn Conflicts cho phép so sánh, merge (sửa tay) hoặc xoá bản copy.

Không dùng last-write-wins. Không bao giờ xoá âm thầm thay đổi của người dùng.

### Tombstone

- Xoá record = set `deleted=1`, payload rỗng, tăng revision + seq.
- Tombstone giữ vĩnh viễn trên server (dung lượng nhỏ), để máy offline lâu không hồi sinh tài khoản.
- Nếu local dirty mà server tombstone → giữ bản local thành conflict copy, áp dụng tombstone cho record gốc.

### Retry và trạng thái

- Lỗi mạng: retry exponential backoff 2s → 5 phút, có jitter; không chặn UI.
- 401: thử refresh token một lần; thất bại → chuyển trạng thái "Cần đăng nhập lại", dữ liệu local vẫn dùng được.
- Sync định kỳ mặc định 60 giây khi app mở; sync ngay sau khi sửa (debounce 2 giây); nút "Sync now".
- Trạng thái hiển thị: `Online/Offline`, `Đang sync`, `Lần cuối <thời gian>`, `N thay đổi chờ`.

### Lần sync đầu tiên

- `since=0`, pull toàn bộ theo trang.
- Nếu local đã có dữ liệu (restore/import) → áp dụng quy tắc revision như trên.

---

## 7. API server

### Cấu hình (env)

| Biến | Bắt buộc | Mô tả |
|---|---|---|
| `BIND_ADDR` | không | Mặc định `127.0.0.1:8080` |
| `DATABASE_URL` | có | `sqlite:///var/lib/gmail-vault/vault.db` |
| `JWT_SECRET` | có | ≥ 32 byte random |
| `ALLOW_REGISTRATION` | không | Mặc định `false`; user đầu tiên luôn đăng ký được |
| `RUST_LOG` | không | Mặc định `info` |
| `MAX_BODY_BYTES` | không | Mặc định 2 MiB |

### Endpoints

```
POST /v1/auth/register
POST /v1/auth/login
POST /v1/auth/recover/login
POST /v1/auth/refresh
POST /v1/auth/logout
GET  /v1/keys
PUT  /v1/keys
GET  /v1/sync/changes
POST /v1/sync/push
GET  /healthz
```

**Register** — body:

```json
{
  "user_id": "<uuid do client sinh>",
  "email": "you@example.com",
  "auth_key": "<base64 32B>",
  "kdf": {"algo": "argon2id", "salt": "<base64 16B>", "m_kib": 65536, "t": 3, "p": 2},
  "wrapped_key": {"nonce": "<base64 24B>", "ciphertext": "<base64>"},
  "recovery_wrapped_key": {"nonce": "<base64 24B>", "ciphertext": "<base64>"},
  "recovery_auth_key": "<base64 32B>"
}
```

- `user_id` do client sinh (UUID v4) để client có thể dùng làm AAD khi wrap `vault_key` trước khi gọi server.
- Server từ chối `user_id` trùng hoặc không phải UUID hợp lệ.
- `recovery_auth_key` chỉ dùng để xác thực luồng quên mật khẩu; server hash bằng Argon2id.

**Login** — body `{email, auth_key}` → `{access_token, refresh_token, expires_in, kdf, wrapped_key}`.

**Recover login** — body `{email, recovery_auth_key}` → `{access_token, refresh_token, expires_in, kdf, wrapped_key, recovery_wrapped_key}`; sai → 401, rate limit như login.

**Refresh** — body `{refresh_token}` → cặp token mới; token cũ bị revoke.

**Keys** — `GET` trả `{kdf, wrapped_key, recovery_wrapped_key}`; `PUT` nhận `{kdf, wrapped_key, recovery_wrapped_key?, recovery_auth_key?}` để đổi master password hoặc tạo lại recovery key, yêu cầu access token. Server revoke toàn bộ refresh token khác sau khi đổi.

**Errors**:

```json
{"error": {"code": "invalid_credentials", "message": "Email hoặc mật khẩu không đúng"}}
```

Mã lỗi: `invalid_request`, `invalid_credentials`, `unauthorized`, `forbidden`, `conflict`, `rate_limited`, `payload_too_large`, `internal`.

- Không trả chi tiết gây lộ thông tin (email tồn tại hay không).
- Log request id, status, latency; không log body.

### Rate limit

- Login: 5 lần / 15 phút / (email + IP).
- Register: 3 lần / giờ / IP.
- Sync: 120 request / phút / user.
- Lưu trong bộ nhớ (không cần Redis cho 1 user).

---

## 8. Client UI

### Màn hình Setup (lần đầu)

1. Nhập server URL (mặc định `https://vault.example.com`), email.
2. Nhập master password + xác nhận, hiện strength meter.
3. Sinh `vault_key`, KDF, wrap; gọi register.
4. Hiện recovery key (Base32 chia nhóm 5), nút copy, checkbox "Tôi đã lưu recovery key".
5. Vào Main.

Nếu server không kết nối được ở lần đầu → báo lỗi rõ, cho phép thử lại; không tạo vault local một nửa.

### Màn hình Unlock

- Email nhớ sẵn (đọc từ meta), master password, nút Unlock.
- Trạng thái server: Online/Offline/Checking.
- Link "Mở bằng recovery key".
- Nếu offline: vẫn unlock bằng cache local; banner "Đang offline, thay đổi sẽ sync sau".
- Sai mật khẩu: thông báo chung, tăng delay sau nhiều lần sai.

### Màn hình Main

Bố cục 3 vùng:

- **Sidebar trái:** All, Free, Pro, Ultra; trạng thái Active/Banned/Sold/Deleted; tags; "Sắp hết hạn 30 ngày"; "Mật khẩu yếu"; số đếm từng mục.
- **Toolbar trên:** ô search, sort dropdown, nút "Sync now", trạng thái sync, nút Lock.
- **Bảng giữa:** virtualized (`egui_extras::TableBuilder`), cột:
  Email · Plan · Status · Ngày tạo (kèm tuổi) · Hết hạn · Dùng gần nhất · Tags · Cập nhật.
- **Panel phải:** form chi tiết khi chọn row.

Hành vi:

- Search tức thời, chuẩn hoá lowercase + bỏ dấu tiếng Việt (`đ → d`).
- Lọc kết hợp sidebar + search + khoảng ngày (tuỳ chọn nâng cao).
- Click row mở editor; double-click email copy email.
- Nút copy password cạnh field; toast "Đã copy — tự xoá sau 30s".
- TOTP hiện mã 6 số + vòng đếm ngược, nút copy.
- Nút "Đánh dấu đã dùng" cập nhật `last_used_on` + `use_count`.
- Xoá yêu cầu xác nhận; xoá hàng loạt có confirm.
- Empty state hướng dẫn thêm tài khoản hoặc import.

### Phím tắt

| Phím | Hành động |
|---|---|
| `Ctrl+F` | Focus search |
| `Ctrl+N` | Tạo tài khoản mới |
| `Ctrl+Shift+C` | Copy password của row đang chọn |
| `Ctrl+L` | Lock ngay |
| `Esc` | Đóng panel/editor |
| `Ctrl+S` | Lưu editor |

### Dashboard

- Tổng số tài khoản; số theo Free/Pro/Ultra; số theo trạng thái.
- Sắp hết hạn trong 30 ngày (danh sách).
- Tổng tiền theo từng currency.
- Mật khẩu yếu (zxcvbn score ≤ 2) và mật khẩu trùng nhau.
- Tài khoản lâu không dùng (> 90 ngày).
- Biểu đồ cột đơn giản vẽ bằng egui painter hoặc `egui_plot`.

### Settings

- Server URL, device label.
- Sync interval (15–600 giây), nút sync now.
- Auto-lock timeout, lock on minimize.
- Clipboard clear timeout (10–120 giây).
- Theme sáng/tối, cỡ chữ.
- Đổi master password; tạo lại recovery key (hiện một lần).
- Import/Export; Backup/Restore.
- Logout (xoá token, giữ dữ liệu local) và "Xoá dữ liệu local" (confirm mạnh).

### Conflicts

- Danh sách account có tag `conflict`.
- So sánh side-by-side với bản gốc (tìm theo email gần nhất nếu còn).
- Nút "Giữ bản này" (xoá tag, sửa note) hoặc "Xoá bản copy".
- Banner ở Main khi có conflict chưa xử lý.

### Import

- Chọn CSV hoặc JSON.
- CSV: map cột tự động theo alias (`email/user/username/login`, `password/pass`, `created/created_on/date`, `plan/tier`, `status`, `tags`, `notes`, `expires`, `price`, `recovery_email`, `recovery_phone`, `totp`); cột lạ → custom fields.
- Preview 10 dòng đầu; báo lỗi từng dòng.
- Trùng email: chọn Skip / Replace / Tạo bản mới.
- Import trong transaction; báo cáo thành công/lỗi/skip.

### Backup / Restore

- Danh sách snapshot với thời gian, dung lượng.
- Restore: xác nhận, tự backup bản hiện tại trước, thay DB, yêu cầu unlock lại bằng master password của bản backup.
- Export encrypted `.gvault` (JSON envelope chứa meta ciphertext + records) để mang sang máy khác hoặc cất ngoài.

---

## 9. Tính năng chi tiết

### TOTP

- Hỗ trợ secret base32 và `otpauth://totp/...`.
- Thuật toán SHA-1, 6 chữ số, chu kỳ 30 giây (đọc từ URI nếu có).
- Hiển thị mã + đếm ngược; copy mã.
- Secret nằm trong payload đã mã hoá; chỉ giải mã trong RAM.

### Password generator + strength

- Mặc định 20 ký tự; tuỳ chọn độ dài 8–128, chữ hoa/thường/số/ký tự đặc biệt, loại ký tự dễ nhầm (`I l 1 O 0`).
- Đảm bảo có ít nhất một ký tự mỗi loại được chọn; dùng `OsRng`.
- Strength bằng crate `zxcvbn`, hiển thị score 0–4 + nhãn tiếng Việt.
- Cảnh báo khi lưu: mật khẩu yếu, trùng với tài khoản khác, hoặc trùng mật khẩu cũ trong history.

### Import/Export

- CSV export: UTF-8 BOM để mở đúng trong Excel; cột cố định; tuỳ chọn bao gồm mật khẩu (mặc định tắt) và secret 2FA (mặc định tắt); dialog cảnh báo plaintext.
- JSON export: plaintext nếu người dùng chọn; encrypted `.gvault` là mặc định cho backup.
- Định dạng `.gvault` (JSON, version 1):
  ```json
  {
    "format": "gmail-vault-export",
    "version": 1,
    "user_id": "<uuid>",
    "kdf": {"algo": "argon2id", "salt": "<base64>", "m_kib": 65536, "t": 3, "p": 2},
    "wrapped_key": {"nonce": "<base64>", "ciphertext": "<base64>"},
    "records": [
      {"id": "<uuid>", "revision": 3, "updated_at": 1762.., "deleted": false,
       "nonce": "<base64>", "payload": "<base64>"}
    ]
  }
  ```
  File này không chứa plaintext; mở/restore cần master password hoặc recovery key tương ứng.
- Import JSON chấp nhận mảng `Account` hoặc envelope export.
- Giới hạn 50.000 dòng/lần import; báo lỗi rõ nếu vượt.

### Backup tự động

- Snapshot bằng SQLite backup API (nhất quán khi đang mở).
- Trigger: lần mở app đầu tiên trong ngày; sau 50 thay đổi ghi; trước import lớn, restore, đổi master password.
- Lưu `%APPDATA%\GmailVault\backups\vault-YYYYMMDD-HHMMSS.db`, giữ 10 bản mới nhất.
- File snapshot là ciphertext; không cần mã hoá thêm.
- Export `.gvault` là định dạng portable gồm meta KDF + wrapped key + toàn bộ records ciphertext.

### Dashboard

- Tính từ danh sách account trong RAM, cập nhật sau mỗi thay đổi.
- Không query DB riêng.

---

## 10. Xử lý lỗi

- Domain error dùng `thiserror`, map sang thông báo tiếng Việt ở UI.
- Lỗi mạng/sync: banner không chặn, retry tự động; thao tác local vẫn thành công.
- Lỗi DB local: hiện hướng dẫn restore từ backup; không tự xoá dữ liệu.
- Lỗi 401: refresh một lần; nếu thất bại yêu cầu đăng nhập lại, không xoá dữ liệu local.
- Lỗi server 5xx: giữ dirty record, retry sau.
- Đĩa đầy/quyền file: thông báo rõ đường dẫn và hành động.
- Panic: bắt ở worker, gửi event lỗi; app không crash im lặng.

---

## 11. Testing

### Unit (vault-core)

- Crypto: roundtrip wrap/unwrap; sai password; sai nonce/AAD; tamper ciphertext → lỗi.
- Serialize CBOR roundtrip với đầy đủ field, Unicode tiếng Việt, custom fields.
- Validation: email, tag, price, date, TOTP URI.
- Search normalization: "Đặng" khớp "dang".
- CSV mapping + import dedupe.
- Backup rotation.

### Sync engine

- Mock `SyncApi` in-memory:
  - push mới, push update, tombstone.
  - pull cursor, phân trang, `has_more`.
  - conflict response → tạo conflict copy đúng, không mất dữ liệu.
  - pull đè local dirty → conflict copy.
  - offline queue, retry, refresh 401.
- Transaction: cursor chỉ tăng sau commit.

### Server integration

- SQLite tạm + axum test (`tower::ServiceExt::oneshot`).
- Register user đầu tiên; register lần hai bị 403.
- Login đúng/sai; rate limit 429; refresh rotate; token cũ bị revoke.
- Push accept/conflict; revision + change_seq tăng đúng; batch rollback khi lỗi.
- Changes since/limit; auth thiếu/sai → 401.
- Body quá lớn → 413.

### Client

- `egui_kittest` cho Unlock, Main table, editor (nếu ổn định với phiên bản egui chọn).
- Checklist thủ công: setup, unlock offline, copy/auto-clear clipboard, auto-lock, TOTP countdown, import/export, backup/restore.

### E2E thủ công

1. Chạy server local, tạo vault ở profile A.
2. Tạo profile B (data dir khác), login cùng tài khoản, pull dữ liệu.
3. Tắt mạng cả hai, sửa cùng một account khác nhau.
4. Bật mạng, sync lần lượt → kiểm tra conflict copy + không mất dữ liệu.
5. Xoá account ở A, sync B → B ẩn account, không hồi sinh.
6. Restore backup cũ → dữ liệu đúng, có backup bản trước restore.
7. Kiểm tra file DB local/server không chứa chuỗi email/mật khẩu (grep nhị phân).

---

## 12. Triển khai

### Build

- Workspace Rust edition 2024, stable 1.99+.
- Client Windows: `cargo build --release -p vault-client` → `gmail-vault.exe` portable (MVP chưa đóng MSI).
- Server Linux: build trên VPS hoặc cross-compile `x86_64-unknown-linux-gnu`; binary tĩnh càng tốt.

### Cài server

```
/opt/gmail-vault/gmail-vault-server
/etc/gmail-vault/server.env
/var/lib/gmail-vault/vault.db
```

`server.env`:

```
BIND_ADDR=127.0.0.1:8080
DATABASE_URL=sqlite:///var/lib/gmail-vault/vault.db
JWT_SECRET=<32+ byte random>
ALLOW_REGISTRATION=false
RUST_LOG=info
```

Systemd unit (rút gọn):

```ini
[Unit]
Description=Gmail Vault Server
After=network.target

[Service]
User=vault
Group=vault
ExecStart=/opt/gmail-vault/gmail-vault-server
EnvironmentFile=/etc/gmail-vault/server.env
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/gmail-vault

[Install]
WantedBy=multi-user.target
```

Caddy:

```
vault.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

- Firewall chỉ mở 80/443; server bind localhost.
- Migration chạy tự động khi khởi động (sqlx migrate).
- Backup server: systemd timer hằng ngày chạy `sqlite3 .backup` hoặc lệnh backup của app, giữ 7 ngày.
- Nâng cấp: thay binary → `systemctl restart`; migration phải backward-compatible trong một phiên bản.

---

## 13. Cấu trúc project & dependencies

```
gmail-vault/
├─ Cargo.toml
├─ crates/
│  ├─ vault-core/
│  │  └─ src/{lib,model,crypto,store,sync,portability,error}.rs
│  ├─ vault-server/
│  │  ├─ src/{main,config,db,error}.rs
│  │  ├─ src/api/{auth,keys,sync,mod}.rs
│  │  └─ migrations/
│  └─ vault-client/
│     ├─ src/{main,app,state}.rs
│     ├─ src/ui/{unlock,main,dashboard,editor,import,conflicts,settings,backup}.rs
│     ├─ src/workers/{store,crypto,sync}.rs
│     └─ src/platform/{paths,keychain,clipboard}.rs
├─ deploy/{Caddyfile,systemd/gmail-vault-server.service,systemd/gmail-vault-backup.*,server.env.example}
├─ docs/superpowers/specs/
└─ scripts/{dev-server.ps1,dev-client.ps1}
```

### Dependencies chính

**vault-core:** `serde`, `ciborium`, `uuid`, `chrono`, `time`, `rust_decimal`, `argon2`, `hkdf`, `sha2`, `chacha20poly1305`, `zeroize`, `rand`, `rusqlite` (bundled), `reqwest` (rustls), `thiserror`, `tracing`, `totp-rs`, `zxcvbn`, `csv`, `unicode-normalization`, `directories`.

**vault-server:** `axum`, `tokio`, `sqlx` (sqlite, runtime-tokio-rustls), `serde`, `serde_json`, `jsonwebtoken`, `argon2`, `sha2`, `rand`, `uuid`, `tower`, `tower-http` (limit, trace, cors không cần), `tracing`, `tracing-subscriber`, `thiserror`, `dotenvy`.

**vault-client:** `eframe`, `egui`, `egui_extras`, `egui_plot` (tuỳ chọn), `rfd`, `arboard`, `keyring`, `tokio`, `crossbeam-channel`, `serde`, `serde_json`, `chrono`, `uuid`, `tracing`, `tracing-subscriber`, `vault-core`, `zxcvbn`.

---

## 14. Milestones

| # | Deliverable | Điều kiện hoàn thành |
|---|---|---|
| 1 | Workspace + model + crypto | Unit test crypto/model pass; `cargo test` sạch |
| 2 | Local store + sync engine | Mock sync test pass; conflict copy test pass |
| 3 | Server auth/keys/sync | Integration test pass; chạy local bằng curl |
| 4 | Client setup/unlock + CRUD table | Tạo vault, thêm/sửa/xoá, tìm/lọc hoạt động |
| 5 | TOTP, generator, import/export, dashboard | Checklist tính năng pass |
| 6 | Backup/restore, conflicts UI, settings | Restore + conflict E2E pass |
| 7 | Deploy systemd/Caddy + E2E 2 máy | Sync 2 profile, offline conflict pass |

---

## 15. Quyết định đã chốt

- Một người dùng (chủ vault); server chỉ cho đăng ký user đầu tiên.
- Sync theo từng record, cursor `change_seq`, revision do server cấp.
- Xung đột giải quyết bằng **conflict copy**, không last-write-wins, không CRDT.
- Server dùng SQLite WAL, không Postgres, không Docker; binary + systemd + Caddy.
- E2E encryption; server không giữ plaintext email/mật khẩu Gmail.
- Client local-first, offline đầy đủ sau lần đăng nhập đầu.
- UI tiếng Việt, ngày `dd/MM/yyyy`, tiền VND/USD.
- Auto-lock mặc định 5 phút; clipboard tự xoá sau 30 giây.
- Backup local tự động giữ 10 bản; recovery key là phương án cứu duy nhất khi quên master password.
- Không làm multi-user, mobile, extension, auto-login trong MVP.

---

## 16. Rủi ro và cách giảm thiểu

| Rủi ro | Giảm thiểu |
|---|---|
| Mất master password + recovery key | Cảnh báo rõ lúc setup; bắt xác nhận đã lưu recovery key; hướng dẫn in/cất offline |
| Conflict copy gây trùng lặp | Banner + màn Conflicts merge tay; hiếm vì 1 người dùng |
| SQLite server bị lock khi ghi nhiều | WAL + transaction ngắn; 1 user nên tải thấp |
| Argon2id chậm trên máy yếu | m=64 MiB, t=3 ~100–300 ms; chạy background, hiện progress |
| Rò rỉ plaintext qua log/panic | Không log payload; zeroize key; review code phần crypto |
| Backup nằm cùng ổ hỏng | Cho phép chọn thư mục backup ngoài (OneDrive/ổ khác) + export `.gvault` định kỳ |
| Quên chưa sync đã tắt máy | Sync ngay sau sửa + debounce 2s; hiện số thay đổi chờ |
| Mất VPS | Dữ liệu local vẫn còn; setup server mới, login lại, push lên |
| Clock lệch giữa máy | Server không dùng `updated_at` để phân xử; chỉ dùng revision/seq |
| Recovery key bị lộ | Cất offline; có thể tạo lại (wrap mới) trong Settings |
| DB local hỏng | Backup snapshot + restore; export `.gvault` định kỳ |

---

## 17. Acceptance criteria

- [ ] Setup tạo vault mới, hiện recovery key một lần, đăng ký server thành công.
- [ ] Unlock đúng/sai master password; offline vẫn unlock được sau lần đầu.
- [ ] CRUD đầy đủ trường; tìm kiếm bỏ dấu; lọc/sort hoạt động.
- [ ] Copy password tự xoá sau 30s; auto-lock 5 phút.
- [ ] TOTP sinh mã đúng theo test vector; đếm ngược.
- [ ] Password generator + strength + cảnh báo trùng/yếu.
- [ ] Import CSV/JSON với dedupe; export CSV/JSON có cảnh báo.
- [ ] Dashboard số liệu đúng.
- [ ] Backup tự động + restore; export `.gvault`.
- [ ] Sync 2 máy; offline edit; conflict copy không mất dữ liệu; tombstone đúng.
- [ ] File DB local/server không chứa plaintext email tài khoản Gmail đã lưu hoặc mật khẩu (email đăng nhập vault là ngoại lệ đã biết).
- [ ] Server chạy systemd + Caddy HTTPS; rate limit hoạt động.
- [ ] Toàn bộ test tự động pass; checklist E2E pass.
```

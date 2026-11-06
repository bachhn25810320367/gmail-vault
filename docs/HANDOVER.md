# Gmail Vault — bàn giao toàn bộ dự án (2026-11-06)

Tài liệu này là điểm vào duy nhất: dự án là gì, đang ở đâu, đã xong gì, còn gì, chạy thế nào,
và những gì **chưa** được kiểm chứng. Mọi quyết định kỹ thuật đã chốt nằm ở mục 8.

---

## 1. Dự án là gì

Ứng dụng desktop Rust (egui, chạy trên Windows là chính) quản lý tài khoản Gmail:
email, mật khẩu, ngày tạo, gói Free/Pro/Ultra, trạng thái, tags, notes, recovery email/SĐT, 2FA,
ngày hết hạn + giá, lịch sử dùng, custom fields.

- **E2E encryption**: master password → Argon2id → HKDF ra `auth_key` (gửi server) và `KEK` (ở lại máy);
  `vault_key` 32 byte được wrap bằng XChaCha20-Poly1305. Server chỉ giữ ciphertext + metadata.
- **Local-first**: mở app, sửa dữ liệu khi offline; tự sync khi có mạng; xung đột xử lý bằng **conflict copy**
  (không last-write-wins, không mất dữ liệu).
- **Server riêng**: axum + SQLite WAL, chạy dạng binary + systemd + Caddy, không Docker, không Postgres.
- Người dùng đơn (chỉ user đầu tiên đăng ký được), UI tiếng Việt.

Tài liệu gốc (nguồn chân lý):
- Spec: `docs/superpowers/specs/2026-11-06-gmail-vault-design.md` (943 dòng)
- Plan 15 task / 81 bước (có code mẫu + lệnh verify + commit message từng bước): `docs/superpowers/plans/2026-11-06-gmail-vault.md`

---

## 2. Tài sản ở đâu

| Cái gì | Ở đâu |
|---|---|
| Repo chuẩn | GitHub private `bachhn25810320367/gmail-vault`, nhánh **`feat/gmail-vault-mvp`** @ `51b46ec` (sau commit bàn giao) |
| Bản gốc trên PC | `C:\Users\bach0\Projects\gmail-vault` (nhánh `master`, chỉ có docs — chưa có remote) |
| Worktree cũ trên PC | `C:\Users\bach0\.local\share\opencode\worktree\6a4458\gmail-vault-impl` (nhánh `feat/gmail-vault-mvp` @ `cea8ea8`, cần fetch + ff-merge) |
| Bản làm việc của Hermes | DebianVM `~/gmail-vault` (có Rust 1.99.1) |
| Bản clone cho agent FE | AWS EC2 `~/gmail-vault` (agent `agy`, **không có rustc**) |
| Ledger tiến độ + mọi ruling | `docs/superpowers/sdd/progress.md` (đã commit) |
| Brief 12 task | `docs/superpowers/sdd/task-N-brief.md` (đã commit) |
| Báo cáo 3 task FE | `docs/superpowers/sdd/task-9|10|11-report.md` (đã commit) |
| CI | `.github/workflows/ci.yml` — ubuntu-latest: `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings`, `cargo test --workspace` |

Tất cả artifact từng nằm ngoài repo (brief, report, ledger) đã được copy vào `docs/superpowers/sdd/` —
clone repo là có đủ, không cần hỏi lại máy nào.

---

## 3. Lấy code và verify trong 5 phút

```bash
# trên PC, trong worktree cũ
cd C:\Users\bach0\.local\share\opencode\worktree\6a4458\gmail-vault-impl
git remote add origin https://github.com/bachhn25810320367/gmail-vault.git
git fetch origin
git merge --ff-only origin/feat/gmail-vault-mvp      # cea8ea8 là tổ tiên → ff sạch
cargo test --workspace                                # kỳ vọng: 48 test pass
cargo clippy --workspace --all-targets -- -D warnings  # phải sạch
```

Nếu muốn clone mới hoàn toàn: `git clone https://github.com/bachhn25810320367/gmail-vault.git`
rồi `git checkout feat/gmail-vault-mvp`. (PAT GitHub của mày nằm trong credential store.)

Yêu cầu: Rust stable 1.99+ (edition 2024). Trên Linux cần thêm libxkbcommon/xcb/gtk3/libsecret cho egui +
keyring; trên Windows không cần gì thêm.

---

## 4. Chạy thử (dev)

```bash
# Server (Terminal 1)
export DATABASE_URL="sqlite://$PWD/dev-vault.db?mode=rwc"
export JWT_SECRET="dev-only-secret-0123456789abcdef"   # >= 32 byte
export ALLOW_REGISTRATION=true                          # cho phép đăng ký user đầu tiên
export RUST_LOG="gmail_vault_server=debug,tower_http=warn"
cargo run -p vault-server                               # 127.0.0.1:8080

# Client (Terminal 2, trên desktop)
cargo run -p vault-client
```

Luồng lần đầu: nhập server URL (`http://127.0.0.1:8080`) + email + master password → app sinh
`vault_key`, wrap, gọi `/v1/auth/register`, hiện **recovery key** một lần (bắt tick xác nhận) → vào bảng chính.
Mở lại app lần sau chỉ cần master password; offline vẫn mở được bằng dữ liệu local.

Đổi master password / xoay recovery key: **chưa có UI** (thuộc Task 14); hiện chỉ có hàm core
(`UnlockedVault::rewrap_with_password`, `new_recovery`) + endpoint `PUT /v1/keys`.

---

## 5. Đã xong: Task 1–11 (11/15)

6.421 dòng Rust, 48 test, CI xanh.

| Task | Nội dung | Commit |
|---|---|---|
| 1 | workspace 3 crate + `Account` model + validation | ac1c26a |
| 2 | crypto E2E: Argon2id/HKDF/XChaCha20-Poly1305, recovery key Base32 Crockford, AAD theo record | a5d150c |
| 3 | SQLite local store: meta, records ciphertext, cursor, dirty, tombstone | bb2a8fd |
| 4 | import/export CSV + JSON, file `.gvault`, backup + rotation | e6ec775 |
| 5 | sync engine: push/pull, revision, change_seq, conflict copy | 500e021 |
| 6 | server: config từ env, sqlx migrations, `/healthz` | bf5a12c |
| 7 | server auth: register/login/recovery login/refresh/logout, JWT, rate limit | 285ce78 |
| 8 | server `/v1/keys` + `/v1/sync/{changes,push}` | 3b96a8e |
| — | CI (fmt + clippy + test) | b1adf2b |
| 9 | client: config, platform paths, keychain, API client (auto-refresh 401), màn Setup + Unlock | 71989dd (+dec7a36, 04fc433) |
| 10 | `VaultHandle` worker (join/shutdown), bảng chính, filter/sort/search bỏ dấu, editor | 11e923e (+63b411b, 874d648, 4993a4e) |
| 11 | sync trong client: `SyncApi` impl, sync loop, banner trạng thái + "Sync now" | 3afb9e8 (+766911f, a61acff) |

Phần server đã đủ API cho client dùng; phần core (`vault-core`) đã xong trọn vẹn (Task 1–5) nên các task
còn lại chỉ thêm module mới, không phải sửa nền.

---

## 6. Đang dở: không có gì treo

Task 12 đã được dispatch cho agent trên EC2 nhưng **bị kill trước khi nó commit** — cây làm việc sạch,
không có nhánh dở, không có file rác. Không cần dọn gì.

---

## 7. Còn lại: Task 12–15

Sinh brief từng task (script có sẵn trên PC):

```bash
bash "C:\Users\bach0\.agents\skills\subagent-driven-development\scripts\task-brief" ^
  docs/superpowers/plans/2026-11-06-gmail-vault.md 12
```
(đổi số cuối 13, 14, 15). Script in `wrote <đường dẫn>: N lines` — lấy phần đường dẫn.
Brief của Task 12 cũng đã có sẵn ở `docs/superpowers/sdd/task-12-brief.md`.

**Task 12 — TOTP, password generator, clipboard, auto-lock** (~15 file)
- `vault-core/src/totp.rs`: `current_code(secret, unix_secs) -> (String, u32)`, chấp nhận base32 và `otpauth://`, test vector RFC 6238.
- `vault-core/src/password.rs`: `PasswordOptions`, `generate_password`, `strength_score` (zxcvbn).
- `client/security.rs`: `AutoLock`, `copy_password` (tự xoá clipboard sau N giây).
- `ui/editor.rs`: hiện mã TOTP + đếm ngược, nút copy, generator.
- `app.rs`: timer auto-lock (mặc định 5 phút, đặt được 1–30 phút).

**Task 13 — Dashboard, import/export, backup UI** (~7 file)
- `vault-core/src/stats.rs`: số tài khoản theo plan/status, sắp hết hạn 30 ngày, tổng tiền theo currency,
  mật khẩu yếu/trùng, tài khoản >90 ngày không dùng.
- `ui/dashboard.rs`, `ui/import.rs` (map cột CSV, preview, policy trùng: Skip/Replace/CreateNew), `ui/backup.rs`
  (danh sách snapshot, restore, export `.gvault`), tab routing trong `app.rs`.

**Task 14 — Multi-device login, bulk actions, settings, conflicts, đổi master password, recovery** (21 file, to nhất)
- `ui/settings.rs` (server URL, device label, sync interval, auto-lock, clipboard timeout, theme), `ui/conflicts.rs`
  (so sánh 2 bản, giữ/xoá bản copy).
- Đăng nhập thiết bị mới trên máy B: prelogin lấy KDF → login bằng `auth_key`.
- Đổi master password (wrap lại vault key, revoke refresh token cũ), xoay recovery key, luồng quên mật khẩu
  (recovery login → đặt master mới → PUT /v1/keys).
- Bulk delete/mark-used, `VaultHandle::shutdown_with_logout()`.

**Task 15 — Deploy + docs + E2E**
- `deploy/Caddyfile`, `deploy/gmail-vault.service` (systemd, `NoNewPrivileges`, `ProtectSystem=strict`,
  `ReadWritePaths=/var/lib/gmail-vault`), `gmail-vault-backup.{service,timer}` + `backup.sh`,
  `deploy/server.env.example`, `README.md`, `docs/e2e-checklist.md`, `scripts/dev-server.{sh,ps1}`.
- Vị trí chuẩn khi lên VPS: binary `/opt/gmail-vault/gmail-vault-server`, env `/etc/gmail-vault/server.env`,
  DB `/var/lib/gmail-vault/vault.db`, Caddy `vault.example.com { reverse_proxy 127.0.0.1:8080 }`,
  firewall chỉ mở 80/443, server bind localhost.
- Kiểm tra cuối: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo build --release` (ra `target/release/vault-server` và `gmail-vault.exe`).
- Khi xong hết: `git checkout master && git merge --no-ff feat/gmail-vault-mvp`.

---

## 8. Quyết định đã chốt — đừng sửa lại nếu không có lý do

Thiết kế (spec đã duyệt):
1. Một người dùng, server chỉ cho user đầu tiên đăng ký (`ALLOW_REGISTRATION=false` sau đó).
2. Sync theo record, `revision` do server cấp, cursor `change_seq`; xung đột = **conflict copy**, không LWW/CRDT.
3. Tombstone giữ vĩnh viễn trên server.
4. Server SQLite WAL + binary + systemd + Caddy (không Docker/Postgres).
5. Recovery key là Base32 Crockford có checksum, sinh 1 lần, hiện 1 lần; quên master password là luồng **online-only**.
6. Auto-lock mặc định 5 phút; clipboard tự xoá sau 30 giây.

Ruling trong lúc thi công (đã ghi kèm lý do ở `docs/superpowers/sdd/progress.md`):
7. `VaultHandle` có `join()` + `shutdown()` ngay từ Task 10 (plan gốc để Task 14 → Task 13 sẽ không biên dịch).
8. Test worker dùng `recv_timeout` + deadline, không `.unwrap()`.
9. Argon2id phía server: m=19456 KiB, t=2, p=1 (client vẫn 65536/3/2) — theo spec §4.
10. `UnlockedVault`/`NewVault`/`RecoveryMaterial` **cố tình không derive `Debug`** (chứa khoá) → test không dùng `.unwrap_err()`.
11. `codec.rs` phải `use ::base64::...` vì module con `codec::base64` che tên crate.
12. rusqlite cần feature `backup`. Migration SQLite **không** chứa `PRAGMA journal_mode=WAL` (pool đã set; không set được trong transaction của migration).
13. Test conflict copy: server record phải ở `revision: 2` khi base của client là 1, nếu không mock sẽ accept thay vì conflict.
14. `AppState.config` là `Arc<Config>` → test phải `Arc::new(config)`.
15. `spawn_vault` có `#[allow(clippy::too_many_arguments)]` — đúng 1 caller, tách struct là thừa.

---

## 9. Chưa được kiểm chứng (đọc trước khi tin)

- **Client chưa từng chạy thật.** Mới chỉ biên dịch + unit test trên CI (headless, không GUI). Chưa ai mở app,
  chưa thấy màn Setup/Unlock/bảng chính bằng mắt. Đây là rủi ro số 1 khi mày chạy `cargo run -p vault-client` lần đầu
  trên Windows (font tiếng Việt, layout, `rfd` file dialog, keyring Windows).
- Server chưa chạy ngoài test in-process: chưa `curl` thật, chưa qua Caddy/TLS, chưa rate-limit thực địa.
- Chưa test E2E 2 máy (offline conflict copy) — checklist nằm trong plan Task 15 bước "E2E thủ công".
- Chưa verify "file DB không chứa plaintext" bằng grep nhị phân trên dữ liệu thật (mới có test đơn vị cho `.gvault`).
- Chưa có backfill/rotation thực tế trên DB sống; mọi thứ đang ở schema v1.

---

## 10. Bài học vận hành (để không vấp lại)

- **`cargo fmt` là gate đầu tiên** — agent không có toolchain rất hay viết dòng >100 cột / method chain 1 dòng.
  Bắt implementer tự chạy `cargo fmt` trước khi commit (trên PC làm được ngay; trên EC2 thì không).
- Clippy `-D warnings --all-targets` đã bắt 4 lần: `collapsible_if` (dùng let-chain `if let Some(x) = a && cond`),
  `unnecessary_sort_by` → `sort_by_key`, `derivable_impls` → `#[derive(Default)]` + `#[default]`,
  `field_reassign_with_default`, `large_enum_variant` → bọc `Box`, `type_complexity` → type alias cho tuple
  `sqlx::query_as`, `too_many_arguments`.
- Scaffolding do plan viết sẵn hay làm fail clippy: import thừa trong test, field không đọc → xoá hoặc
  `#[allow(dead_code)]` kèm lý do.
- Thêm dependency mới thì chạy bất kỳ lệnh cargo nào (vd `cargo metadata`) để refresh `Cargo.lock` rồi commit.
- Test crypto Argon2id 64 MiB mất ~35 giây là bình thường (đừng tưởng treo).
- `task-brief` in `wrote <path>: N lines`; lấy đúng phần đường dẫn, đừng nhét cả dòng vào biến.
- Máy 1GB RAM: chạy build/test trong cgroup riêng (`systemd-run --user --scope -p MemoryMax=750M -p MemorySwapMax=2500M`,
  `CARGO_BUILD_JOBS=1`, `CARGO_PROFILE_DEV_DEBUG=0`) để không bị OOM-kill giữa phiên.
- Git push repo >15MB: `git config http.version HTTP/1.1` + `http.postBuffer 524288000`.

---

## 11. Nếu cần tiếp tay

Nói "tiếp tục gmail-vault" — state nằm trọn trong repo: plan, spec, brief, ledger, handoff này.
Máy Hermes giữ clone có toolchain ở `~/gmail-vault` (DebianVM) và skill `software-development/rust-workspace-ops`
ghi lại toàn bộ mẹo build/test trên host nhỏ.

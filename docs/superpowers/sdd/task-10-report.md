# Báo cáo hoàn thành Task 10: Vault service, main table, filters, and editor

## 1. Commit SHA
- Commit: `11e923e579fc395a5071d94a8346282dbc0c116c`
- Branch: `feat/gmail-vault-mvp`
- Message: `feat(client): add vault worker, table, filters, and editor`

## 2. Danh sách file đã tạo / sửa
- Tạo `crates/vault-client/src/workers/mod.rs`: khai báo module `pub mod vault;`.
- Tạo `crates/vault-client/src/workers/vault.rs`: triển khai worker nền `spawn_vault`, quản lý vòng đời SQLite và bộ nhớ `accounts`, `VaultCommand` (`Save`, `SaveMany`, `Delete`, `MarkUsed`, `Reload`, `BackupNow`, `Shutdown`), `VaultEvent` (`Accounts`, `Error`, `BackupDone`), `VaultHandle` kèm `join: Option<JoinHandle<()>>`, `shutdown(mut self)` và `Drop` implementation; phương thức `mark_used` sử dụng `chrono::Local::now().date_naive()`.
- Tạo `crates/vault-client/src/ui/filters.rs`: hàm `normalize_for_search` loại bỏ dấu tiếng Việt (chuẩn hóa Unicode NFD, chuyển `đ -> d` và lọc combining marks), struct `Filters` (`matches`, `apply`), struct `SortState` và enum `SortKey`, hàm `sort_accounts`.
- Tạo `crates/vault-client/src/ui/editor.rs`: struct `EditorDraft` (`account`, `original_password`, `is_new`), các hàm `new`, `from_account`, `validate`, `into_account`.
- Tạo `crates/vault-client/src/ui/main.rs`: struct `MainView` (`filters`, `sort`, `selected`, `draft`, `confirm_delete`, `tags_input`, `focus_search`), phương thức `show(&mut self, ctx, accounts, handle) -> bool`:
  - Xử lý phím tắt: `Ctrl+F` (focus search), `Ctrl+N` (soạn thảo tài khoản mới), `Ctrl+L` (yêu cầu khóa vault), `Esc` (đóng editor), `Ctrl+S` (lưu draft), `Ctrl+Shift+C` (sao chép mật khẩu).
  - Top toolbar: ô tìm kiếm, combobox plan/status/sort, nút đảo chiều sắp xếp, nút tạo mới, nút Sync (disabled), nút khóa Vault.
  - SidePanel bên trái: số lượng tài khoản theo Plan (All/Free/Pro/Ultra) và danh sách tags để lọc nhanh.
  - SidePanel bên phải (khi có `draft`): form chỉnh sửa chi tiết các trường của Account, nút Lưu, nút Đánh dấu đã dùng, nút Xóa kèm xác nhận 2 bước.
  - CentralPanel: empty state khi không có bản ghi kèm nút tạo tài khoản, bảng ảo hóa `egui_extras::TableBuilder` với 8 cột từ spec, click chọn row để mở editor, double click để sao chép email.
- Sửa `crates/vault-client/src/app.rs`: bổ sung các trường `vault: Option<VaultHandle>`, `accounts: Vec<Account>`, `main_view: MainView`, `last_activity: Instant`, `toast: Option<(String, Instant)>`; cập nhật sự kiện `UnlockEvent::Done` gọi `spawn_vault` chuyển sang màn hình `Screen::Main`; vòng lặp poll `handle.rx.try_recv()`; render `MainView::show`; triển khai phương thức `lock()` dọn dẹp bộ nhớ nhạy cảm và shutdown worker thread.
- Sửa `crates/vault-client/src/ui/mod.rs`: re-export `pub mod editor; pub mod filters; pub mod main;`.
- Sửa `crates/vault-client/src/main.rs`: khai báo `pub mod workers;` để root module compile submodules của worker.
- Sửa `crates/vault-client/Cargo.toml`: thêm dependency `unicode-normalization.workspace = true` phục vụ tính năng tìm kiếm bỏ dấu tiếng Việt.

## 3. Các test đã viết
1. `ui::filters::tests::search_removes_vietnamese_diacritics`: kiểm tra chuẩn hóa loại bỏ dấu tiếng Việt (ví dụ `"Đặng Văn"` thành `"dang van"`) và tìm kiếm không dấu trong ghi chú tài khoản.
2. `ui::filters::tests::filters_by_plan_status_and_tag`: kiểm tra logic lọc theo Plan (`Pro`/`Ultra`) và Tag (`vip`).
3. `ui::editor::tests::draft_commits_changes`: kiểm tra cập nhật ghi chú từ draft và giữ nguyên id tài khoản.
4. `ui::editor::tests::draft_rejects_empty_email`: kiểm tra `validate()` từ chối email rỗng trên bản ghi mới.
5. `workers::vault::tests::save_and_delete_roundtrip`: kiểm tra trọn vẹn luồng thêm (`Save`) và xóa (`Delete`) bản ghi qua channel của worker nền `spawn_vault`, xác nhận sự kiện phản hồi `VaultEvent::Accounts`, gọi `handle.shutdown()` đợi join thread và kiểm tra file sqlite được đóng an toàn.

## 4. Phần chưa chắc chắn / điều còn nghi ngờ
- Môi trường cục bộ không có sẵn `rustc`/`cargo`, việc kiểm tra biên dịch và test phụ thuộc hoàn toàn vào CI GitHub Actions.
- Cấu trúc `MainView::show` sử dụng `egui_extras::TableBuilder` với `body.rows` và `row.response()`: các tương tác click chọn dòng và double click được ghi nhận qua biến tạm ngoài closure `rows` trước khi cập nhật `self` để đảm bảo tuân thủ chặt chẽ borrow checker của Rust.
- Phím tắt `Ctrl+Shift+C` trong Task 10 sử dụng `ctx.copy_text(...)` để copy password do module `crate::security::copy_password` chỉ được tạo ở Task 12 theo kế hoạch.

## 5. Vòng sửa clippy
- Commit: `874d648a2b54cee8fa1fc17a65ff9b3fe27ce352`
- Message: `fix(client): resolve clippy warnings in task 10 code`
- Sửa 4 cảnh báo `-D warnings` từ Clippy:
  1. `crates/vault-client/src/ui/main.rs:30`: `clippy::derivable_impls` — chuyển `impl Default for MainView` thành `#[derive(Default)]` trực tiếp trên struct `MainView` và xoá block `impl Default` thủ công.
  2. `crates/vault-client/src/workers/vault.rs:81`: `clippy::unnecessary_sort_by` — thay `.sort_by(|a, b| a.normalized_email().cmp(&b.normalized_email()))` bằng `.sort_by_key(|a| a.normalized_email())`.
  3. `crates/vault-client/src/workers/vault.rs:171`: `clippy::unnecessary_sort_by` — thay `.sort_by(|a, b| a.normalized_email().cmp(&b.normalized_email()))` bằng `.sort_by_key(|a| a.normalized_email())`.
  4. `crates/vault-client/src/workers/vault.rs:219`: `clippy::unnecessary_sort_by` — thay `.sort_by(|a, b| a.normalized_email().cmp(&b.normalized_email()))` bằng `.sort_by_key(|a| a.normalized_email())`.


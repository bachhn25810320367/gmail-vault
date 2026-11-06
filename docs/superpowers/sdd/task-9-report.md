# Báo cáo hoàn thành Task 9: Client scaffold, setup, and unlock

## 1. Commit SHA
- Commit: `71989ddbfea3b91da1145432208b9671e75c8353`
- Branch: `feat/gmail-vault-mvp`
- Message: `feat(client): add setup, unlock, config, and API client`

## 2. Danh sách file đã tạo / sửa
- Sửa `Cargo.toml`: thêm các client workspace dependencies (`eframe = "0.32"`, `egui = "0.32"`, `egui_extras = "0.32"`, `rfd = "0.15"`, `arboard = "3"`, `keyring = "3"`, `crossbeam-channel = "0.5"`).
- Sửa `crates/vault-client/Cargo.toml`: khai báo binary `gmail-vault`, cấu hình dependencies và dev-dependencies.
- Sửa `crates/vault-client/src/main.rs`: khởi tạo tracing subscriber, thiết lập `eframe::NativeOptions` với `egui::ViewportBuilder`, chạy `eframe::run_native` với `VaultApp`.
- Tạo `crates/vault-client/src/app.rs`: struct `VaultApp` triển khai `eframe::App`, quản lý màn hình `Screen` (`Setup`, `ShowRecovery`, `Unlock`, `Main`, `Fatal`), quản lý polling crossbeam channels, render các màn hình `render_setup`, `render_recovery`, `render_unlock`, `render_placeholder_main`, `render_fatal`.
- Tạo `crates/vault-client/src/config.rs`: `ClientConfig` (`server_url`, `email`, `device_label`, `sync_interval_secs`, `auto_lock_minutes`, `clipboard_secs`, `theme`), `ThemePref`, các hàm `load` (có clamp giá trị hợp lệ) và `save`.
- Tạo `crates/vault-client/src/platform.rs`: xác định thư mục dữ liệu ứng dụng (`directories::ProjectDirs`), đường dẫn db, config, backup, và lưu/đọc/xóa refresh token qua OS keychain (`keyring = "3"`).
- Tạo `crates/vault-client/src/api.rs`: client HTTP `VaultApi` (`new`, `set_email`, `store_tokens`, `prelogin`, `register`, `login`, `recover_login`, `refresh`, `authorized_get`, `authorized_put`, `get_keys`, `put_keys`), tự động retry refresh token khi gặp HTTP 401 Unauthorized, xử lý mã hóa payload base64.
- Tạo `crates/vault-client/src/state.rs`: `Screen`, `SetupForm`, `UnlockedSession`.
- Tạo `crates/vault-client/src/ui/mod.rs`: re-export `setup` và `unlock`.
- Tạo `crates/vault-client/src/ui/setup.rs`: hàm `validate_setup` kiểm tra URL, email, master password; worker `start_setup` chạy Tokio runtime nền gọi `VaultApi::register`, tạo `LocalStore`, lưu `LocalMeta`, trả về `SetupEvent`.
- Tạo `crates/vault-client/src/ui/unlock.rs`: worker `start_unlock` giải mã `vault_key`, đọc và giải mã tất cả record chưa xóa, trả về `UnlockEvent::Done(UnlockedSession)`.

## 3. Các test đã viết
1. `config::tests::config_roundtrip`: kiểm tra lưu và đọc cấu hình từ file json tạm thời.
2. `config::tests::missing_file_uses_defaults`: kiểm tra fallback về cấu hình mặc định khi không tìm thấy file.
3. `config::tests::load_clamps_settings_to_supported_ranges`: kiểm tra logic clamp các tham số `sync_interval_secs` [15, 600], `auto_lock_minutes` [1, 30], `clipboard_secs` [10, 120].
4. `ui::setup::tests::validate_setup_rejects_bad_input`: kiểm tra validation của `server_url`, `email`, độ dài master password (>= 12 ký tự), và khớp mật khẩu xác nhận.
5. `api::tests::register_request_uses_base64_strings`: kiểm tra serialization của `RegisterRequest` sử dụng base64 string cho `auth_key`, `kdf.salt`, `wrapped_key.nonce`.

## 4. Phần chưa chắc chắn / điều còn nghi ngờ
- Môi trường không có sẵn `rustc`/`cargo`, việc kiểm tra biên dịch và test phụ thuộc hoàn toàn vào CI GitHub Actions.
- Phiên bản eframe/egui `0.32`: API `ctx.copy_text(...)` và `egui::ViewportBuilder` trong `eframe::NativeOptions` đã được đối chiếu theo tài liệu eframe 0.31/0.32, nhưng cần CI xác nhận đầy đủ tính tương thích với toàn bộ toolchain trên CI runner.
- Chức năng lưu credential qua `keyring` phụ thuộc vào backend secret service trên OS (CI Ubuntu runner có cài đặt `libsecret-1-dev` theo workflow).

## 5. Vòng sửa clippy
- Commit: `04fc433b0110054d79332aea7a106cfe24dc6a18`
- Message: `fix(client): resolve clippy warnings in task 9 code`
- Sửa 7 cảnh báo `-D warnings` từ Clippy:
  1. `crates/vault-client/src/api.rs:168`: collapsible_if — gộp `if let Ok(err_payload) = ... && let Some(err_obj) = err_payload.get("error")` bằng let-chain.
  2. `crates/vault-client/src/app.rs:39-40`: collapsible_if hai tầng — gộp `if db_path.exists() && let Ok(store) = LocalStore::open(&db_path) && let Ok(Some(meta)) = store.load_meta()` thành một điều kiện let-chain.
  3. `crates/vault-client/src/app.rs:272`: collapsible_if — gộp `if let Some(ref rx) = self.setup_rx && let Ok(event) = rx.try_recv()` bằng let-chain.
  4. `crates/vault-client/src/app.rs:283`: collapsible_if — gộp `if let Ok(store) = LocalStore::open(&platform::db_path()) && let Ok(Some(meta)) = store.load_meta()` bằng let-chain.
  5. `crates/vault-client/src/app.rs:296`: collapsible_if — gộp `if let Some(ref rx) = self.unlock_rx && let Ok(event) = rx.try_recv()` bằng let-chain.
  6. `crates/vault-client/src/config.rs:70-71` và `:91-92`: clippy::field_reassign_with_default trong unit tests — khởi tạo trực tiếp struct kết hợp `..Default::default()`.
  7. `crates/vault-client/src/ui/unlock.rs:8`: clippy::large_enum_variant — bọc payload `UnlockedSession` trong `Box<UnlockedSession>` (`UnlockEvent::Done(Box<UnlockedSession>)`), cập nhật `Box::new` tại `start_unlock` và unbox `*session` tại `app.rs`.


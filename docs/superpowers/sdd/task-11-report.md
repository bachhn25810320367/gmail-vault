# Báo cáo hoàn thành Task 11: Client sync integration and status banner

## 1. Thông tin commit
- **Commit SHA**: `3afb9e89cd5b0142cd2475a99208ce4446584023`
- **Short SHA**: `3afb9e8`
- **Branch**: `feat/gmail-vault-mvp`
- **Commit Message**: `feat(client): sync encrypted records with status banner`

## 2. Danh sách file đã sửa
1. `crates/vault-core/src/sync.rs`:
   - Bổ sung `serde::Serialize, serde::Deserialize` cho `PushItem`, `PullResponse`, `PushResponse`, `Accepted`, `Conflict`.
   - Áp dụng `#[serde(with = "crate::codec::base64")]` cho `nonce` và `payload` trong `PushItem`.
   - Bổ sung test `push_item_serializes_base64_and_snake_case` kiểm tra serialization base64 và snake_case.
2. `crates/vault-client/Cargo.toml`:
   - Bổ sung dependency `async-trait.workspace = true`.
3. `crates/vault-client/src/api.rs`:
   - Triển khai `impl SyncApi for VaultApi` với các phương thức `pull` (`/v1/sync/changes`) và `push` (`/v1/sync/push` với body `{ "records": items }`).
   - Bổ sung phương thức `send_authorized` xử lý gửi request kèm Bearer token: tự động gọi `refresh().await` khi chưa có access token nhưng đã có email; tự động refresh và retry 1 lần khi nhận HTTP 401.
   - Thêm chuyển đổi lỗi `ApiError::into_core` tương thích `vault_core::CoreError`.
4. `crates/vault-client/src/state.rs`:
   - Bổ sung struct `SyncStatus` với các trường `online`, `syncing`, `last_sync`, `pending`, `last_error`, `conflicts`.
   - Triển khai `SyncStatus::pending_label` trả về tiếng Việt ("3 thay đổi chờ", "Đã đồng bộ", "Offline").
   - Viết unit test `pending_label_is_vietnamese`.
5. `crates/vault-client/src/workers/vault.rs`:
   - Bổ sung `VaultCommand::SyncNow` và `VaultEvent::SyncStatus(SyncStatus)`.
   - Mở rộng hàm `spawn_vault` với chữ ký 8 tham số nhận `sync_api: Arc<dyn SyncApi>` và `sync_interval: Duration`.
   - Khởi tạo tokio current-thread runtime cho worker thread để xử lý `SyncEngine::sync_once()`.
   - Thêm phương thức `sync_now` và `sync_and_emit` trên `WorkerState`: tự động reload và tính số lượng conflict, cập nhật trạng thái `pending`.
   - Trong vòng lặp worker: gọi `sync_and_emit` sau mỗi thao tác ghi cục bộ (`Save`, `SaveMany`, `Delete`, `MarkUsed`); kiểm tra timeout (500ms) để trigger sync chu kỳ hoặc đẩy pending records (giới hạn tần suất tối đa 5 giây một lần).
   - Cập nhật unit test `save_and_delete_roundtrip` sử dụng mock `NoopApi`.
6. `crates/vault-client/src/app.rs`:
   - Lưu trữ `api: Option<Arc<VaultApi>>` và `sync_status: SyncStatus` trong `VaultApp`.
   - Khi mở khóa thành công (`UnlockEvent::Done`), khởi tạo `VaultApi`, gán email, ép kiểu thành `Arc<dyn SyncApi>` và truyền vào `spawn_vault` cùng interval được clamp trong khoảng `[15, 600]` giây.
   - Lắng nghe sự kiện `VaultEvent::SyncStatus(s)` từ channel và cập nhật `self.sync_status`.
   - Truyền `&self.sync_status` vào `MainView::show`.
7. `crates/vault-client/src/ui/main.rs`:
   - Cập nhật chữ ký `MainView::show` nhận tham số `sync_status: &SyncStatus`.
   - Triển khai thanh trạng thái sync trên toolbar: nhãn trạng thái `pending_label()` đổi màu theo trạng thái (cam khi pending, xanh khi online, xám khi offline kèm hover tooltip báo lỗi nếu có), spinner khi đang sync, nút "Sync now" (gửi `VaultCommand::SyncNow` qua worker).

## 3. Các test đã cập nhật / bổ sung
1. `crates/vault-core/src/sync.rs:push_item_serializes_base64_and_snake_case`: xác nhận cấu trúc `PushItem` serialize đúng base64 cho `nonce`, `payload` và snake_case cho `base_revision`.
2. `crates/vault-client/src/state.rs:pending_label_is_vietnamese`: xác nhận nhãn trạng thái `SyncStatus::pending_label` trả về tiếng Việt chuẩn xác theo giá trị `pending` và `online`.
3. `crates/vault-client/src/workers/vault.rs:save_and_delete_roundtrip`: xác nhận chu trình lưu và xóa dữ liệu với `spawn_vault` nhận `Arc<NoopApi>` và interval 3600s mà không phát sinh gọi mạng, tắt an toàn qua `handle.shutdown()`.

## 4. Điều chưa chắc chắn / lưu ý
- Môi trường không có sẵn công cụ biên dịch `cargo`/`rustc`/`rustfmt`, việc xác nhận compile và chạy test suite phụ thuộc vào CI GitHub Actions.
- Mã nguồn đã được kiểm tra tính toàn vẹn cú pháp (đóng mở ngoặc `()`, `[]`, `{}` và string escape qua script python) và rà soát kỹ lưỡng các quy tắc Clippy (`-D warnings --all-targets`) cùng chuẩn formatting.

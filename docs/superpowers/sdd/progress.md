# SDD ledger — plan: docs/superpowers/plans/2026-11-06-gmail-vault.md

Spec: docs/superpowers/specs/2026-11-06-gmail-vault-design.md (read, binding authority).
Host: DebianVM (Hermes) — implementer for BE tasks; branch `feat/gmail-vault-mvp`.
Roles (user ruling 2026-11-06): Hermes = BE coder; gemini-3.8-flash-high = FE coder;
codex / opus-5.5 / gemini-4-argon are NOT to be used on this project.

Recovered from the PC session (IMPORTANT.txt): preflight was already run on the PC and its
findings were folded into the plan at commit cea8ea8. This ledger recreates those rulings.
The PC worktree (`C:\Users\bach0\.local\share\opencode\worktree\6a4458\gmail-vault-impl`) held
no code; canonical repo copied to GitHub `bachhn25810320367/gmail-vault` (private), both
branches: master=c53158f, feat/gmail-vault-mvp=cea8ea8.

## Preflight scan

| Pair / self | Produces → consumes | Finding |
|---|---|---|
| T1 → T2..T15 | workspace + `Account`/`CoreError` | clean (T2 adds codec/crypto modules, `lib.rs` re-export extended) |
| T2 → T3 | `RecordRow` in crypto.rs | clean (T3 explicitly modifies crypto.rs for `RecordRow`) |
| T2 → T5 | crypto seal/open + codec | clean |
| T3 → T5 | store API | clean |
| T4 → T13 | portability.rs used by stats/import UI | clean (T13 UI calls core, no core change) |
| T5 → T11 | `SyncApi`, sync engine | clean (T11 adds serde derives on sync.rs + client impl) |
| T5 → T11 self | tokio dev-dependency | T5 adds `tokio` to core dev-deps; T11 needs `async-trait` in client — both declared in their own task |
| T6 → T7/T8 | server scaffold, db, config, api/mod | clean (T7/T8 only add modules + re-exports) |
| T7 → T14 | auth/recovery endpoints | T14 extends dto.rs/auth.rs/keys.rs — same files, sequential, no overlap in time |
| T9 → T10/T11/T13 | client app/state/config/api/platform | clean (later tasks modify, never recreate) |
| T10 → T11/T13/T14 | `VaultHandle` | RULING 1 below (join + `shutdown()` must exist from T10) |
| T10 → T14 | worker test | RULING 2 below (`recv_timeout` + deadline, not `.unwrap()`) |
| T7 → T14 | server Argon2id params | RULING 3 below (m=19456, t=2, p=1 — spec §4) |
| T12 → T14 | totp.rs/password.rs, ui/editor.rs | clean |
| T13 → T14 | dashboard/import/backup UI | clean (T14 modifies backup.rs, adds settings/conflicts) |
| T14 → T15 | full workspace | clean (T15 only deploy/docs/scripts + final verify) |
| T15 self | release binaries | clean — verification gates are `cargo fmt/clippy/test/build` |
| T1 self | tests vs code | clean, verified by running the brief's test module (5 pass) |
| T2..T8 self | tests vs code | not re-scanned line-by-line here; the per-task test run is the gate |
| T9..T14 self | egui UI tasks | Known host risk, not a plan defect: eframe/keyring/arboard need system libs (xcb, dbus, libsecret) absent on this headless host — see Risks |

### Rulings

1. Ruling: `VaultHandle` carries `join` + `shutdown()` from Task 10 (the plan originally added
   them in Task 14, which would leave Task 13's `restore` path uncompilable). Task 14 adds only
   `shutdown_with_logout()`. — Why: T13 calls restore/shutdown; compile order matters. — Cost if
   wrong: T14 must re-add a method name; one-line rework.
2. Ruling: Task 10's worker test uses a `recv_timeout` loop with a deadline instead of `.unwrap()`
   on the channel. — Why: `.unwrap()` panics/flakes on slow hosts. — Cost if wrong: a slower test.
3. Ruling: Task 7 server-side Argon2id params are m=19456 KiB, t=2, p=1 (spec §4), not the
   client KDF's m=65536/t=3/p=2. — Why: spec fixes separate server hash params. — Cost if wrong:
   changed constant + re-hash on next login.

### Host rulings (this session, not from the plan)

4. Ruling: BE implementation runs on DebianVM (39 GB free disk) with rustup minimal 1.99.1,
   builds under a systemd cgroup (`MemoryMax=700M`, `MemorySwapMax=2000M`, `CARGO_BUILD_JOBS=1`,
   no debuginfo) because the host has 903 MB RAM. — Why: EC2 (939 MB, 253 MB free disk, no rust)
   cannot host a Rust build; the PC is unreachable from this host. — Cost if wrong: slow builds.
5. Ruling: canonical repo mirrored to private GitHub `bachhn25810320367/gmail-vault`; the PC
   worktree is no longer the only copy. — Why: transport + CI escape hatch. — Cost if wrong: none.

## Progress

- [x] Task 1: complete (commits cea8ea8..ac1c26a; `cargo test -p vault-core model::tests` 5 passed)
- [x] Task 2: complete (commits ac1c26a..a5d150c; `cargo test -p vault-core crypto::tests` 7 passed, 35.7s — Argon2id 64 MiB per call on this host)
- Ruling (Task 2): the plan's `wrong_password_is_distinct_error` test calls `.unwrap_err()` on `Result<UnlockedVault, _>`, which needs `UnlockedVault: Debug` — and the plan itself forbids `Debug` there because the struct holds the raw vault key. Kept the ban, replaced the test's error extraction with a `match` + `panic!`. — Why: leaking key material into a debug print is worse than a two-line test change; the assertion is unchanged. — Cost if wrong: none, the test still asserts `CoreError::WrongPassword`.
- Ruling (Task 2): `codec.rs` imports the crate as `::base64` (absolute path) because the module `codec::base64` shadows the crate name inside `codec`. — Why: the module name is part of the required interface, so the import must be absolute. — Cost if wrong: none.
- Note (Task 2): `EncryptedRecord` added to the `lib.rs` re-export list (the plan's list omitted it) because `T3`/`T5` need the type nameable outside the module.
- [x] Task 3: complete (commits a5d150c..bb2a8fd; `cargo test -p vault-core store::tests` 4 passed)
- [x] Task 4: complete (commits bb2a8fd..e6ec775; `cargo test -p vault-core portability::tests` 5 passed)
- Ruling (Task 4): the plan's `backup_database` uses `rusqlite::backup::Backup`, which needs rusqlite's `backup` feature; the plan's workspace dependency declared only `bundled`. Added `backup` to the root `Cargo.toml`. — Why: the task cannot compile otherwise. — Cost if wrong: none.
- [x] Task 5: complete (commits e6ec775..HEAD; `cargo test -p vault-core` 25 passed, 0 warnings)
- Ruling (Task 5, demonstrated): `conflict_copy_preserves_both_versions` as written places the server record at `revision: 1` while the local edit's base revision is also 1, so the mock server ACCEPTS the push and no conflict arises — the test fails (`left: 0, right: 1`). I set the server record to `revision: 2` (a genuine "someone wrote after my base" case) with every assertion untouched; verified both ways: revision 1 → FAILED, revision 2 → ok. — Why: this protocol only conflicts when the server revision moved past the client's base. — Cost if wrong: none, same invariants asserted.
- Note (Task 5): brief says "Expected: 5 tests pass" but its test module defines 4; 4 pass.
- [x] Task 6: complete (commits 500e021..bf5a12c; `cargo test -p vault-server` 3 passed)
- Ruling (Task 6): the migration file omits `PRAGMA journal_mode = WAL` from the spec's schema block — `db::connect` already sets WAL on every connection, and SQLite refuses to switch journal mode inside the migration transaction. Tables/indexes match spec §5 exactly. — Cost if wrong: none.
- Ruling (Task 6): the brief's `tests/health.rs` built `AppState { pool, config }` with a bare `Config` while `AppState.config` is `Arc<Config>` (as its own `main.rs` uses). Test wraps it in `Arc::new`. — Cost if wrong: none.
- [x] Task 7: complete (commits bf5a12c..285ce78; `cargo test -p vault-server` 7 passed)
- Note (Task 7): `tests/common::TestApp` fields `pool`/`config` and the `login` helper are unused by the current tests; marked `#[allow(dead_code)]` so the Task 15 `clippy -D warnings` gate stays clean.
- [x] Task 8: complete (commits 285ce78..HEAD; `cargo test -p vault-server` 11 passed: 2 config + 1 health + 4 auth + 4 sync)
- BE half done (Tasks 1-8). Remaining: Tasks 9-15 are client/FE (egui) + deploy.
- Ruling (host): FE tasks are written by `agy --model gemini-3.8-flash-high` on EC2 (writes only — that box has no rustc) and verified by GitHub Actions (`.github/workflows/ci.yml`: fmt --check, clippy -D warnings, `cargo test --workspace`). Loop = FE pushes → CI runs → failure log goes back to the FE agent as a numbered fix list. — Why: EC2 has 252 MB free and no toolchain; DebianVM has 39 GB but 903 MB RAM, too little for egui codegen. — Cost if wrong: each FE round trip is 10-20 min.
- [x] Task 9: complete (commits 3f17882..04fc433; CI run 42271847895 success — fmt + clippy + workspace tests, client 5 tests)
  - FE agent commit 71989dd, Hermes `cargo fmt` ​dec7a36 (the agent cannot run rustfmt), FE clippy fix 04fc433 (7 lints: collapsible_if ×6, field_reassign_with_default, large_enum_variant).
- Task 10 dispatched to the same FE agent (commit pending).
- [x] Task 10: complete (commits 04fc433..4993a4e; CI run 42278085799 success — 46 tests total on the workspace)
  - FE 11e923e (worker/table/filters/editor), Hermes fmt 63b411b, FE clippy fix 874d648 (`derivable_impls` + `unnecessary_sort_by` ×3), Hermes `Cargo.lock` refresh 4993a4e (the FE host cannot run cargo, so its added eframe deps left the lock stale and CI re-locked on every run).
- Task 11 dispatched to the FE agent (client sync integration + banner).

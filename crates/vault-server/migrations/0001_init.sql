CREATE TABLE users (
    id                   TEXT PRIMARY KEY,
    email                TEXT NOT NULL UNIQUE,
    auth_hash            TEXT NOT NULL,
    kdf_salt             BLOB NOT NULL,
    kdf_params           TEXT NOT NULL,
    wrapped_vault_key    BLOB NOT NULL,
    wrapped_key_nonce    BLOB NOT NULL,
    recovery_wrapped_key BLOB,
    recovery_nonce       BLOB,
    recovery_auth_hash   TEXT,
    created_at           INTEGER NOT NULL
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

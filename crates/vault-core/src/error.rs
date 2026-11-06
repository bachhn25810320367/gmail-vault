#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid input: {0}")]
    Validation(String),
    #[error("wrong password")]
    WrongPassword,
    #[error("crypto failure")]
    Crypto,
    #[error("record not found")]
    NotFound,
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("network error: {0}")]
    Network(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;

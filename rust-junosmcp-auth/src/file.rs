//! On-disk token store: load, validate, atomic save.

#[derive(Debug, thiserror::Error)]
pub enum TokenStoreError {
    #[error("token store invalid: {0}")]
    Invalid(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct TokenStoreFile;

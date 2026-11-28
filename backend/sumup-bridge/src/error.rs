use thiserror::Error;

pub type Result<T> = std::result::Result<T, SumUpError>;

#[derive(Debug, Error)]
pub enum SumUpError {
    #[error("invalid SumUp configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid payment request: {0}")]
    InvalidRequest(String),
    #[error("SumUp API returned HTTP {status}: {body}")]
    Api { status: u16, body: String },
    #[error("SumUp network request failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("failed to encode or decode SumUp data: {0}")]
    Serialization(#[from] serde_json::Error),
}

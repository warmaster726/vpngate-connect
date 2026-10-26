use thiserror::Error;

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("DNS-over-HTTPS resolution failed for '{host}'")]
    DohResolutionFailed { host: String },

    #[error("No live VPN Gate servers matched the requested filter")]
    NoMatchingServers,

    #[error("Server {ip} does not provide an OpenVPN configuration")]
    MissingOpenVpnConfig { ip: String },
}

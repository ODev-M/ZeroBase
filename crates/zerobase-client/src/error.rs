//! Client-side error type. Maps every failure mode the SDK can surface:
//! transport, encoding, and structured error frames returned by the daemon.

use thiserror::Error;
use zerobase_proto::ProtoError;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("wire: {0}")]
    Wire(#[from] ProtoError),

    #[error("protocol violation: {0}")]
    Protocol(String),

    /// The daemon returned an `Error` frame. `code` follows the same numeric
    /// scheme used by the daemon (e.g. 401 unauth, 403 forbidden, 422 SQL).
    #[error("server error {code}: {message}")]
    Server { code: u16, message: String },
}

pub type Result<T> = std::result::Result<T, ClientError>;

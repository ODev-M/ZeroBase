//! Error type for `zerobase-auth`.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("bad signature")]
    BadSignature,
    #[error("identity mismatch")]
    IdentityMismatch,
    #[error("chain link does not extend the previous tip")]
    BrokenChain,
    #[error("empty identity chain")]
    EmptyChain,
    #[error("encoding error")]
    Encoding,
}

impl From<bincode::Error> for AuthError {
    fn from(_: bincode::Error) -> Self {
        AuthError::Encoding
    }
}

impl From<ed25519_dalek::SignatureError> for AuthError {
    fn from(_: ed25519_dalek::SignatureError) -> Self {
        AuthError::BadSignature
    }
}

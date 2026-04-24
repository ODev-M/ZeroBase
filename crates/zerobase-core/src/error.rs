//! Unified error type. Error messages are **carefully generic** in public
//! paths — we never leak ciphertext, keys, or plaintext in error strings.

use thiserror::Error;

/// Result alias used throughout Zerobase.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors produced by the Zerobase engine.
#[derive(Debug, Error)]
pub enum Error {
    /// Filesystem I/O failure.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),

    /// Decryption / authentication failure. Opaque on purpose.
    #[error("cryptographic verification failed")]
    CryptoFail,

    /// A signature on a WAL entry or SSTable block did not verify.
    #[error("signature verification failed")]
    SignatureFail,

    /// Corruption detected (hash mismatch, bad magic, truncated frame).
    #[error("data corruption: {0}")]
    Corrupt(&'static str),

    /// Wrong password or tampered keyring.
    #[error("unable to unlock keyring (wrong passphrase or tampered data)")]
    Unlock,

    /// A versioned on-disk format was newer than this build understands.
    #[error("unsupported on-disk version: {0}")]
    UnsupportedVersion(u32),

    /// Generic encoding failure (bincode, etc.).
    #[error("encoding")]
    Encoding,
}

impl From<bincode::Error> for Error {
    fn from(_: bincode::Error) -> Self {
        // Avoid leaking format details in the error string.
        Error::Encoding
    }
}

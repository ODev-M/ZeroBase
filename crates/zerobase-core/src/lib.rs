//! Zerobase — a zero-trust, encrypted key-value store.
//!
//! Every byte written to disk is authenticated (AEAD) and every log entry is
//! signed (Ed25519). Secrets are protected in memory with `zeroize` and
//! compared in constant time with `subtle`.
//!
//! See [`docs/THREAT_MODEL.md`](../../docs/THREAT_MODEL.md) for the threat
//! model and [`SECURITY.md`](../../SECURITY.md) for vulnerability reporting.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod crypto;
pub mod engine;
pub mod error;
pub mod keyring;
pub mod manifest;
pub mod memtable;
pub mod sstable;
pub mod wal;

pub use engine::Db;

pub use error::{Error, Result};

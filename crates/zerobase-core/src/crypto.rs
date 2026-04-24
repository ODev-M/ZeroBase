//! Cryptographic primitives used across the engine.
//!
//! **Design choices**
//!
//! * AEAD: AES-256-GCM. 96-bit nonces generated from a 32-bit domain prefix
//!   (frame type) plus a 64-bit monotonically-increasing counter. We never
//!   reuse `(key, nonce)` — violating this would break GCM completely.
//! * KDF: Argon2id, 256 MiB memory cost, 3 passes, parallelism = 1.
//! * Signatures: Ed25519 (RustCrypto `ed25519-dalek`).
//! * Hashing: BLAKE3 (fast, prefix-free, built-in keyed mode).
//! * RNG: `OsRng` (OS-provided, non-deterministic).
//!
//! All secret material implements `Zeroize + ZeroizeOnDrop`. Secret-to-secret
//! equality uses `subtle` for constant-time comparison.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

/// Size of an AES-256 key, in bytes.
pub const KEY_LEN: usize = 32;
/// Size of an AES-GCM nonce, in bytes.
pub const NONCE_LEN: usize = 12;
/// Size of the authentication tag produced by AES-GCM.
pub const TAG_LEN: usize = 16;

/// A 256-bit symmetric key. Zeroized on drop; never `Copy`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymKey([u8; KEY_LEN]);

impl SymKey {
    /// Generate a fresh key from the operating system RNG.
    #[must_use]
    pub fn random() -> Self {
        let mut k = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut k);
        Self(k)
    }

    /// Construct from raw bytes. Caller must have derived these from a safe
    /// source (e.g. Argon2id output).
    #[must_use]
    pub fn from_bytes(k: [u8; KEY_LEN]) -> Self {
        Self(k)
    }

    /// Expose the underlying bytes. Avoid calling outside this crate.
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Private accessor used by sibling modules that need a raw key for
/// keyed-BLAKE3. Kept out of the public API on purpose.
pub(crate) fn _mac_bytes(k: &SymKey) -> &[u8; KEY_LEN] {
    k.as_bytes()
}

impl ConstantTimeEq for SymKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Nonce domains. The 4-byte prefix makes it impossible to mix up frames from
/// different parts of the engine even if the counter ever overflowed.
#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum NonceDomain {
    /// WAL entry bodies.
    Wal = 0x5741_4C00,
    /// SSTable data blocks.
    Sstable = 0x5353_5400,
    /// Keyring envelope.
    Keyring = 0x4B52_0000,
    /// Metadata / manifest blocks.
    Manifest = 0x4D41_4E00,
}

/// Build a 12-byte nonce = 4-byte domain || 8-byte counter.
#[must_use]
pub fn nonce_for(domain: NonceDomain, counter: u64) -> [u8; NONCE_LEN] {
    let mut out = [0u8; NONCE_LEN];
    out[..4].copy_from_slice(&(domain as u32).to_be_bytes());
    out[4..].copy_from_slice(&counter.to_be_bytes());
    out
}

/// Encrypt `plaintext` with AES-256-GCM. `aad` is bound into the tag.
///
/// The returned vector layout is `ciphertext || tag` (AEAD std).
pub fn seal(
    key: &SymKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| Error::CryptoFail)?;
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::CryptoFail)
}

/// Authenticate and decrypt. Returns `CryptoFail` on tag mismatch — **never**
/// includes any part of the ciphertext or derived state in the error.
pub fn open(
    key: &SymKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| Error::CryptoFail)?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| Error::CryptoFail)
}

/// Keyed BLAKE3 — used to derive per-table MAC keys and Merkle roots.
#[must_use]
pub fn keyed_hash(key: &SymKey, data: &[u8]) -> [u8; 32] {
    blake3::keyed_hash(key.as_bytes(), data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let k = SymKey::random();
        let n = nonce_for(NonceDomain::Wal, 1);
        let ct = seal(&k, &n, b"aad", b"hello").unwrap();
        let pt = open(&k, &n, b"aad", &ct).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let k = SymKey::random();
        let n = nonce_for(NonceDomain::Wal, 2);
        let mut ct = seal(&k, &n, b"aad", b"hello").unwrap();
        ct[0] ^= 0x01;
        assert!(matches!(open(&k, &n, b"aad", &ct), Err(Error::CryptoFail)));
    }

    #[test]
    fn wrong_aad_fails() {
        let k = SymKey::random();
        let n = nonce_for(NonceDomain::Wal, 3);
        let ct = seal(&k, &n, b"right", b"hello").unwrap();
        assert!(matches!(open(&k, &n, b"wrong", &ct), Err(Error::CryptoFail)));
    }

    #[test]
    fn nonce_domains_are_disjoint() {
        let a = nonce_for(NonceDomain::Wal, 1);
        let b = nonce_for(NonceDomain::Sstable, 1);
        assert_ne!(a, b);
    }
}

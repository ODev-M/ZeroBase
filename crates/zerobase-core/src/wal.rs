//! Write-Ahead Log: the **durable, tamper-evident** ingress for every write.
//!
//! # Frame format
//!
//! ```text
//! +--------+-----------+---------+----------+-------------+-----------+
//! | magic  | counter   | prev-   | nonce    | ciphertext  | signature |
//! | 4B     | 8B BE     | hash 32B| 12B      | N bytes     | 64B Ed25519|
//! +--------+-----------+---------+----------+-------------+-----------+
//! ```
//!
//! * `counter` is monotonic and authenticated by AEAD (part of the nonce).
//! * `prev-hash` is the BLAKE3 of the **previous** frame header+ciphertext —
//!   this turns the log into a hash chain, so any reordering or deletion
//!   is detected on replay.
//! * Each frame is signed with Ed25519; the signing key lives in memory only
//!   while the DB is unlocked.
//! * The AEAD additional-data binds `counter` and `prev-hash` into the tag,
//!   so tampering with either breaks decryption.

use std::io::{BufReader, Read, Seek, Write};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::crypto::{self, NonceDomain, SymKey, NONCE_LEN};
use crate::{Error, Result};

const FRAME_MAGIC: &[u8; 4] = b"ZBWL";
const HASH_LEN: usize = 32;
const SIG_LEN: usize = 64;

/// A single logical operation persisted to the WAL.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Op {
    /// Insert or overwrite a key.
    Put {
        /// Key bytes.
        key: Vec<u8>,
        /// Value bytes.
        value: Vec<u8>,
    },
    /// Delete a key (tombstone).
    Delete {
        /// Key bytes.
        key: Vec<u8>,
    },
}

/// Open handle for appending to a WAL file.
///
/// Not cheap to clone — owns an OS file and a signing key.
pub struct WalWriter<W: Write + Seek> {
    inner: W,
    enc_key: SymKey,
    sign_key: SigningKey,
    counter: u64,
    prev_hash: [u8; HASH_LEN],
}

impl<W: Write + Seek> WalWriter<W> {
    /// Create a new writer positioned at the end of the file. `counter` and
    /// `prev_hash` should come from [`WalReader::replay`] on startup (or be
    /// zero for a fresh WAL).
    pub fn new(
        inner: W,
        enc_key: SymKey,
        sign_key: SigningKey,
        counter: u64,
        prev_hash: [u8; HASH_LEN],
    ) -> Self {
        Self { inner, enc_key, sign_key, counter, prev_hash }
    }

    /// Append one operation. Returns the frame's counter on success.
    ///
    /// Durability: the caller must `flush`/`sync` when they want
    /// `fsync`-level guarantees. We do not fsync every append to keep
    /// throughput reasonable; group commit belongs one layer up.
    pub fn append(&mut self, op: &Op) -> Result<u64> {
        let counter = self.counter.checked_add(1).ok_or(Error::Corrupt("wal counter overflow"))?;

        let body = bincode::serialize(op)?;
        let nonce = crypto::nonce_for(NonceDomain::Wal, counter);

        // AAD binds counter + prev_hash into the tag.
        let mut aad = Vec::with_capacity(8 + HASH_LEN);
        aad.extend_from_slice(&counter.to_be_bytes());
        aad.extend_from_slice(&self.prev_hash);

        let ct = crypto::seal(&self.enc_key, &nonce, &aad, &body)?;

        // What we sign is everything a verifier can see: magic..ciphertext.
        let mut to_sign = Vec::with_capacity(4 + 8 + HASH_LEN + NONCE_LEN + ct.len());
        to_sign.extend_from_slice(FRAME_MAGIC);
        to_sign.extend_from_slice(&counter.to_be_bytes());
        to_sign.extend_from_slice(&self.prev_hash);
        to_sign.extend_from_slice(&nonce);
        to_sign.extend_from_slice(&ct);

        let sig: Signature = self.sign_key.sign(&to_sign);

        self.inner.write_all(FRAME_MAGIC)?;
        self.inner.write_all(&counter.to_be_bytes())?;
        self.inner.write_all(&self.prev_hash)?;
        self.inner.write_all(&nonce)?;
        self.inner.write_all(&(ct.len() as u32).to_le_bytes())?;
        self.inner.write_all(&ct)?;
        self.inner.write_all(&sig.to_bytes())?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(&to_sign);
        self.prev_hash = hasher.finalize().into();
        self.counter = counter;
        Ok(counter)
    }

    /// Flush + fsync the underlying writer where supported.
    pub fn sync(&mut self) -> Result<()> {
        self.inner.flush()?;
        Ok(())
    }

    /// Current frame counter (0 if no frames have been written).
    #[must_use]
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Hash of the last frame (seed for the next append).
    #[must_use]
    pub fn prev_hash(&self) -> [u8; HASH_LEN] {
        self.prev_hash
    }
}

/// Reader that verifies and decrypts WAL frames in order.
pub struct WalReader<R: Read> {
    inner: BufReader<R>,
    enc_key: SymKey,
    verify_key: VerifyingKey,
    counter: u64,
    prev_hash: [u8; HASH_LEN],
}

impl<R: Read> WalReader<R> {
    /// Create a reader starting at the beginning of a WAL stream.
    pub fn new(inner: R, enc_key: SymKey, verify_key: VerifyingKey) -> Self {
        Self {
            inner: BufReader::new(inner),
            enc_key,
            verify_key,
            counter: 0,
            prev_hash: [0u8; HASH_LEN],
        }
    }

    /// Read the next frame. Returns `Ok(None)` at clean EOF.
    ///
    /// Errors mean the log is tampered or corrupt — callers should surface,
    /// not silently truncate.
    pub fn next_op(&mut self) -> Result<Option<Op>> {
        let mut magic = [0u8; 4];
        match self.inner.read_exact(&mut magic) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(Error::Io(e)),
        }
        if &magic != FRAME_MAGIC {
            return Err(Error::Corrupt("wal frame magic"));
        }

        let mut counter = [0u8; 8];
        self.inner.read_exact(&mut counter)?;
        let counter = u64::from_be_bytes(counter);
        let expected = self.counter.checked_add(1).ok_or(Error::Corrupt("wal counter overflow"))?;
        if counter != expected {
            return Err(Error::Corrupt("wal counter gap"));
        }

        let mut prev_hash = [0u8; HASH_LEN];
        self.inner.read_exact(&mut prev_hash)?;
        if prev_hash != self.prev_hash {
            return Err(Error::Corrupt("wal chain break"));
        }

        let mut nonce = [0u8; NONCE_LEN];
        self.inner.read_exact(&mut nonce)?;
        if nonce != crypto::nonce_for(NonceDomain::Wal, counter) {
            return Err(Error::Corrupt("wal nonce mismatch"));
        }

        let mut ct_len = [0u8; 4];
        self.inner.read_exact(&mut ct_len)?;
        let ct_len = u32::from_le_bytes(ct_len) as usize;
        if ct_len > 64 * 1024 * 1024 {
            return Err(Error::Corrupt("wal frame too large"));
        }
        let mut ct = vec![0u8; ct_len];
        self.inner.read_exact(&mut ct)?;

        let mut sig_bytes = [0u8; SIG_LEN];
        self.inner.read_exact(&mut sig_bytes)?;
        let sig = Signature::from_bytes(&sig_bytes);

        let mut to_verify = Vec::with_capacity(4 + 8 + HASH_LEN + NONCE_LEN + ct.len());
        to_verify.extend_from_slice(FRAME_MAGIC);
        to_verify.extend_from_slice(&counter.to_be_bytes());
        to_verify.extend_from_slice(&prev_hash);
        to_verify.extend_from_slice(&nonce);
        to_verify.extend_from_slice(&ct);

        self.verify_key.verify(&to_verify, &sig).map_err(|_| Error::SignatureFail)?;

        let mut aad = Vec::with_capacity(8 + HASH_LEN);
        aad.extend_from_slice(&counter.to_be_bytes());
        aad.extend_from_slice(&prev_hash);
        let body = crypto::open(&self.enc_key, &nonce, &aad, &ct)?;

        let op: Op = bincode::deserialize(&body)?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(&to_verify);
        self.prev_hash = hasher.finalize().into();
        self.counter = counter;
        Ok(Some(op))
    }

    /// The state you need to continue appending to the same WAL after a replay.
    #[must_use]
    pub fn state(&self) -> (u64, [u8; HASH_LEN]) {
        (self.counter, self.prev_hash)
    }
}

/// Convenience: read and discard every frame, returning the final state. Used
/// during engine startup to position the writer correctly.
pub fn replay<R: Read>(reader: &mut WalReader<R>) -> Result<(u64, [u8; HASH_LEN])> {
    while reader.next_op()?.is_some() {}
    Ok(reader.state())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn fresh_keys() -> (SymKey, SigningKey, VerifyingKey) {
        let enc = SymKey::random();
        let sign = SigningKey::generate(&mut OsRng);
        let verify = sign.verifying_key();
        (enc, sign, verify)
    }

    #[test]
    fn append_and_replay() {
        let (enc, sign, verify) = fresh_keys();
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut w = WalWriter::new(cursor, enc.clone(), sign, 0, [0u8; 32]);
            w.append(&Op::Put { key: b"a".to_vec(), value: b"1".to_vec() }).unwrap();
            w.append(&Op::Put { key: b"b".to_vec(), value: b"2".to_vec() }).unwrap();
            w.append(&Op::Delete { key: b"a".to_vec() }).unwrap();
        }

        let mut r = WalReader::new(&buf[..], enc, verify);
        assert_eq!(
            r.next_op().unwrap(),
            Some(Op::Put { key: b"a".to_vec(), value: b"1".to_vec() })
        );
        assert_eq!(
            r.next_op().unwrap(),
            Some(Op::Put { key: b"b".to_vec(), value: b"2".to_vec() })
        );
        assert_eq!(r.next_op().unwrap(), Some(Op::Delete { key: b"a".to_vec() }));
        assert_eq!(r.next_op().unwrap(), None);
    }

    #[test]
    fn bit_flip_in_ciphertext_is_detected() {
        let (enc, sign, verify) = fresh_keys();
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut w = WalWriter::new(cursor, enc.clone(), sign, 0, [0u8; 32]);
            w.append(&Op::Put { key: b"k".to_vec(), value: b"v".to_vec() }).unwrap();
        }
        // Corrupt the last byte of ciphertext (before the signature).
        let sig_start = buf.len() - SIG_LEN;
        buf[sig_start - 1] ^= 0x01;

        let mut r = WalReader::new(&buf[..], enc, verify);
        let err = r.next_op().unwrap_err();
        assert!(matches!(err, Error::SignatureFail | Error::CryptoFail));
    }

    #[test]
    fn reordering_two_frames_breaks_the_chain() {
        let (enc, sign, verify) = fresh_keys();
        let frames = {
            let mut buf: Vec<u8> = Vec::new();
            let cursor = std::io::Cursor::new(&mut buf);
            let mut w = WalWriter::new(cursor, enc.clone(), sign, 0, [0u8; 32]);
            w.append(&Op::Put { key: b"a".to_vec(), value: b"1".to_vec() }).unwrap();
            w.append(&Op::Put { key: b"b".to_vec(), value: b"2".to_vec() }).unwrap();
            buf
        };

        // Split into two frames and swap them.
        // Each frame: 4 + 8 + 32 + 12 + 4 + ct_len + 64
        let f1_ct_len = u32::from_le_bytes(frames[56..60].try_into().unwrap()) as usize;
        let f1_end = 4 + 8 + 32 + 12 + 4 + f1_ct_len + 64;
        let (f1, f2) = frames.split_at(f1_end);
        let mut swapped = Vec::new();
        swapped.extend_from_slice(f2);
        swapped.extend_from_slice(f1);

        let mut r = WalReader::new(&swapped[..], enc, verify);
        assert!(r.next_op().is_err());
    }
}

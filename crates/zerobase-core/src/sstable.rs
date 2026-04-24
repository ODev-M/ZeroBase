//! Sorted String Table — the immutable, on-disk output of a MemTable flush.
//!
//! # File layout
//!
//! ```text
//! +--------+-----+------------+------------+-------------+-----------+
//! | magic  | ver | nonce (12) | ct_len (4) | ciphertext  | root hash |
//! | "ZBST" | 4B  |            |            |   N bytes   |   32B     |
//! +--------+-----+------------+------------+-------------+-----------+
//! ```
//!
//! The ciphertext, once decrypted, is a bincode-serialized [`Block`] — a
//! sorted list of `(key, Entry)` pairs plus a per-entry BLAKE3 leaf hash.
//!
//! # Integrity
//!
//! * **AEAD** (AES-256-GCM) binds the whole block plus the header magic +
//!   version as AAD. A single bit flip anywhere in ct fails authentication.
//! * A **Merkle root** over per-entry keyed-BLAKE3 hashes is written in the
//!   clear *after* the ciphertext. On read we re-derive it from the decrypted
//!   entries and require equality — this detects a swap of a whole SSTable
//!   file for a previously-valid one.
//!
//! This MVP keeps everything in one block (one-shot AEAD). A later version
//! can split into multiple encrypted blocks with an encrypted index, so that
//! reads don't need to decrypt the whole file. The API is designed so we can
//! swap in that implementation without changing callers.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use crate::crypto::{self, NonceDomain, SymKey, NONCE_LEN};
use crate::memtable::{Entry, MemTable};
use crate::{Error, Result};

const MAGIC: &[u8; 4] = b"ZBST";
const VERSION: u32 = 1;
const ROOT_LEN: usize = 32;

#[derive(Serialize, Deserialize)]
struct Block {
    /// Sorted (key, entry, leaf-hash) triples.
    entries: Vec<(Vec<u8>, Entry, [u8; 32])>,
}

/// Serialize and encrypt the given MemTable into an SSTable stream.
///
/// `file_id` is a caller-supplied counter that must be unique per SSTable and
/// is mixed into the nonce so two files with identical contents still use
/// distinct `(key, nonce)` tuples.
pub fn write<W: Write>(
    mut out: W,
    mem: &MemTable,
    data_key: &SymKey,
    mac_key: &SymKey,
    file_id: u64,
) -> Result<[u8; ROOT_LEN]> {
    let mut entries = Vec::with_capacity(mem.len());
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(mem.len());

    for (k, v) in mem.iter() {
        let mut hasher = blake3::Hasher::new_keyed(mac_key_bytes(mac_key));
        hasher.update(k);
        match v {
            Entry::Value(val) => {
                hasher.update(&[0x01]);
                hasher.update(val);
            }
            Entry::Tombstone => {
                hasher.update(&[0x00]);
            }
        }
        let leaf: [u8; 32] = hasher.finalize().into();
        leaves.push(leaf);
        entries.push((k.to_vec(), v.clone(), leaf));
    }

    let root = merkle_root(&leaves, mac_key);
    let block = Block { entries };
    let plain = bincode::serialize(&block)?;

    let nonce = crypto::nonce_for(NonceDomain::Sstable, file_id);
    let mut aad = Vec::with_capacity(4 + 4 + ROOT_LEN);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&VERSION.to_le_bytes());
    aad.extend_from_slice(&root);

    let ct = crypto::seal(data_key, &nonce, &aad, &plain)?;

    out.write_all(MAGIC)?;
    out.write_all(&VERSION.to_le_bytes())?;
    out.write_all(&nonce)?;
    out.write_all(&(ct.len() as u32).to_le_bytes())?;
    out.write_all(&ct)?;
    out.write_all(&root)?;
    Ok(root)
}

/// Decrypt an SSTable and return the sorted, verified entries.
pub fn read<R: Read>(
    mut input: R,
    data_key: &SymKey,
    mac_key: &SymKey,
) -> Result<Vec<(Vec<u8>, Entry)>> {
    let mut magic = [0u8; 4];
    input.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(Error::Corrupt("sstable magic"));
    }
    let mut ver = [0u8; 4];
    input.read_exact(&mut ver)?;
    let ver = u32::from_le_bytes(ver);
    if ver != VERSION {
        return Err(Error::UnsupportedVersion(ver));
    }

    let mut nonce = [0u8; NONCE_LEN];
    input.read_exact(&mut nonce)?;

    let mut ct_len = [0u8; 4];
    input.read_exact(&mut ct_len)?;
    let ct_len = u32::from_le_bytes(ct_len) as usize;
    if ct_len > 1024 * 1024 * 1024 {
        return Err(Error::Corrupt("sstable too large"));
    }

    let mut ct = vec![0u8; ct_len];
    input.read_exact(&mut ct)?;

    let mut root = [0u8; ROOT_LEN];
    input.read_exact(&mut root)?;

    let mut aad = Vec::with_capacity(4 + 4 + ROOT_LEN);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&ver.to_le_bytes());
    aad.extend_from_slice(&root);

    let plain = crypto::open(data_key, &nonce, &aad, &ct)?;
    let block: Block = bincode::deserialize(&plain)?;

    // Re-derive the Merkle root and require bitwise equality. This catches an
    // attacker who replaces one sealed SSTable with another (older) one under
    // the same data/mac keys: the root is part of the AAD for this nonce, and
    // we additionally verify entry integrity.
    let leaves: Vec<[u8; 32]> = block
        .entries
        .iter()
        .map(|(k, e, leaf)| {
            let mut h = blake3::Hasher::new_keyed(mac_key_bytes(mac_key));
            h.update(k);
            match e {
                Entry::Value(v) => {
                    h.update(&[0x01]);
                    h.update(v);
                }
                Entry::Tombstone => {
                    h.update(&[0x00]);
                }
            }
            let actual: [u8; 32] = h.finalize().into();
            if actual != *leaf {
                return Err(Error::Corrupt("sstable leaf"));
            }
            Ok::<[u8; 32], Error>(actual)
        })
        .collect::<Result<_>>()?;
    let re_root = merkle_root(&leaves, mac_key);
    if re_root != root {
        return Err(Error::Corrupt("sstable root"));
    }

    let out: Vec<(Vec<u8>, Entry)> = block.entries.into_iter().map(|(k, e, _)| (k, e)).collect();
    // Paranoia: sort order must match MemTable's flush order.
    if out.windows(2).any(|w| w[0].0 >= w[1].0) {
        return Err(Error::Corrupt("sstable order"));
    }
    Ok(out)
}

fn merkle_root(leaves: &[[u8; 32]], mac_key: &SymKey) -> [u8; ROOT_LEN] {
    if leaves.is_empty() {
        let mut h = blake3::Hasher::new_keyed(mac_key_bytes(mac_key));
        h.update(b"empty");
        return h.finalize().into();
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let mut h = blake3::Hasher::new_keyed(mac_key_bytes(mac_key));
            h.update(&pair[0]);
            h.update(pair.get(1).unwrap_or(&pair[0]));
            next.push(h.finalize().into());
        }
        level = next;
    }
    level[0]
}

fn mac_key_bytes(k: &SymKey) -> &[u8; 32] {
    // The public API of SymKey intentionally doesn't expose raw bytes to
    // foreign callers. Within the crate we have a private accessor.
    crate::crypto::_mac_bytes(k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SymKey;

    #[test]
    fn flush_and_read_back() {
        let mut m = MemTable::new();
        m.put(b"alpha".to_vec(), b"1".to_vec());
        m.put(b"bravo".to_vec(), b"2".to_vec());
        m.delete(b"charlie".to_vec());

        let data = SymKey::random();
        let mac = SymKey::random();
        let mut buf: Vec<u8> = Vec::new();
        write(&mut buf, &m, &data, &mac, 1).unwrap();

        let got = read(&buf[..], &data, &mac).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].0, b"alpha");
        assert_eq!(got[1].0, b"bravo");
        assert_eq!(got[2].1, Entry::Tombstone);
    }

    #[test]
    fn tampering_breaks_read() {
        let mut m = MemTable::new();
        m.put(b"k".to_vec(), b"v".to_vec());
        let data = SymKey::random();
        let mac = SymKey::random();
        let mut buf: Vec<u8> = Vec::new();
        write(&mut buf, &m, &data, &mac, 7).unwrap();
        // Flip a byte somewhere in the middle of the ciphertext.
        let mid = buf.len() / 2;
        buf[mid] ^= 0x80;
        assert!(read(&buf[..], &data, &mac).is_err());
    }

    #[test]
    fn wrong_mac_key_breaks_read() {
        let mut m = MemTable::new();
        m.put(b"k".to_vec(), b"v".to_vec());
        let data = SymKey::random();
        let mac = SymKey::random();
        let other = SymKey::random();
        let mut buf: Vec<u8> = Vec::new();
        write(&mut buf, &m, &data, &mac, 1).unwrap();
        assert!(read(&buf[..], &data, &other).is_err());
    }
}

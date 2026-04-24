//! The **manifest** records which SSTable files belong to the live DB and in
//! what order they were written. It is small enough to rewrite on every flush
//! and is sealed the same way as an SSTable (AEAD + keyed-BLAKE3 root).

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use crate::crypto::{self, NonceDomain, SymKey, NONCE_LEN};
use crate::{Error, Result};

const MAGIC: &[u8; 4] = b"ZBMF";
const VERSION: u32 = 1;

/// Serializable, on-disk manifest body.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Manifest {
    /// Ever-increasing counter used to allocate the next SSTable file id.
    pub next_file_id: u64,
    /// SSTable file ids in insertion order (newest last).
    pub sstables: Vec<u64>,
    /// Monotonically-increasing generation — lets callers detect an attacker
    /// who swapped in an older manifest.
    pub generation: u64,
}

/// Seal + write a manifest. Caller must advance `generation` on every save.
pub fn write<W: Write>(mut out: W, manifest: &Manifest, key: &SymKey) -> Result<()> {
    let body = bincode::serialize(manifest)?;
    let nonce = crypto::nonce_for(NonceDomain::Manifest, manifest.generation);

    let mut aad = Vec::with_capacity(4 + 4);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&VERSION.to_le_bytes());

    let ct = crypto::seal(key, &nonce, &aad, &body)?;

    out.write_all(MAGIC)?;
    out.write_all(&VERSION.to_le_bytes())?;
    out.write_all(&nonce)?;
    out.write_all(&(ct.len() as u32).to_le_bytes())?;
    out.write_all(&ct)?;
    Ok(())
}

/// Read + authenticate a manifest.
pub fn read<R: Read>(mut input: R, key: &SymKey) -> Result<Manifest> {
    let mut magic = [0u8; 4];
    input.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(Error::Corrupt("manifest magic"));
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
    if ct_len > 16 * 1024 * 1024 {
        return Err(Error::Corrupt("manifest too large"));
    }
    let mut ct = vec![0u8; ct_len];
    input.read_exact(&mut ct)?;

    let mut aad = Vec::with_capacity(4 + 4);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&ver.to_le_bytes());

    let plain = crypto::open(key, &nonce, &aad, &ct)?;
    let manifest: Manifest = bincode::deserialize(&plain)?;

    // Nonce reuse detection: the nonce must match our domain/generation scheme.
    if nonce != crypto::nonce_for(NonceDomain::Manifest, manifest.generation) {
        return Err(Error::Corrupt("manifest nonce"));
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SymKey;

    #[test]
    fn roundtrip() {
        let k = SymKey::random();
        let m = Manifest { next_file_id: 7, sstables: vec![1, 3, 5], generation: 2 };
        let mut buf: Vec<u8> = Vec::new();
        write(&mut buf, &m, &k).unwrap();
        let m2 = read(&buf[..], &k).unwrap();
        assert_eq!(m.next_file_id, m2.next_file_id);
        assert_eq!(m.sstables, m2.sstables);
        assert_eq!(m.generation, m2.generation);
    }

    #[test]
    fn tampered_manifest_fails() {
        let k = SymKey::random();
        let m = Manifest::default();
        let mut buf: Vec<u8> = Vec::new();
        write(&mut buf, &m, &k).unwrap();
        *buf.last_mut().unwrap() ^= 0x01;
        assert!(read(&buf[..], &k).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = SymKey::random();
        let k2 = SymKey::random();
        let m = Manifest::default();
        let mut buf: Vec<u8> = Vec::new();
        write(&mut buf, &m, &k1).unwrap();
        assert!(read(&buf[..], &k2).is_err());
    }
}

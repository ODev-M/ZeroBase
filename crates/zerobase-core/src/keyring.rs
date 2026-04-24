//! The **keyring** stores the database's master key, sealed with a passphrase.
//!
//! Layout on disk (little-endian unless noted):
//!
//! ```text
//! +--------+--------+-----------+---------+----------+------------+
//! | magic  | ver    | argon2    | salt    | nonce    | sealed key |
//! | 4B     | 4B     | params 16B| 32B     | 12B      | 32B+16B    |
//! +--------+--------+-----------+---------+----------+------------+
//! ```
//!
//! The Argon2id parameters live in the header so we can strengthen them in
//! future versions without breaking existing keyrings.
//!
//! The master key never leaves memory unencrypted except inside
//! [`UnlockedKeyring`], which zeroizes on drop.

use std::io::{Read, Write};

use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{self, NonceDomain, SymKey, KEY_LEN, NONCE_LEN};
use crate::{Error, Result};

const MAGIC: &[u8; 4] = b"ZBKR";
const VERSION: u32 = 1;

/// Argon2id work parameters. Stored on disk so each keyring documents its
/// own cost.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB. Default: 256 MiB.
    pub m_cost_kib: u32,
    /// Number of iterations. Default: 3.
    pub t_cost: u32,
    /// Degree of parallelism. Default: 1.
    pub parallelism: u32,
    /// Reserved for future use. Must be zero.
    pub _reserved: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self { m_cost_kib: 256 * 1024, t_cost: 3, parallelism: 1, _reserved: 0 }
    }
}

/// The sealed, on-disk keyring.
#[derive(Serialize, Deserialize)]
pub struct SealedKeyring {
    version: u32,
    params: Argon2Params,
    salt: [u8; 32],
    nonce: [u8; NONCE_LEN],
    sealed: Vec<u8>, // ciphertext || tag
}

/// The in-memory, decrypted keyring. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UnlockedKeyring {
    master: SymKey,
}

impl UnlockedKeyring {
    /// Access the master symmetric key.
    #[must_use]
    pub fn master(&self) -> &SymKey {
        &self.master
    }
}

/// Create a brand-new keyring: generates a master key, then seals it with a
/// key derived from `passphrase` via Argon2id.
pub fn create(
    passphrase: &SecretString,
    params: Argon2Params,
) -> Result<(SealedKeyring, UnlockedKeyring)> {
    let master = SymKey::random();
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let kek = derive_kek(passphrase, &salt, &params)?;
    let nonce = crypto::nonce_for(NonceDomain::Keyring, 0);
    let sealed = crypto::seal(&kek, &nonce, MAGIC, master.as_bytes())?;

    Ok((
        SealedKeyring { version: VERSION, params, salt, nonce, sealed },
        UnlockedKeyring { master },
    ))
}

impl SealedKeyring {
    /// Unlock with a passphrase. Constant-time path: any failure surfaces as
    /// [`Error::Unlock`] with no further discrimination.
    pub fn unlock(&self, passphrase: &SecretString) -> Result<UnlockedKeyring> {
        if self.version != VERSION {
            return Err(Error::UnsupportedVersion(self.version));
        }
        let kek = derive_kek(passphrase, &self.salt, &self.params).map_err(|_| Error::Unlock)?;
        let pt = crypto::open(&kek, &self.nonce, MAGIC, &self.sealed).map_err(|_| Error::Unlock)?;

        if pt.len() != KEY_LEN {
            return Err(Error::Unlock);
        }
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(&pt);
        // Explicitly zero the heap buffer before it's dropped.
        let mut pt = pt;
        pt.zeroize();
        Ok(UnlockedKeyring { master: SymKey::from_bytes(bytes) })
    }

    /// Serialize to the given writer (length-prefixed bincode).
    pub fn write_to<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(MAGIC)?;
        let body = bincode::serialize(self)?;
        w.write_all(&(body.len() as u32).to_le_bytes())?;
        w.write_all(&body)?;
        Ok(())
    }

    /// Read from the given reader.
    pub fn read_from<R: Read>(mut r: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(Error::Corrupt("keyring magic"));
        }
        let mut len_bytes = [0u8; 4];
        r.read_exact(&mut len_bytes)?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > 4 * 1024 {
            return Err(Error::Corrupt("keyring too large"));
        }
        let mut body = vec![0u8; len];
        r.read_exact(&mut body)?;
        let kr: Self = bincode::deserialize(&body)?;
        Ok(kr)
    }
}

fn derive_kek(pass: &SecretString, salt: &[u8; 32], p: &Argon2Params) -> Result<SymKey> {
    let params = Params::new(p.m_cost_kib, p.t_cost, p.parallelism, Some(KEY_LEN))
        .map_err(|_| Error::CryptoFail)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(pass.expose_secret().as_bytes(), salt, &mut out)
        .map_err(|_| Error::CryptoFail)?;
    let k = SymKey::from_bytes(out);
    // `out` and the copy we passed already live as parts of `k`; overwrite
    // the stack copy anyway.
    let mut out_overwrite = out;
    out_overwrite.zeroize();
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn weak_params() -> Argon2Params {
        // Weaker params keep the test suite fast; production defaults are 256 MiB.
        Argon2Params { m_cost_kib: 8 * 1024, t_cost: 1, parallelism: 1, _reserved: 0 }
    }

    #[test]
    fn create_and_unlock_roundtrip() {
        let pass = SecretString::new("correct horse battery staple".into());
        let (sealed, unlocked) = create(&pass, weak_params()).unwrap();
        let again = sealed.unlock(&pass).unwrap();
        // Constant-time equality check.
        use subtle::ConstantTimeEq;
        assert!(bool::from(unlocked.master().ct_eq(again.master())));
    }

    #[test]
    fn wrong_password_fails_opaquely() {
        let pass = SecretString::new("right".into());
        let bad = SecretString::new("wrong".into());
        let (sealed, _) = create(&pass, weak_params()).unwrap();
        assert!(matches!(sealed.unlock(&bad), Err(Error::Unlock)));
    }

    #[test]
    fn serialization_roundtrip() {
        let pass = SecretString::new("hunter2".into());
        let (sealed, _) = create(&pass, weak_params()).unwrap();
        let mut buf = Vec::new();
        sealed.write_to(&mut buf).unwrap();
        let parsed = SealedKeyring::read_from(&buf[..]).unwrap();
        assert!(parsed.unlock(&pass).is_ok());
    }
}

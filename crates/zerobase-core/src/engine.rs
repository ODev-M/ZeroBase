//! The top-level Zerobase engine. Ties together:
//!
//! * **Keyring** — sealed master key, unlocked with a passphrase.
//! * **WAL** — signed + encrypted write-ahead log, replayed on open.
//! * **MemTable** — sorted in-memory table of live writes.
//! * **SSTables** — immutable, encrypted, Merkle-rooted flush outputs.
//! * **Manifest** — ordered list of live SSTables, sealed per generation.
//!
//! # On-disk layout
//!
//! ```text
//! <root>/
//!   keyring.zbkr       # sealed master key
//!   manifest.zbmf      # sealed manifest (newest)
//!   manifest.zbmf.tmp  # atomic rename destination
//!   wal-000001.zbwl    # active WAL
//!   sst-000001.zbst    # SSTables, numbered by file_id
//!   sst-000002.zbst
//!   ...
//! ```
//!
//! # Subkey derivation
//!
//! From the 32-byte master key we derive four domain-separated 32-byte
//! subkeys via keyed-BLAKE3:
//!
//! | label            | purpose                                        |
//! |------------------|------------------------------------------------|
//! | `zb:wal:enc`     | AEAD for WAL frames                            |
//! | `zb:sst:data`    | AEAD for SSTable blocks                        |
//! | `zb:sst:mac`     | keyed-BLAKE3 for per-entry leaves + Merkle     |
//! | `zb:manifest`    | AEAD for the manifest                          |
//!
//! The WAL **signing** key is a separate Ed25519 keypair generated the first
//! time the DB is created; the private half is sealed inside the keyring
//! alongside the master key. (MVP note: this MVP stores the WAL signing key
//! as a subkey of the master via HKDF-like keyed-BLAKE3 of a fixed seed, so
//! the keyring stays small. See `TODO.md` for upgrading to a real Ed25519
//! keypair rotated per-open.)

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use secrecy::SecretString;

use crate::crypto::SymKey;
use crate::keyring::{self, Argon2Params, SealedKeyring, UnlockedKeyring};
use crate::manifest::{self, Manifest};
use crate::memtable::{Entry, MemTable};
use crate::sstable;
use crate::wal::{Op, WalReader, WalWriter};
use crate::{Error, Result};

/// Default flush threshold: 4 MiB of keys+values before we roll the MemTable
/// into a new SSTable.
pub const DEFAULT_FLUSH_BYTES: usize = 4 * 1024 * 1024;

/// In-memory snapshot of one flushed SSTable: `(file_id, sorted entries)`.
type LoadedSst = (u64, Vec<(Vec<u8>, Entry)>);

/// Handle to an open Zerobase database.
pub struct Db {
    root: PathBuf,
    flush_threshold: usize,

    keys: Keys,
    manifest: Manifest,

    memtable: MemTable,
    wal: WalWriter<File>,

    sstables: Vec<LoadedSst>,
}

struct Keys {
    wal_enc: SymKey,
    wal_sign: SigningKey,
    sst_data: SymKey,
    sst_mac: SymKey,
    manifest: SymKey,
}

impl Keys {
    fn derive(unlocked: &UnlockedKeyring) -> Self {
        let sub =
            |label: &[u8]| SymKey::from_bytes(crate::crypto::keyed_hash(unlocked.master(), label));
        let sign_seed = crate::crypto::keyed_hash(unlocked.master(), b"zb:wal:sign");
        Self {
            wal_enc: sub(b"zb:wal:enc"),
            wal_sign: SigningKey::from_bytes(&sign_seed),
            sst_data: sub(b"zb:sst:data"),
            sst_mac: sub(b"zb:sst:mac"),
            manifest: sub(b"zb:manifest"),
        }
    }
}

impl Db {
    /// Create a **new** database at `root`. Fails if a keyring already exists.
    pub fn create(root: impl AsRef<Path>, passphrase: &SecretString) -> Result<Self> {
        Self::create_with(root, passphrase, Argon2Params::default(), DEFAULT_FLUSH_BYTES)
    }

    /// Create a new database with explicit parameters (mostly for tests).
    pub fn create_with(
        root: impl AsRef<Path>,
        passphrase: &SecretString,
        params: Argon2Params,
        flush_threshold: usize,
    ) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;

        let keyring_path = root.join("keyring.zbkr");
        if keyring_path.exists() {
            return Err(Error::Corrupt("keyring already exists"));
        }

        let (sealed, unlocked) = keyring::create(passphrase, params)?;
        let mut kf =
            OpenOptions::new().write(true).create_new(true).mode_0600().open(&keyring_path)?;
        sealed.write_to(&mut kf)?;
        kf.sync_all()?;
        drop(kf);

        let keys = Keys::derive(&unlocked);
        let manifest = Manifest::default();
        Self::persist_manifest(&root, &manifest, &keys.manifest)?;

        let wal_path = root.join("wal-000001.zbwl");
        let wal_file =
            OpenOptions::new().create(true).append(true).read(true).mode_0600().open(&wal_path)?;
        let wal =
            WalWriter::new(wal_file, keys.wal_enc.clone(), keys.wal_sign.clone(), 0, [0u8; 32]);

        Ok(Self {
            root,
            flush_threshold,
            keys,
            manifest,
            memtable: MemTable::new(),
            wal,
            sstables: Vec::new(),
        })
    }

    /// Open an **existing** database, replaying the WAL on top of the loaded
    /// SSTables.
    pub fn open(root: impl AsRef<Path>, passphrase: &SecretString) -> Result<Self> {
        Self::open_with(root, passphrase, DEFAULT_FLUSH_BYTES)
    }

    /// Open an existing database with a custom flush threshold.
    pub fn open_with(
        root: impl AsRef<Path>,
        passphrase: &SecretString,
        flush_threshold: usize,
    ) -> Result<Self> {
        let root = root.as_ref().to_path_buf();

        let mut kf = File::open(root.join("keyring.zbkr"))?;
        let sealed = SealedKeyring::read_from(&mut kf)?;
        let unlocked = sealed.unlock(passphrase)?;
        let keys = Keys::derive(&unlocked);

        let manifest = Self::load_manifest(&root, &keys.manifest)?;

        // Load every SSTable into memory (MVP: read-mostly, small-ish DBs).
        let mut sstables: Vec<LoadedSst> = Vec::with_capacity(manifest.sstables.len());
        for id in &manifest.sstables {
            let p = root.join(format!("sst-{:06}.zbst", id));
            let f = File::open(&p)?;
            let entries = sstable::read(BufReader::new(f), &keys.sst_data, &keys.sst_mac)?;
            sstables.push((*id, entries));
        }

        // Replay WAL into a fresh MemTable on top of the SSTables.
        let wal_path = root.join("wal-000001.zbwl");
        let mut memtable = MemTable::new();
        let (counter, prev_hash) = if wal_path.exists() {
            let f = File::open(&wal_path)?;
            let verify = keys.wal_sign.verifying_key();
            let mut r = WalReader::new(f, keys.wal_enc.clone(), verify);
            while let Some(op) = r.next_op()? {
                match op {
                    Op::Put { key, value } => memtable.put(key, value),
                    Op::Delete { key } => memtable.delete(key),
                }
            }
            r.state()
        } else {
            (0, [0u8; 32])
        };

        let wal_file =
            OpenOptions::new().create(true).append(true).read(true).mode_0600().open(&wal_path)?;
        let wal = WalWriter::new(
            wal_file,
            keys.wal_enc.clone(),
            keys.wal_sign.clone(),
            counter,
            prev_hash,
        );

        Ok(Self { root, flush_threshold, keys, manifest, memtable, wal, sstables })
    }

    /// Insert or overwrite a key/value pair.
    pub fn put(&mut self, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Result<()> {
        let key = key.into();
        let value = value.into();
        self.wal.append(&Op::Put { key: key.clone(), value: value.clone() })?;
        self.memtable.put(key, value);
        self.maybe_flush()?;
        Ok(())
    }

    /// Delete a key.
    pub fn delete(&mut self, key: impl Into<Vec<u8>>) -> Result<()> {
        let key = key.into();
        self.wal.append(&Op::Delete { key: key.clone() })?;
        self.memtable.delete(key);
        self.maybe_flush()?;
        Ok(())
    }

    /// Fetch a value. Returns `None` if the key is absent or tombstoned.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(e) = self.memtable.get(key) {
            return match e {
                Entry::Value(v) => Some(v.clone()),
                Entry::Tombstone => None,
            };
        }
        for (_id, entries) in self.sstables.iter().rev() {
            if let Ok(idx) = entries.binary_search_by(|(k, _)| k.as_slice().cmp(key)) {
                return match &entries[idx].1 {
                    Entry::Value(v) => Some(v.clone()),
                    Entry::Tombstone => None,
                };
            }
        }
        None
    }

    /// Force an immediate MemTable → SSTable flush.
    pub fn flush(&mut self) -> Result<()> {
        if self.memtable.is_empty() {
            return Ok(());
        }
        let file_id = self.manifest.next_file_id + 1;
        let path = self.root.join(format!("sst-{:06}.zbst", file_id));
        let tmp = path.with_extension("zbst.tmp");

        {
            let mut f = OpenOptions::new().create_new(true).write(true).mode_0600().open(&tmp)?;
            sstable::write(
                &mut f,
                &self.memtable,
                &self.keys.sst_data,
                &self.keys.sst_mac,
                file_id,
            )?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;

        // Snapshot the flushed entries for in-process reads.
        let mut flushed: Vec<(Vec<u8>, Entry)> =
            self.memtable.iter().map(|(k, e)| (k.to_vec(), e.clone())).collect();
        flushed.sort_by(|a, b| a.0.cmp(&b.0));
        self.sstables.push((file_id, flushed));

        self.manifest.next_file_id = file_id;
        self.manifest.sstables.push(file_id);
        self.manifest.generation += 1;
        Self::persist_manifest(&self.root, &self.manifest, &self.keys.manifest)?;

        // WAL is redundant now that the data lives in an SSTable. Truncate.
        let wal_path = self.root.join("wal-000001.zbwl");
        let new_wal = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .read(true)
            .mode_0600()
            .open(&wal_path)?;
        self.wal = WalWriter::new(
            new_wal,
            self.keys.wal_enc.clone(),
            self.keys.wal_sign.clone(),
            0,
            [0u8; 32],
        );

        self.memtable = MemTable::new();
        Ok(())
    }

    /// Flush + sync and drop the engine. Prefer this over `drop(db)` so that
    /// the WAL is always persisted before the process exits.
    pub fn close(mut self) -> Result<()> {
        self.wal.sync()?;
        self.flush()?;
        Ok(())
    }

    fn maybe_flush(&mut self) -> Result<()> {
        if self.memtable.approx_bytes() >= self.flush_threshold {
            self.flush()?;
        }
        Ok(())
    }

    fn persist_manifest(root: &Path, manifest: &Manifest, key: &SymKey) -> Result<()> {
        let tmp = root.join("manifest.zbmf.tmp");
        let final_path = root.join("manifest.zbmf");
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode_0600()
                .open(&tmp)?;
            manifest::write(&mut f, manifest, key)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &final_path)?;
        Ok(())
    }

    fn load_manifest(root: &Path, key: &SymKey) -> Result<Manifest> {
        let path = root.join("manifest.zbmf");
        if !path.exists() {
            return Ok(Manifest::default());
        }
        let mut f = File::open(&path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        manifest::read(&buf[..], key)
    }
}

// Small helper trait: `.mode_0600()` so secrets never land with world-read
// permissions on POSIX. Non-Unix builds get a no-op.
#[cfg(unix)]
trait OpenOptionsExt600 {
    fn mode_0600(&mut self) -> &mut Self;
}
#[cfg(unix)]
impl OpenOptionsExt600 for OpenOptions {
    fn mode_0600(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.mode(0o600)
    }
}
#[cfg(not(unix))]
trait OpenOptionsExt600 {
    fn mode_0600(&mut self) -> &mut Self;
}
#[cfg(not(unix))]
impl OpenOptionsExt600 for OpenOptions {
    fn mode_0600(&mut self) -> &mut Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    use tempfile::TempDir;

    fn weak_pass() -> SecretString {
        SecretString::new("test-passphrase".into())
    }

    #[test]
    fn create_put_get_delete() {
        let dir = TempDir::new().unwrap();
        let mut db = Db::create_with(
            dir.path(),
            &weak_pass(),
            Argon2Params { m_cost_kib: 8 * 1024, t_cost: 1, parallelism: 1, _reserved: 0 },
            1024 * 1024,
        )
        .unwrap();

        db.put("a", "1").unwrap();
        db.put("b", "2").unwrap();
        db.delete("a").unwrap();
        assert_eq!(db.get(b"a"), None);
        assert_eq!(db.get(b"b"), Some(b"2".to_vec()));
    }

    #[test]
    fn survives_reopen_via_wal_replay() {
        let dir = TempDir::new().unwrap();
        {
            let mut db = Db::create_with(
                dir.path(),
                &weak_pass(),
                Argon2Params { m_cost_kib: 8 * 1024, t_cost: 1, parallelism: 1, _reserved: 0 },
                1024 * 1024,
            )
            .unwrap();
            db.put("k1", "v1").unwrap();
            db.put("k2", "v2").unwrap();
            // Intentionally don't flush — we want to prove WAL replay works.
            db.wal.sync().unwrap();
            std::mem::forget(db); // avoid Drop flushing
        }
        let db = Db::open(dir.path(), &weak_pass()).unwrap();
        assert_eq!(db.get(b"k1"), Some(b"v1".to_vec()));
        assert_eq!(db.get(b"k2"), Some(b"v2".to_vec()));
    }

    #[test]
    fn survives_reopen_via_sstable() {
        let dir = TempDir::new().unwrap();
        {
            let mut db = Db::create_with(
                dir.path(),
                &weak_pass(),
                Argon2Params { m_cost_kib: 8 * 1024, t_cost: 1, parallelism: 1, _reserved: 0 },
                1024 * 1024,
            )
            .unwrap();
            db.put("persist-me", "forever").unwrap();
            db.flush().unwrap();
            db.close().unwrap();
        }
        let db = Db::open(dir.path(), &weak_pass()).unwrap();
        assert_eq!(db.get(b"persist-me"), Some(b"forever".to_vec()));
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let dir = TempDir::new().unwrap();
        {
            let db = Db::create_with(
                dir.path(),
                &weak_pass(),
                Argon2Params { m_cost_kib: 8 * 1024, t_cost: 1, parallelism: 1, _reserved: 0 },
                1024 * 1024,
            )
            .unwrap();
            db.close().unwrap();
        }
        let res = Db::open(dir.path(), &SecretString::new("WRONG".into()));
        assert!(matches!(res.err(), Some(Error::Unlock)));
    }
}

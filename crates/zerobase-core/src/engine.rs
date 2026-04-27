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

/// One entry returned by a scan or range iterator. Tombstones are filtered
/// out before they reach the caller.
#[derive(Clone, Debug)]
pub struct ScanItem {
    /// Key bytes.
    pub key: Vec<u8>,
    /// Value bytes.
    pub value: Vec<u8>,
}

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

    /// Derive a subkey under an external label. The label is prefixed with
    /// `ext:` on the wire so external consumers (auth, sql) cannot collide
    /// with any internal label (`zb:…`).
    fn derive_external(&self, label: &[u8]) -> SymKey {
        // We need the master to derive; but we only keep the derived
        // subkeys. Re-derive from one of them is not correct. Instead,
        // expose a separate path that re-uses `wal_enc` as an intermediate
        // key: HKDF-style `keyed_hash(wal_enc, "ext:" || label)`. That keeps
        // the master never-leaving semantics while giving every external
        // caller a fresh domain.
        let mut input = Vec::with_capacity(4 + label.len());
        input.extend_from_slice(b"ext:");
        input.extend_from_slice(label);
        SymKey::from_bytes(crate::crypto::keyed_hash(&self.wal_enc, &input))
    }
}

/// Compute the exclusive upper bound for `scan(prefix)`. Returns `None` when
/// the prefix is entirely 0xFF (no tighter upper bound exists).
fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut out = prefix.to_vec();
    while let Some(last) = out.last_mut() {
        if *last < 0xFF {
            *last += 1;
            return Some(out);
        }
        out.pop();
    }
    None
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

    /// Write a batch of operations under a single fsync. Each op still
    /// produces its own WAL frame (so the hash chain keeps its per-op
    /// granularity) but we only sync once at the end.
    ///
    /// Atomicity: if an earlier append succeeds but a later one fails,
    /// already-written frames remain on disk. WAL replay on next open will
    /// either accept the tail (if every frame is valid) or refuse the open
    /// outright — we never silently truncate.
    pub fn batch(&mut self, ops: &[Op]) -> Result<()> {
        if ops.is_empty() {
            return Ok(());
        }
        for op in ops {
            self.wal.append(op)?;
        }
        self.wal.sync()?;
        for op in ops {
            match op.clone() {
                Op::Put { key, value } => self.memtable.put(key, value),
                Op::Delete { key } => self.memtable.delete(key),
            }
        }
        self.maybe_flush()?;
        Ok(())
    }

    /// Derive a domain-separated subkey from the master. Used by upper
    /// layers (auth, SQL) to get their own signing/encryption keys without
    /// needing access to the master directly.
    #[must_use]
    pub fn derive_subkey(&self, label: &[u8]) -> SymKey {
        self.keys.derive_external(label)
    }

    /// Iterate every live entry whose key starts with `prefix`, in ascending
    /// key order. Tombstones and values shadowed by newer tombstones are
    /// filtered out. Results are materialized eagerly into a snapshot.
    #[must_use]
    pub fn scan(&self, prefix: &[u8]) -> Vec<ScanItem> {
        let end = prefix_upper_bound(prefix);
        self.range_inner(prefix, end.as_deref().unwrap_or(&[]))
    }

    /// Iterate every live entry in `[start, end)`. An empty `end` (`&[]`)
    /// means unbounded. Results are eagerly materialized into a snapshot.
    #[must_use]
    pub fn range(&self, start: &[u8], end: &[u8]) -> Vec<ScanItem> {
        self.range_inner(start, end)
    }

    fn range_inner(&self, start: &[u8], end: &[u8]) -> Vec<ScanItem> {
        // Newest-wins merge across memtable + sstables (newest first).
        // We walk every source's sorted slice and de-duplicate by key.
        use std::collections::BTreeMap;

        // Accumulate `key -> (age_rank, entry)` where a smaller age_rank means
        // newer. Rank 0 is the memtable; sstables follow in reverse order
        // (newest first, since self.sstables is insertion order oldest..newest
        // — flush() pushes newer ones at the end).
        let mut best: BTreeMap<Vec<u8>, (usize, Entry)> = BTreeMap::new();

        for (k, e) in self.memtable.range(start, end) {
            best.insert(k.to_vec(), (0, e.clone()));
        }

        for (rank_offset, (_id, entries)) in self.sstables.iter().rev().enumerate() {
            let rank = rank_offset + 1;
            let lo = entries.partition_point(|(k, _)| k.as_slice() < start);
            let hi = if end.is_empty() {
                entries.len()
            } else {
                entries.partition_point(|(k, _)| k.as_slice() < end)
            };
            for (k, e) in &entries[lo..hi] {
                best.entry(k.clone()).or_insert_with(|| (rank, e.clone()));
            }
        }

        best.into_iter()
            .filter_map(|(k, (_rank, e))| match e {
                Entry::Value(v) => Some(ScanItem { key: k, value: v }),
                Entry::Tombstone => None,
            })
            .collect()
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
    fn scan_and_range_honor_newest_wins() {
        let dir = TempDir::new().unwrap();
        let mut db = Db::create_with(
            dir.path(),
            &weak_pass(),
            Argon2Params { m_cost_kib: 8 * 1024, t_cost: 1, parallelism: 1, _reserved: 0 },
            1024 * 1024,
        )
        .unwrap();

        db.put(b"a".to_vec(), b"1".to_vec()).unwrap();
        db.put(b"b".to_vec(), b"2".to_vec()).unwrap();
        db.put(b"c".to_vec(), b"3".to_vec()).unwrap();
        db.flush().unwrap(); // push to an SSTable

        db.put(b"b".to_vec(), b"22".to_vec()).unwrap(); // override in memtable
        db.delete(b"c".to_vec()).unwrap(); // tombstone newer than SSTable

        let all = db.scan(b"");
        let pairs: Vec<(&[u8], &[u8])> =
            all.iter().map(|i| (i.key.as_slice(), i.value.as_slice())).collect();
        assert_eq!(pairs, vec![(&b"a"[..], &b"1"[..]), (&b"b"[..], &b"22"[..])]);

        let between = db.range(b"b", b"c");
        let keys: Vec<&[u8]> = between.iter().map(|i| i.key.as_slice()).collect();
        assert_eq!(keys, vec![&b"b"[..]]);
    }

    #[test]
    fn batch_writes_are_visible_after_reopen() {
        let dir = TempDir::new().unwrap();
        {
            let mut db = Db::create_with(
                dir.path(),
                &weak_pass(),
                Argon2Params { m_cost_kib: 8 * 1024, t_cost: 1, parallelism: 1, _reserved: 0 },
                1024 * 1024,
            )
            .unwrap();
            db.batch(&[
                Op::Put { key: b"k1".to_vec(), value: b"v1".to_vec() },
                Op::Put { key: b"k2".to_vec(), value: b"v2".to_vec() },
                Op::Delete { key: b"k1".to_vec() },
            ])
            .unwrap();
            db.close().unwrap();
        }
        let db = Db::open(dir.path(), &weak_pass()).unwrap();
        assert_eq!(db.get(b"k1"), None);
        assert_eq!(db.get(b"k2"), Some(b"v2".to_vec()));
    }

    #[test]
    fn derive_subkey_is_stable_and_domain_separated() {
        let dir = TempDir::new().unwrap();
        let db = Db::create_with(
            dir.path(),
            &weak_pass(),
            Argon2Params { m_cost_kib: 8 * 1024, t_cost: 1, parallelism: 1, _reserved: 0 },
            1024 * 1024,
        )
        .unwrap();
        let a1 = db.derive_subkey(b"zb:auth:cap:sign");
        let a2 = db.derive_subkey(b"zb:auth:cap:sign");
        let b = db.derive_subkey(b"zb:auth:cap:other");
        use subtle::ConstantTimeEq;
        assert!(bool::from(a1.ct_eq(&a2)));
        assert!(!bool::from(a1.ct_eq(&b)));
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

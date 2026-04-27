//! In-memory table. A sorted map of `Vec<u8>` keys to [`Entry`] values.
//!
//! The MemTable is the hot path for writes: appends go to the WAL and then
//! land here. Reads check the MemTable first, then fall through to older
//! SSTables on disk.
//!
//! Memory safety: values live in an ordinary `BTreeMap`. Because Zerobase
//! stores user data (which may itself be secret), we keep per-entry bytes on
//! the heap and rely on the OS to swap-lock the whole process (via `mlockall`
//! configured by the engine). We do **not** try to zeroize every value on
//! eviction — that would be expensive and only mildly useful; the
//! authoritative secret-management story is encryption at rest.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Value stored for a key. A [`Tombstone`](Entry::Tombstone) shadows any older
/// value for the same key in older SSTables.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Entry {
    /// Live value.
    Value(Vec<u8>),
    /// Deletion marker. Carried through flushes so deletes survive restart.
    Tombstone,
}

/// Sorted in-memory map backing the write path.
#[derive(Debug, Default)]
pub struct MemTable {
    map: BTreeMap<Vec<u8>, Entry>,
    bytes: usize,
}

impl MemTable {
    /// A fresh empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or overwrite a key.
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        let new_bytes = key.len() + value.len();
        if let Some(old) = self.map.insert(key, Entry::Value(value)) {
            self.bytes = self.bytes.saturating_sub(Self::entry_bytes(&old));
        }
        self.bytes = self.bytes.saturating_add(new_bytes);
    }

    /// Insert a tombstone for `key`.
    pub fn delete(&mut self, key: Vec<u8>) {
        let new_bytes = key.len();
        if let Some(old) = self.map.insert(key, Entry::Tombstone) {
            self.bytes = self.bytes.saturating_sub(Self::entry_bytes(&old));
        }
        self.bytes = self.bytes.saturating_add(new_bytes);
    }

    /// Look up a key. Returns `Some(Tombstone)` if the key was deleted in
    /// this table — callers need to honor that and *not* look at older files.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<&Entry> {
        self.map.get(key)
    }

    /// Number of entries (values + tombstones).
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when no entries are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Rough in-memory footprint (keys + values). Used to decide when to flush.
    #[must_use]
    pub fn approx_bytes(&self) -> usize {
        self.bytes
    }

    /// Iterate entries in sorted key order. Used when flushing to an SSTable.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &Entry)> {
        self.map.iter().map(|(k, v)| (k.as_slice(), v))
    }

    /// Iterate entries in `[start, end)` in sorted key order. An empty `end`
    /// (`&[]`) means unbounded.
    pub fn range<'a>(
        &'a self,
        start: &'a [u8],
        end: &'a [u8],
    ) -> impl Iterator<Item = (&'a [u8], &'a Entry)> + 'a {
        use std::ops::Bound;
        let hi: Bound<&[u8]> = if end.is_empty() { Bound::Unbounded } else { Bound::Excluded(end) };
        self.map.range::<[u8], _>((Bound::Included(start), hi)).map(|(k, v)| (k.as_slice(), v))
    }

    fn entry_bytes(entry: &Entry) -> usize {
        match entry {
            Entry::Value(v) => v.len(),
            Entry::Tombstone => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_delete() {
        let mut m = MemTable::new();
        m.put(b"a".to_vec(), b"1".to_vec());
        m.put(b"b".to_vec(), b"2".to_vec());
        assert_eq!(m.get(b"a"), Some(&Entry::Value(b"1".to_vec())));

        m.delete(b"a".to_vec());
        assert_eq!(m.get(b"a"), Some(&Entry::Tombstone));
        assert_eq!(m.get(b"missing"), None);
    }

    #[test]
    fn range_respects_bounds() {
        let mut m = MemTable::new();
        for k in [b"a", b"b", b"c", b"d"] {
            m.put(k.to_vec(), b"x".to_vec());
        }
        let got: Vec<&[u8]> = m.range(b"b", b"d").map(|(k, _)| k).collect();
        assert_eq!(got, vec![&b"b"[..], &b"c"[..]]);
        let all: Vec<&[u8]> = m.range(b"", b"").map(|(k, _)| k).collect();
        assert_eq!(all, vec![&b"a"[..], &b"b"[..], &b"c"[..], &b"d"[..]]);
    }

    #[test]
    fn iter_is_sorted() {
        let mut m = MemTable::new();
        m.put(b"c".to_vec(), b"3".to_vec());
        m.put(b"a".to_vec(), b"1".to_vec());
        m.put(b"b".to_vec(), b"2".to_vec());
        let keys: Vec<&[u8]> = m.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec![&b"a"[..], &b"b"[..], &b"c"[..]]);
    }
}

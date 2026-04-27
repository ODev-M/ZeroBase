//! In-memory catalog backed by reserved KV keys (`sys/schema/...`).
//!
//! The catalog is loaded once at engine start and mutated only by DDL
//! statements running under the engine's exclusive write guard. Higher
//! layers must invalidate / reload through the engine — direct callers
//! shouldn't construct a `Catalog` outside of `SqlEngine`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zerobase::{wal::Op, Db};

use crate::error::{SqlError, SqlResult};
use crate::types::{ColumnMeta, SqlType};

const SCHEMA_PREFIX: &[u8] = b"sys/schema/";
const SCHEMA_LIST_KEY: &[u8] = b"sys/schema-list";

/// Persistent metadata for a table.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TableMeta {
    /// User-visible name.
    pub name: String,
    /// Columns in declaration order.
    pub columns: Vec<ColumnMeta>,
    /// Indices into `columns` that form the primary key (>= 1).
    pub primary_key: Vec<usize>,
    /// Secondary indexes declared on this table.
    pub indexes: Vec<IndexMeta>,
}

/// A secondary index over one or more columns.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexMeta {
    /// Index name (unique per table).
    pub name: String,
    /// Indices into the parent table's `columns`. The MVP supports
    /// single-column indexes only — kept as a vec for forward compat.
    pub columns: Vec<usize>,
}

impl TableMeta {
    /// Look up a column by name (case-sensitive, like the parser keeps it).
    pub fn column_index(&self, name: &str) -> SqlResult<usize> {
        self.columns.iter().position(|c| c.name == name).ok_or(SqlError::UnknownColumn)
    }

    /// Convenience accessor for the column type.
    pub fn column_type(&self, idx: usize) -> SqlType {
        self.columns[idx].ty
    }
}

/// In-memory catalog, mirroring `sys/schema/*` and `sys/schema-list`.
#[derive(Default, Debug)]
pub struct Catalog {
    tables: HashMap<String, TableMeta>,
}

impl Catalog {
    /// Load the catalog from a `Db`. Reads `sys/schema-list` (if present)
    /// and then materializes every named table.
    pub fn load(db: &Db) -> SqlResult<Self> {
        let mut tables = HashMap::new();
        if let Some(bytes) = db.get(SCHEMA_LIST_KEY) {
            let names: Vec<String> = bincode::deserialize(&bytes)?;
            for name in names {
                let key = schema_key(&name);
                if let Some(raw) = db.get(&key) {
                    let meta: TableMeta = bincode::deserialize(&raw)?;
                    tables.insert(meta.name.clone(), meta);
                }
            }
        }
        Ok(Self { tables })
    }

    /// Build the WAL ops needed to persist a `CREATE TABLE`. The caller
    /// drives `Db::batch(&ops)` and then calls `register_local` to update
    /// the in-memory cache atomically.
    pub fn create_table_ops(&self, db: &Db, meta: &TableMeta) -> SqlResult<Vec<Op>> {
        if self.tables.contains_key(&meta.name) {
            return Err(SqlError::SchemaMismatch);
        }

        let mut names: Vec<String> = self.tables.keys().cloned().collect();
        names.push(meta.name.clone());
        names.sort();

        // Sanity: persist the same view that load() will read back.
        let _ = db; // not used yet — kept to allow future read-modify-write checks
        Ok(vec![
            Op::Put { key: schema_key(&meta.name), value: bincode::serialize(meta)? },
            Op::Put { key: SCHEMA_LIST_KEY.to_vec(), value: bincode::serialize(&names)? },
        ])
    }

    /// Mirror of `create_table_ops` for the in-memory cache. Call only
    /// after `Db::batch` succeeds.
    pub fn register_local(&mut self, meta: TableMeta) {
        self.tables.insert(meta.name.clone(), meta);
    }

    /// Build the WAL op needed to persist an updated `TableMeta` (for
    /// adding an index, etc). The caller drives `Db::batch(&ops)`.
    pub fn update_table_op(&self, meta: &TableMeta) -> SqlResult<Op> {
        Ok(Op::Put { key: schema_key(&meta.name), value: bincode::serialize(meta)? })
    }

    /// Mirror of `update_table_op` for the in-memory cache. Call only
    /// after `Db::batch` succeeds.
    pub fn replace_local(&mut self, meta: TableMeta) {
        self.tables.insert(meta.name.clone(), meta);
    }

    /// Get a table by name.
    pub fn get(&self, name: &str) -> SqlResult<&TableMeta> {
        self.tables.get(name).ok_or(SqlError::UnknownTable)
    }

    /// Returns true if a table with this name exists.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.tables.contains_key(name)
    }

    /// Number of registered tables.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tables.len()
    }

    /// Convenience for tests / introspection.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tables.is_empty()
    }
}

fn schema_key(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(SCHEMA_PREFIX.len() + name.len());
    out.extend_from_slice(SCHEMA_PREFIX);
    out.extend_from_slice(name.as_bytes());
    out
}

/// Reject reserved or syntactically dangerous identifiers.
pub fn validate_table_name(name: &str) -> SqlResult<()> {
    if name.is_empty()
        || name.contains('/')
        || name.eq_ignore_ascii_case("sys")
        || name.to_ascii_lowercase().starts_with("sys")
        || name.to_ascii_lowercase().starts_with("tbl/")
    {
        return Err(SqlError::ReservedIdent);
    }
    Ok(())
}

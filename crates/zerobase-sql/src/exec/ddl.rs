//! DDL execution. CREATE TABLE persists schema + bumps `sys/schema-list`
//! atomically through a single `Db::batch` call. CREATE INDEX persists
//! the updated `TableMeta` and back-fills index entries for existing
//! rows in the same batch.

use zerobase::wal::Op;
use zerobase::Db;

use crate::catalog::{Catalog, IndexMeta, TableMeta};
use crate::codec;
use crate::error::SqlResult;
use crate::types::{Row, SqlOutput};

pub(super) fn create_table(
    meta: TableMeta,
    db: &mut Db,
    catalog: &mut Catalog,
) -> SqlResult<SqlOutput> {
    let ops = catalog.create_table_ops(db, &meta)?;
    db.batch(&ops)?;
    catalog.register_local(meta);
    Ok(SqlOutput::DdlOk)
}

pub(super) fn create_index(
    table: TableMeta,
    index: IndexMeta,
    db: &mut Db,
    catalog: &mut Catalog,
) -> SqlResult<SqlOutput> {
    let mut new_meta = table.clone();
    new_meta.indexes.push(index.clone());

    let mut ops: Vec<Op> = Vec::new();
    ops.push(catalog.update_table_op(&new_meta)?);

    // Back-fill: every existing row gets an index entry.
    let col_idx = index.columns[0];
    let col_name = &table.columns[col_idx].name;
    let prefix = codec::row_prefix(&table.name);
    for item in db.scan(&prefix) {
        let row: Row = bincode::deserialize(&item.value)?;
        let pk_refs: Vec<&_> = table.primary_key.iter().map(|i| &row[*i]).collect();
        let encoded_pk = codec::encode_pk(&pk_refs)?;
        let value_bytes = codec::encode_value_for_key(&row[col_idx])?;
        let key = codec::index_key(&table.name, col_name, &value_bytes, &encoded_pk);
        ops.push(Op::Put { key, value: Vec::new() });
    }

    db.batch(&ops)?;
    catalog.replace_local(new_meta);
    Ok(SqlOutput::DdlOk)
}

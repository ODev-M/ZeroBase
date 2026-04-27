//! DML execution. Week 2: INSERT. Week 3 adds UPDATE/DELETE.

use zerobase::wal::Op;
use zerobase::Db;

use super::expr::{eval, truthy};
use crate::catalog::TableMeta;
use crate::codec;
use crate::error::{SqlError, SqlResult};
use crate::parse::Expr;
use crate::plan::{VirtualColumn, VirtualSchema};
use crate::types::{Row, SqlOutput, Value};

pub(super) fn insert(table: &TableMeta, rows: Vec<Row>, db: &mut Db) -> SqlResult<SqlOutput> {
    let mut ops: Vec<Op> = Vec::with_capacity(rows.len());
    let affected = rows.len() as u64;

    for mut row in rows {
        // Coerce column-by-column into the declared type.
        for (val, col) in row.iter_mut().zip(table.columns.iter()) {
            let v = std::mem::replace(val, Value::Null);
            *val = codec::coerce(v, col.ty)?;
        }
        codec::validate_row(&row, &table.columns)?;

        // Reject NULLs in PK columns.
        let pk_refs: Vec<&Value> = table.primary_key.iter().map(|i| &row[*i]).collect();
        if pk_refs.iter().any(|v| matches!(v, Value::Null)) {
            return Err(SqlError::Constraint);
        }
        let encoded_pk = codec::encode_pk(&pk_refs)?;
        let key = codec::row_key(&table.name, &encoded_pk);

        // Uniqueness check on PK. Ignores values pending in `ops` of this
        // same batch — duplicate PKs in a single INSERT are rejected here
        // because we do a get-then-write under the same write lock.
        if db.get(&key).is_some() {
            return Err(SqlError::Constraint);
        }

        let payload = bincode::serialize(&row)?;
        ops.push(Op::Put { key, value: payload });

        // Add an entry to each declared secondary index.
        for idx in &table.indexes {
            let col_idx = idx.columns[0];
            let value_bytes = codec::encode_value_for_key(&row[col_idx])?;
            let ikey = codec::index_key(
                &table.name,
                &table.columns[col_idx].name,
                &value_bytes,
                &encoded_pk,
            );
            ops.push(Op::Put { key: ikey, value: Vec::new() });
        }
    }

    db.batch(&ops)?;
    Ok(SqlOutput::Affected(affected))
}

pub(super) fn delete(
    table: &TableMeta,
    filter: Option<Expr>,
    db: &mut Db,
) -> SqlResult<SqlOutput> {
    let schema = table_schema(table);
    let prefix = codec::row_prefix(&table.name);
    let mut ops: Vec<Op> = Vec::new();

    let mut affected: u64 = 0;
    for item in db.scan(&prefix) {
        let row: Row = bincode::deserialize(&item.value)?;
        if let Some(f) = &filter {
            if !truthy(&eval(f, &row, &schema)?) {
                continue;
            }
        }
        for ikey in index_keys_for_row(table, &row)? {
            ops.push(Op::Delete { key: ikey });
        }
        ops.push(Op::Delete { key: item.key });
        affected += 1;
    }

    db.batch(&ops)?;
    Ok(SqlOutput::Affected(affected))
}

pub(super) fn update(
    table: &TableMeta,
    filter: Option<Expr>,
    assignments: Vec<(usize, Expr)>,
    db: &mut Db,
) -> SqlResult<SqlOutput> {
    let schema = table_schema(table);
    let prefix = codec::row_prefix(&table.name);
    let mut ops: Vec<Op> = Vec::new();
    let mut affected: u64 = 0;

    for item in db.scan(&prefix) {
        let row: Row = bincode::deserialize(&item.value)?;
        if let Some(f) = &filter {
            if !truthy(&eval(f, &row, &schema)?) {
                continue;
            }
        }

        let mut new_row = row.clone();
        for (idx, e) in &assignments {
            let v = eval(e, &row, &schema)?;
            new_row[*idx] = codec::coerce(v, table.columns[*idx].ty)?;
        }
        codec::validate_row(&new_row, &table.columns)?;

        // Refresh secondary index entries: drop old, insert new. PK is
        // immutable (planner rejects PK assignment) so the row key is
        // stable and we don't touch the primary record's identity.
        for ikey in index_keys_for_row(table, &row)? {
            ops.push(Op::Delete { key: ikey });
        }
        for ikey in index_keys_for_row(table, &new_row)? {
            ops.push(Op::Put { key: ikey, value: Vec::new() });
        }

        let payload = bincode::serialize(&new_row)?;
        ops.push(Op::Put { key: item.key, value: payload });
        affected += 1;
    }

    db.batch(&ops)?;
    Ok(SqlOutput::Affected(affected))
}

fn index_keys_for_row(table: &TableMeta, row: &Row) -> SqlResult<Vec<Vec<u8>>> {
    if table.indexes.is_empty() {
        return Ok(Vec::new());
    }
    let pk_refs: Vec<&Value> = table.primary_key.iter().map(|i| &row[*i]).collect();
    let encoded_pk = codec::encode_pk(&pk_refs)?;
    let mut out = Vec::with_capacity(table.indexes.len());
    for idx in &table.indexes {
        let col_idx = idx.columns[0];
        let value_bytes = codec::encode_value_for_key(&row[col_idx])?;
        out.push(codec::index_key(
            &table.name,
            &table.columns[col_idx].name,
            &value_bytes,
            &encoded_pk,
        ));
    }
    Ok(out)
}

fn table_schema(table: &TableMeta) -> VirtualSchema {
    VirtualSchema {
        columns: table
            .columns
            .iter()
            .map(|c| VirtualColumn { qualifier: table.name.clone(), meta: c.clone() })
            .collect(),
    }
}

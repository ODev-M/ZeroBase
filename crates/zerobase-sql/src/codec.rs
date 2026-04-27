//! Encoders for primary keys, index keys, and row payloads.
//!
//! See `docs/KEYSPACE.md` for the full layout. The TL;DR:
//!
//! * Composite PKs: `be_u32(col_count) || foreach { be_u32(len) || bytes }`.
//! * Integers in keys: BE bytes with the sign bit XORed (so negatives sort
//!   before positives lexicographically).
//! * Floats in keys: total-order encoding (sign-flip positives, complement
//!   negatives) so byte-compare matches numeric order.
//! * Index keys append a `0x00` separator before the row's PK bytes to
//!   avoid prefix ambiguity (`"abc"` vs `"abcd"`).

use crate::error::{SqlError, SqlResult};
use crate::types::{Row, SqlType, Value};

/// Encode an integer column for use inside a key.
#[must_use]
pub fn encode_i64_for_key(v: i64) -> [u8; 8] {
    let mut b = v.to_be_bytes();
    b[0] ^= 0x80;
    b
}

/// Encode an `f64` column for use inside a key. Produces a total-order
/// encoding so `[u8] cmp` matches IEEE-754 magnitude order.
#[must_use]
pub fn encode_f64_for_key(v: f64) -> [u8; 8] {
    let bits = v.to_bits();
    let mut b = bits.to_be_bytes();
    if b[0] & 0x80 == 0 {
        // Non-negative: flip sign bit so it sorts after negatives.
        b[0] ^= 0x80;
    } else {
        // Negative: complement everything (closer to zero ⇒ greater).
        for x in &mut b {
            *x = !*x;
        }
    }
    b
}

/// Encode a single value as the bytes that will go into a key. Used for
/// both PK columns and index column values.
pub fn encode_value_for_key(v: &Value) -> SqlResult<Vec<u8>> {
    match v {
        Value::Null => Err(SqlError::Constraint), // NULLs are not allowed in keys
        Value::Bool(b) => Ok(vec![u8::from(*b)]),
        Value::Int64(i) => Ok(encode_i64_for_key(*i).to_vec()),
        Value::F64(f) => Ok(encode_f64_for_key(*f).to_vec()),
        Value::Text(s) => Ok(s.as_bytes().to_vec()),
        Value::Blob(b) => Ok(b.clone()),
    }
}

/// Encode a primary key tuple. The encoding is self-delimiting so that
/// `Db::scan(prefix)` cannot accidentally cross PK boundaries.
pub fn encode_pk(pk_values: &[&Value]) -> SqlResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&(pk_values.len() as u32).to_be_bytes());
    for v in pk_values {
        let bytes = encode_value_for_key(v)?;
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

/// Build the full row key: `tbl/<table>/row/<encoded-pk>`.
pub fn row_key(table: &str, encoded_pk: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(table.len() + encoded_pk.len() + 9);
    out.extend_from_slice(b"tbl/");
    out.extend_from_slice(table.as_bytes());
    out.extend_from_slice(b"/row/");
    out.extend_from_slice(encoded_pk);
    out
}

/// Build a row prefix for a full-table scan: `tbl/<table>/row/`.
#[must_use]
pub fn row_prefix(table: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(table.len() + 9);
    out.extend_from_slice(b"tbl/");
    out.extend_from_slice(table.as_bytes());
    out.extend_from_slice(b"/row/");
    out
}

/// Build an index key: `tbl/<table>/idx/<col>/<encoded-value>\x00<encoded-pk>`.
pub fn index_key(table: &str, column: &str, value_bytes: &[u8], encoded_pk: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(table.len() + column.len() + value_bytes.len() + 16);
    out.extend_from_slice(b"tbl/");
    out.extend_from_slice(table.as_bytes());
    out.extend_from_slice(b"/idx/");
    out.extend_from_slice(column.as_bytes());
    out.push(b'/');
    out.extend_from_slice(value_bytes);
    out.push(0x00);
    out.extend_from_slice(encoded_pk);
    out
}

/// Build an index lookup prefix: `tbl/<t>/idx/<col>/<v>\x00`.
#[must_use]
pub fn index_lookup_prefix(table: &str, column: &str, value_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(table.len() + column.len() + value_bytes.len() + 16);
    out.extend_from_slice(b"tbl/");
    out.extend_from_slice(table.as_bytes());
    out.extend_from_slice(b"/idx/");
    out.extend_from_slice(column.as_bytes());
    out.push(b'/');
    out.extend_from_slice(value_bytes);
    out.push(0x00);
    out
}

/// Coerce a raw `Value` to match a declared `SqlType`. Returns
/// `SchemaMismatch` if the conversion would change the value's category.
pub fn coerce(value: Value, ty: SqlType) -> SqlResult<Value> {
    use SqlType as T;
    use Value as V;
    Ok(match (value, ty) {
        (V::Null, _) => V::Null,
        (V::Bool(b), T::Bool) => V::Bool(b),
        (V::Int64(i), T::Int) | (V::Int64(i), T::BigInt) => V::Int64(i),
        (V::F64(f), T::Double) => V::F64(f),
        (V::Text(s), T::Text) => V::Text(s),
        (V::Blob(b), T::Blob) => V::Blob(b),
        // Light coercions: text → text, ints fit into doubles, etc.
        (V::Int64(i), T::Double) => V::F64(i as f64),
        _ => return Err(SqlError::SchemaMismatch),
    })
}

/// Validate that a row matches a column list. Used by `INSERT`.
pub fn validate_row(row: &Row, columns: &[crate::types::ColumnMeta]) -> SqlResult<()> {
    if row.len() != columns.len() {
        return Err(SqlError::SchemaMismatch);
    }
    for (v, c) in row.iter().zip(columns.iter()) {
        if v.is_null() && c.not_null {
            return Err(SqlError::Constraint);
        }
        if !v.is_null() {
            // Cheap structural check; full coerce happens at INSERT time.
            match (c.ty, v) {
                (SqlType::Bool, Value::Bool(_))
                | (SqlType::Int, Value::Int64(_))
                | (SqlType::BigInt, Value::Int64(_))
                | (SqlType::Double, Value::F64(_) | Value::Int64(_))
                | (SqlType::Text, Value::Text(_))
                | (SqlType::Blob, Value::Blob(_)) => {}
                _ => return Err(SqlError::SchemaMismatch),
            }
        }
    }
    Ok(())
}

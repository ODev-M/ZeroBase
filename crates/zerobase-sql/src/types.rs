//! Value, type, and row representations for the SQL layer.

use serde::{Deserialize, Serialize};

/// A SQL scalar value. Stored on disk as bincode and on the wire as a
/// `RowWire` (defined in `zerobase-proto`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Value {
    /// SQL NULL.
    Null,
    /// Boolean.
    Bool(bool),
    /// 64-bit signed integer. Covers INT and BIGINT.
    Int64(i64),
    /// 64-bit IEEE-754 float.
    F64(f64),
    /// UTF-8 string.
    Text(String),
    /// Opaque byte string.
    Blob(Vec<u8>),
}

impl Value {
    /// Returns `true` if this value is SQL `NULL`.
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Best-effort type tag for diagnostics.
    #[must_use]
    pub fn sql_type_tag(&self) -> Option<SqlType> {
        match self {
            Value::Null => None,
            Value::Bool(_) => Some(SqlType::Bool),
            Value::Int64(_) => Some(SqlType::BigInt),
            Value::F64(_) => Some(SqlType::Double),
            Value::Text(_) => Some(SqlType::Text),
            Value::Blob(_) => Some(SqlType::Blob),
        }
    }
}

/// A row is an ordered list of values, one per column in the table's
/// declared order. Both on-disk rows and executor rows share this shape.
pub type Row = Vec<Value>;

/// SQL types supported by ZeroBase. `Int` and `BigInt` are aliased to
/// `Int64` at runtime; we keep the distinction in the schema only.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SqlType {
    /// `BOOL`.
    Bool,
    /// `INT` (32-bit logical, stored as i64).
    Int,
    /// `BIGINT` (64-bit signed).
    BigInt,
    /// `DOUBLE` / `FLOAT`.
    Double,
    /// `TEXT` / `VARCHAR` (UTF-8).
    Text,
    /// `BLOB` / `BYTEA`.
    Blob,
}

/// Schema description of one column.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ColumnMeta {
    /// Column name (case-preserved as written in `CREATE TABLE`).
    pub name: String,
    /// Declared SQL type.
    pub ty: SqlType,
    /// Whether the column rejects NULL.
    pub not_null: bool,
}

/// Aggregate function kind. Week 3 supports the SQL-92 set without
/// `DISTINCT` (that's a week-4 follow-up).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AggregateFn {
    /// `COUNT(*)` — counts every group row.
    CountStar,
    /// `COUNT(expr)` — counts non-null evaluations of `expr`.
    Count,
    /// `SUM(expr)` over numeric values.
    Sum,
    /// `AVG(expr)` over numeric values.
    Avg,
    /// `MIN(expr)` — order-comparable values.
    Min,
    /// `MAX(expr)` — order-comparable values.
    Max,
}

/// What `SqlEngine::execute` returns to the caller.
#[derive(Debug)]
pub enum SqlOutput {
    /// `SELECT` result: row stream plus column metadata.
    Rows {
        /// Column metadata in projection order.
        columns: Vec<ColumnMeta>,
        /// Materialized rows.
        rows: Vec<Row>,
    },
    /// `INSERT`/`UPDATE`/`DELETE`: number of rows affected.
    Affected(u64),
    /// `CREATE TABLE` / `CREATE INDEX`: success without rows.
    DdlOk,
}

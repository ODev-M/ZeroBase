//! Errors raised by the SQL layer.
//!
//! On the wire the server collapses every variant into an opaque
//! `ErrorCode` (see `zerobase-proto`). Inside the process we keep richer
//! variants because they help tests and logging. Display impls deliberately
//! avoid echoing user-supplied SQL.

use thiserror::Error;

/// Result alias used across the SQL crate.
pub type SqlResult<T> = std::result::Result<T, SqlError>;

/// All errors produced by the SQL layer.
#[derive(Debug, Error)]
pub enum SqlError {
    /// Parser rejected the input.
    #[error("sql parse error")]
    Parse,

    /// AST contained a feature that ZeroBase does not implement.
    #[error("sql feature not supported: {0}")]
    Unsupported(&'static str),

    /// Reference to a table that does not exist in the catalog.
    #[error("table not found")]
    UnknownTable,

    /// Reference to a column that does not exist on the resolved table.
    #[error("column not found")]
    UnknownColumn,

    /// Mismatched column count or type at INSERT/UPDATE time.
    #[error("schema mismatch")]
    SchemaMismatch,

    /// A NOT NULL column got NULL, or a primary-key uniqueness check failed.
    #[error("constraint violation")]
    Constraint,

    /// Statement targeted a table outside the bound capability scope.
    #[error("out of scope")]
    OutOfScope,

    /// Reserved name (e.g. starts with `sys`) used as a user table name.
    #[error("reserved identifier")]
    ReservedIdent,

    /// I/O or encoding error from the storage layer.
    #[error(transparent)]
    Engine(#[from] zerobase::Error),

    /// Bincode failure, kept opaque.
    #[error("encoding")]
    Encoding,
}

impl From<bincode::Error> for SqlError {
    fn from(_: bincode::Error) -> Self {
        SqlError::Encoding
    }
}

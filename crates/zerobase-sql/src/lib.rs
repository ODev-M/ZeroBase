//! SQL layer for ZeroBase.
//!
//! Wraps the byte-opaque `Db` from `zerobase-core` with a relational front
//! end: parser, rule-based planner, and pull-based executor. The on-disk
//! layout follows `docs/KEYSPACE.md` — every table, row, and index lives in
//! the same encrypted KV store under reserved key prefixes.
//!
//! Scope (MVP, week 2 deliverable): `CREATE TABLE`, `INSERT`,
//! `SELECT ... [WHERE]`. Week 3 adds `JOIN`, `GROUP BY`, `ORDER BY`,
//! `CREATE INDEX`, `UPDATE`, `DELETE`.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod catalog;
pub mod codec;
pub mod engine;
pub mod error;
pub mod exec;
pub mod parse;
pub mod plan;
pub mod types;

pub use engine::SqlEngine;
pub use error::{SqlError, SqlResult};
pub use types::{ColumnMeta, Row, SqlOutput, SqlType, Value};

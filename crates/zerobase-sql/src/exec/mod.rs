//! Pull-based executor. Each operator is a small struct with a `next()`
//! method. The top-level `run` function takes a planned `Plan` and a `&mut
//! Db` (held under the engine's exclusive write guard for DML, shared read
//! guard for SELECT) and produces a `SqlOutput`.

mod ddl;
mod dml;
mod expr;
mod scan;

use zerobase::Db;

use crate::catalog::Catalog;
use crate::error::SqlResult;
use crate::plan::Plan;
use crate::types::SqlOutput;

/// Execute a planned statement.
///
/// Catalog mutations (DDL) are applied to `catalog` after the underlying
/// `Db::batch` succeeds, so on-disk and in-memory state stay in sync.
pub fn run(plan: Plan, db: &mut Db, catalog: &mut Catalog) -> SqlResult<SqlOutput> {
    match plan {
        Plan::CreateTable(meta) => ddl::create_table(meta, db, catalog),
        Plan::Insert { table, rows } => dml::insert(&table, rows, db),
        Plan::Query(q) => scan::run_select(q, db),
        // Week-3 surface parsed but not yet executed. The parser/planner
        // accept these so tests can exercise the front end; the executor
        // refuses loudly until the corresponding milestones land.
        Plan::CreateIndex { table, index } => ddl::create_index(table, index, db, catalog),
        Plan::Update { table, filter, assignments } => dml::update(&table, filter, assignments, db),
        Plan::Delete { table, filter } => dml::delete(&table, filter, db),
    }
}

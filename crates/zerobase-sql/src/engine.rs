//! Top-level façade. `SqlEngine` ties parser → planner → executor together,
//! caches the catalog, and exposes a single `execute(sql)` entry point.

use zerobase::Db;

use crate::catalog::Catalog;
use crate::error::SqlResult;
use crate::types::SqlOutput;
use crate::{exec, parse, plan};

/// Stateful façade owning a catalog cache. Constructed once per server
/// startup; mutated only under the engine's exclusive write guard.
pub struct SqlEngine {
    catalog: Catalog,
}

impl SqlEngine {
    /// Open the SQL engine on top of an existing `Db`. Loads the catalog
    /// from `sys/schema-list`.
    pub fn open(db: &Db) -> SqlResult<Self> {
        Ok(Self { catalog: Catalog::load(db)? })
    }

    /// Read-only access to the loaded catalog.
    #[must_use]
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// Parse, plan, and execute a single SQL statement.
    pub fn execute(&mut self, sql: &str, db: &mut Db) -> SqlResult<SqlOutput> {
        let stmt = parse::parse(sql)?;
        let p = plan::plan(stmt, &self.catalog)?;
        exec::run(p, db, &mut self.catalog)
    }
}

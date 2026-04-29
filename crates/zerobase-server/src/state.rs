//! Shared server state.
//!
//! `Db` and `SqlEngine` are not internally `Send + Sync`, so we serialise
//! all data-plane access through a single `Mutex`. v1 trades raw concurrency
//! for simplicity — the engine itself buffers writes in-memory, so a
//! single-writer model is fine for the first daemon iteration.

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use secrecy::SecretString;
use zerobase::Db;
use zerobase_auth::{Identity, PublicIdentity};
use zerobase_sql::SqlEngine;

pub struct ServerState {
    #[allow(dead_code)]
    pub identity: Identity,
    pub trusted_issuers: Vec<PublicIdentity>,
    pub data: Mutex<DataPlane>,
}

/// Mutex-guarded bundle: the SQL engine borrows the `Db` mutably on every
/// `execute`, so they share one lock.
pub struct DataPlane {
    pub db: Db,
    pub sql: SqlEngine,
}

impl ServerState {
    pub fn new(identity: Identity, root: &Path, passphrase: SecretString) -> Result<Arc<Self>> {
        let db = Db::open(root, &passphrase).context("opening Zerobase store")?;
        let sql = SqlEngine::open(&db).context("opening SQL catalog")?;
        let public = identity.public().clone();
        Ok(Arc::new(Self {
            identity,
            trusted_issuers: vec![public],
            data: Mutex::new(DataPlane { db, sql }),
        }))
    }
}

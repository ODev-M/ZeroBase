//! CLI / runtime configuration for `zerobased`.

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "zerobased", about = "Zerobase daemon (TCP listener)")]
pub struct Cli {
    /// Address to listen on (e.g. `127.0.0.1:7878` or `0.0.0.0:7878`).
    #[arg(long, default_value = "127.0.0.1:7878", env = "ZB_LISTEN")]
    pub listen: String,

    /// Root directory of the Zerobase data store. Must already be initialized
    /// via the `zerobase` CLI.
    #[arg(long, env = "ZB_ROOT")]
    pub root: PathBuf,

    /// Passphrase used to unlock the data store (Argon2id-derived key).
    #[arg(long, env = "ZB_PASSPHRASE")]
    pub passphrase: String,

    /// Path to the server's identity file: 32 raw bytes of Ed25519 secret seed.
    /// If missing, a fresh one is generated and written.
    #[arg(long, env = "ZB_IDENTITY")]
    pub identity: PathBuf,
}

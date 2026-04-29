//! `zerobased` — Zerobase daemon entry point.
//!
//! ```text
//! TCP listener (sync, thread-per-conn) ──▶ session::handle
//!     ├─ HandshakeHello + signed challenge → identity proven
//!     ├─ Capabilities validated against server's trusted-issuer set
//!     └─ Kv / Sql commands enforced against the granted scope set
//! ```
//!
//! v1 ships unencrypted on the wire; the existing zerobase-auth handshake
//! pins identity, and capabilities are signature-bound to claims, so a MITM
//! cannot impersonate a client. TLS is intentionally deferred to a later
//! milestone.

#![forbid(unsafe_code)]

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use zerobase_server::config::Cli;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .init();

    let cli = Cli::parse();
    info!(addr = %cli.listen, root = %cli.root.display(), "starting zerobased");
    zerobase_server::run(cli)
}

//! TCP listener: accept loop + per-connection thread.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rand::RngCore;
use secrecy::SecretString;
use tracing::{error, info, warn};
use zerobase_auth::Identity;

use crate::config::Cli;
use crate::session;
use crate::state::ServerState;

pub fn run(cli: Cli) -> Result<()> {
    let identity = load_or_create_identity(&cli.identity)
        .with_context(|| format!("loading identity {}", cli.identity.display()))?;
    info!(id = %hex::encode(identity.id()), "server identity ready");

    let passphrase = SecretString::new(cli.passphrase.into());
    let state = ServerState::new(identity, &cli.root, passphrase)?;

    let listener = TcpListener::bind(&cli.listen)
        .with_context(|| format!("bind {}", cli.listen))?;
    info!(addr = %cli.listen, "listening");
    serve(state, listener)
}

/// Drive an existing listener with the given shared state. Blocks until the
/// listener errors fatally. Used by integration tests with an ephemeral port.
pub fn serve(state: Arc<ServerState>, listener: TcpListener) -> Result<()> {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        let peer = stream.peer_addr().ok();
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            if let Err(e) = session::handle(state, stream) {
                error!(?peer, error = %e, "session ended with error");
            }
        });
    }
    Ok(())
}

/// Load a 32-byte Ed25519 secret seed from disk, or generate one and persist
/// it with mode `0600` if missing.
fn load_or_create_identity(path: &Path) -> Result<Identity> {
    if path.exists() {
        let mut f = std::fs::File::open(path)?;
        let mut buf = [0u8; 32];
        f.read_exact(&mut buf).context("identity file must be exactly 32 bytes")?;
        Ok(Identity::from_secret(buf))
    } else {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let mut opts = OpenOptions::new();
        opts.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(path)?;
        f.write_all(&seed)?;
        f.sync_all()?;
        info!(path = %path.display(), "generated new server identity");
        Ok(Identity::from_secret(seed))
    }
}

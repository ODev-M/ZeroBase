# Zerobase quickstart

Run the daemon, talk to it from Rust. End-to-end in under five minutes.

## 1. Build

```bash
cargo build --release --workspace
```

That produces three binaries you'll care about:

* `target/release/zerobase` — the local CLI for offline data work.
* `target/release/zerobased` — the network daemon.
* the `zerobase-client` library, used from your own code.

## 2. Initialise a store

```bash
mkdir -p /var/lib/zerobase
target/release/zerobase init --root /var/lib/zerobase
# Argon2id-derives the master key from your passphrase.
```

## 3. Run the daemon

```bash
target/release/zerobased \
  --listen 127.0.0.1:7878 \
  --root /var/lib/zerobase \
  --passphrase "your-passphrase" \
  --identity /var/lib/zerobase/server.key
```

If `server.key` doesn't exist, `zerobased` generates a fresh 32-byte Ed25519
seed and writes it with mode `0600`. Don't lose it: every capability the
server issues is signed by that key, and rotating it invalidates them all.

`ZB_LISTEN`, `ZB_ROOT`, `ZB_PASSPHRASE` and `ZB_IDENTITY` work as drop-in
replacements for the equivalent flags.

## 4. Connect from Rust

```rust
use zerobase_auth::Identity;
use zerobase_caps::{Capability, CapabilityClaims, Scope};
use zerobase_client::Client;

let client_identity = Identity::generate();

// Self-capability conveys our pubkey to the server in a signature-bound
// way. Read the protocol doc for why this exists.
let self_cap = Capability::issue(
    &client_identity,
    CapabilityClaims {
        subject: client_identity.public().id,
        scope: Scope::KvRead { prefix: vec![] },
        expires_at: now() + 300,
    },
)?;

// In real deployments the *server* mints this and hands it back over an
// out-of-band channel. For local testing, copy the server identity into
// the test harness and issue caps from there.
let write_cap = Capability::issue(
    &server_identity_copy,
    CapabilityClaims {
        subject: client_identity.public().id,
        scope: Scope::KvWrite { prefix: b"app/".to_vec() },
        expires_at: now() + 300,
    },
)?;

let mut client = Client::connect(
    "127.0.0.1:7878",
    &client_identity,
    vec![self_cap, write_cap],
)?;

client.kv_put(b"app/hello", b"world")?;
let value = client.kv_get(b"app/hello")?;
assert_eq!(value.as_deref(), Some(b"world".as_slice()));
client.bye()?;
```

## 5. SQL

```rust
client.sql("CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT)")?;
client.sql("INSERT INTO users (id, name) VALUES (1, 'alice')")?;
match client.sql("SELECT id, name FROM users")? {
    SqlResult::Rows { columns, rows } => { /* … */ }
    other => panic!("unexpected: {other:?}"),
}
```

You need a `Scope::SqlRead { table }` or `Scope::SqlWrite { table }` for
any SQL to be accepted. The engine itself does per-table enforcement via
the catalog; the daemon's edge check only ensures the session has *some*
SQL grant.

## 6. Production checklist (v1)

* Run behind a tunnel (WireGuard / ssh) — v1 is plaintext on the wire.
* Keep `server.key` on a fast local disk with mode `0600`.
* Issue capabilities with short `expires_at` windows (minutes-to-hours).
  Revocation = rotate the server identity and re-issue.
* Add a systemd unit so the daemon survives reboots:

```ini
[Unit]
Description=Zerobase daemon
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/zerobase/env
ExecStart=/usr/local/bin/zerobased
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/zerobase
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

`/etc/zerobase/env` then sets `ZB_*` variables.

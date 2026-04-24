# Zerobase

> A **zero-trust, encrypted key-value store** written in Rust.

Zerobase treats the disk as an adversary. Every byte it writes is sealed with
AES-256-GCM, every log entry is signed with Ed25519, and every SSTable is
Merkle-rooted so a single tampered bit anywhere in the database is caught on
read. Secret material in memory implements `zeroize`, and every compare
touching secrets is constant-time.

```
┌────────────────────────────────────────────────────────────────┐
│                         Zerobase Engine                        │
│                                                                │
│    ┌────────┐   ┌───────────────┐   ┌───────────────────────┐  │
│    │   CLI  ├──▶│   MemTable    ├──▶│  SSTables (AES+Merkle)│  │
│    └────────┘   └──────┬────────┘   └───────────────────────┘  │
│                        │                                       │
│                        ▼                                       │
│                 ┌─────────────────┐    ┌─────────────────┐     │
│                 │   WAL (Ed25519  │    │    Keyring      │     │
│                 │    signed,      │    │  (Argon2id +    │     │
│                 │    AES-GCM)     │    │   master key)   │     │
│                 └─────────────────┘    └─────────────────┘     │
└────────────────────────────────────────────────────────────────┘
```

## Why it's interesting

* **Authenticated everywhere.** Every persisted byte is covered by either
  AEAD, an Ed25519 signature, or both. Bit-flips, truncation, swaps — all
  caught at read time.
* **Chain-of-custody WAL.** Each WAL frame embeds the hash of the previous
  frame. A reordered or dropped entry breaks replay.
* **Merkle-rooted SSTables.** Per-entry keyed-BLAKE3 leaves; whole-file swap
  is detected even if the attacker keeps the AEAD consistent.
* **Argon2id KDF.** 256 MiB × 3 passes by default; parameters stored in the
  keyring so we can strengthen them without breaking existing databases.
* **`#![forbid(unsafe_code)]`** across the codebase. No `unsafe` blocks.
* **Zero-trust defaults.** Database files live at `0600`. Passphrases read
  from a TTY (no echo) or from a dedicated env var, never from argv.

## Quick start

```bash
# Install Rust, then:
git clone https://github.com/ODev-M/zerobase
cd zerobase
cargo build --release

# Create a DB
./target/release/zerobase --db mydb.zbdb init
# -> prompts for passphrase

# Store a value
./target/release/zerobase --db mydb.zbdb put secret "hello zero-trust"

# Fetch it
./target/release/zerobase --db mydb.zbdb get secret
# -> hello zero-trust

# Delete it
./target/release/zerobase --db mydb.zbdb del secret
```

Non-interactive use: set `ZEROBASE_PASSPHRASE` in the environment.

## Library

```rust
use secrecy::SecretString;
use zerobase::Db;

let pass = SecretString::new("correct horse battery staple".into());
let mut db = Db::create("/var/lib/mydb", &pass)?;
db.put("user:42", r#"{"name":"Alice"}"#)?;
assert_eq!(db.get(b"user:42").as_deref(), Some(&b"{\"name\":\"Alice\"}"[..]));
db.close()?;
```

## Cryptography

| Primitive   | Use                                              |
|-------------|--------------------------------------------------|
| AES-256-GCM | AEAD for WAL, SSTables, manifest, sealed keyring |
| Ed25519     | Per-frame signatures on the WAL                  |
| Argon2id    | KDF for the passphrase-derived master key        |
| BLAKE3      | Keyed MAC for Merkle leaves + sub-key derivation |

Nonces are 12 bytes = **4-byte domain prefix || 8-byte counter**. Domains
partition WAL / SSTable / keyring / manifest so a counter overflow can never
produce colliding `(key, nonce)` tuples across subsystems.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full threat model
and [`SECURITY.md`](SECURITY.md) for how to report vulnerabilities.

## Status

**Pre-alpha.** The API and on-disk format are unstable until v1.0. Do not use
for production data you cannot afford to lose. Zerobase has not been
externally audited.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).

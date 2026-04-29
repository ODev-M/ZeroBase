# Zerobase wire protocol (v1)

This document describes how `zerobased` and its clients talk over TCP.
`zerobase-proto`, `zerobase-server` and `zerobase-client` all implement
exactly what's written here — if they disagree, the code wins and this
file is the bug.

## Framing

Every message is a single length-prefixed bincode payload:

```
+---------------------+--------------------------------+
| 4-byte big-endian   | bincode-encoded payload bytes  |
| payload length      | (Request or Response)          |
+---------------------+--------------------------------+
```

* `length` is a `u32` in network byte order.
* Maximum payload size is `MAX_FRAME_BYTES` (8 MiB). A peer claiming more
  is dropped with `ProtoError::FrameTooLarge`.
* No multiplexing, no streaming: one request always elicits exactly one
  response, in declaration order.

## Lifecycle

```
client                                  server
   │                                       │
   │── HandshakeHello ────────────────────▶│
   │                                       │
   │◀──────────────── HandshakeChallenge ──│
   │                                       │
   │── HandshakeProof ────────────────────▶│
   │                                       │
   │◀──────────────────── HandshakeAck ────│
   │                                       │
   │   Kv / Sql commands, in any order     │
   │                                       │
   │── Bye ───────────────────────────────▶│
   │                                       │
   │◀──────────────────────── Goodbye ─────│
```

Once authenticated, the server enforces capability scopes on every Kv/Sql
request before touching the engine.

## Handshake details

1. **`HandshakeHello`** — `{ identity_id, protocol_version }`. The server
   picks the minimum supported version or returns `Error { code: 505 }` if
   no version is mutually understood. v1 only knows version 1.

2. **`HandshakeChallenge`** — a 32-byte `Challenge { nonce }` generated
   from the OS RNG.

3. **`HandshakeProof`** — `{ signed: SignedChallenge, capabilities: Vec<Capability> }`.
   `signed` is a detached Ed25519 signature over `b"zb-auth-v1|" || nonce`.
   The server's verification chain is:

   * Pull a **self-capability** (one whose `issuer.id == subject == identity_id`)
     out of the presented list. Its `issuer.public_key` is the client's
     pubkey, conveyed in a way that's signature-bound to the cap claims.
   * Verify `BLAKE3(public_key) == identity_id`.
   * Verify `signed.signature` against that pubkey.
   * Walk every other capability: if the issuer is in the server's
     `trusted_issuers` list, the cap signature is valid, the subject equals
     `identity_id`, and `expires_at > now`, the scope is added to the
     session's grants. Anything else is silently ignored.

4. **`HandshakeAck`** — `{ protocol_version, granted: Vec<Scope> }`.
   `granted` is the union of scopes the server accepted; the client now
   knows what it can do without round-tripping.

A client that presents only a self-cap authenticates but receives an empty
grant set, so every subsequent Kv/Sql command will return `Error { code: 403 }`.

## Capabilities

```rust
struct Capability {
    claims: CapabilityClaims { subject, scope, expires_at },
    issuer: PublicIdentity,
    signature: [u8; 64],
}

enum Scope {
    KvRead { prefix: Vec<u8> },
    KvWrite { prefix: Vec<u8> },
    SqlRead { table: String },
    SqlWrite { table: String },
}
```

* Caps are signed over `b"zb-cap-v1|" || bincode(claims)`. Tampering with
  any field invalidates the signature.
* `KvWrite` implies `KvRead` over the same prefix. `SqlWrite` implies
  `SqlRead` over the same table.
* Prefixes match by `starts_with`; tables match by exact string equality.

## Commands

### KV

| Request                                | Response                |
|----------------------------------------|-------------------------|
| `Kv(Get { key })`                      | `Kv(Value(Option<Vec<u8>>))` |
| `Kv(Put { key, value })`               | `Kv(Ack)`               |
| `Kv(Delete { key })`                   | `Kv(Ack)`               |
| `Kv(Scan { prefix, limit: Option<u32> })` | `Kv(Items(Vec<(K,V)>))` |

Every variant is checked against the granted scope set. The exact scope
required is:

* `Get` / `Scan`: `KvRead { prefix: <the requested key or prefix> }`
* `Put` / `Delete`: `KvWrite { prefix: <the key> }`

### SQL

| Request                              | Response                                          |
|--------------------------------------|---------------------------------------------------|
| `Sql(Execute { sql: String })`       | `Sql(DdlOk \| Affected(u64) \| Rows { columns, rows })` |

`rows` is `Vec<Vec<u8>>` where each inner blob is `bincode(Vec<Value>)`.
The client decodes them back into `zerobase_sql::Value`. v1 enforces a
coarse "any SqlRead/SqlWrite scope" check at the daemon edge; per-table
enforcement is handled by the SQL engine via the catalog.

## Error frames

`Response::Error { code, message }` codes used by the daemon:

| Code | Meaning                                  |
|------|------------------------------------------|
| 400  | Protocol violation (out-of-order frame)  |
| 401  | Unauthenticated (handshake failure)      |
| 403  | Forbidden (scope check denied)           |
| 422  | SQL execution error                      |
| 423  | KV engine error                          |
| 500  | Internal (e.g. poisoned mutex)           |
| 505  | Unsupported protocol version             |

Clients SHOULD surface `code` to callers as a stable contract; messages
are advisory.

## Security notes

* v1 ships **unencrypted on the wire**. The signed challenge pins identity
  and the signed caps bound damage, so a passive MITM cannot impersonate
  the client, but it can read traffic. TLS will be added in a later
  milestone — clients should use a tunnel (WireGuard, ssh) until then.
* The server's identity is generated on first start and persisted as 32
  raw secret bytes at the path passed via `--identity` (mode 0600).
  Rotating it invalidates every cap that names the old issuer.
* Caps are bearer tokens: anyone holding a valid cap can present it.
  Use short `expires_at` windows and revoke by rotating the issuer key
  if needed.

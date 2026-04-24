# Security Policy

Zerobase is a security-first project. We take vulnerability reports seriously.

## Reporting a vulnerability

**Do NOT open a public issue for security bugs.**

Send details to: `security@oryzon.cv` (PGP preferred; key on request).

You should receive an acknowledgement within **72 hours**.
Triage + patch target: **14 days** for high severity.

## Scope

In scope:
- Cryptographic weaknesses (key derivation, AEAD usage, RNG, signature handling)
- Memory safety issues (secret leaks, missing zeroization, `unsafe` misuse)
- Tampering detection bypasses (WAL, SSTable, manifest)
- Timing / side-channel vulnerabilities in secret-handling paths
- Supply-chain issues in dependencies

Out of scope:
- Attacks requiring physical access while the DB is **unlocked in RAM**
  (documented limitation — see `docs/THREAT_MODEL.md`)
- DoS via unbounded resource consumption at the API layer (known, tracked)

## Threat model

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full model.

Short version:

| Attacker capability              | Protected? |
|----------------------------------|------------|
| Steals cold disk image           | ✅ AES-256-GCM at rest |
| Tampers with files on disk       | ✅ Ed25519 per-entry + Merkle root |
| Reads swap / core dumps          | ✅ `mlock` + `zeroize` on drop |
| Observes timing of compare       | ✅ `subtle` constant-time |
| Replays an old snapshot          | ✅ version vectors + manifest lineage |
| Has RCE while DB unlocked        | ❌ (out of scope — standard OS isolation) |

## Guarantees we do NOT make

- Zerobase has not been externally audited (yet).
- Do not use in production for secrets you cannot afford to lose.
- APIs are unstable until v1.0.

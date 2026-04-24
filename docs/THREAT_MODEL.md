# Zerobase — Threat model

## Who we're defending against

| # | Attacker                                                              | Capability                               |
|---|-----------------------------------------------------------------------|------------------------------------------|
| 1 | *Cold-storage thief* — steals the disk while the DB is **locked**      | Read + offline cryptanalysis             |
| 2 | *Lab tamperer* — can modify files on disk while the DB is locked       | Arbitrary read/write of any file         |
| 3 | *Replay attacker* — keeps an old snapshot and swaps it back            | Arbitrary rename/swap of whole files     |
| 4 | *Memory peeper* — inspects swap or a core dump                         | Read of process memory at arbitrary time |
| 5 | *Timing observer* — can measure secret-dependent branch times          | Nanosecond-grade timing                  |
| 6 | *Supply-chain meddler* — hostile transitive dependency                 | Can introduce any Rust code we pull in   |

## Our defenses

**(1) Confidentiality at rest.** AES-256-GCM encrypts every persisted byte.
Master key is derived via Argon2id (256 MiB × 3) from the passphrase; derived
subkeys are domain-separated with keyed-BLAKE3. Nonces never repeat under a
given subkey (12-byte layout: 4-byte domain || 8-byte strictly-monotonic
counter).

**(2) Integrity of disk state.** Every WAL frame is Ed25519-signed; the
ciphertext AAD binds the frame counter plus the hash of the previous frame,
turning the log into a verifiable chain. Every SSTable is Merkle-rooted over
keyed-BLAKE3 leaves, with the root sealed into the AEAD. The manifest has its
own sealed record and embeds a monotonically-increasing `generation`, so an
old manifest cannot be "accepted back".

**(3) Replay / downgrade.** The manifest `generation` counter is baked into
the manifest's nonce — a swapped-in older file fails AEAD authentication. For
WALs, the hash-chain makes any reordering or removal of frames detectable on
replay.

**(4) Memory hygiene.** All symmetric keys are `Zeroize + ZeroizeOnDrop`.
Secrets are wrapped in `secrecy::SecretString` where they enter from the
outside. We never log plaintext or key material; we never expose raw key
bytes through the public API.

**(5) Timing side-channels.** Key comparisons go through `subtle`. Failure
paths in decryption and unlock return a single opaque variant so wrong
passphrase and tampered ciphertext are indistinguishable to the caller.

**(6) Supply chain.** `#![forbid(unsafe_code)]`. Dependencies are pinned in
`Cargo.toml` (range-pinned) with `deny.toml` enforcing no wildcards, no
unknown registries, no copyleft, and vulnerability + yank denial. Plan: CI
runs `cargo audit` + `cargo deny` on every PR.

## Out of scope

* **RCE while DB is unlocked.** If an attacker can execute code in the same
  process while the master key is in RAM, they can read anything. This is
  a fundamental property of any online database; we don't pretend otherwise.
* **Denial of service.** We don't rate-limit writes or reads. A malicious
  caller can fill the disk or exhaust memory.
* **Kernel-level attackers.** Cold boot, DMA, rowhammer — the usual hardware
  defenses apply; we don't try to reproduce them in software.
* **Side-channels outside `subtle` / AEAD.** Cache timing attacks on AES-NI
  are considered mitigated by hardware AES; pure-software builds might leak
  on hostile co-tenants.

## What "zero-trust" means here

We assume:

* The disk is hostile (attacker #1-3).
* The operator may mishandle the file (swap backups, restore an old one).
* The OS is honest when the DB is unlocked, but not after.

Zerobase does **not** require trust in:

* The filesystem to preserve order of writes (we fsync on demand and store
  `generation` counters to detect stale state).
* Any kind of secure element or TPM (we want it to work on any VPS).
* A central authority (no network involved in the MVP).

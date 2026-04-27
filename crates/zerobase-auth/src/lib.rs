//! Identity and authentication primitives for Zerobase.
//!
//! - [`Identity`] — an Ed25519 keypair with a stable BLAKE3 fingerprint.
//! - [`Challenge`] / [`SignedChallenge`] — a 32-byte server nonce that the
//!   client signs to prove possession of the private key.
//! - [`IdentityChain`] — an append-only sequence of pubkeys where each new
//!   key is signed by the previous one. Models key rotation without losing
//!   the link back to the original identity.
//!
//! Wire format for everything is bincode, so callers can freely embed these
//! types in their own framed protocols.

#![forbid(unsafe_code)]

mod chain;
mod challenge;
mod error;
mod identity;

pub use chain::{ChainEntry, IdentityChain};
pub use challenge::{Challenge, SignedChallenge, CHALLENGE_DOMAIN, CHALLENGE_LEN};
pub use error::AuthError;
pub use identity::{Identity, IdentityId, PublicIdentity};

/// Re-exported for downstream crates that build their own bincode-backed
/// types containing Ed25519 signatures.
pub use serde_big_array;

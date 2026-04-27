//! Challenge / response handshake.
//!
//! Server flow:
//! 1. `Challenge::new()` — generates a random 32-byte nonce.
//! 2. Send the nonce to the client.
//! 3. Receive a `SignedChallenge` and call `verify` against the expected
//!    public identity.
//!
//! Client flow:
//! 1. Receive the nonce.
//! 2. `SignedChallenge::sign(&identity, &nonce)`.
//! 3. Send back the `SignedChallenge`.
//!
//! All signatures are domain-separated by [`CHALLENGE_DOMAIN`] so a nonce
//! signed for the auth handshake cannot be replayed as anything else.

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::error::AuthError;
use crate::identity::{Identity, PublicIdentity};

/// Domain separation tag mixed into every signed challenge.
pub const CHALLENGE_DOMAIN: &[u8] = b"zb-auth-v1|";

/// Length of a challenge nonce in bytes.
pub const CHALLENGE_LEN: usize = 32;

/// A 32-byte server-generated nonce.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Challenge {
    pub nonce: [u8; CHALLENGE_LEN],
}

impl Challenge {
    /// Generate a fresh challenge from the OS RNG.
    pub fn new() -> Self {
        let mut nonce = [0u8; CHALLENGE_LEN];
        OsRng.fill_bytes(&mut nonce);
        Self { nonce }
    }

    fn message(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(CHALLENGE_DOMAIN.len() + CHALLENGE_LEN);
        buf.extend_from_slice(CHALLENGE_DOMAIN);
        buf.extend_from_slice(&self.nonce);
        buf
    }
}

impl Default for Challenge {
    fn default() -> Self {
        Self::new()
    }
}

/// Client's response: the original nonce + a detached Ed25519 signature
/// over `CHALLENGE_DOMAIN || nonce`, plus the responding identity's
/// fingerprint so the server can pick the right public key to verify.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedChallenge {
    pub challenge: Challenge,
    pub identity_id: [u8; 32],
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl SignedChallenge {
    /// Sign a challenge with the given local identity.
    pub fn sign(identity: &Identity, challenge: &Challenge) -> Self {
        let signature = identity.sign(&challenge.message());
        Self { challenge: challenge.clone(), identity_id: identity.id(), signature }
    }

    /// Verify against the expected public identity. Returns `Ok(())` on
    /// success or an `AuthError` describing why verification failed.
    pub fn verify(&self, expected: &PublicIdentity) -> Result<(), AuthError> {
        if self.identity_id != expected.id {
            return Err(AuthError::IdentityMismatch);
        }
        expected.verify(&self.challenge.message(), &self.signature)
    }
}

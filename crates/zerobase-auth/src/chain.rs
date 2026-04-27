//! Identity chain — append-only sequence of public keys where each new
//! entry is signed by the previous one. Used for key rotation: the chain's
//! head is the current "live" key, but old keys remain anchored.
//!
//! Verification rule: for every entry past the genesis, its `signature`
//! is a valid Ed25519 signature over `CHAIN_DOMAIN || prev_pubkey || new_pubkey`
//! produced by `prev_pubkey`'s private half.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::error::AuthError;
use crate::identity::{Identity, IdentityId, PublicIdentity};

/// Domain separation tag for chain link signatures.
pub const CHAIN_DOMAIN: &[u8] = b"zb-chain-v1|";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainEntry {
    pub public: PublicIdentity,
    /// Genesis entry has all-zero signature; subsequent entries are signed
    /// by the previous public key.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityChain {
    entries: Vec<ChainEntry>,
}

impl IdentityChain {
    /// Start a chain with a genesis key. The entry's signature is all
    /// zeros; verification short-circuits the genesis check.
    pub fn genesis(genesis: &PublicIdentity) -> Self {
        Self {
            entries: vec![ChainEntry { public: genesis.clone(), signature: [0u8; 64] }],
        }
    }

    /// Append a new entry signed by the current tip's private key.
    /// `prev` must be the local identity matching the current tip.
    pub fn rotate(&mut self, prev: &Identity, next: &PublicIdentity) -> Result<(), AuthError> {
        let tip = self.tip().ok_or(AuthError::EmptyChain)?;
        if tip.public.id != prev.id() {
            return Err(AuthError::IdentityMismatch);
        }
        let msg = link_message(&tip.public.public_key, &next.public_key);
        let signature = prev.sign(&msg);
        self.entries.push(ChainEntry { public: next.clone(), signature });
        Ok(())
    }

    /// Verify the entire chain. Returns `Ok(())` if every link checks out.
    pub fn verify(&self) -> Result<(), AuthError> {
        if self.entries.is_empty() {
            return Err(AuthError::EmptyChain);
        }
        for window in self.entries.windows(2) {
            let prev = &window[0];
            let next = &window[1];
            let msg = link_message(&prev.public.public_key, &next.public.public_key);
            prev.public.verify(&msg, &next.signature).map_err(|_| AuthError::BrokenChain)?;
        }
        Ok(())
    }

    /// Current head — the identity considered "live".
    pub fn tip(&self) -> Option<&ChainEntry> {
        self.entries.last()
    }

    /// Genesis entry — the original anchor identity.
    pub fn genesis_entry(&self) -> Option<&ChainEntry> {
        self.entries.first()
    }

    /// Stable identifier for the chain: BLAKE3 of the genesis pubkey.
    pub fn id(&self) -> Option<IdentityId> {
        self.entries.first().map(|e| e.public.id)
    }

    pub fn entries(&self) -> &[ChainEntry] {
        &self.entries
    }

    /// Append an unverified entry. Useful for negative tests and for
    /// callers that load a chain piecemeal and verify at the end via
    /// [`Self::verify`]. Production code should normally use
    /// [`Self::rotate`].
    pub fn push_raw(&mut self, entry: ChainEntry) {
        self.entries.push(entry);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn link_message(prev_pk: &[u8; 32], next_pk: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CHAIN_DOMAIN.len() + 64);
    buf.extend_from_slice(CHAIN_DOMAIN);
    buf.extend_from_slice(prev_pk);
    buf.extend_from_slice(next_pk);
    buf
}

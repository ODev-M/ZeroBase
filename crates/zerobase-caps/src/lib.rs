//! Capability tokens.
//!
//! A `Capability` is a signed grant: "the server with this public key
//! authorises subject `S` to perform actions in `Scope` until time T".
//! The signature covers the full canonical encoding, so any tampering
//! invalidates it.
//!
//! Time is expressed as **Unix seconds since the epoch**. The verifier
//! supplies the current time, so this crate stays free of any clock /
//! `std::time` coupling and can be used in deterministic tests.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;
use zerobase_auth::{AuthError, Identity, IdentityId, PublicIdentity};

/// Domain-separation tag for capability signatures.
pub const CAP_DOMAIN: &[u8] = b"zb-cap-v1|";

/// What an action is allowed to touch. Variants are intentionally coarse
/// for v1; finer-grained per-row policy can be layered on later.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Scope {
    /// Read any KV key whose bytes start with this prefix.
    KvRead { prefix: Vec<u8> },
    /// Write any KV key whose bytes start with this prefix.
    KvWrite { prefix: Vec<u8> },
    /// Run read-only SQL (SELECT) over the named table.
    SqlRead { table: String },
    /// Run any SQL (incl. INSERT/UPDATE/DELETE/DDL) over the named table.
    SqlWrite { table: String },
}

impl Scope {
    /// True if `self` permits the action described by `requested`.
    pub fn permits(&self, requested: &Scope) -> bool {
        match (self, requested) {
            (Scope::KvRead { prefix }, Scope::KvRead { prefix: r })
            | (Scope::KvWrite { prefix }, Scope::KvWrite { prefix: r })
            | (Scope::KvWrite { prefix }, Scope::KvRead { prefix: r }) => r.starts_with(prefix),
            (Scope::SqlRead { table }, Scope::SqlRead { table: r })
            | (Scope::SqlWrite { table }, Scope::SqlWrite { table: r })
            | (Scope::SqlWrite { table }, Scope::SqlRead { table: r }) => table == r,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityClaims {
    pub subject: IdentityId,
    pub scope: Scope,
    /// Unix seconds. The verifier rejects any capability whose `expires_at`
    /// is `<= now`.
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    pub claims: CapabilityClaims,
    /// Public key of the issuer. Verifier compares this against the set
    /// of trusted issuers it knows; signature alone is not enough.
    pub issuer: PublicIdentity,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Debug, Error)]
pub enum CapError {
    #[error("expired")]
    Expired,
    #[error("subject mismatch")]
    SubjectMismatch,
    #[error("scope not permitted")]
    ScopeDenied,
    #[error("signature invalid")]
    BadSignature,
    #[error("issuer not trusted")]
    UntrustedIssuer,
    #[error("encoding")]
    Encoding,
}

impl From<AuthError> for CapError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::BadSignature => CapError::BadSignature,
            _ => CapError::Encoding,
        }
    }
}

impl From<bincode::Error> for CapError {
    fn from(_: bincode::Error) -> Self {
        CapError::Encoding
    }
}

impl Capability {
    /// Issue a new capability signed by `issuer`.
    pub fn issue(issuer: &Identity, claims: CapabilityClaims) -> Result<Self, CapError> {
        let msg = signing_message(&claims)?;
        let signature = issuer.sign(&msg);
        Ok(Self { claims, issuer: issuer.public().clone(), signature })
    }

    /// Verify signature, expiry, subject, and the requested scope.
    ///
    /// The `trusted_issuers` slice lets the verifier accept tokens issued
    /// by any of several known servers (useful when rotating keys).
    pub fn verify(
        &self,
        subject: &IdentityId,
        requested: &Scope,
        now: u64,
        trusted_issuers: &[PublicIdentity],
    ) -> Result<(), CapError> {
        if !trusted_issuers.iter().any(|i| i.id == self.issuer.id) {
            return Err(CapError::UntrustedIssuer);
        }
        if self.claims.expires_at <= now {
            return Err(CapError::Expired);
        }
        if &self.claims.subject != subject {
            return Err(CapError::SubjectMismatch);
        }
        if !self.claims.scope.permits(requested) {
            return Err(CapError::ScopeDenied);
        }
        let msg = signing_message(&self.claims)?;
        self.issuer.verify(&msg, &self.signature).map_err(|_| CapError::BadSignature)
    }
}

fn signing_message(claims: &CapabilityClaims) -> Result<Vec<u8>, CapError> {
    let mut buf = Vec::with_capacity(CAP_DOMAIN.len() + 64);
    buf.extend_from_slice(CAP_DOMAIN);
    buf.extend_from_slice(&bincode::serialize(claims)?);
    Ok(buf)
}

//! Top-level request / response shapes the daemon understands.
//!
//! Connection lifecycle:
//!
//! 1. Client opens a TCP connection.
//! 2. Client sends [`Request::HandshakeHello`] with its claimed identity id.
//! 3. Server replies with [`Response::HandshakeChallenge`] (a 32-byte nonce).
//! 4. Client sends [`Request::HandshakeProof`] with the signed challenge
//!    and any [`Capability`] tokens it wants to present.
//! 5. Server validates and replies [`Response::HandshakeAck`] with the
//!    granted scope set.
//! 6. Client now issues [`Request::Kv(_)`] / [`Request::Sql(_)`] as it
//!    wishes; server responds 1:1 in declaration order.

use serde::{Deserialize, Serialize};
use zerobase_auth::{Challenge, IdentityId, SignedChallenge};
use zerobase_caps::{Capability, Scope};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeHello {
    /// Fingerprint of the identity the client claims.
    pub identity_id: IdentityId,
    /// Wire-protocol version the client speaks. The server picks the
    /// minimum of its own and the client's, or rejects on mismatch.
    pub protocol_version: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeAck {
    /// Final negotiated protocol version.
    pub protocol_version: u16,
    /// Scopes the server is willing to honor for this session, derived
    /// from the validated capability tokens the client presented.
    pub granted: Vec<Scope>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    HandshakeHello(HandshakeHello),
    HandshakeProof {
        signed: SignedChallenge,
        capabilities: Vec<Capability>,
    },
    Kv(KvCmd),
    Sql(SqlCmd),
    Bye,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Response {
    HandshakeChallenge(Challenge),
    HandshakeAck(HandshakeAck),
    Kv(KvResult),
    Sql(SqlResult),
    Error { code: u16, message: String },
    Goodbye,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KvCmd {
    Get { key: Vec<u8> },
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
    Scan { prefix: Vec<u8>, limit: Option<u32> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KvResult {
    Value(Option<Vec<u8>>),
    Ack,
    Items(Vec<(Vec<u8>, Vec<u8>)>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SqlCmd {
    Execute { sql: String },
}

/// SQL response. We re-encode rows as `Vec<Vec<u8>>` (bincode of `Value`)
/// so this crate doesn't depend on `zerobase-sql` types directly. The
/// daemon side does the conversion.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SqlResult {
    DdlOk,
    Affected(u64),
    Rows {
        columns: Vec<String>,
        rows: Vec<Vec<u8>>,
    },
}

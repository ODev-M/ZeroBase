//! Synchronous client SDK for `zerobased`.
//!
//! ```no_run
//! use zerobase_auth::Identity;
//! use zerobase_caps::Capability;
//! use zerobase_client::Client;
//!
//! # fn caps() -> Vec<Capability> { vec![] }
//! let identity = Identity::generate();
//! let mut client = Client::connect("127.0.0.1:7878", &identity, caps()).unwrap();
//! client.kv_put(b"hello", b"world").unwrap();
//! let v = client.kv_get(b"hello").unwrap();
//! assert_eq!(v.as_deref(), Some(b"world".as_slice()));
//! ```
//!
//! The SDK owns one TCP connection and is **not** thread-safe. Wrap it in
//! `Arc<Mutex<>>` if you want to share it across threads.

#![forbid(unsafe_code)]

mod error;

use std::io::{BufReader, BufWriter};
use std::net::{TcpStream, ToSocketAddrs};

use zerobase_auth::{Identity, SignedChallenge};
use zerobase_caps::Capability;
use zerobase_proto::{
    read_frame, write_frame, HandshakeHello, KvCmd, KvResult, Request, Response, SqlCmd, SqlResult,
};

pub use error::{ClientError, Result};
pub use zerobase_proto::Response as RawResponse;

/// Default protocol version this SDK speaks.
pub const PROTOCOL_VERSION: u16 = 1;

/// A connected, authenticated session against `zerobased`.
pub struct Client {
    reader: BufReader<TcpStream>,
    writer: BufWriter<TcpStream>,
    granted: Vec<zerobase_caps::Scope>,
}

impl Client {
    /// Connect, handshake, and authenticate. Blocks until the server
    /// returns either `HandshakeAck` or an error frame.
    pub fn connect<A: ToSocketAddrs>(
        addr: A,
        identity: &Identity,
        capabilities: Vec<Capability>,
    ) -> Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true).ok();
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut writer = BufWriter::new(stream);

        write_frame(
            &mut writer,
            &Request::HandshakeHello(HandshakeHello {
                identity_id: identity.public().id,
                protocol_version: PROTOCOL_VERSION,
            }),
        )?;

        let challenge = match read_frame::<_, Response>(&mut reader)? {
            Response::HandshakeChallenge(c) => c,
            Response::Error { code, message } => return Err(ClientError::Server { code, message }),
            other => return Err(ClientError::Protocol(format!("expected challenge: {other:?}"))),
        };

        let signed = SignedChallenge::sign(identity, &challenge);
        write_frame(&mut writer, &Request::HandshakeProof { signed, capabilities })?;

        let granted = match read_frame::<_, Response>(&mut reader)? {
            Response::HandshakeAck(ack) => ack.granted,
            Response::Error { code, message } => return Err(ClientError::Server { code, message }),
            other => return Err(ClientError::Protocol(format!("expected ack: {other:?}"))),
        };

        Ok(Self { reader, writer, granted })
    }

    /// Scopes the server confirmed for this session.
    #[must_use]
    pub fn granted_scopes(&self) -> &[zerobase_caps::Scope] {
        &self.granted
    }

    /// Send a request frame and read exactly one response frame.
    pub(crate) fn round_trip(&mut self, req: Request) -> Result<Response> {
        write_frame(&mut self.writer, &req)?;
        let resp = read_frame::<_, Response>(&mut self.reader)?;
        match resp {
            Response::Error { code, message } => Err(ClientError::Server { code, message }),
            other => Ok(other),
        }
    }

    /// Execute a single SQL statement.
    pub fn sql(&mut self, statement: &str) -> Result<SqlResult> {
        match self.round_trip(Request::Sql(SqlCmd::Execute { sql: statement.into() }))? {
            Response::Sql(r) => Ok(r),
            other => Err(ClientError::Protocol(format!("expected SQL response: {other:?}"))),
        }
    }

    /// Tell the server we're done; consumes the client.
    pub fn bye(mut self) -> Result<()> {
        let _ = write_frame(&mut self.writer, &Request::Bye);
        // Best-effort read; the server replies with Goodbye.
        let _ = read_frame::<_, Response>(&mut self.reader);
        Ok(())
    }
}

// KV helpers live in `kv.rs` to keep this file readable.
impl Client {
    /// Fetch a single key. Returns `None` if absent or tombstoned.
    pub fn kv_get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.round_trip(Request::Kv(KvCmd::Get { key: key.to_vec() }))? {
            Response::Kv(KvResult::Value(v)) => Ok(v),
            other => Err(ClientError::Protocol(format!("expected KvResult::Value: {other:?}"))),
        }
    }

    /// Insert or overwrite a key.
    pub fn kv_put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        match self.round_trip(Request::Kv(KvCmd::Put { key: key.to_vec(), value: value.to_vec() }))?
        {
            Response::Kv(KvResult::Ack) => Ok(()),
            other => Err(ClientError::Protocol(format!("expected ack: {other:?}"))),
        }
    }

    /// Delete a key.
    pub fn kv_delete(&mut self, key: &[u8]) -> Result<()> {
        match self.round_trip(Request::Kv(KvCmd::Delete { key: key.to_vec() }))? {
            Response::Kv(KvResult::Ack) => Ok(()),
            other => Err(ClientError::Protocol(format!("expected ack: {other:?}"))),
        }
    }

    /// Range scan by prefix.
    pub fn kv_scan(&mut self, prefix: &[u8], limit: Option<u32>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        match self
            .round_trip(Request::Kv(KvCmd::Scan { prefix: prefix.to_vec(), limit }))?
        {
            Response::Kv(KvResult::Items(items)) => Ok(items),
            other => Err(ClientError::Protocol(format!("expected items: {other:?}"))),
        }
    }
}

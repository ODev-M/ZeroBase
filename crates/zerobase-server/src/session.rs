//! Per-connection session.
//!
//! State machine:
//!
//! ```text
//! Connected
//!   └─▶ HandshakeHello                ─▶ send Challenge
//!         └─▶ HandshakeProof          ─▶ verify, send Ack
//!               └─▶ Authenticated     ─▶ Kv / Sql until Bye
//! ```
//!
//! Authentication contract (v1):
//!
//! 1. Server sends a 32-byte nonce.
//! 2. Client signs it and replies with the signed challenge plus a list of
//!    [`Capability`] tokens.
//! 3. The first capability whose `issuer.id == subject == identity_id` is the
//!    client's "self-cap" and carries the subject's pubkey. We verify the
//!    BLAKE3 fingerprint of that pubkey matches the claimed identity, then
//!    use that pubkey to verify the signed challenge.
//! 4. Every other capability must be signed by a trusted issuer (the server
//!    or one of its delegates), have `subject == identity_id`, and not yet
//!    be expired. Each one contributes its `Scope` to the granted set.
//! 5. After Ack, every Kv/Sql command is checked against the granted scopes.

use std::io::{BufReader, BufWriter, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use tracing::{debug, info};
use zerobase_auth::{Challenge, IdentityId, PublicIdentity};
use zerobase_caps::{Capability, CapabilityClaims, Scope, CAP_DOMAIN};
use zerobase_proto::{
    read_frame, write_frame, HandshakeAck, HandshakeHello, KvCmd, KvResult, ProtoError, Request,
    Response, SqlCmd, SqlResult,
};

use crate::state::ServerState;

const PROTOCOL_VERSION: u16 = 1;

mod ec {
    pub const PROTOCOL: u16 = 400;
    pub const UNAUTHENTICATED: u16 = 401;
    pub const FORBIDDEN: u16 = 403;
    pub const INTERNAL: u16 = 500;
    pub const VERSION: u16 = 505;
    pub const SQL_ERROR: u16 = 422;
    pub const KV_ERROR: u16 = 423;
}

pub fn handle(state: Arc<ServerState>, stream: TcpStream) -> Result<()> {
    let peer = stream.peer_addr().ok();
    stream.set_nodelay(true).ok();
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = BufWriter::new(stream);

    let session = match handshake(&state, &mut reader, &mut writer)? {
        Some(s) => s,
        None => return Ok(()),
    };
    info!(?peer, subject = %hex::encode(session.subject), scopes = session.granted.len(),
        "session authenticated");

    loop {
        let req: Request = match read_frame(&mut reader) {
            Ok(r) => r,
            Err(ProtoError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!(?peer, "peer closed");
                return Ok(());
            }
            Err(e) => return Err(anyhow!(e)),
        };
        match req {
            Request::Bye => {
                let _ = write_frame(&mut writer, &Response::Goodbye);
                return Ok(());
            }
            Request::HandshakeHello(_) | Request::HandshakeProof { .. } => {
                send_error(&mut writer, ec::PROTOCOL, "handshake already complete")?;
            }
            Request::Kv(cmd) => {
                let resp = dispatch_kv(&state, &session, cmd);
                write_frame(&mut writer, &resp)?;
            }
            Request::Sql(cmd) => {
                let resp = dispatch_sql(&state, &session, cmd);
                write_frame(&mut writer, &resp)?;
            }
        }
    }
}

struct Session {
    subject: IdentityId,
    granted: Vec<Scope>,
}

fn handshake<R: std::io::Read, W: Write>(
    state: &ServerState,
    reader: &mut R,
    writer: &mut W,
) -> Result<Option<Session>> {
    let hello: Request = read_frame(reader).context("reading hello")?;
    let hello = match hello {
        Request::HandshakeHello(h) => h,
        _ => {
            send_error(writer, ec::PROTOCOL, "expected HandshakeHello")?;
            return Ok(None);
        }
    };
    if hello.protocol_version != PROTOCOL_VERSION {
        send_error(writer, ec::VERSION, "unsupported protocol version")?;
        return Ok(None);
    }
    let HandshakeHello { identity_id, .. } = hello;

    let challenge = Challenge::new();
    write_frame(writer, &Response::HandshakeChallenge(challenge.clone()))?;

    let proof: Request = read_frame(reader).context("reading proof")?;
    let (signed, capabilities) = match proof {
        Request::HandshakeProof { signed, capabilities } => (signed, capabilities),
        _ => {
            send_error(writer, ec::PROTOCOL, "expected HandshakeProof")?;
            return Ok(None);
        }
    };

    if signed.identity_id != identity_id || signed.challenge != challenge {
        send_error(writer, ec::UNAUTHENTICATED, "challenge mismatch")?;
        return Ok(None);
    }

    let subject_pk = match find_self_cap_pubkey(&capabilities, &identity_id) {
        Some(pk) => pk,
        None => {
            send_error(writer, ec::UNAUTHENTICATED, "missing self-capability")?;
            return Ok(None);
        }
    };
    let subject_public = PublicIdentity::from_bytes(subject_pk);
    if subject_public.id != identity_id {
        send_error(writer, ec::UNAUTHENTICATED, "fingerprint mismatch")?;
        return Ok(None);
    }
    if signed.verify(&subject_public).is_err() {
        send_error(writer, ec::UNAUTHENTICATED, "bad signature")?;
        return Ok(None);
    }

    let now = unix_now();
    let mut granted: Vec<Scope> = Vec::new();
    for cap in &capabilities {
        if cap.claims.subject != identity_id {
            continue;
        }
        if cap.verify(&identity_id, &cap.claims.scope, now, &state.trusted_issuers).is_ok() {
            granted.push(cap.claims.scope.clone());
        }
    }

    write_frame(
        writer,
        &Response::HandshakeAck(HandshakeAck {
            protocol_version: PROTOCOL_VERSION,
            granted: granted.clone(),
        }),
    )?;

    Ok(Some(Session { subject: identity_id, granted }))
}

/// A self-cap is a capability where `issuer == subject == identity_id`.
/// Its only job is to convey the subject's pubkey to the server in a
/// signature-bound way: the cap signature verifies against the embedded
/// pubkey, and the BLAKE3 fingerprint of that pubkey equals the claimed id.
fn find_self_cap_pubkey(caps: &[Capability], id: &IdentityId) -> Option<[u8; 32]> {
    for cap in caps {
        if &cap.issuer.id != id || &cap.claims.subject != id {
            continue;
        }
        let msg = self_cap_message(&cap.claims);
        if cap.issuer.verify(&msg, &cap.signature).is_ok() {
            return Some(cap.issuer.public_key);
        }
    }
    None
}

fn self_cap_message(claims: &CapabilityClaims) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CAP_DOMAIN.len() + 64);
    buf.extend_from_slice(CAP_DOMAIN);
    if let Ok(b) = bincode::serialize(claims) {
        buf.extend_from_slice(&b);
    }
    buf
}

fn dispatch_kv(state: &ServerState, session: &Session, cmd: KvCmd) -> Response {
    let needed = match &cmd {
        KvCmd::Get { key } => Scope::KvRead { prefix: key.clone() },
        KvCmd::Scan { prefix, .. } => Scope::KvRead { prefix: prefix.clone() },
        KvCmd::Put { key, .. } | KvCmd::Delete { key } => Scope::KvWrite { prefix: key.clone() },
    };
    if !session.granted.iter().any(|s| s.permits(&needed)) {
        return Response::Error { code: ec::FORBIDDEN, message: "scope denied".into() };
    }

    let mut data = match state.data.lock() {
        Ok(g) => g,
        Err(_) => return Response::Error { code: ec::INTERNAL, message: "lock poisoned".into() },
    };

    match cmd {
        KvCmd::Get { key } => Response::Kv(KvResult::Value(data.db.get(&key))),
        KvCmd::Put { key, value } => match data.db.put(key, value) {
            Ok(()) => Response::Kv(KvResult::Ack),
            Err(e) => Response::Error { code: ec::KV_ERROR, message: e.to_string() },
        },
        KvCmd::Delete { key } => match data.db.delete(key) {
            Ok(()) => Response::Kv(KvResult::Ack),
            Err(e) => Response::Error { code: ec::KV_ERROR, message: e.to_string() },
        },
        KvCmd::Scan { prefix, limit } => {
            let mut items: Vec<(Vec<u8>, Vec<u8>)> =
                data.db.scan(&prefix).into_iter().map(|i| (i.key, i.value)).collect();
            if let Some(n) = limit {
                items.truncate(n as usize);
            }
            Response::Kv(KvResult::Items(items))
        }
    }
}

fn dispatch_sql(state: &ServerState, session: &Session, cmd: SqlCmd) -> Response {
    let has_sql_scope = session
        .granted
        .iter()
        .any(|s| matches!(s, Scope::SqlRead { .. } | Scope::SqlWrite { .. }));
    if !has_sql_scope {
        return Response::Error { code: ec::FORBIDDEN, message: "no SQL scope".into() };
    }

    let SqlCmd::Execute { sql } = cmd;
    let mut data = match state.data.lock() {
        Ok(g) => g,
        Err(_) => return Response::Error { code: ec::INTERNAL, message: "lock poisoned".into() },
    };
    let data = &mut *data;
    match data.sql.execute(&sql, &mut data.db) {
        Ok(zerobase_sql::SqlOutput::DdlOk) => Response::Sql(SqlResult::DdlOk),
        Ok(zerobase_sql::SqlOutput::Affected(n)) => Response::Sql(SqlResult::Affected(n)),
        Ok(zerobase_sql::SqlOutput::Rows { columns, rows }) => {
            let cols: Vec<String> = columns.into_iter().map(|c| c.name).collect();
            let encoded: Vec<Vec<u8>> =
                rows.into_iter().map(|r| bincode::serialize(&r).unwrap_or_default()).collect();
            Response::Sql(SqlResult::Rows { columns: cols, rows: encoded })
        }
        Err(e) => Response::Error { code: ec::SQL_ERROR, message: e.to_string() },
    }
}

fn send_error<W: Write>(w: &mut W, code: u16, msg: &str) -> Result<()> {
    write_frame(w, &Response::Error { code, message: msg.to_string() }).map_err(|e| anyhow!(e))?;
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

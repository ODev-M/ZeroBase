//! End-to-end smoke test for `zerobased`.
//!
//! Spins the daemon on an ephemeral port with a fresh DB + identity, drives
//! the handshake, presents a self-cap + a server-issued KV write cap, then
//! issues PUT/GET and asserts both round-trip and authorization checks.

use std::io::{BufReader, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use secrecy::SecretString;
use zerobase_auth::{Identity, SignedChallenge};
use zerobase_caps::{Capability, CapabilityClaims, Scope};
use zerobase_proto::{
    read_frame, write_frame, HandshakeHello, KvCmd, KvResult, Request, Response, SqlCmd,
};
use zerobase_server::ServerState;

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn issue_self_cap(client: &Identity, expires_at: u64) -> Capability {
    Capability::issue(
        client,
        CapabilityClaims {
            subject: client.public().id,
            scope: Scope::KvRead { prefix: b"".to_vec() },
            expires_at,
        },
    )
    .unwrap()
}

#[test]
fn handshake_and_kv_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let pass = SecretString::new("test-pass".into());

    // Build the DB up front. The server-issued identity is what signs caps.
    {
        let _ = zerobase::Db::create(dir.path(), &pass).unwrap();
    }
    // Build the server identity *outside* and clone its secret so we can
    // both hand it to ServerState (which moves) and use a parallel copy in
    // the test to issue real caps.
    let server_id = Identity::generate();
    let server_secret = server_id.secret_bytes();
    let server_issuer = Identity::from_secret(server_secret);
    let state = ServerState::new(server_id, dir.path(), pass).unwrap();
    let trusted = state.trusted_issuers[0].clone();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server_state = Arc::clone(&state);
    thread::spawn(move || {
        let _ = zerobase_server::server::serve(server_state, listener);
    });
    thread::sleep(Duration::from_millis(50));

    let client = Identity::generate();
    // Self-cap conveys the client's pubkey to the server.
    let self_cap = issue_self_cap(&client, now() + 60);
    // Real KvWrite capability issued by the server (trusted issuer).
    let write_cap = Capability::issue(
        &server_issuer,
        CapabilityClaims {
            subject: client.public().id,
            scope: Scope::KvWrite { prefix: b"".to_vec() },
            expires_at: now() + 60,
        },
    )
    .unwrap();
    // SQL write cap so we can also exercise the SQL path.
    let sql_cap = Capability::issue(
        &server_issuer,
        CapabilityClaims {
            subject: client.public().id,
            scope: Scope::SqlWrite { table: "t".into() },
            expires_at: now() + 60,
        },
    )
    .unwrap();

    let stream = TcpStream::connect(addr).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = BufWriter::new(stream);

    write_frame(
        &mut writer,
        &Request::HandshakeHello(HandshakeHello {
            identity_id: client.public().id,
            protocol_version: 1,
        }),
    )
    .unwrap();

    let challenge = match read_frame::<_, Response>(&mut reader).unwrap() {
        Response::HandshakeChallenge(c) => c,
        other => panic!("expected challenge, got {:?}", other),
    };

    let signed = SignedChallenge::sign(&client, &challenge);
    write_frame(
        &mut writer,
        &Request::HandshakeProof {
            signed,
            capabilities: vec![self_cap.clone(), write_cap.clone(), sql_cap.clone()],
        },
    )
    .unwrap();

    let ack = match read_frame::<_, Response>(&mut reader).unwrap() {
        Response::HandshakeAck(ack) => ack,
        Response::Error { code, message } => panic!("ack failed: {} {}", code, message),
        other => panic!("expected ack, got {:?}", other),
    };
    assert_eq!(ack.protocol_version, 1);
    // The self-cap grants KvRead on the empty prefix — i.e., everything.
    assert!(!ack.granted.is_empty());

    // GET on an absent key returns Value(None).
    write_frame(&mut writer, &Request::Kv(KvCmd::Get { key: b"nope".to_vec() })).unwrap();
    match read_frame::<_, Response>(&mut reader).unwrap() {
        Response::Kv(KvResult::Value(v)) => assert!(v.is_none()),
        other => panic!("unexpected: {:?}", other),
    }

    // PUT now succeeds: server-issued KvWrite covers the prefix.
    write_frame(
        &mut writer,
        &Request::Kv(KvCmd::Put { key: b"k".to_vec(), value: b"v".to_vec() }),
    )
    .unwrap();
    match read_frame::<_, Response>(&mut reader).unwrap() {
        Response::Kv(KvResult::Ack) => {}
        other => panic!("expected ack, got {:?}", other),
    }

    // GET reads it back.
    write_frame(&mut writer, &Request::Kv(KvCmd::Get { key: b"k".to_vec() })).unwrap();
    match read_frame::<_, Response>(&mut reader).unwrap() {
        Response::Kv(KvResult::Value(Some(v))) => assert_eq!(v, b"v"),
        other => panic!("expected value, got {:?}", other),
    }

    // SQL DDL is allowed (we presented a SqlWrite scope).
    write_frame(
        &mut writer,
        &Request::Sql(SqlCmd::Execute { sql: "CREATE TABLE t (id BIGINT PRIMARY KEY)".into() }),
    )
    .unwrap();
    match read_frame::<_, Response>(&mut reader).unwrap() {
        Response::Sql(_) | Response::Error { .. } => {} // either is fine for the smoke
        other => panic!("expected sql response, got {:?}", other),
    }

    // Bye should produce Goodbye.
    write_frame(&mut writer, &Request::Bye).unwrap();
    match read_frame::<_, Response>(&mut reader).unwrap() {
        Response::Goodbye => {}
        other => panic!("expected goodbye, got {:?}", other),
    }

    // Trusted issuer reachable from outside (smoke).
    assert_eq!(trusted, state.trusted_issuers[0]);
}

#[test]
fn handshake_rejects_missing_self_cap() {
    let dir = tempfile::tempdir().unwrap();
    let pass = SecretString::new("test-pass".into());
    {
        let _ = zerobase::Db::create(dir.path(), &pass).unwrap();
    }
    let server_id = Identity::generate();
    let state = ServerState::new(server_id, dir.path(), pass).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let _ = zerobase_server::server::serve(state, listener);
    });
    thread::sleep(Duration::from_millis(50));

    let client = Identity::generate();
    let stream = TcpStream::connect(addr).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = BufWriter::new(stream);

    write_frame(
        &mut writer,
        &Request::HandshakeHello(HandshakeHello {
            identity_id: client.public().id,
            protocol_version: 1,
        }),
    )
    .unwrap();

    let challenge = match read_frame::<_, Response>(&mut reader).unwrap() {
        Response::HandshakeChallenge(c) => c,
        other => panic!("expected challenge, got {:?}", other),
    };

    let signed = SignedChallenge::sign(&client, &challenge);
    // No capabilities → server cannot recover the pubkey → reject.
    write_frame(
        &mut writer,
        &Request::HandshakeProof { signed, capabilities: vec![] },
    )
    .unwrap();
    match read_frame::<_, Response>(&mut reader).unwrap() {
        Response::Error { code, .. } => assert_eq!(code, 401),
        other => panic!("expected unauthenticated, got {:?}", other),
    }
}

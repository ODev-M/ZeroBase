//! End-to-end test: client SDK ↔ `zerobased`.
//!
//! Boots the daemon on an ephemeral port with a fresh DB, drives the SDK
//! through KV + SQL, then reopens the DB to prove writes hit disk.

use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use secrecy::SecretString;
use zerobase_auth::Identity;
use zerobase_caps::{Capability, CapabilityClaims, Scope};
use zerobase_client::{Client, ClientError};
use zerobase_proto::SqlResult;
use zerobase_server::ServerState;

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Boot a daemon on 127.0.0.1:<ephemeral>, returning the bound address and
/// a parallel copy of the server identity that the test uses to mint caps.
fn boot(dir: &std::path::Path, pass: &SecretString) -> (std::net::SocketAddr, Identity) {
    let server_id = Identity::generate();
    let issuer_copy = Identity::from_secret(server_id.secret_bytes());
    let state = ServerState::new(server_id, dir, pass.clone()).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server_state = Arc::clone(&state);
    thread::spawn(move || {
        let _ = zerobase_server::server::serve(server_state, listener);
    });
    thread::sleep(Duration::from_millis(50));
    (addr, issuer_copy)
}

fn caps_for(client: &Identity, issuer: &Identity, scopes: Vec<Scope>) -> Vec<Capability> {
    let mut out = Vec::with_capacity(scopes.len() + 1);
    // Self-cap to convey the client's pubkey to the server.
    out.push(
        Capability::issue(
            client,
            CapabilityClaims {
                subject: client.public().id,
                scope: Scope::KvRead { prefix: vec![] },
                expires_at: now() + 300,
            },
        )
        .unwrap(),
    );
    for scope in scopes {
        out.push(
            Capability::issue(
                issuer,
                CapabilityClaims {
                    subject: client.public().id,
                    scope,
                    expires_at: now() + 300,
                },
            )
            .unwrap(),
        );
    }
    out
}

#[test]
fn kv_roundtrip_through_sdk() {
    let dir = tempfile::tempdir().unwrap();
    let pass = SecretString::new("pw".into());
    {
        zerobase::Db::create(dir.path(), &pass).unwrap();
    }
    let (addr, issuer) = boot(dir.path(), &pass);

    let client_id = Identity::generate();
    let caps = caps_for(
        &client_id,
        &issuer,
        vec![
            Scope::KvRead { prefix: vec![] },
            Scope::KvWrite { prefix: vec![] },
        ],
    );

    let mut client = Client::connect(addr, &client_id, caps).unwrap();
    assert!(!client.granted_scopes().is_empty());

    client.kv_put(b"alpha", b"one").unwrap();
    client.kv_put(b"beta", b"two").unwrap();
    client.kv_put(b"gamma", b"three").unwrap();

    assert_eq!(client.kv_get(b"alpha").unwrap().as_deref(), Some(b"one".as_slice()));
    assert_eq!(client.kv_get(b"missing").unwrap(), None);

    let mut scan = client.kv_scan(b"", None).unwrap();
    scan.sort_by(|a, b| a.0.cmp(&b.0));
    let keys: Vec<&[u8]> = scan.iter().map(|(k, _)| k.as_slice()).collect();
    assert_eq!(keys, vec![&b"alpha"[..], &b"beta"[..], &b"gamma"[..]]);

    client.kv_delete(b"beta").unwrap();
    assert_eq!(client.kv_get(b"beta").unwrap(), None);

    client.bye().unwrap();
}

#[test]
fn forbidden_when_scope_missing() {
    let dir = tempfile::tempdir().unwrap();
    let pass = SecretString::new("pw".into());
    {
        zerobase::Db::create(dir.path(), &pass).unwrap();
    }
    let (addr, issuer) = boot(dir.path(), &pass);

    let client_id = Identity::generate();
    // Only read scope — write must be denied.
    let caps = caps_for(&client_id, &issuer, vec![Scope::KvRead { prefix: vec![] }]);
    let mut client = Client::connect(addr, &client_id, caps).unwrap();

    let err = client.kv_put(b"x", b"y").unwrap_err();
    match err {
        ClientError::Server { code, .. } => assert_eq!(code, 403),
        other => panic!("expected 403, got {other:?}"),
    }
}

#[test]
fn sql_through_sdk() {
    let dir = tempfile::tempdir().unwrap();
    let pass = SecretString::new("pw".into());
    {
        zerobase::Db::create(dir.path(), &pass).unwrap();
    }
    let (addr, issuer) = boot(dir.path(), &pass);

    let client_id = Identity::generate();
    let caps = caps_for(
        &client_id,
        &issuer,
        vec![
            Scope::SqlWrite { table: "users".into() },
            Scope::SqlRead { table: "users".into() },
        ],
    );
    let mut client = Client::connect(addr, &client_id, caps).unwrap();

    match client.sql("CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT)").unwrap() {
        SqlResult::DdlOk => {}
        other => panic!("expected DdlOk, got {other:?}"),
    }
    match client.sql("INSERT INTO users (id, name) VALUES (1, 'alice')").unwrap() {
        SqlResult::Affected(n) => assert_eq!(n, 1),
        other => panic!("expected Affected, got {other:?}"),
    }
    match client.sql("SELECT id, name FROM users").unwrap() {
        SqlResult::Rows { columns, rows } => {
            assert_eq!(columns, vec!["id", "name"]);
            assert_eq!(rows.len(), 1);
        }
        other => panic!("expected Rows, got {other:?}"),
    }
}

#[test]
fn handshake_fails_without_caps() {
    let dir = tempfile::tempdir().unwrap();
    let pass = SecretString::new("pw".into());
    {
        zerobase::Db::create(dir.path(), &pass).unwrap();
    }
    let (addr, _issuer) = boot(dir.path(), &pass);

    let client_id = Identity::generate();
    match Client::connect(addr, &client_id, vec![]) {
        Err(ClientError::Server { code, .. }) => assert_eq!(code, 401),
        Ok(_) => panic!("expected handshake to fail"),
        Err(e) => panic!("expected 401, got {e:?}"),
    }
}

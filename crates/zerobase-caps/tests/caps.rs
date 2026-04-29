//! Capability issue/verify tests.

use zerobase_auth::Identity;
use zerobase_caps::{Capability, CapError, CapabilityClaims, Scope};

fn fixed_now() -> u64 {
    1_700_000_000
}

#[test]
fn issue_then_verify_passes() {
    let server = Identity::generate();
    let alice = Identity::generate();
    let now = fixed_now();

    let cap = Capability::issue(
        &server,
        CapabilityClaims {
            subject: alice.public().id.clone(),
            scope: Scope::KvRead { prefix: b"users/alice/".to_vec() },
            expires_at: now + 60,
        },
    )
    .unwrap();

    let trusted = vec![server.public().clone()];
    cap.verify(
        &alice.public().id,
        &Scope::KvRead { prefix: b"users/alice/contacts".to_vec() },
        now,
        &trusted,
    )
    .unwrap();
}

#[test]
fn expired_capability_is_rejected() {
    let server = Identity::generate();
    let alice = Identity::generate();
    let now = fixed_now();

    let cap = Capability::issue(
        &server,
        CapabilityClaims {
            subject: alice.public().id.clone(),
            scope: Scope::KvRead { prefix: b"x".to_vec() },
            expires_at: now,
        },
    )
    .unwrap();

    let trusted = vec![server.public().clone()];
    let err = cap
        .verify(&alice.public().id, &Scope::KvRead { prefix: b"x".to_vec() }, now, &trusted)
        .unwrap_err();
    assert!(matches!(err, CapError::Expired));
}

#[test]
fn untrusted_issuer_is_rejected() {
    let server = Identity::generate();
    let attacker = Identity::generate();
    let alice = Identity::generate();
    let now = fixed_now();

    let cap = Capability::issue(
        &attacker,
        CapabilityClaims {
            subject: alice.public().id.clone(),
            scope: Scope::KvWrite { prefix: b"x".to_vec() },
            expires_at: now + 60,
        },
    )
    .unwrap();

    let trusted = vec![server.public().clone()];
    let err = cap
        .verify(&alice.public().id, &Scope::KvWrite { prefix: b"x".to_vec() }, now, &trusted)
        .unwrap_err();
    assert!(matches!(err, CapError::UntrustedIssuer));
}

#[test]
fn subject_mismatch_is_rejected() {
    let server = Identity::generate();
    let alice = Identity::generate();
    let bob = Identity::generate();
    let now = fixed_now();

    let cap = Capability::issue(
        &server,
        CapabilityClaims {
            subject: alice.public().id.clone(),
            scope: Scope::KvRead { prefix: b"x".to_vec() },
            expires_at: now + 60,
        },
    )
    .unwrap();

    let trusted = vec![server.public().clone()];
    let err = cap
        .verify(&bob.public().id, &Scope::KvRead { prefix: b"x".to_vec() }, now, &trusted)
        .unwrap_err();
    assert!(matches!(err, CapError::SubjectMismatch));
}

#[test]
fn scope_outside_prefix_is_denied() {
    let server = Identity::generate();
    let alice = Identity::generate();
    let now = fixed_now();

    let cap = Capability::issue(
        &server,
        CapabilityClaims {
            subject: alice.public().id.clone(),
            scope: Scope::KvRead { prefix: b"users/alice/".to_vec() },
            expires_at: now + 60,
        },
    )
    .unwrap();

    let trusted = vec![server.public().clone()];
    let err = cap
        .verify(
            &alice.public().id,
            &Scope::KvRead { prefix: b"users/bob/secrets".to_vec() },
            now,
            &trusted,
        )
        .unwrap_err();
    assert!(matches!(err, CapError::ScopeDenied));
}

#[test]
fn write_implies_read() {
    let server = Identity::generate();
    let alice = Identity::generate();
    let now = fixed_now();

    let cap = Capability::issue(
        &server,
        CapabilityClaims {
            subject: alice.public().id.clone(),
            scope: Scope::KvWrite { prefix: b"sessions/".to_vec() },
            expires_at: now + 60,
        },
    )
    .unwrap();

    let trusted = vec![server.public().clone()];
    cap.verify(
        &alice.public().id,
        &Scope::KvRead { prefix: b"sessions/abc".to_vec() },
        now,
        &trusted,
    )
    .unwrap();
}

#[test]
fn tampered_signature_is_rejected() {
    let server = Identity::generate();
    let alice = Identity::generate();
    let now = fixed_now();

    let mut cap = Capability::issue(
        &server,
        CapabilityClaims {
            subject: alice.public().id.clone(),
            scope: Scope::KvRead { prefix: b"x".to_vec() },
            expires_at: now + 60,
        },
    )
    .unwrap();

    cap.signature[0] ^= 0xFF;

    let trusted = vec![server.public().clone()];
    let err = cap
        .verify(&alice.public().id, &Scope::KvRead { prefix: b"x".to_vec() }, now, &trusted)
        .unwrap_err();
    assert!(matches!(err, CapError::BadSignature));
}

#[test]
fn sql_table_match() {
    let server = Identity::generate();
    let alice = Identity::generate();
    let now = fixed_now();

    let cap = Capability::issue(
        &server,
        CapabilityClaims {
            subject: alice.public().id.clone(),
            scope: Scope::SqlWrite { table: "orders".into() },
            expires_at: now + 60,
        },
    )
    .unwrap();
    let trusted = vec![server.public().clone()];

    cap.verify(&alice.public().id, &Scope::SqlRead { table: "orders".into() }, now, &trusted)
        .unwrap();

    let err = cap
        .verify(&alice.public().id, &Scope::SqlWrite { table: "customers".into() }, now, &trusted)
        .unwrap_err();
    assert!(matches!(err, CapError::ScopeDenied));
}

//! End-to-end tests for the Week 4 auth surface.

use zerobase_auth::{
    AuthError, Challenge, ChainEntry, Identity, IdentityChain, PublicIdentity, SignedChallenge,
};

#[test]
fn identity_round_trips_through_secret_seed() {
    let id = Identity::generate();
    let secret = id.secret_bytes();
    let restored = Identity::from_secret(secret);
    assert_eq!(id.id(), restored.id());
    assert_eq!(id.public(), restored.public());
}

#[test]
fn challenge_signed_and_verified() {
    let id = Identity::generate();
    let pubid = id.public().clone();

    let challenge = Challenge::new();
    let signed = SignedChallenge::sign(&id, &challenge);

    signed.verify(&pubid).expect("valid signature must verify");
}

#[test]
fn signed_challenge_rejects_wrong_identity() {
    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let challenge = Challenge::new();
    let signed = SignedChallenge::sign(&id_a, &challenge);

    let err = signed.verify(id_b.public()).unwrap_err();
    assert!(matches!(err, AuthError::IdentityMismatch));
}

#[test]
fn signed_challenge_rejects_tampered_nonce() {
    let id = Identity::generate();
    let challenge = Challenge::new();
    let mut signed = SignedChallenge::sign(&id, &challenge);
    signed.challenge.nonce[0] ^= 0xff;
    let err = signed.verify(id.public()).unwrap_err();
    assert!(matches!(err, AuthError::BadSignature));
}

#[test]
fn challenge_round_trips_through_bincode() {
    let id = Identity::generate();
    let signed = SignedChallenge::sign(&id, &Challenge::new());
    let bytes = bincode::serialize(&signed).unwrap();
    let decoded: SignedChallenge = bincode::deserialize(&bytes).unwrap();
    assert_eq!(signed, decoded);
    decoded.verify(id.public()).unwrap();
}

#[test]
fn identity_chain_genesis_verifies() {
    let id = Identity::generate();
    let chain = IdentityChain::genesis(id.public());
    chain.verify().unwrap();
    assert_eq!(chain.len(), 1);
    assert_eq!(chain.id(), Some(id.id()));
}

#[test]
fn identity_chain_rotation_verifies() {
    let id_v1 = Identity::generate();
    let id_v2 = Identity::generate();
    let id_v3 = Identity::generate();

    let mut chain = IdentityChain::genesis(id_v1.public());
    chain.rotate(&id_v1, id_v2.public()).unwrap();
    chain.rotate(&id_v2, id_v3.public()).unwrap();

    chain.verify().unwrap();
    assert_eq!(chain.len(), 3);
    assert_eq!(chain.tip().unwrap().public, *id_v3.public());
    assert_eq!(chain.id(), Some(id_v1.id()));
}

#[test]
fn rotation_with_wrong_prev_rejected() {
    let id_v1 = Identity::generate();
    let id_v2 = Identity::generate();
    let imposter = Identity::generate();

    let mut chain = IdentityChain::genesis(id_v1.public());
    let err = chain.rotate(&imposter, id_v2.public()).unwrap_err();
    assert!(matches!(err, AuthError::IdentityMismatch));
}

#[test]
fn tampered_chain_link_fails_verify() {
    let id_v1 = Identity::generate();
    let id_v2 = Identity::generate();
    let imposter = Identity::generate();

    let mut chain = IdentityChain::genesis(id_v1.public());
    chain.rotate(&id_v1, id_v2.public()).unwrap();

    // Append a forged link signed by an unrelated key.
    let third = Identity::generate();
    let bogus_signature = imposter.sign(b"anything");
    chain.push_raw(ChainEntry {
        public: PublicIdentity::from_bytes(third.public().public_key),
        signature: bogus_signature,
    });

    let err = chain.verify().unwrap_err();
    assert!(matches!(err, AuthError::BrokenChain));
}

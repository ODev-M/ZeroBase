//! Local identity: an Ed25519 keypair plus a stable BLAKE3 fingerprint.
//!
//! `Identity` owns the private key and zeroizes it on drop. `PublicIdentity`
//! is the exportable part: pubkey + id, suitable for sharing or persisting
//! in plaintext.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::error::AuthError;

/// 32-byte BLAKE3 hash of the public key. Used as a stable handle for an
/// identity even across local key rotations within a chain.
pub type IdentityId = [u8; 32];

/// Public, shareable view of an identity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicIdentity {
    pub id: IdentityId,
    pub public_key: [u8; 32],
}

impl PublicIdentity {
    pub fn from_bytes(public_key: [u8; 32]) -> Self {
        Self { id: fingerprint(&public_key), public_key }
    }

    pub(crate) fn verifying_key(&self) -> Result<VerifyingKey, AuthError> {
        VerifyingKey::from_bytes(&self.public_key).map_err(Into::into)
    }

    /// Verify a detached signature over `msg`.
    pub fn verify(&self, msg: &[u8], signature: &[u8; 64]) -> Result<(), AuthError> {
        let vk = self.verifying_key()?;
        let sig = Signature::from_bytes(signature);
        vk.verify(msg, &sig).map_err(Into::into)
    }
}

/// Local identity: holds the private key. Drop zeroizes the secret bytes.
#[derive(ZeroizeOnDrop)]
pub struct Identity {
    #[zeroize(skip)]
    public: PublicIdentity,
    secret: [u8; SECRET_KEY_LENGTH],
}

impl Identity {
    /// Generate a fresh identity from the OS RNG.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        Self::from_signing_key(signing)
    }

    /// Reconstruct from a 32-byte secret seed (Ed25519 spec).
    pub fn from_secret(secret: [u8; SECRET_KEY_LENGTH]) -> Self {
        let signing = SigningKey::from_bytes(&secret);
        Self::from_signing_key(signing)
    }

    fn from_signing_key(signing: SigningKey) -> Self {
        let pk_bytes = signing.verifying_key().to_bytes();
        let secret = signing.to_bytes();
        Self { public: PublicIdentity::from_bytes(pk_bytes), secret }
    }

    pub fn public(&self) -> &PublicIdentity {
        &self.public
    }

    pub fn id(&self) -> IdentityId {
        self.public.id
    }

    pub fn secret_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.secret
    }

    /// Sign `msg` with the identity's private key.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let signing = SigningKey::from_bytes(&self.secret);
        signing.sign(msg).to_bytes()
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity").field("id", &hex::encode(self.public.id)).finish()
    }
}

fn fingerprint(public_key: &[u8; 32]) -> IdentityId {
    let mut out = [0u8; 32];
    out.copy_from_slice(blake3::hash(public_key).as_bytes());
    out
}

//! Identity: chain-signer public keys and JWT evidence signing, both kept
//! behind traits so this crate never needs to receive, generate, or store a
//! caller's long-lived private key material itself.
//!
//! Two different keys are in play here, and they get two different traits:
//!
//! - A chain identity ([`ChainIdentity`]) only ever needs to expose a
//!   *public* key — submitting a signed chain transaction (creating a ring,
//!   granting an ACP relation, ...) is operator/admin work, out of scope for
//!   this crate. So this trait never signs anything.
//! - JWT evidence ([`JwtIdentitySigner`]) does need a real signature, so its
//!   trait signs — but only ever receives the exact bytes to sign, never the
//!   key itself.
//!
//! PRE's ephemeral reader keypair is deliberately *not* behind either trait
//! — see [`crate::pre`]'s own doc comment for why.

use sha2::{Digest, Sha256};

use crate::error::{Result, SdkError};

/// A chain identity's public key — enough to derive the `did:key` ACP
/// resolves a signed transaction's actor to (see [`derive_signer_did`]),
/// never the private key that produced it. A caller with its own key
/// custody (HSM, KMS, OS keychain) implements this directly over its own
/// client; [`InMemoryChainIdentity`] is the convenience on-ramp for a
/// caller that already holds raw key bytes.
pub trait ChainIdentity {
    /// Compressed SEC1 secp256k1 public key (33 bytes).
    fn compressed_public_key(&self) -> [u8; 33];
}

/// A [`ChainIdentity`] backed by a raw secp256k1 private key held in
/// process memory for the lifetime of this value.
pub struct InMemoryChainIdentity {
    signing_key: cosmrs::crypto::secp256k1::SigningKey,
}

impl InMemoryChainIdentity {
    /// Builds an identity from a hex-encoded secp256k1 private key. Unlike
    /// chain transaction signing, deriving a DID from a public key needs no
    /// `ChainConfig` (no account prefix, no RPC endpoint) — it's pure key
    /// math.
    pub fn from_hex_key(hex_key: &str) -> Result<Self> {
        let key_bytes = hex::decode(hex_key)
            .map_err(|e| SdkError::Encoding(format!("invalid hex key: {e}")))?;
        let signing_key = cosmrs::crypto::secp256k1::SigningKey::from_slice(&key_bytes)
            .map_err(|e| SdkError::Crypto(format!("invalid secp256k1 private key: {e}")))?;
        Ok(Self { signing_key })
    }
}

impl ChainIdentity for InMemoryChainIdentity {
    fn compressed_public_key(&self) -> [u8; 33] {
        self.signing_key
            .public_key()
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("cosmrs secp256k1 public key is always a 33-byte compressed point")
    }
}

/// Derives a did:key from a compressed secp256k1 public key, using the same
/// multicodec encoding (0xe7 0x01 prefix, base58) Vera uses to resolve the
/// ACP actor identity for a signed transaction (e.g. `MsgCreateRing`'s
/// `create_ring` permission, `MsgFinalizeRing`'s `update_ring` permission)
/// — a different derivation from the Ed25519 reader-DID scheme
/// ([`reader_did_from_seed`]), since those transactions are authenticated
/// by tx signature, not a JWT.
pub fn secp256k1_pubkey_to_did(compressed_pubkey: &[u8; 33]) -> String {
    let mut prefixed = Vec::with_capacity(2 + compressed_pubkey.len());
    prefixed.extend_from_slice(&[0xe7, 0x01]);
    prefixed.extend_from_slice(compressed_pubkey);
    format!("did:key:z{}", bs58::encode(&prefixed).into_string())
}

/// Derives the compressed secp256k1 public key (hex) and did:key for a
/// chain identity. Pure local computation, no network calls. Use this to
/// find out, ahead of time, which DID needs an ACP relation granted (e.g.
/// `ring_creator`) before a transaction signed with this identity's key —
/// such as `create-ring` — will be authorized.
pub fn derive_signer_did(identity: &impl ChainIdentity) -> (String, String) {
    let compressed = identity.compressed_public_key();
    let pubkey_hex = hex::encode(compressed);
    let did = secp256k1_pubkey_to_did(&compressed);
    (pubkey_hex, did)
}

/// Derive a 32-byte seed from an arbitrary string via SHA-256. Hashing to 32
/// bytes ensures a consistent, reproducible identity for any input length —
/// the lower-security convenience this ecosystem's tooling has long used
/// for quick dev/test identities (`--reader-did-pk`), not a substitute for
/// a securely generated key in production.
pub fn did_seed(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}

/// Derive the Ed25519 did:key from an arbitrary seed string — the same
/// scheme every JWT-authenticated orbis-node endpoint accepts via
/// `--reader-did-pk` (PRE, Sign, StoreSecret). Public so a caller granting
/// an ACP relation to a chosen seed (e.g. an "owner" relation for a PET
/// audit target) can independently recompute the exact DID that ends up
/// on-chain.
pub fn reader_did_from_seed(seed: &str) -> String {
    authn::JwtSigner::from_seed(did_seed(seed)).did_uri
}

/// Signs JWT evidence as a `did:key` identity's Ed25519 keypair, without
/// this crate ever needing to hold or generate that keypair itself. JWT
/// assembly ([`crate::jwt`]) reuses `authn::BearerToken`'s exact wire
/// format, so a signature produced through any implementation of this
/// trait verifies identically to one `authn::JwtSigner` would have produced
/// for the same key.
pub trait JwtIdentitySigner {
    /// This identity's `did:key:z...` URI.
    fn did(&self) -> &str;
    /// Signs `signing_input` (a JWT's `base64url(header).base64url(payload)`)
    /// and returns the raw 64-byte Ed25519 signature.
    fn sign(&self, signing_input: &[u8]) -> [u8; 64];
}

/// A [`JwtIdentitySigner`] backed by a raw Ed25519 seed held in process
/// memory for the lifetime of this value — the convenience on-ramp for a
/// caller that already has key bytes (or just a string it's happy to hash
/// into one via [`InMemoryEd25519Signer::from_seed_str`]). A caller with its
/// own key custody implements [`JwtIdentitySigner`] directly instead, and
/// never hands this crate anything but a signature.
pub struct InMemoryEd25519Signer {
    seed: zeroize::Zeroizing<[u8; 32]>,
    did_uri: String,
}

impl InMemoryEd25519Signer {
    /// Builds a signer from a raw 32-byte Ed25519 seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let did_uri = authn::JwtSigner::from_seed(seed).did_uri;
        Self {
            seed: zeroize::Zeroizing::new(seed),
            did_uri,
        }
    }

    /// Builds a signer from an arbitrary string, hashed into a seed via
    /// [`did_seed`] — the same low-security dev/test convenience
    /// [`reader_did_from_seed`] offers for deriving a DID alone. Prefer
    /// [`InMemoryEd25519Signer::from_seed`] with real key material for
    /// anything production-grade.
    pub fn from_seed_str(seed: &str) -> Self {
        Self::from_seed(did_seed(seed))
    }
}

impl JwtIdentitySigner for InMemoryEd25519Signer {
    fn did(&self) -> &str {
        &self.did_uri
    }

    fn sign(&self, signing_input: &[u8]) -> [u8; 64] {
        let key_pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(self.seed.as_ref())
            .expect("a 32-byte Ed25519 seed is always valid");
        key_pair
            .sign(signing_input)
            .as_ref()
            .try_into()
            .expect("an Ed25519 signature is always 64 bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_seed_is_always_32_bytes() {
        assert_eq!(did_seed("").len(), 32);
        assert_eq!(
            did_seed("a much longer input string than 32 bytes").len(),
            32
        );
    }

    #[test]
    fn did_seed_is_deterministic_and_input_sensitive() {
        assert_eq!(did_seed("alice"), did_seed("alice"));
        assert_ne!(did_seed("alice"), did_seed("bob"));
    }

    #[test]
    fn reader_did_from_seed_is_deterministic_and_starts_with_did_key() {
        let did = reader_did_from_seed("alice");
        assert!(did.starts_with("did:key:"));
        assert_eq!(did, reader_did_from_seed("alice"));
        assert_ne!(did, reader_did_from_seed("bob"));
    }

    #[test]
    fn in_memory_ed25519_signer_sign_matches_ring_directly() {
        let seed = did_seed("alice");
        let signer = InMemoryEd25519Signer::from_seed(seed);
        assert_eq!(signer.did(), reader_did_from_seed("alice"));

        let key_pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let expected = key_pair.sign(b"hello").as_ref().to_vec();
        assert_eq!(signer.sign(b"hello").to_vec(), expected);
    }

    #[test]
    fn derive_signer_did_round_trips_from_a_hex_key() {
        // A fixed, arbitrary 32-byte secp256k1 private key (64 hex chars).
        let hex_key = "1".repeat(64);
        let identity = InMemoryChainIdentity::from_hex_key(&hex_key).expect("valid key");
        let (pubkey_hex, did) = derive_signer_did(&identity);
        assert!(!pubkey_hex.is_empty());
        assert!(did.starts_with("did:key:z"));
        // Deterministic for the same key.
        let identity_again = InMemoryChainIdentity::from_hex_key(&hex_key).expect("valid key");
        assert_eq!(derive_signer_did(&identity_again), (pubkey_hex, did));
    }
}

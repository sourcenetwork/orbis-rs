//! Crypto trait definitions
//!
//! This module defines the core cryptography abstractions that can be implemented
//! by various Curves.
use crate::error::Result;
use std::collections::HashMap;
use std::fmt::Debug;

/// A share distributed by one participant to another
#[derive(Clone, Debug)]
pub struct DistributedShare<ShareValue> {
    pub from_id: u32,
    pub to_id: u32,
    pub value: ShareValue,
    pub nonce: [u8; 16], // Nonce to prevent replay attacks
    pub session_id: u64, // Session ID to prevent replay attacks
}

/// Private share containing an index and a scalar value
#[derive(Clone, Debug)]
pub struct PriShare<ShareValue> {
    pub i: u32,
    pub v: ShareValue,
}

pub trait PubPoly: Clone + Debug + Send + Sync {
    type PublicKey;
    /// Evaluate the public polynomial at index i
    fn eval(&self, i: u32) -> Self::PublicKey;
}

pub trait PolynomialCommitment: Clone + Debug + Send + Sync {
    type PublicKey;
    type ShareValue;
    /// Evaluate the polynomial commitment at index i
    fn eval(&self, i: u32) -> Self::PublicKey;
    /// Verify a share against this commitment using constant-time comparison
    fn verify_share(&self, share_id: u32, share_value: &Self::ShareValue) -> bool;
}
/// Trait for DKG
pub trait Dkg: Send + Sync {
    type ShareValue;
    type PublicKey;
    type PubPoly: PubPoly<PublicKey = Self::PublicKey>;
    type PolynomialCommitment: PolynomialCommitment<
        PublicKey = Self::PublicKey,
        ShareValue = Self::ShareValue,
    >;
    /// Initialize a new DKG node
    ///
    /// # Arguments
    /// * `id` - Unique identifier for this node (1-indexed)
    /// * `threshold` - Minimum number of nodes needed to reconstruct (t)
    /// * `total_nodes` - Total number of participating nodes (n)
    fn new(id: u32, threshold: usize, total_nodes: usize) -> Result<Box<Self>>
    where
        Self: Sized;
    /// Phase 1: Generate and broadcast polynomial commitment
    ///
    /// Each node generates a random polynomial of degree (threshold - 1)
    /// and creates commitments to its coefficients.
    fn generate_polynomial(&mut self) -> Result<()>;
    /// Phase 2: Generate shares for all other nodes
    ///
    /// Returns a vector of shares to be sent to each node
    fn generate_shares(&self) -> Result<Vec<DistributedShare<Self::ShareValue>>>;

    /// Phase 3: Receive and verify a share from another node
    fn receive_share(&mut self, share: DistributedShare<Self::ShareValue>) -> Result<()>;

    /// Receive a commitment from another node
    fn receive_commitment(
        &mut self,
        from_id: u32,
        commitment: Self::PolynomialCommitment,
    ) -> Result<()>;

    /// Phase 4: Compute the final secret share
    ///
    /// Once all shares are received and verified, compute the final share
    /// by summing all received shares (including own share)
    fn compute_secret_share(&self) -> Result<PriShare<Self::ShareValue>>;

    /// Compute the aggregate public key
    ///
    /// The aggregate public key is the sum of all nodes' constant terms
    /// in their polynomial commitments
    fn compute_aggregate_public_key(&self) -> Result<Self::PublicKey>;
    /// Get complaints about malicious nodes
    fn get_complaints(&self) -> &HashMap<u32, Vec<u32>>;
    /// Compute the public polynomial (sum of all commitments)
    ///
    /// This is used for verification in the re-encryption protocol
    fn compute_public_polynomial(&self) -> Result<Self::PubPoly>;
}

/// Trait for PRE
pub trait ThresholdDealer {
    type DistKeyShare;
    type Secret;
    type PublicKey;
    type ShareValue;
    type ReencryptReply;
    type PubPoly: PubPoly<PublicKey = Self::PublicKey>;
    type PubShare;

    /// Re-encrypt a secret share using the receiver's public key.
    ///
    /// Input:
    ///   dkg_ski (ski) - Private share of secret key of DKG.
    ///   rdr_pk  (xG)  - Public key of the reader.
    ///   enc_cmt (rG)  - Schnorr commit of encoded keys.
    ///
    /// Output:
    ///   xnc_ski (Ui) - Re-encrypted secret share.
    ///   chlgi  (ei)  - Random oracle challenge.
    ///   proofi (fi)  - NIZK proof of re-encryption.
    fn reencrypt(
        &self,
        dist_key_share: &Self::DistKeyShare,
        scrt: &Self::Secret,
        rdr_pk: &Self::PublicKey,
    ) -> Result<Self::ReencryptReply>;

    /// Verify a re-encryption proof.
    ///
    /// Input:
    ///   rdr_pk  (xG)  - Public key of the reader.
    ///   enc_cmt (rG)  - Schnorr commit of encoded keys.
    ///   dkg_ski (Ui)  - Re-encrypted share of commitment.
    ///   chlgi  (ei)   - Random oracle challenge at index i.
    ///   proofi (fi)   - NIZK proof of re-encryption at index i.
    ///   dkg_cmt (ci)  - Commitment (public polynomial) of DKG at index i.
    fn verify(
        &self,
        rdr_pk: &Self::PublicKey,
        dkg_cmt: &Self::PubPoly,
        enc_cmt: &Self::PublicKey,
        reply: &Self::ReencryptReply,
    ) -> Result<()>;

    /// Recover the re-encrypted commitment from shares
    fn recover(
        &self,
        xnc_ski: &[Self::PubShare],
        t: usize,
        n: usize,
    ) -> Result<Option<Self::PublicKey>>;

    // TODO: next two functions are not needed in PRE at the node but for encryptor and decryptor
    // may want to remove them from this trait, however it does need to exist for an implementation to be complete and tested
    // think on this

    /// Encrypt a secret using the aggregate public key of the DKG.
    ///
    /// Input:
    ///   dkg_pk (sG) - Aggregate public key of the DKG.
    ///   scrt  (k)   - Secret to be encrypted.
    ///
    /// Output:
    ///   enc_cmt  - Schnorr commit (rG)
    ///   enc_scrt - Encrypted key-slices (rsG + Ki)
    fn encrypt_secret(
        dkg_pk: &Self::PublicKey,
        data: &[u8],
    ) -> Result<(Self::PublicKey, Self::Secret)>;

    /// Decrypt a secret using the reader's secret key.
    ///
    /// Input:
    ///   dkg_pk  (sG)       - Aggregate public key of DKG.
    ///   xnc_cmt (rsG + xsG) - Re-encrypted schnorr-commit.
    ///   rdr_sk  (x)        - Secret key of the reader.
    ///
    /// Output:
    ///   scrt - Recovered secret.
    fn decrypt_secret(
        dkg_pk: &Self::PublicKey,
        xnc_cmt: &Self::PublicKey, // Recovered from re-encryption
        rdr_sk: &Self::ShareValue,
        secret: &Self::Secret,
    ) -> Result<Vec<u8>>;
}

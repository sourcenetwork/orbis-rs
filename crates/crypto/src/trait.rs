//! Crypto trait definitions
//!
//! This module defines the core cryptography abstractions that can be implemented
//! by various Curves.
use crate::error::Result;
use std::collections::HashMap;
use std::fmt::Debug;

/// Trait for types that can be serialized to bytes.
///
/// This provides a generic interface for crypto type serialization,
/// allowing implementations to use any serialization format (e.g., ark-serialize).
pub trait CryptoSerialize: Sized {
    /// Serialize this value to bytes (compressed format preferred).
    fn to_bytes(&self) -> Result<Vec<u8>>;

    /// Returns the size in bytes of the serialized representation.
    /// This can be used for pre-allocation and validation.
    fn serialized_size() -> usize;
}

/// Trait for types that can be deserialized from bytes.
///
/// This provides a generic interface for crypto type deserialization,
/// allowing implementations to use any serialization format (e.g., ark-serialize).
pub trait CryptoDeserialize: Sized {
    /// Deserialize a value from bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

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

/// Public share containing an index and a point value
#[derive(Clone, Debug)]
pub struct PubShare<PublicKey> {
    pub i: u32,
    pub v: PublicKey,
}

/// Distributed key share
#[derive(Clone, Debug)]
pub struct DistKeyShare<ShareValue> {
    pub pri_share: PriShare<ShareValue>,
}

/// Secret structure
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Secret {
    pub enc_cmt: Vec<u8>,        // rG - Schnorr commitment
    pub encrypted_data: Vec<u8>, // AES-GCM encrypted data
    pub nonce: Vec<u8>,          // AES-GCM nonce (12 bytes)
    pub auth_tag: Vec<u8>,       // Authentication tag
}

/// Chaum-Pedersen NIZK proof that encryption was performed correctly.
/// Proves that enc_cmt = rG and shared_point = r*dkg_pk use the same randomness r.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EncryptionProof {
    pub shared_point: Vec<u8>, // rsG - the shared point used for key derivation
    pub challenge: Vec<u8>,    // c - Fiat-Shamir challenge
    pub response: Vec<u8>,     // s - proof response (s = k + c*r)
}

/// Re-encryption reply
#[derive(Clone, Debug)]
pub struct ReencryptReply<ShareValue, PublicKey> {
    pub share: PubShare<PublicKey>,
    pub challenge: ShareValue,
    pub proof: ShareValue,
}

// ============================================================================
// Serialization implementations for generic structs
// ============================================================================

impl<ShareValue: CryptoSerialize + CryptoDeserialize> CryptoSerialize
    for DistributedShare<ShareValue>
{
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let value_bytes = self.value.to_bytes()?;
        let value_len = value_bytes.len() as u32;

        // Format: from_id (4) + to_id (4) + session_id (8) + nonce (16) + value_len (4) + value
        let mut bytes = Vec::with_capacity(4 + 4 + 8 + 16 + 4 + value_bytes.len());
        bytes.extend_from_slice(&self.from_id.to_le_bytes());
        bytes.extend_from_slice(&self.to_id.to_le_bytes());
        bytes.extend_from_slice(&self.session_id.to_le_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&value_len.to_le_bytes());
        bytes.extend_from_slice(&value_bytes);
        Ok(bytes)
    }

    fn serialized_size() -> usize {
        // 4 + 4 + 8 + 16 + 4 + ShareValue::serialized_size()
        36 + ShareValue::serialized_size()
    }
}

impl<ShareValue: CryptoSerialize + CryptoDeserialize> CryptoDeserialize
    for DistributedShare<ShareValue>
{
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        use crate::error::CryptoError;

        if bytes.len() < 36 {
            return Err(CryptoError::DKGError(
                "DistributedShare bytes too short".to_string(),
            ));
        }

        let from_id = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| CryptoError::DKGError("Invalid from_id bytes".to_string()))?,
        );
        let to_id = u32::from_le_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| CryptoError::DKGError("Invalid to_id bytes".to_string()))?,
        );
        let session_id = u64::from_le_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| CryptoError::DKGError("Invalid session_id bytes".to_string()))?,
        );
        let nonce: [u8; 16] = bytes[16..32]
            .try_into()
            .map_err(|_| CryptoError::DKGError("Invalid nonce bytes".to_string()))?;
        let value_len = u32::from_le_bytes(
            bytes[32..36]
                .try_into()
                .map_err(|_| CryptoError::DKGError("Invalid value_len bytes".to_string()))?,
        ) as usize;

        if bytes.len() < 36 + value_len {
            return Err(CryptoError::DKGError(
                "DistributedShare bytes too short for value".to_string(),
            ));
        }

        let value = ShareValue::from_bytes(&bytes[36..36 + value_len])?;

        Ok(Self {
            from_id,
            to_id,
            value,
            nonce,
            session_id,
        })
    }
}

impl<ShareValue: CryptoSerialize + CryptoDeserialize> CryptoSerialize for PriShare<ShareValue> {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let value_bytes = self.v.to_bytes()?;

        // Format: i (4) + value
        let mut bytes = Vec::with_capacity(4 + value_bytes.len());
        bytes.extend_from_slice(&self.i.to_le_bytes());
        bytes.extend_from_slice(&value_bytes);
        Ok(bytes)
    }

    fn serialized_size() -> usize {
        4 + ShareValue::serialized_size()
    }
}

impl<ShareValue: CryptoSerialize + CryptoDeserialize> CryptoDeserialize for PriShare<ShareValue> {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        use crate::error::CryptoError;

        if bytes.len() < 4 {
            return Err(CryptoError::DKGError(
                "PriShare bytes too short".to_string(),
            ));
        }

        let i = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| CryptoError::DKGError("Invalid PriShare index bytes".to_string()))?,
        );
        let v = ShareValue::from_bytes(&bytes[4..])?;

        Ok(Self { i, v })
    }
}

impl<PublicKey: CryptoSerialize + CryptoDeserialize> CryptoSerialize for PubShare<PublicKey> {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let value_bytes = self.v.to_bytes()?;

        // Format: i (4) + value
        let mut bytes = Vec::with_capacity(4 + value_bytes.len());
        bytes.extend_from_slice(&self.i.to_le_bytes());
        bytes.extend_from_slice(&value_bytes);
        Ok(bytes)
    }

    fn serialized_size() -> usize {
        4 + PublicKey::serialized_size()
    }
}

impl<PublicKey: CryptoSerialize + CryptoDeserialize> CryptoDeserialize for PubShare<PublicKey> {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        use crate::error::CryptoError;

        if bytes.len() < 4 {
            return Err(CryptoError::DKGError(
                "PubShare bytes too short".to_string(),
            ));
        }

        let i = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| CryptoError::DKGError("Invalid PubShare index bytes".to_string()))?,
        );
        let v = PublicKey::from_bytes(&bytes[4..])?;

        Ok(Self { i, v })
    }
}

impl<ShareValue: CryptoSerialize + CryptoDeserialize> CryptoSerialize for DistKeyShare<ShareValue> {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        self.pri_share.to_bytes()
    }

    fn serialized_size() -> usize {
        PriShare::<ShareValue>::serialized_size()
    }
}

impl<ShareValue: CryptoSerialize + CryptoDeserialize> CryptoDeserialize
    for DistKeyShare<ShareValue>
{
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let pri_share = PriShare::from_bytes(bytes)?;
        Ok(Self { pri_share })
    }
}

impl<
        ShareValue: CryptoSerialize + CryptoDeserialize,
        PublicKey: CryptoSerialize + CryptoDeserialize,
    > CryptoSerialize for ReencryptReply<ShareValue, PublicKey>
{
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let share_bytes = self.share.to_bytes()?;
        let challenge_bytes = self.challenge.to_bytes()?;
        let proof_bytes = self.proof.to_bytes()?;

        // Format: share_len (4) + share + challenge_len (4) + challenge + proof_len (4) + proof
        let mut bytes =
            Vec::with_capacity(12 + share_bytes.len() + challenge_bytes.len() + proof_bytes.len());
        bytes.extend_from_slice(&(share_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&share_bytes);
        bytes.extend_from_slice(&(challenge_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&challenge_bytes);
        bytes.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&proof_bytes);
        Ok(bytes)
    }

    fn serialized_size() -> usize {
        // 4 + PubShare size + 4 + ShareValue size + 4 + ShareValue size
        12 + PubShare::<PublicKey>::serialized_size()
            + ShareValue::serialized_size()
            + ShareValue::serialized_size()
    }
}

impl<
        ShareValue: CryptoSerialize + CryptoDeserialize,
        PublicKey: CryptoSerialize + CryptoDeserialize,
    > CryptoDeserialize for ReencryptReply<ShareValue, PublicKey>
{
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        use crate::error::CryptoError;

        if bytes.len() < 12 {
            return Err(CryptoError::DKGError(
                "ReencryptReply bytes too short".to_string(),
            ));
        }

        let mut offset = 0;

        let share_len = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| CryptoError::DKGError("Invalid share_len bytes".to_string()))?,
        ) as usize;
        offset += 4;
        if bytes.len() < offset + share_len + 8 {
            return Err(CryptoError::DKGError(
                "ReencryptReply bytes too short for share".to_string(),
            ));
        }
        let share = PubShare::from_bytes(&bytes[offset..offset + share_len])?;
        offset += share_len;

        let challenge_len = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| CryptoError::DKGError("Invalid challenge_len bytes".to_string()))?,
        ) as usize;
        offset += 4;
        if bytes.len() < offset + challenge_len + 4 {
            return Err(CryptoError::DKGError(
                "ReencryptReply bytes too short for challenge".to_string(),
            ));
        }
        let challenge = ShareValue::from_bytes(&bytes[offset..offset + challenge_len])?;
        offset += challenge_len;

        let proof_len = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| CryptoError::DKGError("Invalid proof_len bytes".to_string()))?,
        ) as usize;
        offset += 4;
        if bytes.len() < offset + proof_len {
            return Err(CryptoError::DKGError(
                "ReencryptReply bytes too short for proof".to_string(),
            ));
        }
        let proof = ShareValue::from_bytes(&bytes[offset..offset + proof_len])?;

        Ok(Self {
            share,
            challenge,
            proof,
        })
    }
}

pub trait PubPoly: Clone + Debug + Send + Sync + CryptoSerialize + CryptoDeserialize {
    type PublicKey: CryptoSerialize + CryptoDeserialize;
    /// Evaluate the public polynomial at index i
    fn eval(&self, i: u32) -> Self::PublicKey;
}

pub trait PolynomialCommitment:
    Clone + Debug + Send + Sync + CryptoSerialize + CryptoDeserialize
{
    type PublicKey: CryptoSerialize + CryptoDeserialize;
    type ShareValue: CryptoSerialize + CryptoDeserialize;
    /// Evaluate the polynomial commitment at index i
    fn eval(&self, i: u32) -> Self::PublicKey;
    /// Verify a share against this commitment using constant-time comparison
    fn verify_share(&self, share_id: u32, share_value: &Self::ShareValue) -> bool;
}
/// Trait for DKG
pub trait Dkg: Send + Sync {
    type ShareValue: CryptoSerialize + CryptoDeserialize + Clone;
    type PublicKey: CryptoSerialize + CryptoDeserialize + Clone;
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

    /// Get the node ID
    fn node_id(&self) -> u32;

    /// Get the threshold value
    fn threshold(&self) -> usize;

    /// Get the total number of nodes
    fn total_nodes(&self) -> usize;

    /// Get a reference to the polynomial commitment
    fn commitment(&self) -> &Self::PolynomialCommitment;

    /// Set the session ID for this DKG instance
    ///
    /// This must be called after creating a new DKG node to ensure all nodes
    /// use the same session ID for share verification.
    fn set_session_id(&mut self, session_id: u64);
}

/// Trait for PRE
pub trait ThresholdDealer {
    type DistKeyShare;
    type Secret;
    type PublicKey: CryptoSerialize + CryptoDeserialize + Clone;
    type ShareValue: CryptoSerialize + CryptoDeserialize + Clone;
    type ReencryptReply;
    type PubPoly: PubPoly<PublicKey = Self::PublicKey>;

    fn new() -> Self;
    fn name(&self) -> &str;

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
        xnc_ski: &[PubShare<Self::PublicKey>],
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
    ///   proof    - Chaum-Pedersen NIZK proof of correct encryption
    fn encrypt_secret(
        dkg_pk: &Self::PublicKey,
        data: &[u8],
    ) -> Result<(Self::PublicKey, Self::Secret, EncryptionProof)>;

    /// Verify that a secret was correctly encrypted to the given DKG public key.
    /// Uses Chaum-Pedersen NIZK proof to verify enc_cmt and shared_point use same randomness.
    fn verify_encryption(
        dkg_pk: &Self::PublicKey,
        enc_cmt: &Self::PublicKey,
        proof: &EncryptionProof,
    ) -> Result<()>;

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

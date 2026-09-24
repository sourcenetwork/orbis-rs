//! `CryptoSerialize`/`CryptoDeserialize` implementations for the generic
//! structs in [`super::types`], plus the unit-type impls used by
//! non-interactive signing schemes.

use super::codec::{CryptoDeserialize, CryptoSerialize};
use super::types::{DistKeyShare, DistributedShare, PriShare, PubShare, ReencryptReply};
use crate::error::{CryptoError, Result};
use zeroize::Zeroize;

impl<ShareValue: CryptoSerialize + CryptoDeserialize + Zeroize> CryptoSerialize
    for DistributedShare<ShareValue>
{
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let value_bytes = zeroize::Zeroizing::new(self.value.to_bytes()?);
        let value_len = value_bytes.len() as u32;

        // Format: from_id (4) + to_id (4) + session_id (16) + nonce (16) + value_len (4) + value
        let mut bytes = Vec::with_capacity(4 + 4 + 16 + 16 + 4 + value_bytes.len());
        bytes.extend_from_slice(&self.from_id.to_le_bytes());
        bytes.extend_from_slice(&self.to_id.to_le_bytes());
        bytes.extend_from_slice(&self.session_id.to_le_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&value_len.to_le_bytes());
        bytes.extend_from_slice(&value_bytes);
        Ok(bytes)
    }

    fn min_serialized_size() -> usize {
        // 4 + 4 + 16 + 16 + 4 + ShareValue::min_serialized_size()
        44 + ShareValue::min_serialized_size()
    }
}

impl<ShareValue: CryptoSerialize + CryptoDeserialize + Zeroize> CryptoDeserialize
    for DistributedShare<ShareValue>
{
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 44 {
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
        let session_id = u128::from_le_bytes(
            bytes[8..24]
                .try_into()
                .map_err(|_| CryptoError::DKGError("Invalid session_id bytes".to_string()))?,
        );
        let nonce: [u8; 16] = bytes[24..40]
            .try_into()
            .map_err(|_| CryptoError::DKGError("Invalid nonce bytes".to_string()))?;
        let value_len = u32::from_le_bytes(
            bytes[40..44]
                .try_into()
                .map_err(|_| CryptoError::DKGError("Invalid value_len bytes".to_string()))?,
        ) as usize;

        let expected_len = 44 + value_len;
        if bytes.len() < expected_len {
            return Err(CryptoError::DKGError(
                "DistributedShare bytes too short for value".to_string(),
            ));
        }
        if bytes.len() != expected_len {
            return Err(CryptoError::DKGError(format!(
                "DistributedShare bytes length mismatch: expected {}, got {}",
                expected_len,
                bytes.len()
            )));
        }

        let value = ShareValue::from_bytes(&bytes[44..expected_len])?;

        Ok(Self {
            from_id,
            to_id,
            value,
            nonce,
            session_id,
        })
    }
}

impl<ShareValue: CryptoSerialize + CryptoDeserialize + Zeroize> CryptoSerialize
    for PriShare<ShareValue>
{
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let value_bytes = zeroize::Zeroizing::new(self.v.to_bytes()?);

        // Format: i (4) + value
        let mut bytes = Vec::with_capacity(4 + value_bytes.len());
        bytes.extend_from_slice(&self.i.to_le_bytes());
        bytes.extend_from_slice(&value_bytes);
        Ok(bytes)
    }

    fn min_serialized_size() -> usize {
        4 + ShareValue::min_serialized_size()
    }
}

impl<ShareValue: CryptoSerialize + CryptoDeserialize + Zeroize> CryptoDeserialize
    for PriShare<ShareValue>
{
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
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

    fn min_serialized_size() -> usize {
        4 + PublicKey::min_serialized_size()
    }
}

impl<PublicKey: CryptoSerialize + CryptoDeserialize> CryptoDeserialize for PubShare<PublicKey> {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
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

impl<ShareValue: CryptoSerialize + CryptoDeserialize + Zeroize> CryptoSerialize
    for DistKeyShare<ShareValue>
{
    fn to_bytes(&self) -> Result<Vec<u8>> {
        self.pri_share.to_bytes()
    }

    fn min_serialized_size() -> usize {
        PriShare::<ShareValue>::min_serialized_size()
    }
}

impl<ShareValue: CryptoSerialize + CryptoDeserialize + Zeroize> CryptoDeserialize
    for DistKeyShare<ShareValue>
{
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let pri_share = PriShare::from_bytes(bytes)?;
        Ok(Self { pri_share })
    }
}

impl<
        ShareValue: CryptoSerialize + CryptoDeserialize + Zeroize,
        PublicKey: CryptoSerialize + CryptoDeserialize,
    > CryptoSerialize for ReencryptReply<ShareValue, PublicKey>
{
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let share_bytes = self.share.to_bytes()?;
        let challenge_bytes = zeroize::Zeroizing::new(self.challenge.to_bytes()?);
        let proof_bytes = zeroize::Zeroizing::new(self.proof.to_bytes()?);

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

    fn min_serialized_size() -> usize {
        // 4 + PubShare size + 4 + ShareValue size + 4 + ShareValue size
        12 + PubShare::<PublicKey>::min_serialized_size()
            + ShareValue::min_serialized_size()
            + ShareValue::min_serialized_size()
    }
}

impl<
        ShareValue: CryptoSerialize + CryptoDeserialize + Zeroize,
        PublicKey: CryptoSerialize + CryptoDeserialize,
    > CryptoDeserialize for ReencryptReply<ShareValue, PublicKey>
{
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
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
        let expected_len = offset + proof_len;
        if bytes.len() < expected_len {
            return Err(CryptoError::DKGError(
                "ReencryptReply bytes too short for proof".to_string(),
            ));
        }
        if bytes.len() != expected_len {
            return Err(CryptoError::DKGError(format!(
                "ReencryptReply bytes length mismatch: expected {}, got {}",
                expected_len,
                bytes.len()
            )));
        }
        let proof = ShareValue::from_bytes(&bytes[offset..expected_len])?;

        Ok(Self {
            share,
            challenge,
            proof,
        })
    }
}

// ============================================================================
// CryptoSerialize/CryptoDeserialize for unit type (used by non-interactive schemes)
// ============================================================================

impl CryptoSerialize for () {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn min_serialized_size() -> usize {
        0
    }
}

impl CryptoDeserialize for () {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            Ok(())
        } else {
            Err(CryptoError::SerializationError(
                ark_serialize::SerializationError::InvalidData,
            ))
        }
    }
}

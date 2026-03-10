use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;

use crate::error::{BulletinError, Result};

/// EVM transaction signer wrapping a secp256k1 private key
pub struct EvmSigner {
    signer: PrivateKeySigner,
    chain_id: u64,
}

impl EvmSigner {
    /// Create a signer from a hex-encoded private key and chain ID
    pub fn from_hex(hex_key: &str, chain_id: u64) -> Result<Self> {
        let key_bytes =
            hex::decode(hex_key).map_err(|e| BulletinError::ChainError(format!("Invalid hex key: {}", e)))?;
        let signing_key = k256::ecdsa::SigningKey::from_slice(&key_bytes)
            .map_err(|e| BulletinError::ChainError(format!("Invalid private key: {}", e)))?;
        let signer = PrivateKeySigner::from_signing_key(signing_key);
        Ok(Self { signer, chain_id })
    }

    /// Get the EVM address of this signer
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    /// Sign a legacy transaction and return EIP-2718 encoded bytes
    pub fn sign_tx(&self, to: Address, calldata: Vec<u8>, nonce: u64) -> Result<Vec<u8>> {
        let tx = TxLegacy {
            chain_id: Some(self.chain_id),
            nonce,
            gas_price: 0,
            gas_limit: 10_000_000,
            to: TxKind::Call(to),
            value: U256::ZERO,
            input: calldata.into(),
        };

        let sig_hash = tx.signature_hash();
        let sig = self
            .signer
            .sign_hash_sync(&sig_hash)
            .map_err(|e| BulletinError::ChainError(format!("Failed to sign transaction: {}", e)))?;

        let signed_tx = tx.into_signed(sig);
        Ok(signed_tx.encoded_2718())
    }
}

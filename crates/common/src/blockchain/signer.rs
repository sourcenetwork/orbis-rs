//! Transaction signing for Cosmos SDK chains.

use crate::blockchain::{BlockchainError, ChainConfig, Result};
use cosmrs::{
    crypto::secp256k1::SigningKey,
    tx::{self, Fee, SignDoc, SignerInfo},
    AccountId, Any, Coin,
};
use std::sync::atomic::{AtomicU64, Ordering};

/// Transaction signer using secp256k1.
///
/// The nonce (sequence number) and account number are managed in memory to
/// support concurrent transaction signing without querying the chain each time.
pub struct TxSigner {
    signing_key: SigningKey,
    account_id: AccountId,
    config: ChainConfig,
    /// The account number from the chain (fixed once account is created).
    /// Uses atomic for interior mutability since we set it after construction.
    account_number: AtomicU64,
    /// The current nonce (sequence number) for transaction signing.
    /// Uses atomic operations for thread-safe concurrent access.
    nonce: AtomicU64,
}

impl TxSigner {
    /// Create a new TxSigner from raw private key bytes.
    ///
    /// The nonce is initialized to 0. Call `set_nonce()` after creation
    /// to set the correct sequence number from the chain.
    pub fn new(private_key_bytes: &[u8], config: ChainConfig) -> Result<Self> {
        let signing_key = SigningKey::from_slice(private_key_bytes)
            .map_err(|e| BlockchainError::Signing(format!("Invalid private key: {}", e)))?;

        let public_key = signing_key.public_key();
        let account_id = public_key
            .account_id(&config.account_prefix)
            .map_err(|e| BlockchainError::Signing(format!("Failed to derive account ID: {}", e)))?;

        Ok(Self {
            signing_key,
            account_id,
            config,
            account_number: AtomicU64::new(0),
            nonce: AtomicU64::new(0),
        })
    }

    /// Create a TxSigner from a hex-encoded private key.
    pub fn from_hex_key(hex_key: &str, config: ChainConfig) -> Result<Self> {
        let key_bytes = hex::decode(hex_key)
            .map_err(|e| BlockchainError::Signing(format!("Invalid hex key: {}", e)))?;
        Self::new(&key_bytes, config)
    }

    /// Create a TxSigner from a mnemonic phrase.
    ///
    /// Uses the standard Cosmos HD path: m/44'/118'/0'/0/0
    ///
    /// Note: Requires cosmrs to be built with bip39 support.
    pub fn from_mnemonic(mnemonic_phrase: &str, config: ChainConfig) -> Result<Self> {
        use cosmrs::bip32;

        // Parse mnemonic using English language
        let mnemonic = bip32::Mnemonic::new(mnemonic_phrase, bip32::Language::English)
            .map_err(|e| BlockchainError::Signing(format!("Invalid mnemonic: {}", e)))?;

        let seed = mnemonic.to_seed("");

        // Standard Cosmos HD path: m/44'/118'/0'/0/0
        let path = "m/44'/118'/0'/0/0";
        let child_path: bip32::DerivationPath = path
            .parse()
            .map_err(|e| BlockchainError::Signing(format!("Invalid derivation path: {}", e)))?;

        let child_xprv = bip32::XPrv::derive_from_path(seed, &child_path)
            .map_err(|e| BlockchainError::Signing(format!("Key derivation failed: {}", e)))?;

        let private_key_bytes = child_xprv.private_key().to_bytes();
        Self::new(&private_key_bytes, config)
    }

    /// Get the signer's account address (bech32 encoded).
    pub fn address(&self) -> String {
        self.account_id.to_string()
    }

    /// Get the signer's compressed public key as hex.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.public_key().to_bytes())
    }

    /// Get the signer's account ID.
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Get the account number.
    pub fn account_number(&self) -> u64 {
        self.account_number.load(Ordering::SeqCst)
    }

    /// Set the account number.
    ///
    /// This should be called once when initializing from the chain.
    /// The account number is fixed for an account and doesn't change.
    pub fn set_account_number(&self, value: u64) {
        self.account_number.store(value, Ordering::SeqCst);
    }

    /// Get the current nonce value without modifying it.
    pub fn nonce(&self) -> u64 {
        self.nonce.load(Ordering::SeqCst)
    }

    /// Set the nonce to a specific value.
    ///
    /// Use this to initialize the nonce from the chain's sequence number,
    /// or to resync after a nonce mismatch error.
    pub fn set_nonce(&self, value: u64) {
        self.nonce.store(value, Ordering::SeqCst);
    }

    /// Atomically fetch the current nonce and increment it for the next transaction.
    ///
    /// Returns the nonce value to use for the current transaction.
    /// The internal counter is incremented, so the next call returns nonce + 1.
    ///
    /// This is the primary method for getting nonces when sending transactions,
    /// as it ensures concurrent transactions get unique sequential nonces.
    pub fn fetch_and_increment_nonce(&self) -> u64 {
        self.nonce.fetch_add(1, Ordering::SeqCst)
    }

    /// Sign a transaction.
    ///
    /// # Arguments
    /// * `messages` - The transaction messages (as Any types)
    /// * `account_number` - The account number from the chain
    /// * `sequence` - The account sequence number
    /// * `gas_limit` - Gas limit for the transaction (or None for default)
    /// * `memo` - Optional memo string
    ///
    /// # Returns
    /// The signed transaction as raw bytes, ready to broadcast.
    pub fn sign_tx(
        &self,
        messages: Vec<Any>,
        account_number: u64,
        sequence: u64,
        gas_limit: Option<u64>,
        memo: Option<&str>,
    ) -> Result<Vec<u8>> {
        let gas_limit = gas_limit.unwrap_or(self.config.default_gas_limit);
        let fee_amount = self.config.calculate_fee(gas_limit);

        let fee =
            Fee::from_amount_and_gas(
                Coin {
                    denom: self.config.gas_price.denom.parse().map_err(|e| {
                        BlockchainError::Signing(format!("Invalid fee denom: {}", e))
                    })?,
                    amount: fee_amount.into(),
                },
                gas_limit,
            );

        let tx_body = tx::Body::new(messages, memo.unwrap_or(""), 0u32);

        let auth_info =
            SignerInfo::single_direct(Some(self.signing_key.public_key()), sequence).auth_info(fee);

        let chain_id = self
            .config
            .chain_id
            .parse()
            .map_err(|e| BlockchainError::Signing(format!("Invalid chain ID: {}", e)))?;

        let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id, account_number)
            .map_err(|e| BlockchainError::Signing(format!("Failed to create sign doc: {}", e)))?;

        let tx_signed = sign_doc
            .sign(&self.signing_key)
            .map_err(|e| BlockchainError::Signing(format!("Failed to sign transaction: {}", e)))?;

        tx_signed.to_bytes().map_err(|e| {
            BlockchainError::Signing(format!("Failed to serialize transaction: {}", e))
        })
    }

    /// Create an Any message from a type URL and JSON value.
    ///
    /// This is useful for creating messages when you don't have proto-generated types.
    pub fn create_any_msg(type_url: &str, value: &[u8]) -> Any {
        Any {
            type_url: type_url.to_string(),
            value: value.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_from_hex_key() {
        // Test private key (32 bytes, DO NOT USE IN PRODUCTION)
        // This is just a test key - never use in production
        let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let config = ChainConfig::local();

        let signer = TxSigner::from_hex_key(hex_key, config).unwrap();
        let address = signer.address();

        // Address should be bech32 encoded with the configured prefix
        assert!(address.starts_with("source1"));
        println!("Test address: {}", address);
    }

    #[test]
    fn test_signer_public_key_hex_is_compressed_key() {
        let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let config = ChainConfig::local();

        let signer = TxSigner::from_hex_key(hex_key, config).unwrap();
        let public_key_hex = signer.public_key_hex();

        assert_eq!(public_key_hex.len(), 66);
        assert_eq!(
            public_key_hex,
            hex::encode(signer.signing_key.public_key().to_bytes())
        );
    }

    #[test]
    fn test_signer_from_raw_bytes() {
        // Test with raw bytes
        let key_bytes = [0x01u8; 32]; // Simple test key
        let config = ChainConfig::local();

        let signer = TxSigner::new(&key_bytes, config).unwrap();
        let address = signer.address();

        assert!(address.starts_with("source1"));
    }

    #[test]
    fn print_integration_test_node_keys() {
        // Compute and assert the secp256k1 compressed pubkeys for private keys 1, 2, 3.
        // These are the fixed keys used by the integration-test docker-compose nodes.
        let config = ChainConfig::local();
        for (n, expected) in [
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000003",
                "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            ),
        ] {
            let signer = TxSigner::from_hex_key(n, config.clone()).unwrap();
            let got = signer.public_key_hex();
            println!("privkey={n}\npubkey ={got}");
            assert_eq!(got, expected, "pubkey mismatch for private key {n}");
        }
    }
}

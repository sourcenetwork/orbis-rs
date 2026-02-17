//! Secret lifecycle tests: encrypt → store → reencrypt → decrypt.
//!
//! This is the primary Amygdala use case:
//! 1. Alice encrypts a secret to the ring's collective public key
//! 2. Alice stores the encrypted secret via StoreSecret
//! 3. Bob requests re-encryption via StartPre (authorized by ACP policy)
//! 4. Ring nodes cooperatively re-encrypt (T-of-N must participate)
//! 5. Bob decrypts with his private key
//!
//! Requires: DKG + PRE services, bulletin board, ACP authorization

use std::time::Duration;

use orbis_e2e::ring::OrbisRing;

/// Full secret lifecycle: encrypt, store, reencrypt, decrypt.
#[tokio::test]
#[ignore = "requires DKG + PRE + StoreSecret implementation"]
async fn secret_encrypt_store_reencrypt_decrypt() {
    let ring = OrbisRing::builder()
        .nodes(3)
        .threshold(2)
        .build()
        .await
        .expect("ring should start");

    ring.wait_ready(Duration::from_secs(30))
        .await
        .expect("all nodes should be healthy");

    // TODO: Form ring (DKG ceremony)
    // TODO: Get collective public key
    // TODO: Alice encrypts a secret to the ring's public key (utility endpoint)
    // TODO: Alice stores encrypted secret via StoreSecret
    // TODO: Bob generates a keypair
    // TODO: Bob requests re-encryption via StartPre
    // TODO: Ring performs threshold re-encryption
    // TODO: Bob decrypts the re-encrypted secret with his private key
    // TODO: Verify Bob's decrypted secret matches Alice's original
    todo!("implement when full PRE pipeline is working");
}

/// Store multiple secrets and reencrypt each to different recipients.
#[tokio::test]
#[ignore = "requires full secret pipeline"]
async fn multiple_secrets_different_recipients() {
    let _ring = OrbisRing::builder()
        .nodes(3)
        .threshold(2)
        .build()
        .await
        .expect("ring should start");

    todo!("implement when full PRE pipeline is working");
}

/// Verify that storing a secret returns a valid object_id on the bulletin.
#[tokio::test]
#[ignore = "requires StoreSecret + bulletin"]
async fn store_secret_returns_object_id() {
    let _ring = OrbisRing::builder()
        .nodes(3)
        .threshold(2)
        .build()
        .await
        .expect("ring should start");

    todo!("implement when StoreSecret is working");
}

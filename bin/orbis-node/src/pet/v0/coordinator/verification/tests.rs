#[cfg(feature = "unsafe-testing")]
mod decrypt_fault;
mod generation_reports;

use super::*;
use crate::helpers::test_helpers::{
    cleanup_db, create_test_app_state_with_bulletin, test_db_path, TestKeyPair,
};
use crate::pet::v0::messages::{CommitRequest, PetMessage, RevealRequest};
use crate::reporting::v0::types::{
    pet_blind_selection_digest, PetBlindCertificate, PetBlindSignedDecrypt, PetBlindSignedReveal,
    PET_BLIND_DECRYPT_RESPONSE_DOMAIN, PET_BLIND_REVEAL_RESPONSE_DOMAIN,
};
use authz::dummy::DummyAuthZ;
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::{DocumentPayload, NodeInfo, RingPayload};
use common::blockchain::{sign_node_message_with_hex_key, ChainConfig, TxSigner};
use crypto::r#trait::{CryptoSerialize, PriShare};
use crypto::{DkgImpl, PetImpl};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use network::PeerId;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs()
}

const RING_ID: &str = "pet-blind-test-ring";
const AUDIT_TARGET: &str = "pet-blind-cert-test-target";

struct TestSigner {
    secret_hex: String,
    pubkey_hex: String,
}

fn gen_signer() -> TestSigner {
    let mut key = [0u8; 32];
    loop {
        getrandom::getrandom(&mut key).expect("generate test signing key");
        if TxSigner::new(&key, ChainConfig::local()).is_ok() {
            break;
        }
    }
    let secret_hex = hex::encode(key);
    let pubkey_hex = TxSigner::from_hex_key(&secret_hex, ChainConfig::local())
        .expect("construct test signer")
        .public_key_hex();
    TestSigner {
        secret_hex,
        pubkey_hex,
    }
}

/// A ring plus a genuinely tag-knowledge-verifiable document/tag, whose
/// checking-key secret (`pet_sk`) is shared identically by every
/// committee member (a degree-0 polynomial, mirroring the old
/// single-round protocol's own fixture trick) — this is what lets
/// `decrypt_share` below compute genuine, individually-DLEQ-verifiable
/// decrypt shares without a real DKG ceremony.
struct TagFixture {
    ring_payload: RingPayload,
    document: DocumentPayload,
    tag: PetTag,
    signers: Vec<TestSigner>,
    pet_sk: Fr,
}

/// The fixture's document is genuinely bound to its own `object_id` —
/// `verify_pet_check_request` enforces this (finding #7), so callers
/// must derive `object_id` from the actual fixture document.
fn object_id_for(fixture: &TagFixture) -> String {
    common::blockchain::orbis::generate_document_id(
        &fixture.document.ring_id,
        &fixture.document.document,
        &fixture.document.proof,
        &fixture.document.policy_id,
        &fixture.document.resource,
        &fixture.document.permission,
        fixture.document.tier.as_deref(),
        fixture.document.timestamp,
        fixture.document.pet_tag.as_deref(),
        fixture.document.pet_tag_proof.as_deref(),
    )
    .expect("compute object_id for fixture document")
}

/// Builds a ring/document/tag whose tag genuinely matches `target` — a
/// certificate's own validity never depends on this (blinding is
/// target-independent arithmetic; only the final decrypt-phase equality
/// check is target-sensitive), but `verify_pet_check_request` and the
/// admission/handler tests below need a real, tag-knowledge-verifiable
/// document to get past that gate before exercising the check under
/// test.
fn build_fixture(committee_size: usize, threshold: u32, target: &str) -> TagFixture {
    let mut signers: Vec<TestSigner> = (0..committee_size).map(|_| gen_signer()).collect();
    signers.sort_by(|a, b| a.pubkey_hex.cmp(&b.pubkey_hex));
    let peer_node_keys: Vec<String> = signers.iter().map(|s| s.pubkey_hex.clone()).collect();

    let (pet_sk, pet_pk) =
        crypto::helpers::generate_keypair().expect("generate pet checking keypair");
    let ring_payload = RingPayload {
        upgrade_info: Default::default(),
        ring_pk: "aa".repeat(32),
        new_peer_node_keys: None,
        new_threshold: None,
        peer_node_keys,
        threshold,
        pss_interval: 60,
        block_number_nonce: 0,
        policy_id: Some("test-policy".to_string()),
        trusted_auth_relay_dids: None,
        reporting: Default::default(),
        requires_pet: true,
        pet_pk: Some(hex::encode(
            CryptoSerialize::to_bytes(&pet_pk).expect("serialize pet_pk"),
        )),
    };

    let (r_tag, r_point) =
        crypto::helpers::generate_keypair().expect("generate ephemeral tag keypair");
    let combined = crypto::helpers::mul_point(&r_point, &pet_sk).expect("compute pet_sk*R");
    let target_fingerprint =
        PetImpl::owner_fingerprint(target.as_bytes()).expect("compute F(target)");
    let masked = crypto::helpers::add_points(&target_fingerprint, &combined)
        .expect("combine fingerprint and blinding");
    let tag = PetTag {
        ephemeral_point: CryptoSerialize::to_bytes(&r_point).expect("serialize R"),
        masked_fingerprint: CryptoSerialize::to_bytes(&masked).expect("serialize T"),
    };

    let secret = Secret {
        enc_cmt: vec![1, 2, 3],
        encrypted_data: vec![4, 5, 6],
        nonce: vec![7, 8, 9],
    };
    let payload_proof = EncryptionProof {
        challenge: vec![10, 11],
        response: vec![12, 13],
    };
    let mut document = DocumentPayload {
        ring_id: RING_ID.to_string(),
        document: serde_json::to_string(&secret).expect("serialize secret"),
        proof: String::try_from(EncryptionProof {
            challenge: payload_proof.challenge.clone(),
            response: payload_proof.response.clone(),
        })
        .expect("serialize payload proof"),
        policy_id: "test-policy".to_string(),
        resource: "test-resource".to_string(),
        permission: "read".to_string(),
        tier: None,
        timestamp: None,
        pet_tag: None,
        pet_tag_proof: None,
    };

    // Required noncircular construction order: the tag must be on the
    // document *before* the context it's bound into is built.
    let pet_pk_hex = ring_payload.pet_pk.clone().expect("pet_pk");
    let pet_pk_bytes = hex::decode(&pet_pk_hex).expect("decode pet_pk hex");
    document.pet_tag = Some(String::try_from(tag.clone()).expect("serialize tag"));
    let ciphertext_context =
        build_ciphertext_context(&ring_payload.ring_pk, &document, None, Some(&pet_pk_hex))
            .expect("build ciphertext context");
    let digest = crypto::pet_context::tag_proof_digest(
        &tag.ephemeral_point,
        &tag.masked_fingerprint,
        &pet_pk_bytes,
        &document.ring_id,
        &ciphertext_context,
        &secret,
        &payload_proof,
    );
    let tag_proof =
        PetImpl::prove_tag_knowledge(&r_tag, &tag, &digest).expect("prove tag knowledge");
    document.pet_tag_proof = Some(String::try_from(tag_proof).expect("serialize tag proof"));

    TagFixture {
        ring_payload,
        document,
        tag,
        signers,
        pet_sk,
    }
}

fn ring_pub_poly(ring: &RingPayload) -> crypto::PubPolyImpl {
    let pet_pk_bytes =
        hex::decode(ring.pet_pk.as_ref().expect("pet_pk")).expect("decode pet_pk hex");
    let pet_pk = G1Affine::from_bytes(&pet_pk_bytes).expect("decode pet_pk point");
    let identity =
        crypto::helpers::mul_point(&pet_pk, &Fr::from(0u64)).expect("zero coefficient commitment");
    let mut commits = vec![identity; ring.threshold as usize];
    commits[0] = pet_pk;
    crypto::PubPolyImpl { commits }
}

fn fixture_pub_poly(fixture: &TagFixture) -> crypto::PubPolyImpl {
    ring_pub_poly(&fixture.ring_payload)
}

fn fixture_ring_state(fixture: &TagFixture) -> String {
    crate::reporting::v0::types::ring_state_sha256(&fixture.ring_payload)
}

fn fixture_polynomial_bytes(fixture: &TagFixture) -> Vec<u8> {
    CryptoSerialize::to_bytes(&fixture_pub_poly(fixture)).expect("serialize fixture polynomial")
}

fn fixture_blind_context(fixture: &TagFixture, attempt: &str) -> PetBlindContext {
    build_pet_blind_context(
        "vera-localnet".to_string(),
        &fixture.ring_payload,
        fixture.ring_payload.pet_pk.as_ref().expect("pet_pk"),
        0,
        PetImpl::name(),
        &admission_ctx(fixture),
        ADMISSION_ACTOR.to_string(),
        ADMISSION_COORDINATOR.to_string(),
        attempt.to_string(),
    )
}

/// This node's round-1 output plus everything round 2 needs to open it —
/// `z_i` stays around so the test can build the real, selection-bound
/// proof once `all_commitments` is fixed, exactly like
/// `pending_blind::PendingBlinding` does in production.
struct Contribution {
    node_id: u32,
    z_i: Fr,
    commit_salt: [u8; 32],
    commitment: [u8; 32],
}

fn commit(
    tag: &PetTag,
    target_fingerprint: &G1Affine,
    attempt_id: &str,
    context_digest: [u8; 32],
    node_id: u32,
) -> Contribution {
    let (z_i, _unused) = crypto::helpers::generate_keypair().expect("sample blinding scalar");
    let preliminary =
        PetImpl::prove_blinding_correctness(&z_i, tag, target_fingerprint, &[0u8; 32])
            .expect("compute blinding points");
    let blinded_r_bytes =
        CryptoSerialize::to_bytes(&preliminary.blinded_r).expect("serialize blinded_r");
    let blinded_diff_bytes =
        CryptoSerialize::to_bytes(&preliminary.blinded_diff).expect("serialize blinded_diff");
    let commit_salt: [u8; 32] = rand::random();
    let commitment = pet_blind_commit_hash(
        attempt_id,
        &context_digest,
        node_id,
        &commit_salt,
        &blinded_r_bytes,
        &blinded_diff_bytes,
    );
    Contribution {
        node_id,
        z_i,
        commit_salt,
        commitment,
    }
}

#[allow(clippy::too_many_arguments)]
fn reveal(
    fixture: &TagFixture,
    target_fingerprint: &G1Affine,
    attempt_id: &str,
    context_digest: [u8; 32],
    all_commitments: &[(u32, [u8; 32])],
    contribution: &Contribution,
    signer: &TestSigner,
) -> PetBlindSignedReveal {
    let selection_digest = pet_blind_selection_digest(attempt_id, &context_digest, all_commitments);
    let blind_transcript_digest = pet_blind_proof_transcript_digest(
        attempt_id,
        &context_digest,
        &selection_digest,
        contribution.node_id,
        &contribution.commitment,
    );
    let real_reply = PetImpl::prove_blinding_correctness(
        &contribution.z_i,
        &fixture.tag,
        target_fingerprint,
        &blind_transcript_digest,
    )
    .expect("compute blinding-correctness proof");
    let statement = PetBlindRevealStatement {
        domain: PET_BLIND_REVEAL_RESPONSE_DOMAIN.to_string(),
        chain_id: "vera-localnet".to_string(),
        ring_id: RING_ID.to_string(),
        ring_pk: fixture.ring_payload.ring_pk.clone(),
        ring_state_sha256: crate::reporting::v0::types::ring_state_sha256(&fixture.ring_payload),
        protocol_version: 0,
        attempt_id: attempt_id.to_string(),
        context_digest,
        selection_digest,
        responder_node_key: signer.pubkey_hex.clone(),
        from_node_id: contribution.node_id,
        commitment: contribution.commitment.to_vec(),
        blinded_r: CryptoSerialize::to_bytes(&real_reply.blinded_r).expect("serialize blinded_r"),
        blinded_diff: CryptoSerialize::to_bytes(&real_reply.blinded_diff)
            .expect("serialize blinded_diff"),
        commit_salt: contribution.commit_salt,
        challenge: CryptoSerialize::to_bytes(&real_reply.challenge).expect("serialize challenge"),
        proof: CryptoSerialize::to_bytes(&real_reply.proof).expect("serialize proof"),
        signed_at: 1_700_000_000,
    };
    let response_signature =
        sign_node_message_with_hex_key(&signer.secret_hex, &statement.canonical_bytes())
            .expect("sign reveal");
    PetBlindSignedReveal {
        statement,
        response_signature,
    }
}

fn reveal_statement_to_message(
    statement: PetBlindRevealStatement,
    response_signature: Vec<u8>,
) -> PetMessage {
    PetMessage::RevealResponse {
        request_id: "reveal-attempt-1".to_string(),
        attempt_id: statement.attempt_id,
        context_digest: statement.context_digest,
        selection_digest: statement.selection_digest,
        from_node_id: statement.from_node_id,
        commitment: statement.commitment,
        blinded_r: statement.blinded_r,
        blinded_diff: statement.blinded_diff,
        commit_salt: statement.commit_salt,
        challenge: statement.challenge,
        proof: statement.proof,
        signed_at: statement.signed_at,
        response_signature,
    }
}

fn genuine_reveal_message(
    fixture: &TagFixture,
    target_fingerprint: &G1Affine,
    attempt_id: &str,
    context_digest: [u8; 32],
    all_commitments: &[(u32, [u8; 32])],
    contribution: &Contribution,
) -> PetMessage {
    let signer = &fixture.signers[(contribution.node_id - 1) as usize];
    let signed = reveal(
        fixture,
        target_fingerprint,
        attempt_id,
        context_digest,
        all_commitments,
        contribution,
        signer,
    );
    reveal_statement_to_message(signed.statement, signed.response_signature)
}

/// A reveal claiming `contribution.node_id`'s slot with an invalid
/// signature — exactly what a malicious responder sends to try to
/// preempt an honest participant's id without ever having a real key.
fn spoofed_reveal_message(
    fixture: &TagFixture,
    target_fingerprint: &G1Affine,
    attempt_id: &str,
    context_digest: [u8; 32],
    all_commitments: &[(u32, [u8; 32])],
    contribution: &Contribution,
) -> PetMessage {
    let mut message = genuine_reveal_message(
        fixture,
        target_fingerprint,
        attempt_id,
        context_digest,
        all_commitments,
        contribution,
    );
    if let PetMessage::RevealResponse {
        response_signature, ..
    } = &mut message
    {
        response_signature[0] ^= 0x01;
    }
    message
}

/// A reveal genuinely signed by `contribution.node_id`'s real key,
/// opening its real commitment (`blinded_r`/`blinded_diff`/`commit_salt`
/// all genuine), but with a caller-supplied `challenge`/`proof` —
/// authenticated and self-consistent with its own commitment, but
/// cryptographically wrong (decodable garbage) or undecodable
/// (malformed), depending what the caller passes. Distinguishing these
/// two matters: finding #9 in the old protocol was exactly a malformed
/// response dodging attribution that a decodable-but-wrong one didn't.
#[allow(clippy::too_many_arguments)]
fn reveal_with_bad_proof(
    fixture: &TagFixture,
    target_fingerprint: &G1Affine,
    attempt_id: &str,
    context_digest: [u8; 32],
    all_commitments: &[(u32, [u8; 32])],
    contribution: &Contribution,
    challenge: Vec<u8>,
    proof: Vec<u8>,
) -> PetMessage {
    let signer = &fixture.signers[(contribution.node_id - 1) as usize];
    let selection_digest = pet_blind_selection_digest(attempt_id, &context_digest, all_commitments);
    let points = PetImpl::prove_blinding_correctness(
        &contribution.z_i,
        &fixture.tag,
        target_fingerprint,
        &[0u8; 32],
    )
    .expect("recompute genuine blinded points");
    let statement = PetBlindRevealStatement {
        domain: PET_BLIND_REVEAL_RESPONSE_DOMAIN.to_string(),
        chain_id: "vera-localnet".to_string(),
        ring_id: RING_ID.to_string(),
        ring_pk: fixture.ring_payload.ring_pk.clone(),
        ring_state_sha256: crate::reporting::v0::types::ring_state_sha256(&fixture.ring_payload),
        protocol_version: 0,
        attempt_id: attempt_id.to_string(),
        context_digest,
        selection_digest,
        responder_node_key: signer.pubkey_hex.clone(),
        from_node_id: contribution.node_id,
        commitment: contribution.commitment.to_vec(),
        blinded_r: CryptoSerialize::to_bytes(&points.blinded_r).expect("serialize blinded_r"),
        blinded_diff: CryptoSerialize::to_bytes(&points.blinded_diff)
            .expect("serialize blinded_diff"),
        commit_salt: contribution.commit_salt,
        challenge,
        proof,
        signed_at: 1_700_000_000,
    };
    let response_signature =
        sign_node_message_with_hex_key(&signer.secret_hex, &statement.canonical_bytes())
            .expect("sign reveal with bad proof");
    reveal_statement_to_message(statement, response_signature)
}

fn decrypt_statement_to_message(
    statement: PetBlindDecryptStatement,
    response_signature: Vec<u8>,
) -> PetMessage {
    PetMessage::DecryptResponse {
        request_id: "decrypt-attempt-1".to_string(),
        attempt_id: statement.attempt_id,
        context_digest: statement.context_digest,
        certificate_digest: statement.certificate_digest,
        from_node_id: statement.from_node_id,
        aggregate_r: statement.aggregate_r,
        aggregate_diff: statement.aggregate_diff,
        partial: statement.partial,
        challenge: statement.challenge,
        proof: statement.proof,
        signed_at: statement.signed_at,
        public_polynomial: statement.public_polynomial,
        response_signature,
    }
}

/// A genuine decrypt share from committee member `node_id` against
/// `certificate`'s reconstructed aggregate points — computed from the
/// fixture's real (shared) `pet_sk`, reusing the existing per-share DLEQ
/// (`Pet::partial_pet_check`) unchanged, against `aggregate_r` in place
/// of the old protocol's bare `R`.
fn decrypt_share(
    fixture: &TagFixture,
    certificate: &PetBlindCertificate,
    aggregate_r: &G1Affine,
    aggregate_diff: &G1Affine,
    node_id: u32,
) -> PetBlindSignedDecrypt {
    let aggregate_r_bytes = CryptoSerialize::to_bytes(aggregate_r).expect("serialize aggregate_r");
    let aggregate_diff_bytes =
        CryptoSerialize::to_bytes(aggregate_diff).expect("serialize aggregate_diff");
    let synthetic_tag = PetTag {
        ephemeral_point: aggregate_r_bytes.clone(),
        masked_fingerprint: Vec::new(),
    };
    let reply = PetImpl::partial_pet_check(&fixture.pet_sk, node_id, &synthetic_tag)
        .expect("compute genuine decrypt share");
    let signer = &fixture.signers[(node_id - 1) as usize];
    let statement = PetBlindDecryptStatement {
        domain: PET_BLIND_DECRYPT_RESPONSE_DOMAIN.to_string(),
        chain_id: "vera-localnet".to_string(),
        ring_id: RING_ID.to_string(),
        ring_pk: fixture.ring_payload.ring_pk.clone(),
        ring_state_sha256: crate::reporting::v0::types::ring_state_sha256(&fixture.ring_payload),
        protocol_version: 0,
        attempt_id: certificate.attempt_id.clone(),
        context_digest: certificate.context_digest,
        certificate_digest: certificate.certificate_digest(),
        responder_node_key: signer.pubkey_hex.clone(),
        from_node_id: node_id,
        aggregate_r: aggregate_r_bytes,
        aggregate_diff: aggregate_diff_bytes,
        partial: CryptoSerialize::to_bytes(&reply.partial.v).expect("serialize partial"),
        challenge: CryptoSerialize::to_bytes(&reply.challenge).expect("serialize challenge"),
        proof: CryptoSerialize::to_bytes(&reply.proof).expect("serialize proof"),
        signed_at: 1_700_000_000,
        public_polynomial: certificate.public_polynomial.clone(),
    };
    let response_signature =
        sign_node_message_with_hex_key(&signer.secret_hex, &statement.canonical_bytes())
            .expect("sign decrypt share");
    PetBlindSignedDecrypt {
        statement,
        response_signature,
    }
}

/// Genuinely signed by `node_id`, opening cleanly against
/// `certificate`'s real aggregate points, but with undecodable
/// `partial`/`challenge`/`proof` bytes.
fn malformed_decrypt_share(
    fixture: &TagFixture,
    certificate: &PetBlindCertificate,
    aggregate_r: &G1Affine,
    aggregate_diff: &G1Affine,
    node_id: u32,
) -> PetBlindSignedDecrypt {
    let aggregate_r_bytes = CryptoSerialize::to_bytes(aggregate_r).expect("serialize aggregate_r");
    let aggregate_diff_bytes =
        CryptoSerialize::to_bytes(aggregate_diff).expect("serialize aggregate_diff");
    let signer = &fixture.signers[(node_id - 1) as usize];
    let statement = PetBlindDecryptStatement {
        domain: PET_BLIND_DECRYPT_RESPONSE_DOMAIN.to_string(),
        chain_id: "vera-localnet".to_string(),
        ring_id: RING_ID.to_string(),
        ring_pk: fixture.ring_payload.ring_pk.clone(),
        ring_state_sha256: crate::reporting::v0::types::ring_state_sha256(&fixture.ring_payload),
        protocol_version: 0,
        attempt_id: certificate.attempt_id.clone(),
        context_digest: certificate.context_digest,
        certificate_digest: certificate.certificate_digest(),
        responder_node_key: signer.pubkey_hex.clone(),
        from_node_id: node_id,
        aggregate_r: aggregate_r_bytes,
        aggregate_diff: aggregate_diff_bytes,
        partial: vec![0xff, 0xff, 0xff],
        challenge: vec![0xff, 0xff, 0xff],
        proof: vec![0xff, 0xff, 0xff],
        signed_at: 1_700_000_000,
        public_polynomial: certificate.public_polynomial.clone(),
    };
    let response_signature =
        sign_node_message_with_hex_key(&signer.secret_hex, &statement.canonical_bytes())
            .expect("sign malformed decrypt share");
    PetBlindSignedDecrypt {
        statement,
        response_signature,
    }
}

/// Builds a certificate for exactly `node_ids` (sorted, canonical order)
/// against `attempt_id`/`context_digest` — the caller picks these last
/// two explicitly (rather than a fixed placeholder) whenever the result
/// must match an externally, independently recomputed digest, as
/// `verify_pet_admission`'s own tests need.
fn build_certificate_for(
    fixture: &TagFixture,
    target_fingerprint: &G1Affine,
    attempt_id: &str,
    context_digest: [u8; 32],
    node_ids: &[u32],
) -> PetBlindCertificate {
    assert_eq!(
        context_digest,
        fixture_blind_context(fixture, attempt_id).context_digest()
    );
    let contributions: Vec<Contribution> = node_ids
        .iter()
        .map(|&id| {
            commit(
                &fixture.tag,
                target_fingerprint,
                attempt_id,
                context_digest,
                id,
            )
        })
        .collect();
    let all_commitments: Vec<(u32, [u8; 32])> = contributions
        .iter()
        .map(|c| (c.node_id, c.commitment))
        .collect();
    let reveals: Vec<PetBlindSignedReveal> = contributions
        .iter()
        .map(|c| {
            let signer = &fixture.signers[(c.node_id - 1) as usize];
            reveal(
                fixture,
                target_fingerprint,
                attempt_id,
                context_digest,
                &all_commitments,
                c,
                signer,
            )
        })
        .collect();
    PetBlindCertificate {
        public_polynomial: fixture_polynomial_bytes(fixture),
        attempt_id: attempt_id.to_string(),
        context_digest,
        all_commitments: all_commitments
            .iter()
            .map(|(id, bytes)| (*id, bytes.to_vec()))
            .collect(),
        reveals,
    }
}

/// A genuine 2-of-3 certificate bound to this fixture's complete context.
/// Each rejection test mutates one field after this valid base is signed.
fn build_valid_certificate(
    fixture: &TagFixture,
    target_fingerprint: &G1Affine,
) -> PetBlindCertificate {
    build_certificate_for(
        fixture,
        target_fingerprint,
        "attempt-1",
        fixture_blind_context(fixture, "attempt-1").context_digest(),
        &[1, 2],
    )
}

/// A deterministic 64-hex-char peer id for committee member `index` —
/// registered as that signer's `NodeInfo` below so
/// `resolve_coordinator_node_key` (every handler's first line of
/// defense against a spoofed coordinator identity) can resolve it.
fn peer_id_hex_for(index: usize) -> String {
    hex::encode([(index as u8) + 1; 32])
}

async fn test_coordinator(db_name: &str, fixture: &TagFixture) -> PetCoordinator<DkgImpl, PetImpl> {
    test_coordinator_with_bulletin(db_name, fixture).await.0
}

async fn test_coordinator_with_bulletin(
    db_name: &str,
    fixture: &TagFixture,
) -> (PetCoordinator<DkgImpl, PetImpl>, Arc<DummyBulletin>) {
    let ring_payload = &fixture.ring_payload;
    let dummy_bulletin = Arc::new(DummyBulletin::new().await.expect("dummy bulletin"));
    dummy_bulletin
        .set_ring(RING_ID.to_string(), ring_payload.clone())
        .expect("seed ring");
    // Every phase's handler independently resolves the authenticated
    // transport sender's ring identity (never trusting a claimed
    // `from_node_id`) — register a resolvable NodeInfo for each
    // committee member so that resolution can succeed in tests that
    // need it.
    for (i, node_key) in ring_payload.peer_node_keys.iter().enumerate() {
        dummy_bulletin
            .set_node_info(
                node_key.clone(),
                NodeInfo {
                    peer_id: peer_id_hex_for(i),
                    controller_key: "controller".to_string(),
                    whitelisted_policy_ids: vec![],
                    whitelisted_ring_ids: vec![],
                },
            )
            .expect("seed node info");
    }
    let mut app_state =
        create_test_app_state_with_bulletin(true, dummy_bulletin.clone(), db_name).await;
    app_state.node_key = fixture.signers[0].pubkey_hex.clone();
    app_state
        .local_storage
        .set_encrypted(
            LocalStorageKeys::NodeSigningKey,
            Zeroizing::new(fixture.signers[0].secret_hex.as_bytes().to_vec()),
        )
        .expect("store fixture node signing key");

    // A constant polynomial with exactly `threshold` coefficients keeps each
    // share equal to pet_sk, while exercising canonical generation binding.
    let pub_poly = fixture_pub_poly(fixture);
    let share = PriShare {
        i: 1,
        v: fixture.pet_sk,
    };
    let bundle = RingShareBundle {
        share_bytes: Zeroizing::new(
            CryptoSerialize::to_bytes(&share).expect("serialize fixture share"),
        ),
        public_polynomial: hex::encode(
            CryptoSerialize::to_bytes(&pub_poly).expect("serialize pub_poly"),
        ),
        last_pss: 0,
    };
    bundle
        .save_by_pet_ring_key(&app_state.local_storage, RING_ID)
        .expect("seed PET bundle");

    (
        PetCoordinator::<DkgImpl, PetImpl>::with_routes(Arc::new(app_state), &::network::V0),
        dummy_bulletin,
    )
}

// ========================================================================
// Audit finding #7: `document` and `object_id` are independent fields on
// `PetCheckContext`'s wire — nothing upstream of `verify_pet_check_request`
// guarantees a live PET request's initiator supplied a genuinely matching
// pair. Unchanged from the old single-round protocol.
// ========================================================================

#[tokio::test]
#[serial_test::serial]
async fn verify_pet_check_request_rejects_a_document_object_id_mismatch() {
    let db_name = "pet_check_request_rejects_document_object_id_mismatch";
    let fixture_a = build_fixture(3, 2, AUDIT_TARGET);
    let fixture_b = build_fixture(3, 2, AUDIT_TARGET);
    let coordinator = test_coordinator(db_name, &fixture_a).await;

    let ctx = PetCheckContext {
        ring_state_sha256: fixture_ring_state(&fixture_a),
        public_polynomial: fixture_polynomial_bytes(&fixture_a),
        document: fixture_a.document.clone(),
        salt: None,
        object_id: object_id_for(&fixture_b),
        document_inline: false,
        token_string: String::new(),
        audit_target_object_id: String::new(),
        valid_window: None,
    };

    let result = coordinator.verify_pet_check_request(&ctx).await;
    assert!(
        matches!(result, Err(PetError::InvalidInput(_))),
        "document = A paired with object_id = id(B) must be rejected before any proof is \
             computed or signed, got {:?}",
        result
    );
    cleanup_db(&test_db_path(db_name));
}

// ========================================================================
// Every phase's handler is the one
// entry point reachable from a raw wire message with no other upstream
// authentication. `verify_pet_audit_authorization` closes that gap; it
// needs only an `Authz` impl, so most of these tests call it directly.
// ========================================================================

fn audit_authz_fixture() -> (TestKeyPair, DocumentPayload, String) {
    let signer = TestKeyPair::new();
    let document = DocumentPayload {
        ring_id: "audit-authz-ring".to_string(),
        document: String::new(),
        proof: String::new(),
        policy_id: "test-policy".to_string(),
        resource: "test-resource".to_string(),
        permission: "read".to_string(),
        tier: None,
        timestamp: None,
        pet_tag: None,
        pet_tag_proof: None,
    };
    (signer, document, "audit-authz-object".to_string())
}

// ========================================================================
// `check_pet_permission` itself — the ACP gate `verify_pet_audit_authorization`
// (and the normal initiator path) both rely on. Flagged twice before as a real
// gap: `DummyAuthZ` is permissive by construction, so every test above and below
// that uses it can only ever exercise the *accept* path — none of them prove this
// gate actually rejects a denied actor. `DenyingAuthZ` (authz::dummy) closes that.
// ========================================================================

#[tokio::test]
async fn check_pet_permission_rejects_a_denied_actor() {
    let (_signer, document, _object_id) = audit_authz_fixture();
    let authz = authz::dummy::DenyingAuthZ;

    let result = check_pet_permission(&authz, &document, "any-target", "any-actor", None).await;

    assert!(
        matches!(result, Err(PetError::Mismatch)),
        "a denied ACP decision must reject the PET permission gate: {:?}",
        result
    );
}

#[tokio::test]
async fn check_pet_permission_accepts_an_authorized_actor() {
    let (_signer, document, _object_id) = audit_authz_fixture();
    let authz = DummyAuthZ;

    let result = check_pet_permission(&authz, &document, "any-target", "any-actor", None).await;

    assert!(
        result.is_ok(),
        "an authorized ACP decision must pass the PET permission gate: {:?}",
        result
    );
}

#[tokio::test]
async fn verify_pet_audit_authorization_rejects_a_garbage_token() {
    let (_signer, document, object_id) = audit_authz_fixture();
    let ctx = PetCheckContext {
        ring_state_sha256: String::new(),
        public_polynomial: Vec::new(),
        document,
        salt: None,
        object_id,
        document_inline: false,
        token_string: "not-a-jwt".to_string(),
        audit_target_object_id: "any-target".to_string(),
        valid_window: None,
    };
    let authz = DummyAuthZ;
    let result = verify_pet_audit_authorization(&authz, &ctx, None, current_unix_time()).await;
    assert!(
        matches!(result, Err(PetError::InvalidInput(_))),
        "a garbage token must be rejected: {:?}",
        result
    );
}

#[tokio::test]
async fn verify_pet_audit_authorization_rejects_a_token_for_a_different_object_id() {
    let (signer, document, object_id) = audit_authz_fixture();
    let token = signer
        .create_pre_jwt(b"unused".to_vec(), "a-different-object-id", None, None)
        .expect("sign token");
    let ctx = PetCheckContext {
        ring_state_sha256: String::new(),
        public_polynomial: Vec::new(),
        document,
        salt: None,
        object_id,
        document_inline: false,
        token_string: token,
        audit_target_object_id: "any-target".to_string(),
        valid_window: None,
    };
    let authz = DummyAuthZ;
    let result = verify_pet_audit_authorization(&authz, &ctx, None, current_unix_time()).await;
    assert!(
        matches!(result, Err(PetError::InvalidInput(_))),
        "a token authorizing a different object_id must be rejected: {:?}",
        result
    );
}

#[tokio::test]
async fn verify_pet_audit_authorization_rejects_a_token_for_a_different_salt() {
    let (signer, document, object_id) = audit_authz_fixture();
    let token = signer
        .create_pre_jwt(
            b"unused".to_vec(),
            &object_id,
            None,
            Some("original-salt".to_string()),
        )
        .expect("sign token");
    let ctx = PetCheckContext {
        ring_state_sha256: String::new(),
        public_polynomial: Vec::new(),
        document,
        salt: Some("different-salt".to_string()),
        object_id,
        document_inline: false,
        token_string: token,
        audit_target_object_id: "any-target".to_string(),
        valid_window: None,
    };
    let authz = DummyAuthZ;
    let result = verify_pet_audit_authorization(&authz, &ctx, None, current_unix_time()).await;
    assert!(
        matches!(result, Err(PetError::InvalidInput(_))),
        "a token authorizing a different salt must be rejected: {:?}",
        result
    );
}

#[tokio::test]
async fn verify_pet_audit_authorization_accepts_a_genuinely_matching_token() {
    let (signer, document, object_id) = audit_authz_fixture();
    let token = signer
        .create_pre_jwt(b"unused".to_vec(), &object_id, None, None)
        .expect("sign token");
    let ctx = PetCheckContext {
        ring_state_sha256: String::new(),
        public_polynomial: Vec::new(),
        document,
        salt: None,
        object_id,
        document_inline: false,
        token_string: token,
        audit_target_object_id: "any-target".to_string(),
        valid_window: None,
    };
    let authz = DummyAuthZ;
    let result = verify_pet_audit_authorization(&authz, &ctx, None, current_unix_time()).await;
    assert!(
        result.is_ok(),
        "a genuinely matching, valid token must be accepted: {:?}",
        result
    );
}

/// End-to-end wiring check (not just the standalone function): a raw
/// `CommitRequest` with no valid audit authorization must be rejected by
/// the real `handle_message`/`handle_commit_request` path, before this
/// node's secret share is ever touched. `verify_pet_audit_authorization`
/// runs before `resolve_coordinator_node_key`, so an arbitrary peer id
/// (not registered anywhere) is fine here.
#[tokio::test]
#[serial_test::serial]
async fn handle_commit_request_rejects_a_request_with_no_valid_audit_authorization() {
    let db_name = "pet_handle_commit_request_rejects_unauthorized_audit";
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let coordinator = test_coordinator(db_name, &fixture).await;
    let peer_id = PeerId::new(vec![0u8; 32]);

    let request = CommitRequest {
        request_id: "commit-attempt-1".to_string(),
        attempt_id: "attempt-1".to_string(),
        from_node_id: 1,
        context: PetCheckContext {
            ring_state_sha256: fixture_ring_state(&fixture),
            public_polynomial: fixture_polynomial_bytes(&fixture),
            document: fixture.document.clone(),
            salt: None,
            object_id: object_id_for(&fixture),
            document_inline: false,
            token_string: "not-a-jwt".to_string(),
            audit_target_object_id: AUDIT_TARGET.to_string(),
            valid_window: None,
        },
    };

    let result = coordinator
        .handle_message(PetMessage::CommitRequest(Box::new(request)), &peer_id)
        .await;

    assert!(
        matches!(result, Err(PetError::InvalidInput(_))),
        "a CommitRequest with no valid audit authorization must be rejected: {:?}",
        result
    );
    cleanup_db(&test_db_path(db_name));
}

/// Confirms the rejection above isn't vacuous against a gate that
/// rejects every `CommitRequest`: a valid, correctly-bound audit token,
/// from a peer id that genuinely resolves to a ring committee member,
/// must still be accepted end-to-end.
#[tokio::test]
#[serial_test::serial]
async fn handle_commit_request_accepts_a_request_with_valid_audit_authorization() {
    let db_name = "pet_handle_commit_request_accepts_valid_audit_authorization";
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let coordinator = test_coordinator(db_name, &fixture).await;
    // Committee member 1 (`signers[0]`/`peer_id_hex_for(0)`) plays the
    // coordinator here — this node's own stored share is also index 1
    // (see `test_coordinator`), so it can answer as itself.
    let peer_id = PeerId::new(hex::decode(peer_id_hex_for(0)).expect("decode test peer id"));

    let object_id = object_id_for(&fixture);
    let token = TestKeyPair::new()
        .create_pre_jwt(b"unused".to_vec(), &object_id, None, None)
        .expect("sign token");
    let request = CommitRequest {
        request_id: "commit-attempt-1".to_string(),
        attempt_id: "attempt-1".to_string(),
        from_node_id: 1,
        context: PetCheckContext {
            ring_state_sha256: fixture_ring_state(&fixture),
            public_polynomial: fixture_polynomial_bytes(&fixture),
            document: fixture.document.clone(),
            salt: None,
            object_id,
            document_inline: false,
            token_string: token,
            audit_target_object_id: AUDIT_TARGET.to_string(),
            valid_window: None,
        },
    };

    let result = coordinator
        .handle_message(PetMessage::CommitRequest(Box::new(request)), &peer_id)
        .await;

    assert!(
        matches!(result, Ok(Some(PetMessage::CommitResponse { .. }))),
        "a CommitRequest with a valid, correctly-bound audit token from a resolvable \
             coordinator must be accepted: {:?}",
        result
    );
    cleanup_db(&test_db_path(db_name));
}

fn authorized_pet_context(fixture: &TagFixture) -> PetCheckContext {
    let mut context = admission_ctx(fixture);
    context.token_string = TestKeyPair::new()
        .create_pre_jwt(b"unused".to_vec(), &context.object_id, None, None)
        .expect("sign token");
    context
}

#[tokio::test]
#[serial_test::serial]
async fn commit_with_a_valid_former_threshold_polynomial_returns_generation_mismatch() {
    let db_name = "pet_commit_former_threshold_generation";
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let coordinator = test_coordinator(db_name, &fixture).await;
    let peer_id = PeerId::new(hex::decode(peer_id_hex_for(0)).expect("decode peer id"));
    let mut old_ring = fixture.ring_payload.clone();
    old_ring.threshold = 3;
    let old_polynomial =
        CryptoSerialize::to_bytes(&ring_pub_poly(&old_ring)).expect("serialize old polynomial");
    crate::pet::v0::generation::decode::<crypto::PubPolyImpl>(
        &old_polynomial,
        old_ring.threshold,
        old_ring.pet_pk.as_deref().expect("PET key"),
    )
    .expect("the old polynomial is canonical and has the unchanged checking key");
    let mut context = authorized_pet_context(&fixture);
    // The initiator can read the new ring while its local old bundle still awaits promotion.
    context.public_polynomial = old_polynomial;
    let result = coordinator
        .handle_message(
            PetMessage::CommitRequest(Box::new(CommitRequest {
                request_id: "commit-former-threshold".to_string(),
                attempt_id: "former-threshold".to_string(),
                from_node_id: 1,
                context,
            })),
            &peer_id,
        )
        .await
        .expect("an honest threshold transition has a typed response");
    assert!(matches!(
        result,
        Some(PetMessage::GenerationMismatch { request_id })
            if request_id == "commit-former-threshold"
    ));
    cleanup_db(&test_db_path(db_name));
}

#[tokio::test]
#[serial_test::serial]
async fn reveal_after_ring_context_change_returns_generation_mismatch() {
    // The unchanged case proves the request reaches real reveal generation.
    // Only the certified ring metadata changes between the other commit/reveal.
    for ring_changes in [false, true] {
        let db_name = format!("pet_reveal_ring_context_changes_{ring_changes}");
        let fixture = build_fixture(1, 1, AUDIT_TARGET);
        let (coordinator, bulletin) = test_coordinator_with_bulletin(&db_name, &fixture).await;
        let peer_id = PeerId::new(hex::decode(peer_id_hex_for(0)).expect("decode peer id"));
        let context = authorized_pet_context(&fixture);
        let commit_response = coordinator
            .handle_message(
                PetMessage::CommitRequest(Box::new(CommitRequest {
                    request_id: "commit-ring-context".to_string(),
                    attempt_id: "ring-context".to_string(),
                    from_node_id: 1,
                    context: context.clone(),
                })),
                &peer_id,
            )
            .await
            .expect("commit succeeds before the transition");
        let Some(PetMessage::CommitResponse { commitment, .. }) = commit_response else {
            panic!("expected a genuine commitment, got {commit_response:?}");
        };
        if ring_changes {
            let mut next_ring = fixture.ring_payload.clone();
            next_ring.pss_interval += 1;
            assert_ne!(
                crate::reporting::v0::types::ring_state_sha256(&fixture.ring_payload),
                crate::reporting::v0::types::ring_state_sha256(&next_ring),
            );
            bulletin
                .set_ring(RING_ID.to_string(), next_ring)
                .expect("update ring");
        }
        let result = coordinator
            .handle_message(
                PetMessage::RevealRequest(Box::new(RevealRequest {
                    request_id: "reveal-ring-context".to_string(),
                    attempt_id: "ring-context".to_string(),
                    from_node_id: 1,
                    all_commitments: vec![(1, commitment)],
                    context,
                })),
                &peer_id,
            )
            .await
            .expect("an honest ring transition has a typed response");
        if ring_changes {
            assert!(matches!(
                result,
                Some(PetMessage::GenerationMismatch { request_id })
                    if request_id == "reveal-ring-context"
            ));
        } else {
            assert!(matches!(result, Some(PetMessage::RevealResponse { .. })));
        }
        assert!(bulletin.take_submitted_reports().is_empty());
        cleanup_db(&test_db_path(&db_name));
    }
}

#[tokio::test]
#[serial_test::serial]
async fn commit_with_a_previous_member_index_returns_generation_mismatch() {
    let db_name = "pet_commit_previous_member_index";
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let coordinator = test_coordinator(db_name, &fixture).await;
    let mut bundle =
        RingShareBundle::load_by_pet_ring_key(&coordinator.app_state.local_storage, RING_ID)
            .expect("load fixture bundle");
    bundle.share_bytes = Zeroizing::new(
        CryptoSerialize::to_bytes(&PriShare {
            i: 2,
            v: fixture.pet_sk,
        })
        .expect("serialize old member index"),
    );
    bundle
        .save_by_pet_ring_key(&coordinator.app_state.local_storage, RING_ID)
        .expect("persist old member index");
    let peer_id = PeerId::new(hex::decode(peer_id_hex_for(0)).expect("decode peer id"));
    let result = coordinator
        .handle_message(
            PetMessage::CommitRequest(Box::new(CommitRequest {
                request_id: "commit-member-index".to_string(),
                attempt_id: "member-index".to_string(),
                from_node_id: 1,
                context: authorized_pet_context(&fixture),
            })),
            &peer_id,
        )
        .await
        .expect("an honest member-index transition has a typed response");
    assert!(matches!(
        result,
        Some(PetMessage::GenerationMismatch { request_id })
            if request_id == "commit-member-index"
    ));
    cleanup_db(&test_db_path(db_name));
}

#[tokio::test]
#[serial_test::serial]
async fn commit_after_same_threshold_refresh_refuses_old_polynomial_and_accepts_new() {
    let db_name = "pet_commit_refreshed_bundle";
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let coordinator = test_coordinator(db_name, &fixture).await;
    let mut refreshed = fixture_pub_poly(&fixture);
    // Add the deterministic zero-constant polynomial pet_sk*x. The checking
    // key and threshold stay fixed, but the share at index1 and polynomial change.
    refreshed.commits[1] = refreshed.commits[0];
    let refreshed_bytes = CryptoSerialize::to_bytes(&refreshed).expect("serialize refreshed poly");
    assert_ne!(refreshed_bytes, fixture_polynomial_bytes(&fixture));
    RingShareBundle {
        share_bytes: Zeroizing::new(
            CryptoSerialize::to_bytes(&PriShare {
                i: 1,
                v: fixture.pet_sk + fixture.pet_sk,
            })
            .expect("serialize refreshed share"),
        ),
        public_polynomial: hex::encode(&refreshed_bytes),
        last_pss: 1,
    }
    .save_by_pet_ring_key(&coordinator.app_state.local_storage, RING_ID)
    .expect("atomically persist refreshed bundle");
    let peer_id = PeerId::new(hex::decode(peer_id_hex_for(0)).expect("decode peer id"));
    for use_refreshed in [false, true] {
        let mut context = authorized_pet_context(&fixture);
        if use_refreshed {
            context.public_polynomial = refreshed_bytes.clone();
        }
        let result = coordinator
            .handle_message(
                PetMessage::CommitRequest(Box::new(CommitRequest {
                    request_id: format!("commit-refreshed-{use_refreshed}"),
                    attempt_id: format!("refreshed-{use_refreshed}"),
                    from_node_id: 1,
                    context,
                })),
                &peer_id,
            )
            .await
            .expect("a valid refreshed bundle is not a storage or protocol error");
        if use_refreshed {
            assert!(matches!(result, Some(PetMessage::CommitResponse { .. })));
        } else {
            assert!(matches!(
                result,
                Some(PetMessage::GenerationMismatch { request_id })
                    if request_id == "commit-refreshed-false"
            ));
        }
    }
    cleanup_db(&test_db_path(db_name));
}

#[tokio::test]
#[serial_test::serial]
async fn commit_refuses_a_scalar_inconsistent_with_its_atomic_polynomial() {
    let db_name = "pet_commit_corrupt_scalar";
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let coordinator = test_coordinator(db_name, &fixture).await;
    let mut bundle =
        RingShareBundle::load_by_pet_ring_key(&coordinator.app_state.local_storage, RING_ID)
            .expect("load fixture bundle");
    bundle.share_bytes = Zeroizing::new(
        CryptoSerialize::to_bytes(&PriShare {
            i: 1,
            v: fixture.pet_sk + Fr::from(1u64),
        })
        .expect("serialize inconsistent scalar"),
    );
    bundle
        .save_by_pet_ring_key(&coordinator.app_state.local_storage, RING_ID)
        .expect("persist inconsistent bundle");
    let peer_id = PeerId::new(hex::decode(peer_id_hex_for(0)).expect("decode peer id"));
    let result = coordinator
        .handle_message(
            PetMessage::CommitRequest(Box::new(CommitRequest {
                request_id: "commit-corrupt-scalar".to_string(),
                attempt_id: "corrupt-scalar".to_string(),
                from_node_id: 1,
                context: authorized_pet_context(&fixture),
            })),
            &peer_id,
        )
        .await;
    assert!(
        matches!(result, Err(PetError::Storage(_))),
        "an inconsistent stored scalar must never endorse a certificate: {result:?}"
    );
    cleanup_db(&test_db_path(db_name));
}

#[test]
fn generation_mismatch_is_retryable_and_never_an_offline_observation() {
    use crate::reporting::v0::observation::offline_observation_from_pet_error;

    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let peer_ids: Vec<_> = (0..3).map(peer_id_hex_for).collect();
    let observe = |error| {
        offline_observation_from_pet_error(
            RING_ID,
            &peer_ids,
            &fixture.ring_payload.peer_node_keys,
            &peer_ids[0],
            error,
            0,
            "generation-transition",
        )
    };
    let timeout = PetError::Timeout("transport timeout".into());
    assert!(observe(&timeout).is_some());
    assert!(observe(&PetError::GenerationMismatch).is_none());
    let status = tonic::Status::from(crate::pre::v0::error::PreError::from(
        PetError::GenerationMismatch,
    ));
    assert_eq!(status.code(), tonic::Code::Unavailable);
}

// ========================================================================
// `verify_commit_response` — Commit responses carry no signature, so
// `expected_node_id` (the caller's own transport-level authentication of
// who actually sent this response) is the only thing standing between a
// malicious committee member and claiming a different, honest member's
// slot in its own response.
// ========================================================================

#[test]
fn verify_commit_response_rejects_a_response_claiming_a_different_node_id() {
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let mut seen_node_ids = HashSet::new();
    let context_digest = fixture_blind_context(&fixture, "attempt-1").context_digest();

    // The authenticated peer this response actually arrived from is
    // node 1 — but the (otherwise well-formed) response body claims to
    // be node 2's.
    let response = PetMessage::CommitResponse {
        request_id: "commit-attempt-1".to_string(),
        attempt_id: "attempt-1".to_string(),
        context_digest,
        from_node_id: 2,
        commitment: vec![1; 32],
    };

    let result = verify_commit_response(
        response,
        &fixture.ring_payload,
        context_digest,
        1,
        &mut seen_node_ids,
    );

    assert!(
        matches!(result, PetCommitResponseVerification::Rejected),
        "a commit response claiming a node_id other than the one the \
             authenticated peer is assigned must be rejected"
    );
    assert!(
        seen_node_ids.is_empty(),
        "a rejected response must not consume any node_id's slot — \
             otherwise the real node 2 would be locked out once its own \
             genuine response arrives"
    );
}

#[test]
fn verify_commit_response_accepts_a_response_matching_the_authenticated_peer() {
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let mut seen_node_ids = HashSet::new();
    let context_digest = fixture_blind_context(&fixture, "attempt-1").context_digest();

    let response = PetMessage::CommitResponse {
        request_id: "commit-attempt-1".to_string(),
        attempt_id: "attempt-1".to_string(),
        context_digest,
        from_node_id: 1,
        commitment: vec![1; 32],
    };

    let result = verify_commit_response(
        response,
        &fixture.ring_payload,
        context_digest,
        1,
        &mut seen_node_ids,
    );

    assert!(
        matches!(
            result,
            PetCommitResponseVerification::Verified { node_id: 1, .. }
        ),
        "a genuine response whose claimed node_id matches the \
             authenticated peer it arrived from must be accepted"
    );
    assert!(seen_node_ids.contains(&1));
}

// ========================================================================
// `verify_pet_admission` — the PRE-release gate. Every rejection below
// isolates one specific defect in an otherwise-genuine `PetBlindEvidence`
// bundle; the final test confirms genuine evidence is admitted, so the
// rejections above aren't vacuous against a gate that rejects everything.
// ========================================================================

const ADMISSION_ACTOR: &str = "test-actor";
const ADMISSION_COORDINATOR: &str = "admission-coordinator";
const ADMISSION_ATTEMPT: &str = "admission-attempt-1";

fn admission_ctx(fixture: &TagFixture) -> PetCheckContext {
    PetCheckContext {
        ring_state_sha256: fixture_ring_state(fixture),
        public_polynomial: fixture_polynomial_bytes(fixture),
        document: fixture.document.clone(),
        salt: None,
        object_id: object_id_for(fixture),
        document_inline: false,
        token_string: String::new(),
        audit_target_object_id: AUDIT_TARGET.to_string(),
        valid_window: None,
    }
}

/// Independently recomputes exactly what `verify_pet_admission` itself
/// will compute for `context_digest`, so the test's own evidence can be
/// built to genuinely match it — mirrors how a real PRE peer's evidence
/// only ever admits because its signers independently derived the same
/// digest, never because the digest was merely copied.
fn admission_context_digest(
    coordinator: &PetCoordinator<DkgImpl, PetImpl>,
    fixture: &TagFixture,
) -> [u8; 32] {
    let ctx = admission_ctx(fixture);
    let blind_context = build_pet_blind_context(
        coordinator.app_state.bulletin.chain_id(),
        &fixture.ring_payload,
        fixture.ring_payload.pet_pk.as_ref().expect("pet_pk"),
        coordinator.routes.version,
        PetImpl::name(),
        &ctx,
        ADMISSION_ACTOR.to_string(),
        ADMISSION_COORDINATOR.to_string(),
        ADMISSION_ATTEMPT.to_string(),
    );
    blind_context.context_digest()
}

fn build_admission_evidence(
    fixture: &TagFixture,
    target_fingerprint: &G1Affine,
    context_digest: [u8; 32],
    reveal_node_ids: &[u32],
    decrypt_node_ids: &[u32],
) -> PetBlindEvidence {
    let certificate = build_certificate_for(
        fixture,
        target_fingerprint,
        ADMISSION_ATTEMPT,
        context_digest,
        reveal_node_ids,
    );
    let (aggregate_r, aggregate_diff) = build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
        &certificate,
        &fixture.ring_payload,
        &fixture.tag,
        target_fingerprint,
        &fixture_blind_context(fixture, &certificate.attempt_id),
    )
    .expect("certificate must be genuinely valid in this fixture");
    let decrypt_responses = decrypt_node_ids
        .iter()
        .map(|&id| decrypt_share(fixture, &certificate, &aggregate_r, &aggregate_diff, id))
        .collect();
    PetBlindEvidence {
        certificate,
        decrypt_responses,
        coordinator_node_key: ADMISSION_COORDINATOR.to_string(),
    }
}

#[tokio::test]
#[serial_test::serial]
async fn verify_pet_admission_rejects_missing_decrypt_responses() {
    let db_name = "pet_admission_rejects_missing_decrypt_responses";
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let coordinator = test_coordinator(db_name, &fixture).await;
    let context_digest = admission_context_digest(&coordinator, &fixture);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let evidence =
        build_admission_evidence(&fixture, &target_fingerprint, context_digest, &[1, 2], &[]);

    let result = coordinator
        .verify_pet_admission(
            &fixture.document,
            None,
            &object_id_for(&fixture),
            None,
            AUDIT_TARGET,
            ADMISSION_ACTOR,
            None,
            &fixture.ring_payload,
            &evidence,
        )
        .await;

    assert!(
        matches!(
            result,
            Err(PetError::InsufficientShares { got: 0, need: 2 })
        ),
        "expected InsufficientShares, got {:?}",
        result
    );
    cleanup_db(&test_db_path(db_name));
}

#[tokio::test]
#[serial_test::serial]
async fn verify_pet_admission_rejects_insufficient_decrypt_responses() {
    let db_name = "pet_admission_rejects_insufficient_decrypt_responses";
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let coordinator = test_coordinator(db_name, &fixture).await;
    let context_digest = admission_context_digest(&coordinator, &fixture);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let evidence =
        build_admission_evidence(&fixture, &target_fingerprint, context_digest, &[1, 2], &[1]);

    let result = coordinator
        .verify_pet_admission(
            &fixture.document,
            None,
            &object_id_for(&fixture),
            None,
            AUDIT_TARGET,
            ADMISSION_ACTOR,
            None,
            &fixture.ring_payload,
            &evidence,
        )
        .await;

    assert!(
        matches!(
            result,
            Err(PetError::InsufficientShares { got: 1, need: 2 })
        ),
        "expected InsufficientShares, got {:?}",
        result
    );
    cleanup_db(&test_db_path(db_name));
}

#[tokio::test]
#[serial_test::serial]
async fn verify_pet_admission_rejects_duplicate_decrypt_indices() {
    let db_name = "pet_admission_rejects_duplicate_decrypt_indices";
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let coordinator = test_coordinator(db_name, &fixture).await;
    let context_digest = admission_context_digest(&coordinator, &fixture);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    // Two independently-genuine decrypt shares for the *same* slot
    // (byte-identical rebuilds) — isolates the duplicate-index check.
    let evidence = build_admission_evidence(
        &fixture,
        &target_fingerprint,
        context_digest,
        &[1, 2],
        &[1, 1],
    );

    let result = coordinator
        .verify_pet_admission(
            &fixture.document,
            None,
            &object_id_for(&fixture),
            None,
            AUDIT_TARGET,
            ADMISSION_ACTOR,
            None,
            &fixture.ring_payload,
            &evidence,
        )
        .await;

    assert!(
        matches!(result, Err(PetError::Mismatch)),
        "expected a duplicate-index rejection, got {:?}",
        result
    );
    cleanup_db(&test_db_path(db_name));
}

#[tokio::test]
#[serial_test::serial]
async fn verify_pet_admission_rejects_a_forged_decrypt_signature() {
    let db_name = "pet_admission_rejects_a_forged_decrypt_signature";
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let coordinator = test_coordinator(db_name, &fixture).await;
    let context_digest = admission_context_digest(&coordinator, &fixture);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let mut evidence = build_admission_evidence(
        &fixture,
        &target_fingerprint,
        context_digest,
        &[1, 2],
        &[1, 2],
    );
    evidence.decrypt_responses[1].response_signature[0] ^= 0x01;

    let result = coordinator
        .verify_pet_admission(
            &fixture.document,
            None,
            &object_id_for(&fixture),
            None,
            AUDIT_TARGET,
            ADMISSION_ACTOR,
            None,
            &fixture.ring_payload,
            &evidence,
        )
        .await;

    assert!(
        matches!(result, Err(PetError::Mismatch)),
        "expected a signature-verification rejection, got {:?}",
        result
    );
    cleanup_db(&test_db_path(db_name));
}

#[tokio::test]
#[serial_test::serial]
async fn verify_pet_admission_rejects_a_malformed_decrypt_share() {
    let db_name = "pet_admission_rejects_a_malformed_decrypt_share";
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let coordinator = test_coordinator(db_name, &fixture).await;
    let context_digest = admission_context_digest(&coordinator, &fixture);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let certificate = build_certificate_for(
        &fixture,
        &target_fingerprint,
        ADMISSION_ATTEMPT,
        context_digest,
        &[1, 2],
    );
    let (aggregate_r, aggregate_diff) = build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
        &certificate,
        &fixture.ring_payload,
        &fixture.tag,
        &target_fingerprint,
        &fixture_blind_context(&fixture, &certificate.attempt_id),
    )
    .expect("certificate must be genuinely valid in this fixture");
    let genuine = decrypt_share(&fixture, &certificate, &aggregate_r, &aggregate_diff, 1);
    let malformed =
        malformed_decrypt_share(&fixture, &certificate, &aggregate_r, &aggregate_diff, 2);
    let evidence = PetBlindEvidence {
        certificate,
        decrypt_responses: vec![genuine, malformed],
        coordinator_node_key: ADMISSION_COORDINATOR.to_string(),
    };

    let result = coordinator
        .verify_pet_admission(
            &fixture.document,
            None,
            &object_id_for(&fixture),
            None,
            AUDIT_TARGET,
            ADMISSION_ACTOR,
            None,
            &fixture.ring_payload,
            &evidence,
        )
        .await;

    assert!(
        matches!(result, Err(PetError::Mismatch)),
        "expected a malformed-share rejection, got {:?}",
        result
    );
    cleanup_db(&test_db_path(db_name));
}

#[tokio::test]
#[serial_test::serial]
async fn verify_pet_admission_rejects_a_tampered_certificate() {
    let db_name = "pet_admission_rejects_a_tampered_certificate";
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let coordinator = test_coordinator(db_name, &fixture).await;
    let context_digest = admission_context_digest(&coordinator, &fixture);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let mut evidence = build_admission_evidence(
        &fixture,
        &target_fingerprint,
        context_digest,
        &[1, 2],
        &[1, 2],
    );
    let last = evidence.certificate.reveals.len() - 1;
    evidence.certificate.reveals[last].statement.blinded_r[0] ^= 0xFF;

    let result = coordinator
        .verify_pet_admission(
            &fixture.document,
            None,
            &object_id_for(&fixture),
            None,
            AUDIT_TARGET,
            ADMISSION_ACTOR,
            None,
            &fixture.ring_payload,
            &evidence,
        )
        .await;

    assert!(
        matches!(result, Err(PetError::Mismatch)),
        "admission must independently re-detect a tampered certificate, not just trust it, \
             got {:?}",
        result
    );
    cleanup_db(&test_db_path(db_name));
}

/// Confirms the rejections above aren't vacuous against a gate that
/// rejects everything: genuinely signed, correctly combining evidence
/// for a tag that really does match the audited owner must be admitted.
#[tokio::test]
#[serial_test::serial]
async fn verify_pet_admission_accepts_genuine_evidence() {
    let db_name = "pet_admission_accepts_genuine_evidence";
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let coordinator = test_coordinator(db_name, &fixture).await;
    let context_digest = admission_context_digest(&coordinator, &fixture);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let evidence = build_admission_evidence(
        &fixture,
        &target_fingerprint,
        context_digest,
        &[1, 2],
        &[1, 2],
    );

    let result = coordinator
        .verify_pet_admission(
            &fixture.document,
            None,
            &object_id_for(&fixture),
            None,
            AUDIT_TARGET,
            ADMISSION_ACTOR,
            None,
            &fixture.ring_payload,
            &evidence,
        )
        .await;

    assert!(
        result.is_ok(),
        "expected genuine evidence to be admitted: {:?}",
        result
    );
    cleanup_db(&test_db_path(db_name));
}

// ========================================================================
// `verify_reveal_response`'s acceptance ordering must never let a
// rejected or invalid response consume a participant's slot — mirrors
// the old single-round protocol's `verify_check_response` coverage,
// applied to the new, novel reveal phase. Pure functions (no
// `AppState`/local storage/network), so these tests call them directly.
// ========================================================================

#[test]
fn spoofed_reveal_does_not_block_the_honest_participants_later_valid_response() {
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let attempt_id = "attempt-1";
    let context_digest = fixture_blind_context(&fixture, "attempt-1").context_digest();
    let c1 = commit(
        &fixture.tag,
        &target_fingerprint,
        attempt_id,
        context_digest,
        1,
    );
    let c2 = commit(
        &fixture.tag,
        &target_fingerprint,
        attempt_id,
        context_digest,
        2,
    );
    let all_commitments = vec![(1, c1.commitment), (2, c2.commitment)];
    let selection_digest =
        pet_blind_selection_digest(attempt_id, &context_digest, &all_commitments);
    let blind_context = fixture_blind_context(&fixture, "attempt-1");
    let mut seen_node_ids = HashSet::new();

    let spoofed = spoofed_reveal_message(
        &fixture,
        &target_fingerprint,
        attempt_id,
        context_digest,
        &all_commitments,
        &c1,
    );
    let spoofed_result = verify_reveal_response::<PetImpl>(
        spoofed,
        &fixture.document.ring_id,
        &fixture.ring_payload,
        "accused-peer",
        &fixture.tag,
        &target_fingerprint,
        &all_commitments,
        selection_digest,
        &blind_context,
        &None,
        &mut seen_node_ids,
    );
    assert!(
        matches!(spoofed_result, PetRevealResponseVerification::Rejected),
        "a spoofed reveal must be rejected"
    );
    assert!(
        !seen_node_ids.contains(&1),
        "a rejected reveal must not consume the claimed participant's slot"
    );

    let genuine = genuine_reveal_message(
        &fixture,
        &target_fingerprint,
        attempt_id,
        context_digest,
        &all_commitments,
        &c1,
    );
    let genuine_result = verify_reveal_response::<PetImpl>(
        genuine,
        &fixture.document.ring_id,
        &fixture.ring_payload,
        "accused-peer",
        &fixture.tag,
        &target_fingerprint,
        &all_commitments,
        selection_digest,
        &blind_context,
        &None,
        &mut seen_node_ids,
    );
    assert!(
        matches!(genuine_result, PetRevealResponseVerification::Verified(_)),
        "node 1's real, later reveal must still be accepted"
    );
}

#[test]
fn invalid_proof_reveal_does_not_consume_the_slot_for_a_subsequent_valid_contribution() {
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let attempt_id = "attempt-1";
    let context_digest = fixture_blind_context(&fixture, "attempt-1").context_digest();
    let c1 = commit(
        &fixture.tag,
        &target_fingerprint,
        attempt_id,
        context_digest,
        1,
    );
    let c2 = commit(
        &fixture.tag,
        &target_fingerprint,
        attempt_id,
        context_digest,
        2,
    );
    let all_commitments = vec![(1, c1.commitment), (2, c2.commitment)];
    let selection_digest =
        pet_blind_selection_digest(attempt_id, &context_digest, &all_commitments);
    let blind_context = fixture_blind_context(&fixture, "attempt-1");
    let mut seen_node_ids = HashSet::new();

    let bad = reveal_with_bad_proof(
        &fixture,
        &target_fingerprint,
        attempt_id,
        context_digest,
        &all_commitments,
        &c1,
        CryptoSerialize::to_bytes(&Fr::from(7u64)).expect("serialize challenge"),
        CryptoSerialize::to_bytes(&Fr::from(9u64)).expect("serialize proof"),
    );
    let bad_result = verify_reveal_response::<PetImpl>(
        bad,
        &fixture.document.ring_id,
        &fixture.ring_payload,
        "accused-peer",
        &fixture.tag,
        &target_fingerprint,
        &all_commitments,
        selection_digest,
        &blind_context,
        &None,
        &mut seen_node_ids,
    );
    assert!(
        matches!(bad_result, PetRevealResponseVerification::InvalidProof(_)),
        "an authenticated but cryptographically invalid reveal must be reported, not just \
             dropped: {:?}",
        match bad_result {
            PetRevealResponseVerification::InvalidProof(_) => "InvalidProof",
            PetRevealResponseVerification::Rejected => "Rejected",
            PetRevealResponseVerification::Verified(_) => "Verified",
        }
    );
    assert!(
        !seen_node_ids.contains(&1),
        "an invalid-proof reveal must not consume the participant's slot"
    );

    let genuine = genuine_reveal_message(
        &fixture,
        &target_fingerprint,
        attempt_id,
        context_digest,
        &all_commitments,
        &c1,
    );
    let genuine_result = verify_reveal_response::<PetImpl>(
        genuine,
        &fixture.document.ring_id,
        &fixture.ring_payload,
        "accused-peer",
        &fixture.tag,
        &target_fingerprint,
        &all_commitments,
        selection_digest,
        &blind_context,
        &None,
        &mut seen_node_ids,
    );
    assert!(
        matches!(genuine_result, PetRevealResponseVerification::Verified(_)),
        "node 1's real contribution must still be accepted after its own earlier invalid \
             attempt"
    );
}

#[test]
fn malformed_reveal_is_reported_and_does_not_consume_the_slot() {
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let attempt_id = "attempt-1";
    let context_digest = fixture_blind_context(&fixture, "attempt-1").context_digest();
    let c1 = commit(
        &fixture.tag,
        &target_fingerprint,
        attempt_id,
        context_digest,
        1,
    );
    let c2 = commit(
        &fixture.tag,
        &target_fingerprint,
        attempt_id,
        context_digest,
        2,
    );
    let all_commitments = vec![(1, c1.commitment), (2, c2.commitment)];
    let selection_digest =
        pet_blind_selection_digest(attempt_id, &context_digest, &all_commitments);
    let blind_context = fixture_blind_context(&fixture, "attempt-1");
    let mut seen_node_ids = HashSet::new();

    let bad = reveal_with_bad_proof(
        &fixture,
        &target_fingerprint,
        attempt_id,
        context_digest,
        &all_commitments,
        &c1,
        vec![0xff, 0xff, 0xff],
        vec![0xff, 0xff, 0xff],
    );
    let bad_result = verify_reveal_response::<PetImpl>(
        bad,
        &fixture.document.ring_id,
        &fixture.ring_payload,
        "accused-peer",
        &fixture.tag,
        &target_fingerprint,
        &all_commitments,
        selection_digest,
        &blind_context,
        &None,
        &mut seen_node_ids,
    );
    assert!(
        matches!(bad_result, PetRevealResponseVerification::InvalidProof(_)),
        "an authenticated but undecodable reveal must be reported, not just dropped \
             (finding #9)"
    );
    assert!(
        !seen_node_ids.contains(&1),
        "a malformed reveal must not consume the participant's slot"
    );

    let genuine = genuine_reveal_message(
        &fixture,
        &target_fingerprint,
        attempt_id,
        context_digest,
        &all_commitments,
        &c1,
    );
    let genuine_result = verify_reveal_response::<PetImpl>(
        genuine,
        &fixture.document.ring_id,
        &fixture.ring_payload,
        "accused-peer",
        &fixture.tag,
        &target_fingerprint,
        &all_commitments,
        selection_digest,
        &blind_context,
        &None,
        &mut seen_node_ids,
    );
    assert!(
        matches!(genuine_result, PetRevealResponseVerification::Verified(_)),
        "node 1's real contribution must still be accepted after its own earlier malformed \
             attempt"
    );
}

#[test]
fn duplicate_valid_reveals_count_only_once() {
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let attempt_id = "attempt-1";
    let context_digest = fixture_blind_context(&fixture, "attempt-1").context_digest();
    let c1 = commit(
        &fixture.tag,
        &target_fingerprint,
        attempt_id,
        context_digest,
        1,
    );
    let c2 = commit(
        &fixture.tag,
        &target_fingerprint,
        attempt_id,
        context_digest,
        2,
    );
    let all_commitments = vec![(1, c1.commitment), (2, c2.commitment)];
    let selection_digest =
        pet_blind_selection_digest(attempt_id, &context_digest, &all_commitments);
    let blind_context = fixture_blind_context(&fixture, "attempt-1");
    let mut seen_node_ids = HashSet::new();

    let first = verify_reveal_response::<PetImpl>(
        genuine_reveal_message(
            &fixture,
            &target_fingerprint,
            attempt_id,
            context_digest,
            &all_commitments,
            &c1,
        ),
        &fixture.document.ring_id,
        &fixture.ring_payload,
        "accused-peer",
        &fixture.tag,
        &target_fingerprint,
        &all_commitments,
        selection_digest,
        &blind_context,
        &None,
        &mut seen_node_ids,
    );
    assert!(matches!(first, PetRevealResponseVerification::Verified(_)));

    let second = verify_reveal_response::<PetImpl>(
        genuine_reveal_message(
            &fixture,
            &target_fingerprint,
            attempt_id,
            context_digest,
            &all_commitments,
            &c1,
        ),
        &fixture.document.ring_id,
        &fixture.ring_payload,
        "accused-peer",
        &fixture.tag,
        &target_fingerprint,
        &all_commitments,
        selection_digest,
        &blind_context,
        &None,
        &mut seen_node_ids,
    );
    assert!(
        matches!(second, PetRevealResponseVerification::Rejected),
        "a second valid reveal for an already-accepted id must count only once"
    );
}

#[test]
fn three_of_five_reveal_collection_succeeds_despite_earlier_spoofing_and_invalid_proof_attempts() {
    let fixture = build_fixture(5, 3, AUDIT_TARGET);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let attempt_id = "attempt-1";
    let context_digest = fixture_blind_context(&fixture, "attempt-1").context_digest();
    let contributions: Vec<Contribution> = (1..=3)
        .map(|id| {
            commit(
                &fixture.tag,
                &target_fingerprint,
                attempt_id,
                context_digest,
                id,
            )
        })
        .collect();
    let all_commitments: Vec<(u32, [u8; 32])> = contributions
        .iter()
        .map(|c| (c.node_id, c.commitment))
        .collect();
    let selection_digest =
        pet_blind_selection_digest(attempt_id, &context_digest, &all_commitments);
    let blind_context = fixture_blind_context(&fixture, "attempt-1");
    let mut seen_node_ids = HashSet::new();
    let mut verified = Vec::new();

    let messages = vec![
        spoofed_reveal_message(
            &fixture,
            &target_fingerprint,
            attempt_id,
            context_digest,
            &all_commitments,
            &contributions[0],
        ),
        reveal_with_bad_proof(
            &fixture,
            &target_fingerprint,
            attempt_id,
            context_digest,
            &all_commitments,
            &contributions[1],
            CryptoSerialize::to_bytes(&Fr::from(7u64)).expect("serialize challenge"),
            CryptoSerialize::to_bytes(&Fr::from(9u64)).expect("serialize proof"),
        ),
        genuine_reveal_message(
            &fixture,
            &target_fingerprint,
            attempt_id,
            context_digest,
            &all_commitments,
            &contributions[0],
        ),
        genuine_reveal_message(
            &fixture,
            &target_fingerprint,
            attempt_id,
            context_digest,
            &all_commitments,
            &contributions[1],
        ),
        genuine_reveal_message(
            &fixture,
            &target_fingerprint,
            attempt_id,
            context_digest,
            &all_commitments,
            &contributions[2],
        ),
    ];
    for message in messages {
        if let PetRevealResponseVerification::Verified(signed) = verify_reveal_response::<PetImpl>(
            message,
            &fixture.document.ring_id,
            &fixture.ring_payload,
            "accused-peer",
            &fixture.tag,
            &target_fingerprint,
            &all_commitments,
            selection_digest,
            &blind_context,
            &None,
            &mut seen_node_ids,
        ) {
            verified.push(signed);
        }
    }

    assert_eq!(
        seen_node_ids,
        std::collections::HashSet::from([1, 2, 3]),
        "the three genuine reveals must all be accepted despite the earlier spoofing and \
             invalid-proof attempts on nodes 1 and 2"
    );
    assert_eq!(verified.len(), 3, "threshold must be reached");
}

// ========================================================================
// `verify_decrypt_response`'s acceptance ordering — reuses the old
// single-round protocol's per-share DLEQ machinery unchanged, now
// against a certificate's aggregate points, so coverage here is lighter
// than reveal's (which is genuinely new): one ordering test, one
// multi-node collection test.
// ========================================================================

#[test]
fn spoofed_decrypt_does_not_block_the_honest_participants_later_valid_response() {
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let certificate = build_valid_certificate(&fixture, &target_fingerprint);
    let (aggregate_r, aggregate_diff) = build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
        &certificate,
        &fixture.ring_payload,
        &fixture.tag,
        &target_fingerprint,
        &fixture_blind_context(&fixture, &certificate.attempt_id),
    )
    .expect("valid certificate");
    let pub_poly = fixture_pub_poly(&fixture);
    let blind_context = fixture_blind_context(&fixture, "attempt-1");
    let mut seen_node_ids = HashSet::new();
    let aggregate_r_bytes = CryptoSerialize::to_bytes(&aggregate_r).expect("serialize aggregate_r");
    let aggregate_diff_bytes =
        CryptoSerialize::to_bytes(&aggregate_diff).expect("serialize aggregate_diff");

    let genuine_share = decrypt_share(&fixture, &certificate, &aggregate_r, &aggregate_diff, 1);
    let mut spoofed_message = decrypt_statement_to_message(
        genuine_share.statement.clone(),
        genuine_share.response_signature.clone(),
    );
    if let PetMessage::DecryptResponse {
        response_signature, ..
    } = &mut spoofed_message
    {
        response_signature[0] ^= 0x01;
    }
    let spoofed_result = verify_decrypt_response::<PetImpl>(
        spoofed_message,
        &fixture.document.ring_id,
        &fixture.ring_payload,
        "accused-peer",
        &pub_poly,
        certificate.context_digest,
        certificate.certificate_digest(),
        &certificate.attempt_id,
        &aggregate_r_bytes,
        &aggregate_diff_bytes,
        &blind_context,
        &certificate,
        &None,
        &mut seen_node_ids,
    );
    assert!(
        matches!(spoofed_result, PetDecryptResponseVerification::Rejected),
        "a spoofed decrypt share must be rejected"
    );
    assert!(!seen_node_ids.contains(&1));

    let genuine_message =
        decrypt_statement_to_message(genuine_share.statement, genuine_share.response_signature);
    let genuine_result = verify_decrypt_response::<PetImpl>(
        genuine_message,
        &fixture.document.ring_id,
        &fixture.ring_payload,
        "accused-peer",
        &pub_poly,
        certificate.context_digest,
        certificate.certificate_digest(),
        &certificate.attempt_id,
        &aggregate_r_bytes,
        &aggregate_diff_bytes,
        &blind_context,
        &certificate,
        &None,
        &mut seen_node_ids,
    );
    assert!(
        matches!(genuine_result, PetDecryptResponseVerification::Verified(..)),
        "node 1's real decrypt share must still be accepted"
    );
}

#[test]
fn three_of_five_decrypt_collection_succeeds_despite_earlier_spoofing() {
    let fixture = build_fixture(5, 3, AUDIT_TARGET);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let certificate = build_certificate_for(
        &fixture,
        &target_fingerprint,
        "attempt-1",
        fixture_blind_context(&fixture, "attempt-1").context_digest(),
        &[1, 2, 3],
    );
    let (aggregate_r, aggregate_diff) = build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
        &certificate,
        &fixture.ring_payload,
        &fixture.tag,
        &target_fingerprint,
        &fixture_blind_context(&fixture, &certificate.attempt_id),
    )
    .expect("valid certificate");
    let pub_poly = fixture_pub_poly(&fixture);
    let blind_context = fixture_blind_context(&fixture, "attempt-1");
    let mut seen_node_ids = HashSet::new();
    let mut verified = Vec::new();
    let aggregate_r_bytes = CryptoSerialize::to_bytes(&aggregate_r).expect("serialize aggregate_r");
    let aggregate_diff_bytes =
        CryptoSerialize::to_bytes(&aggregate_diff).expect("serialize aggregate_diff");

    let spoofed_share = decrypt_share(&fixture, &certificate, &aggregate_r, &aggregate_diff, 1);
    let mut spoofed_message = decrypt_statement_to_message(
        spoofed_share.statement.clone(),
        spoofed_share.response_signature.clone(),
    );
    if let PetMessage::DecryptResponse {
        response_signature, ..
    } = &mut spoofed_message
    {
        response_signature[0] ^= 0x01;
    }

    let share_2 = decrypt_share(&fixture, &certificate, &aggregate_r, &aggregate_diff, 2);
    let share_3 = decrypt_share(&fixture, &certificate, &aggregate_r, &aggregate_diff, 3);
    let messages = vec![
        spoofed_message,
        decrypt_statement_to_message(spoofed_share.statement, spoofed_share.response_signature),
        decrypt_statement_to_message(share_2.statement, share_2.response_signature),
        decrypt_statement_to_message(share_3.statement, share_3.response_signature),
    ];
    for message in messages {
        if let PetDecryptResponseVerification::Verified(_, share) = verify_decrypt_response::<PetImpl>(
            message,
            &fixture.document.ring_id,
            &fixture.ring_payload,
            "accused-peer",
            &pub_poly,
            certificate.context_digest,
            certificate.certificate_digest(),
            &certificate.attempt_id,
            &aggregate_r_bytes,
            &aggregate_diff_bytes,
            &blind_context,
            &certificate,
            &None,
            &mut seen_node_ids,
        ) {
            verified.push(share);
        }
    }

    assert_eq!(
        seen_node_ids,
        std::collections::HashSet::from([1, 2, 3]),
        "the three genuine decrypt shares must all be accepted despite the earlier spoofing \
             attempt on node 1"
    );
    assert_eq!(verified.len(), 3, "threshold must be reached");
}

#[test]
fn certificate_validates_and_recovers_a_nonidentity_aggregate() {
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let certificate = build_valid_certificate(&fixture, &target_fingerprint);

    let (aggregate_r, _aggregate_diff) =
        build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
            &certificate,
            &fixture.ring_payload,
            &fixture.tag,
            &target_fingerprint,
            &fixture_blind_context(&fixture, &certificate.attempt_id),
        )
        .expect("a genuinely valid certificate must verify");
    assert!(
        !DkgImpl::public_key_is_identity(&aggregate_r),
        "the aggregate ephemeral point must never be the identity"
    );
}

#[test]
fn certificate_rejects_a_tampered_blinded_r() {
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let mut certificate = build_valid_certificate(&fixture, &target_fingerprint);
    let last = certificate.reveals.len() - 1;
    certificate.reveals[last].statement.blinded_r[0] ^= 0xFF;

    let result = build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
        &certificate,
        &fixture.ring_payload,
        &fixture.tag,
        &target_fingerprint,
        &fixture_blind_context(&fixture, &certificate.attempt_id),
    );
    assert!(
        result.is_err(),
        "a tampered blinded_r must fail its commitment opening or its proof"
    );
}

#[test]
fn certificate_rejects_a_non_opening_reveal() {
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let mut certificate = build_valid_certificate(&fixture, &target_fingerprint);
    let last = certificate.reveals.len() - 1;
    certificate.reveals[last].statement.commit_salt[0] ^= 0xFF;

    let result = build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
        &certificate,
        &fixture.ring_payload,
        &fixture.tag,
        &target_fingerprint,
        &fixture_blind_context(&fixture, &certificate.attempt_id),
    );
    assert!(
        result.is_err(),
        "a reveal with the wrong commit_salt must not open its claimed commitment"
    );
}

#[test]
fn certificate_rejects_a_duplicate_node_id() {
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let mut certificate = build_valid_certificate(&fixture, &target_fingerprint);
    let duplicate = certificate.reveals[0].clone();
    certificate.reveals[1] = duplicate;

    let result = build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
        &certificate,
        &fixture.ring_payload,
        &fixture.tag,
        &target_fingerprint,
        &fixture_blind_context(&fixture, &certificate.attempt_id),
    );
    assert!(
        result.is_err(),
        "two reveals claiming the same node id must be rejected"
    );
}

#[test]
fn certificate_rejects_a_short_reveal_list() {
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let mut certificate = build_valid_certificate(&fixture, &target_fingerprint);
    certificate.reveals.pop();

    let result = build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
        &certificate,
        &fixture.ring_payload,
        &fixture.tag,
        &target_fingerprint,
        &fixture_blind_context(&fixture, &certificate.attempt_id),
    );
    assert!(
        result.is_err(),
        "fewer reveals than the ring's threshold must be rejected, never silently accepted"
    );
}

#[test]
fn certificate_rejects_wrong_target_fingerprint() {
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let target_fingerprint =
        PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).expect("compute F(target)");
    let certificate = build_valid_certificate(&fixture, &target_fingerprint);
    let other_fingerprint = PetImpl::owner_fingerprint(b"someone-else").expect("compute F(other)");

    let result = build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
        &certificate,
        &fixture.ring_payload,
        &fixture.tag,
        &other_fingerprint,
        &fixture_blind_context(&fixture, &certificate.attempt_id),
    );
    assert!(
        result.is_err(),
        "a certificate built against one target must not verify against a different one"
    );
}

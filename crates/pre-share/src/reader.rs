//! Reader-side retrieval, verification, and recovery for a Defra-backed PRE
//! delivery (ring `pre_share_endpoints`).
//!
//! [`recover_from_manifest`] is the one entry point a reader needs: given a
//! [`PreShareRetrievalManifest`] (handed back by the relayer, or saved and
//! loaded later — the manifest is self-contained, carrying its own Defra
//! endpoint and ring-size bound) and a Defra bearer token (empty is fine —
//! see below), it fetches every entry's envelope, independently verifies
//! each one against the manifest's own *pinned* fields — never current ring
//! state — and recovers the re-encrypted commitment once a threshold of
//! entries verify. The caller (`cli-tool`) then runs the exact same
//! `ThresholdDealer::decrypt_secret` call the direct-delivery path already
//! uses.
//!
//! A bad entry (tampered signature, tampered proof, a mismatched pinned
//! field, a fetch failure) is logged and skipped, not a hard failure —
//! mirrors the live collection path's per-peer tolerance in
//! `orbis-node`'s own `verify_peer_response`/`verify_peer_ack`. Only
//! insufficient *total* verified entries at the end is an error.
//!
//! Reads from Defra with an empty bearer token deliberately: confirmed
//! against DefraDB's real identity extractor
//! (`crates/http/src/identity_extractor.rs` in the pinned revision) that an
//! absent `Authorization` header and a present-but-empty `Bearer` token both
//! parse as anonymous, not a malformed-token error. A stored envelope is
//! safe to be publicly readable — its content is useless without a
//! threshold of genuine signed shares *and* the reader's own private key;
//! nothing about this feature's security depends on Defra gating reads.

use std::collections::HashSet;

use crypto::r#trait::{PubShare, ReencryptReply, ThresholdDealer};
use crypto::{CryptoDeserialize, GroupAffine, PreImpl, PubPolyImpl, ScalarField};
use reqwest::Url;

use crate::defra::{DefraClient, PRE_SHARE_COLLECTION};
use crate::error::{PreShareError, Result};
use crate::manifest::{PreShareRetrievalManifest, PRE_SHARE_MANIFEST_VERSION};

/// What a reader needs to finish decryption with
/// `ThresholdDealer::decrypt_secret` — everything else (`secret`, `context`,
/// `ring_pk`) comes straight from the manifest the caller already has.
#[derive(Debug)]
pub struct RecoveredReencryption {
    pub xnc_cmt: GroupAffine,
    pub derivation: Option<Vec<u8>>,
}

fn decode_pub_poly(hex_str: &str) -> Result<PubPolyImpl> {
    let bytes = hex::decode(hex_str).map_err(|error| {
        PreShareError::Malformed(format!("invalid pinned_public_polynomial hex: {error}"))
    })?;
    PubPolyImpl::from_bytes(&bytes).map_err(|error| {
        PreShareError::Malformed(format!("invalid pinned_public_polynomial: {error}"))
    })
}

/// Fetches, verifies, dedups, and recovers a manifest's entries into a single
/// re-encrypted commitment. See the module doc for the full verification
/// order and trust model.
pub async fn recover_from_manifest(
    manifest: &PreShareRetrievalManifest,
    defra_bearer_token: &str,
) -> Result<RecoveredReencryption> {
    if manifest.manifest_version != PRE_SHARE_MANIFEST_VERSION {
        return Err(PreShareError::UnsupportedManifestVersion(
            manifest.manifest_version,
        ));
    }

    let endpoint = manifest.pre_share_endpoints.first().ok_or_else(|| {
        PreShareError::Malformed("manifest has no pre_share_endpoints".to_string())
    })?;
    let url = Url::parse(endpoint)
        .map_err(|error| PreShareError::Malformed(format!("invalid Defra endpoint: {error}")))?;
    let client = DefraClient::new(url, defra_bearer_token.to_string())
        .map_err(|error| PreShareError::Malformed(error.to_string()))?;

    let pub_poly = decode_pub_poly(&manifest.pinned_public_polynomial)?;
    let enc_cmt = GroupAffine::from_bytes(&manifest.secret.enc_cmt)
        .map_err(|error| PreShareError::Malformed(format!("invalid enc_cmt: {error}")))?;
    let rdr_pk = GroupAffine::from_bytes(&manifest.rdr_pk_bytes)
        .map_err(|error| PreShareError::Malformed(format!("invalid rdr_pk: {error}")))?;

    let dealer = PreImpl::new();
    let mut seen_node_ids = HashSet::new();
    let mut verified_shares = Vec::new();
    let mut agreed_derivation: Option<Option<Vec<u8>>> = None;

    for entry in &manifest.entries {
        if seen_node_ids.contains(&entry.from_node_id) {
            continue;
        }

        let envelope = match client
            .fetch_envelope(PRE_SHARE_COLLECTION, &entry.defra_locator)
            .await
        {
            Ok(envelope) => envelope,
            Err(error) => {
                tracing::warn!(
                    from_node_id = entry.from_node_id,
                    error = %error,
                    "pre-share reader: failed to fetch envelope, skipping entry"
                );
                continue;
            }
        };

        if let Err(error) = envelope.verify(&entry.responder_node_key) {
            tracing::warn!(
                from_node_id = entry.from_node_id,
                error = %error,
                "pre-share reader: envelope signature invalid, skipping entry"
            );
            continue;
        }

        let statement = &envelope.envelope.statement;
        let fields_match = envelope.envelope.pinned_public_polynomial
            == manifest.pinned_public_polynomial
            && statement.from_node_id == entry.from_node_id
            && statement.responder_node_key == entry.responder_node_key
            && statement.request_id == manifest.request_id
            && statement.object_id == manifest.object_id
            && statement.ring_id == manifest.ring_id
            && statement.ring_pk == manifest.ring_pk
            && statement.rdr_pk == manifest.rdr_pk_bytes;
        if !fields_match {
            tracing::warn!(
                from_node_id = entry.from_node_id,
                "pre-share reader: envelope fields don't match the manifest, skipping entry"
            );
            continue;
        }

        match &agreed_derivation {
            None => agreed_derivation = Some(statement.derivation.clone()),
            Some(expected) if expected != &statement.derivation => {
                return Err(PreShareError::InconsistentDerivation);
            }
            Some(_) => {}
        }

        let (Ok(share_v), Ok(challenge), Ok(proof)) = (
            GroupAffine::from_bytes(&statement.share),
            ScalarField::from_bytes(&statement.challenge),
            ScalarField::from_bytes(&statement.proof),
        ) else {
            tracing::warn!(
                from_node_id = entry.from_node_id,
                "pre-share reader: failed to deserialize share/challenge/proof, skipping entry"
            );
            continue;
        };

        let reply = ReencryptReply {
            share: PubShare {
                i: entry.from_node_id,
                v: share_v,
            },
            challenge,
            proof,
        };

        if let Err(error) = dealer.verify(
            &rdr_pk,
            &pub_poly,
            &enc_cmt,
            &reply,
            statement.derivation.as_deref(),
        ) {
            tracing::warn!(
                from_node_id = entry.from_node_id,
                error = %error,
                "pre-share reader: PRE proof invalid, skipping entry"
            );
            continue;
        }

        seen_node_ids.insert(entry.from_node_id);
        verified_shares.push(reply.share.clone());
    }

    if verified_shares.len() < manifest.threshold {
        return Err(PreShareError::InsufficientVerifiedEntries {
            got: verified_shares.len(),
            need: manifest.threshold,
        });
    }

    let xnc_cmt = dealer
        .recover(
            &verified_shares,
            manifest.threshold,
            manifest.total_participants,
        )
        .map_err(|error| PreShareError::RecoveryFailed(error.to_string()))?
        .ok_or_else(|| PreShareError::RecoveryFailed("recovery returned None".to_string()))?;

    Ok(RecoveredReencryption {
        xnc_cmt,
        derivation: agreed_derivation.flatten(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::StoredShareEnvelope;
    use crate::manifest::{DefraLocator, PreShareManifestEntry};
    use crypto::context::{CiphertextContext, ReaderAuthorizationContext};
    use crypto::r#trait::{DistKeyShare, Dkg, Secret};
    use crypto::test_helper::DKGCoordinator;
    use crypto::{CryptoSerialize, DkgImpl};
    use orbis_reporting::PreReencryptResponseStatement;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SIGNING_KEY_HEX: &str =
        "c4a48e2fce1481cd3294b4490f6678090ea98d3d0e5cd984558ab0968741b104";
    const RESPONDER_NODE_KEY_HEX: &str =
        "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62";

    fn test_ciphertext_context() -> CiphertextContext {
        CiphertextContext {
            ring_pk: vec![],
            policy_id: "policy-1".to_string(),
            resource: "resource".to_string(),
            permission: "read".to_string(),
            tier: None,
            timestamp: None,
            salt: None,
            pet_tag: None,
        }
    }

    fn test_reader_auth_context(
        rdr_pk: &[u8],
        derivation: Option<Vec<u8>>,
    ) -> ReaderAuthorizationContext {
        ReaderAuthorizationContext {
            chain_id: "test-chain".to_string(),
            ring_pk: vec![9, 9, 9],
            jwt_issuer: "did:key:test".to_string(),
            jwt_subject: None,
            resolved_actor: "did:key:test".to_string(),
            jwt_id: "jti-1".to_string(),
            jwt_issued_time: 1_700_000_000,
            jwt_expiration_time: 1_700_003_600,
            jwt_not_before: None,
            object_id: "object-1".to_string(),
            recipient_pk: rdr_pk.to_vec(),
            derivation,
            salt: None,
            valid_window: None,
            audit_target_object_id: None,
        }
    }

    /// Everything a real `n`-of-`t` DKG + real re-encryption produces, for
    /// building test manifests/envelopes against genuine, `dealer.verify`-
    /// passing crypto material — no `orbis-node` dependency, using the same
    /// `DKGCoordinator` + `dist_key_share`/`reencrypt` recipe
    /// `crates/crypto/src/pre_tests.rs::test_dkg_encrypt_decrypt_integration`
    /// already exercises internally for the `crypto` crate's own tests.
    struct RealPreFixture {
        pub_poly: PubPolyImpl,
        secret: Secret,
        rdr_pk_bytes: Vec<u8>,
        replies: Vec<(u32, ReencryptReply<ScalarField, GroupAffine>)>,
        derivation: Option<Vec<u8>>,
        threshold: usize,
        total_participants: usize,
    }

    fn build_real_pre_fixture(n: usize, t: usize, derivation: Option<Vec<u8>>) -> RealPreFixture {
        let mut coordinator = DKGCoordinator::new(
            |id, threshold, total_nodes, session_id, role| {
                DkgImpl::new(id, threshold, total_nodes, session_id, role)
            },
            n,
            t,
        )
        .expect("build DKG coordinator");
        let (aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().expect("run DKG");

        let (_enc_cmt, secret, _proof) = PreImpl::encrypt_secret(
            &aggregate_pk,
            b"the actual plaintext",
            derivation.as_deref(),
            &test_ciphertext_context(),
        )
        .expect("encrypt secret");

        let (rdr_sk, rdr_pk) = crypto::helpers::generate_keypair().expect("reader keypair");
        let rdr_pk_bytes: Vec<u8> = CryptoSerialize::to_bytes(&rdr_pk).expect("serialize rdr_pk");
        let ctx = test_reader_auth_context(&rdr_pk_bytes, derivation.clone());
        let signature =
            PreImpl::sign_reader_authorization(&rdr_sk, &rdr_pk, &ctx).expect("sign reader auth");

        let enc_cmt = GroupAffine::from_bytes(&secret.enc_cmt).expect("deserialize enc_cmt");
        let dealer = PreImpl::new();
        let mut replies = Vec::new();
        for share in secret_shares.iter() {
            let dist_key_share = DistKeyShare {
                pri_share: share.clone(),
            };
            let reply = dealer
                .reencrypt(&dist_key_share, &secret, &rdr_pk, &ctx, &signature)
                .expect("reencrypt");
            dealer
                .verify(&rdr_pk, &pub_poly, &enc_cmt, &reply, derivation.as_deref())
                .expect("genuine reply must verify");
            replies.push((share.i, reply));
        }

        RealPreFixture {
            pub_poly,
            secret,
            rdr_pk_bytes,
            replies,
            derivation,
            threshold: t,
            total_participants: n,
        }
    }

    fn statement_for(
        fixture: &RealPreFixture,
        from_node_id: u32,
        reply: &ReencryptReply<ScalarField, GroupAffine>,
        request_id: &str,
    ) -> PreReencryptResponseStatement {
        PreReencryptResponseStatement {
            domain: "orbis-pre-reencrypt-response-v1".to_string(),
            chain_id: "test-chain".to_string(),
            ring_id: "ring-1".to_string(),
            ring_pk: "ring-pk-hex".to_string(),
            ring_state_sha256: "deadbeef".to_string(),
            protocol_version: 0,
            request_id: request_id.to_string(),
            signed_at: 1_700_000_000,
            responder_node_key: RESPONDER_NODE_KEY_HEX.to_string(),
            origin_protocol: "pre".to_string(),
            object_id: "object-1".to_string(),
            rdr_pk: fixture.rdr_pk_bytes.clone(),
            derivation: fixture.derivation.clone(),
            from_node_id,
            share: CryptoSerialize::to_bytes(&reply.share.v).expect("serialize share"),
            challenge: CryptoSerialize::to_bytes(&reply.challenge).expect("serialize challenge"),
            proof: CryptoSerialize::to_bytes(&reply.proof).expect("serialize proof"),
            crypto_backend: PreImpl::name(),
            timestamp: None,
            document_inline: false,
        }
    }

    fn sign(
        statement: PreReencryptResponseStatement,
        pinned_public_polynomial: &str,
    ) -> crate::envelope::SignedStoredShareEnvelope {
        StoredShareEnvelope::new(statement, pinned_public_polynomial.to_string())
            .sign(SIGNING_KEY_HEX)
            .expect("sign envelope")
    }

    async fn mount_envelope(
        server: &MockServer,
        locator: &str,
        envelope: &crate::envelope::SignedStoredShareEnvelope,
    ) {
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v0/collections/{PRE_SHARE_COLLECTION}/document/{locator}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "envelope": serde_json::to_string(envelope).unwrap(),
            })))
            .mount(server)
            .await;
    }

    fn base_manifest(fixture: &RealPreFixture, server_uri: String) -> PreShareRetrievalManifest {
        PreShareRetrievalManifest {
            manifest_version: PRE_SHARE_MANIFEST_VERSION,
            request_id: "req-1".to_string(),
            ring_id: "ring-1".to_string(),
            ring_pk: "ring-pk-hex".to_string(),
            threshold: fixture.threshold,
            total_participants: fixture.total_participants,
            pinned_public_polynomial: hex::encode(
                CryptoSerialize::to_bytes(&fixture.pub_poly).expect("serialize pub_poly"),
            ),
            rdr_pk_bytes: fixture.rdr_pk_bytes.clone(),
            object_id: "object-1".to_string(),
            secret: fixture.secret.clone(),
            context: test_ciphertext_context(),
            pre_share_endpoints: vec![server_uri],
            entries: vec![],
        }
    }

    #[tokio::test]
    async fn recover_from_manifest_recovers_the_correct_commitment() {
        let fixture = build_real_pre_fixture(3, 2, None);
        let server = MockServer::start().await;
        let mut manifest = base_manifest(&fixture, server.uri());

        for (idx, (from_node_id, reply)) in fixture.replies.iter().enumerate() {
            let locator = format!("bae-{idx}");
            let statement = statement_for(&fixture, *from_node_id, reply, "req-1");
            let envelope = sign(statement, &manifest.pinned_public_polynomial);
            mount_envelope(&server, &locator, &envelope).await;
            manifest.entries.push(PreShareManifestEntry {
                from_node_id: *from_node_id,
                responder_node_key: RESPONDER_NODE_KEY_HEX.to_string(),
                defra_locator: DefraLocator(locator),
            });
        }

        let recovered = recover_from_manifest(&manifest, "")
            .await
            .expect("recovery should succeed");

        let direct_shares: Vec<_> = fixture
            .replies
            .iter()
            .take(fixture.threshold)
            .map(|(id, reply)| PubShare {
                i: *id,
                v: reply.share.v,
            })
            .collect();
        let direct = PreImpl::new()
            .recover(
                &direct_shares,
                fixture.threshold,
                fixture.total_participants,
            )
            .expect("direct recover")
            .expect("some commitment");

        assert_eq!(recovered.xnc_cmt, direct);
        assert_eq!(recovered.derivation, None);
    }

    #[tokio::test]
    async fn recover_from_manifest_survives_a_signed_at_far_outside_the_report_ttl_window() {
        let fixture = build_real_pre_fixture(3, 2, None);
        let server = MockServer::start().await;
        let mut manifest = base_manifest(&fixture, server.uri());

        for (idx, (from_node_id, reply)) in fixture.replies.iter().enumerate() {
            let locator = format!("bae-{idx}");
            let mut statement = statement_for(&fixture, *from_node_id, reply, "req-1");
            // Far older than REPORT_TTL_SECS (120s) — proves that reporting-evidence
            // freshness gate was never accidentally inherited by the reader.
            statement.signed_at = 1;
            let envelope = sign(statement, &manifest.pinned_public_polynomial);
            mount_envelope(&server, &locator, &envelope).await;
            manifest.entries.push(PreShareManifestEntry {
                from_node_id: *from_node_id,
                responder_node_key: RESPONDER_NODE_KEY_HEX.to_string(),
                defra_locator: DefraLocator(locator),
            });
        }

        recover_from_manifest(&manifest, "")
            .await
            .expect("recovery should succeed regardless of how old signed_at is");
    }

    #[tokio::test]
    async fn recover_from_manifest_uses_the_pinned_pub_poly_not_a_different_current_one() {
        // Simulates "the ring refreshed after this request was made": build a
        // *second*, unrelated DKG purely to prove its existence doesn't matter —
        // recovery only ever decodes `manifest.pinned_public_polynomial`, so there
        // is no path by which a different "current" pub_poly could be picked up.
        let _unrelated_refreshed_ring = build_real_pre_fixture(3, 2, None);
        let fixture = build_real_pre_fixture(3, 2, None);
        let server = MockServer::start().await;
        let mut manifest = base_manifest(&fixture, server.uri());

        for (idx, (from_node_id, reply)) in fixture.replies.iter().enumerate() {
            let locator = format!("bae-{idx}");
            let statement = statement_for(&fixture, *from_node_id, reply, "req-1");
            let envelope = sign(statement, &manifest.pinned_public_polynomial);
            mount_envelope(&server, &locator, &envelope).await;
            manifest.entries.push(PreShareManifestEntry {
                from_node_id: *from_node_id,
                responder_node_key: RESPONDER_NODE_KEY_HEX.to_string(),
                defra_locator: DefraLocator(locator),
            });
        }

        recover_from_manifest(&manifest, "")
            .await
            .expect("recovery must use the pinned pub_poly, independent of any other ring state");
    }

    #[tokio::test]
    async fn recover_from_manifest_rejects_a_tampered_envelope_signature() {
        let fixture = build_real_pre_fixture(2, 2, None);
        let server = MockServer::start().await;
        let mut manifest = base_manifest(&fixture, server.uri());

        for (idx, (from_node_id, reply)) in fixture.replies.iter().enumerate() {
            let locator = format!("bae-{idx}");
            let statement = statement_for(&fixture, *from_node_id, reply, "req-1");
            let mut envelope = sign(statement, &manifest.pinned_public_polynomial);
            if idx == 0 {
                let last = envelope.envelope_signature.last_mut().unwrap();
                *last ^= 0xFF;
            }
            mount_envelope(&server, &locator, &envelope).await;
            manifest.entries.push(PreShareManifestEntry {
                from_node_id: *from_node_id,
                responder_node_key: RESPONDER_NODE_KEY_HEX.to_string(),
                defra_locator: DefraLocator(locator),
            });
        }

        let error = recover_from_manifest(&manifest, "")
            .await
            .expect_err("one tampered signature must drop below a 2-of-2 threshold");
        assert!(matches!(
            error,
            PreShareError::InsufficientVerifiedEntries { got: 1, need: 2 }
        ));
    }

    #[tokio::test]
    async fn recover_from_manifest_rejects_a_tampered_proof() {
        let fixture = build_real_pre_fixture(2, 2, None);
        let server = MockServer::start().await;
        let mut manifest = base_manifest(&fixture, server.uri());

        for (idx, (from_node_id, reply)) in fixture.replies.iter().enumerate() {
            let locator = format!("bae-{idx}");
            let mut statement = statement_for(&fixture, *from_node_id, reply, "req-1");
            if idx == 0 {
                *statement.proof.last_mut().unwrap() ^= 0xFF;
            }
            let envelope = sign(statement, &manifest.pinned_public_polynomial);
            mount_envelope(&server, &locator, &envelope).await;
            manifest.entries.push(PreShareManifestEntry {
                from_node_id: *from_node_id,
                responder_node_key: RESPONDER_NODE_KEY_HEX.to_string(),
                defra_locator: DefraLocator(locator),
            });
        }

        let error = recover_from_manifest(&manifest, "")
            .await
            .expect_err("a tampered proof must drop below a 2-of-2 threshold");
        assert!(matches!(
            error,
            PreShareError::InsufficientVerifiedEntries { got: 1, need: 2 }
        ));
    }

    #[tokio::test]
    async fn recover_from_manifest_does_not_double_count_duplicate_entries() {
        let fixture = build_real_pre_fixture(2, 2, None);
        let server = MockServer::start().await;
        let mut manifest = base_manifest(&fixture, server.uri());

        let (from_node_id, reply) = &fixture.replies[0];
        let locator = "bae-0".to_string();
        let statement = statement_for(&fixture, *from_node_id, reply, "req-1");
        let envelope = sign(statement, &manifest.pinned_public_polynomial);
        mount_envelope(&server, &locator, &envelope).await;
        // Same from_node_id twice — must not count as two distinct contributions.
        for _ in 0..2 {
            manifest.entries.push(PreShareManifestEntry {
                from_node_id: *from_node_id,
                responder_node_key: RESPONDER_NODE_KEY_HEX.to_string(),
                defra_locator: DefraLocator(locator.clone()),
            });
        }

        let error = recover_from_manifest(&manifest, "")
            .await
            .expect_err("duplicate entries for the same node must not satisfy threshold 2");
        assert!(matches!(
            error,
            PreShareError::InsufficientVerifiedEntries { got: 1, need: 2 }
        ));
    }

    #[tokio::test]
    async fn recover_from_manifest_rejects_an_envelope_pinned_to_a_different_generation() {
        let fixture = build_real_pre_fixture(2, 2, None);
        let server = MockServer::start().await;
        let mut manifest = base_manifest(&fixture, server.uri());

        for (idx, (from_node_id, reply)) in fixture.replies.iter().enumerate() {
            let locator = format!("bae-{idx}");
            let statement = statement_for(&fixture, *from_node_id, reply, "req-1");
            // idx 0's envelope claims a different generation than the manifest pins —
            // the underlying crypto material is otherwise completely valid.
            let pin = if idx == 0 {
                "a-different-generation"
            } else {
                manifest.pinned_public_polynomial.as_str()
            };
            let envelope = sign(statement, pin);
            mount_envelope(&server, &locator, &envelope).await;
            manifest.entries.push(PreShareManifestEntry {
                from_node_id: *from_node_id,
                responder_node_key: RESPONDER_NODE_KEY_HEX.to_string(),
                defra_locator: DefraLocator(locator),
            });
        }

        let error = recover_from_manifest(&manifest, "")
            .await
            .expect_err("a generation-pin mismatch must drop below a 2-of-2 threshold");
        assert!(matches!(
            error,
            PreShareError::InsufficientVerifiedEntries { got: 1, need: 2 }
        ));
    }

    #[tokio::test]
    async fn recover_from_manifest_rejects_a_statement_from_a_different_request() {
        let fixture = build_real_pre_fixture(2, 2, None);
        let server = MockServer::start().await;
        let mut manifest = base_manifest(&fixture, server.uri());

        for (idx, (from_node_id, reply)) in fixture.replies.iter().enumerate() {
            let locator = format!("bae-{idx}");
            // idx 0's statement is genuinely valid crypto, just for a different request.
            let request_id = if idx == 0 {
                "some-other-request"
            } else {
                "req-1"
            };
            let statement = statement_for(&fixture, *from_node_id, reply, request_id);
            let envelope = sign(statement, &manifest.pinned_public_polynomial);
            mount_envelope(&server, &locator, &envelope).await;
            manifest.entries.push(PreShareManifestEntry {
                from_node_id: *from_node_id,
                responder_node_key: RESPONDER_NODE_KEY_HEX.to_string(),
                defra_locator: DefraLocator(locator),
            });
        }

        let error = recover_from_manifest(&manifest, "")
            .await
            .expect_err("a cross-request statement must drop below a 2-of-2 threshold");
        assert!(matches!(
            error,
            PreShareError::InsufficientVerifiedEntries { got: 1, need: 2 }
        ));
    }

    #[tokio::test]
    async fn recover_from_manifest_tolerates_one_entry_404ing() {
        let fixture = build_real_pre_fixture(3, 2, None);
        let server = MockServer::start().await;
        let mut manifest = base_manifest(&fixture, server.uri());

        for (idx, (from_node_id, reply)) in fixture.replies.iter().enumerate() {
            let locator = format!("bae-{idx}");
            if idx != 0 {
                // idx 0's locator is deliberately never mounted — a real 404.
                let statement = statement_for(&fixture, *from_node_id, reply, "req-1");
                let envelope = sign(statement, &manifest.pinned_public_polynomial);
                mount_envelope(&server, &locator, &envelope).await;
            }
            manifest.entries.push(PreShareManifestEntry {
                from_node_id: *from_node_id,
                responder_node_key: RESPONDER_NODE_KEY_HEX.to_string(),
                defra_locator: DefraLocator(locator),
            });
        }

        recover_from_manifest(&manifest, "")
            .await
            .expect("the other two entries still meet a threshold of 2");
    }

    #[tokio::test]
    async fn recover_from_manifest_rejects_an_unsupported_manifest_version_without_any_network_call(
    ) {
        let fixture = build_real_pre_fixture(2, 2, None);
        // Deliberately unreachable: proves no network call was attempted.
        let mut manifest = base_manifest(&fixture, "http://127.0.0.1:1".to_string());
        manifest.manifest_version = PRE_SHARE_MANIFEST_VERSION + 1;

        let error = recover_from_manifest(&manifest, "")
            .await
            .expect_err("unsupported manifest version must be rejected");
        assert!(matches!(
            error,
            PreShareError::UnsupportedManifestVersion(v) if v == PRE_SHARE_MANIFEST_VERSION + 1
        ));
    }

    #[tokio::test]
    async fn recover_from_manifest_errors_clearly_when_too_few_entries_exist_at_all() {
        let fixture = build_real_pre_fixture(3, 2, None);
        let server = MockServer::start().await;
        let mut manifest = base_manifest(&fixture, server.uri());

        let (from_node_id, reply) = &fixture.replies[0];
        let locator = "bae-0".to_string();
        let statement = statement_for(&fixture, *from_node_id, reply, "req-1");
        let envelope = sign(statement, &manifest.pinned_public_polynomial);
        mount_envelope(&server, &locator, &envelope).await;
        manifest.entries.push(PreShareManifestEntry {
            from_node_id: *from_node_id,
            responder_node_key: RESPONDER_NODE_KEY_HEX.to_string(),
            defra_locator: DefraLocator(locator),
        });

        let error = recover_from_manifest(&manifest, "")
            .await
            .expect_err("only one of two needed entries exists at all");
        assert!(matches!(
            error,
            PreShareError::InsufficientVerifiedEntries { got: 1, need: 2 }
        ));
    }
}

use super::*;
use crate::reporting::v0::error::ReportingError;
use crate::reporting::v0::registry::{
    require_pet_blind_decrypt_verification_failure, ReportValidationContext, ReportValidationMode,
};
use crate::reporting::v0::types::pet_public_polynomial_digest;
use crypto::r#trait::PubPoly;

fn certified_generation(
    fixture: &TagFixture,
    polynomial: &crypto::PubPolyImpl,
) -> (PetBlindContext, PetBlindCertificate, G1Affine, G1Affine) {
    let mut context = fixture_blind_context(fixture, "attempt-1");
    let polynomial = polynomial.to_bytes().unwrap();
    context.public_polynomial_digest = pet_public_polynomial_digest(&polynomial);
    let digest = context.context_digest();
    let target = PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).unwrap();
    let contributions: Vec<_> = [1, 2]
        .into_iter()
        .map(|id| commit(&fixture.tag, &target, &context.attempt_id, digest, id))
        .collect();
    let commitments: Vec<_> = contributions
        .iter()
        .map(|c| (c.node_id, c.commitment))
        .collect();
    let reveals = contributions
        .iter()
        .map(|c| {
            reveal(
                fixture,
                &target,
                &context.attempt_id,
                digest,
                &commitments,
                c,
                &fixture.signers[(c.node_id - 1) as usize],
            )
        })
        .collect();
    let certificate = PetBlindCertificate {
        public_polynomial: polynomial,
        attempt_id: context.attempt_id.clone(),
        context_digest: digest,
        all_commitments: commitments
            .into_iter()
            .map(|(id, bytes)| (id, bytes.to_vec()))
            .collect(),
        reveals,
    };
    let (r, diff) = build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
        &certificate,
        &fixture.ring_payload,
        &fixture.tag,
        &target,
        &context,
    )
    .expect("real threshold reveal certificate");
    (context, certificate, r, diff)
}

async fn report_context(
    fixture: &TagFixture,
    certificate: &PetBlindCertificate,
) -> ReportValidationContext {
    let db_name = format!("pet_generation_report_{}", rand::random::<u64>());
    let (coordinator, bulletin) = test_coordinator_with_bulletin(&db_name, fixture).await;
    bulletin.set_post(
        object_id_for(fixture),
        bulletin::r#trait::BulletinPost {
            id: object_id_for(fixture),
            payload: serde_json::to_vec(&fixture.document).unwrap(),
        },
    );
    let state = &coordinator.app_state;
    ReportValidationContext {
        local_node_key: state.node_key.clone(),
        requester_peer_id: None,
        network: state.network.clone(),
        peer_connection_pool: state.peer_connection_pool.clone(),
        bulletin: state.bulletin.clone(),
        authz: state.authz.clone(),
        local_storage: state.local_storage.clone(),
        routes: &::network::V0,
        now: 1_700_000_010,
        mode: ReportValidationMode::ReporterObservation,
        inline_document: None,
        pet_blind_context: None,
        pet_blind_certificate: Some(certificate.clone()),
    }
}

fn resign(fixture: &TagFixture, reply: &mut PetBlindSignedDecrypt) {
    reply.response_signature = sign_node_message_with_hex_key(
        &fixture.signers[(reply.statement.from_node_id - 1) as usize].secret_hex,
        &reply.statement.canonical_bytes(),
    )
    .unwrap();
}

fn replace_partial(reply: &mut PetBlindSignedDecrypt, scalar: &Fr) {
    let tag = PetTag {
        ephemeral_point: reply.statement.aggregate_r.clone(),
        masked_fingerprint: Vec::new(),
    };
    let partial = PetImpl::partial_pet_check(scalar, reply.statement.from_node_id, &tag).unwrap();
    reply.statement.partial = partial.partial.v.to_bytes().unwrap();
    reply.statement.challenge = partial.challenge.to_bytes().unwrap();
    reply.statement.proof = partial.proof.to_bytes().unwrap();
}

#[tokio::test]
async fn forged_same_key_polynomial_and_valid_fake_share_are_attributable() {
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let actual = fixture_pub_poly(&fixture);
    let (blind, certificate, r, diff) = certified_generation(&fixture, &actual);
    let context = report_context(&fixture, &certificate).await;
    let (known_scalar, known_point) = crypto::helpers::generate_keypair().unwrap();
    let minus_pk = crypto::helpers::mul_point(&actual.eval(0), &(-Fr::from(1u64))).unwrap();
    let fake = crypto::PubPolyImpl {
        commits: vec![
            actual.eval(0),
            crypto::helpers::add_points(&known_point, &minus_pk).unwrap(),
        ],
    };
    assert_eq!(
        fake.eval(0),
        actual.eval(0),
        "same checking key does not authenticate the slope"
    );
    assert_eq!(
        fake.eval(1),
        known_point,
        "attacker knows the fabricated share at node1"
    );
    let mut reply = decrypt_share(&fixture, &certificate, &r, &diff, 1);
    reply.statement.public_polynomial = fake.to_bytes().unwrap();
    replace_partial(&mut reply, &known_scalar);
    resign(&fixture, &mut reply);
    let synthetic_tag = PetTag {
        ephemeral_point: reply.statement.aggregate_r.clone(),
        masked_fingerprint: Vec::new(),
    };
    let partial = PetImpl::partial_pet_check(&known_scalar, 1, &synthetic_tag).unwrap();
    PetImpl::verify_partial_pet_check(&fake, &synthetic_tag, &partial)
        .expect("fake proof is internally valid");
    require_pet_blind_decrypt_verification_failure(
        &blind,
        &reply.statement,
        &reply.response_signature,
        &fixture.ring_payload,
        &context,
    )
    .await
    .expect("signed substitution against an authenticated generation is attributable");
}

#[tokio::test]
async fn honest_certified_old_and_new_generations_never_use_reporter_local_polynomial() {
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let old = fixture_pub_poly(&fixture);
    let new = crypto::PubPolyImpl {
        commits: vec![old.eval(0), old.eval(0)],
    };
    for (certified, certified_share, local, local_share) in [
        (&old, fixture.pet_sk, &new, fixture.pet_sk + fixture.pet_sk),
        (&new, fixture.pet_sk + fixture.pet_sk, &old, fixture.pet_sk),
    ] {
        let (blind, certificate, r, diff) = certified_generation(&fixture, certified);
        let context = report_context(&fixture, &certificate).await;
        RingShareBundle {
            share_bytes: Zeroizing::new(
                PriShare {
                    i: 1,
                    v: local_share,
                }
                .to_bytes()
                .unwrap(),
            ),
            public_polynomial: hex::encode(local.to_bytes().unwrap()),
            last_pss: 0,
        }
        .save_by_pet_ring_key(&context.local_storage, RING_ID)
        .unwrap();
        let mut reply = decrypt_share(&fixture, &certificate, &r, &diff, 1);
        replace_partial(&mut reply, &certified_share);
        resign(&fixture, &mut reply);
        let result = require_pet_blind_decrypt_verification_failure(
            &blind,
            &reply.statement,
            &reply.response_signature,
            &fixture.ring_payload,
            &context,
        )
        .await;
        assert!(
            matches!(result, Err(ReportingError::Unauthorized(_))),
            "genuine certified reply must refute the report: {result:?}"
        );
    }
}

#[tokio::test]
async fn invalid_generation_certificate_cannot_attribute_a_fault() {
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let (blind, certificate, r, diff) = certified_generation(&fixture, &fixture_pub_poly(&fixture));
    let mut context = report_context(&fixture, &certificate).await;
    let mut reply = decrypt_share(&fixture, &certificate, &r, &diff, 1);
    reply.statement.proof.fill(0xff);
    resign(&fixture, &mut reply);
    require_pet_blind_decrypt_verification_failure(
        &blind,
        &reply.statement,
        &reply.response_signature,
        &fixture.ring_payload,
        &context,
    )
    .await
    .expect("valid certificate permits attribution of invalid proof");
    let mut variants = vec![None];
    let mut invalid = certificate.clone();
    invalid.public_polynomial.push(0);
    variants.push(Some(invalid));
    let mut invalid = certificate.clone();
    invalid.reveals.pop();
    variants.push(Some(invalid));
    let mut invalid = certificate.clone();
    invalid.reveals[1] = invalid.reveals[0].clone();
    variants.push(Some(invalid));
    let mut invalid = certificate.clone();
    invalid.reveals[0].response_signature[0] ^= 1;
    variants.push(Some(invalid));
    for certificate in variants {
        context.pet_blind_certificate = certificate;
        let mut claim = reply.clone();
        if let Some(certificate) = &context.pet_blind_certificate {
            claim.statement.certificate_digest = certificate.certificate_digest();
            resign(&fixture, &mut claim);
        }
        let result = require_pet_blind_decrypt_verification_failure(
            &blind,
            &claim.statement,
            &claim.response_signature,
            &fixture.ring_payload,
            &context,
        )
        .await;
        assert!(
            matches!(result, Err(ReportingError::InvalidReport(_))),
            "unverified certificate is not attributable: {result:?}"
        );
    }
    context.pet_blind_certificate = Some(certificate);
    let mut other_context = blind.clone();
    other_context.audit_target_object_id.push('x');
    assert!(matches!(
        require_pet_blind_decrypt_verification_failure(
            &other_context,
            &reply.statement,
            &reply.response_signature,
            &fixture.ring_payload,
            &context
        )
        .await,
        Err(ReportingError::InvalidReport(_))
    ));
    let mut other_ring = fixture.ring_payload.clone();
    other_ring.peer_node_keys.reverse();
    other_ring.pss_interval += 1;
    assert!(matches!(
        require_pet_blind_decrypt_verification_failure(
            &blind,
            &reply.statement,
            &reply.response_signature,
            &other_ring,
            &context
        )
        .await,
        Err(ReportingError::InvalidReport(_))
    ));
}

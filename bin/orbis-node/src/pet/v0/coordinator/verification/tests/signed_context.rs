use super::*;

#[test]
fn signed_context_rejects_cross_context_reveals_and_decrypts() {
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let target = PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).unwrap();
    let certificate = build_valid_certificate(&fixture, &target);
    let context = fixture_blind_context(&fixture, &certificate.attempt_id);
    let (r, diff) = build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
        &certificate,
        &fixture.ring_payload,
        &fixture.tag,
        &target,
        &context,
    )
    .expect("matching signed reveal context must pass");
    let decrypt = decrypt_share(&fixture, &certificate, &r, &diff, 1);
    let polynomial = fixture_pub_poly(&fixture);
    let check_decrypt = |reply: &PetBlindSignedDecrypt| {
        verify_one_decrypt::<PetImpl>(
            &reply.statement,
            &reply.response_signature,
            &fixture.ring_payload,
            &polynomial,
            certificate.context_digest,
            certificate.certificate_digest(),
            &certificate.attempt_id,
            &decrypt.statement.aggregate_r,
            &decrypt.statement.aggregate_diff,
            &context,
        )
    };
    assert!(matches!(
        check_decrypt(&decrypt),
        ContributionCheckOutcome::Verified(_)
    ));

    for field in ["domain", "chain", "ring", "key", "state", "version"] {
        let mut other_certificate = certificate.clone();
        let reveal = &mut other_certificate.reveals[0];
        let mut other_decrypt = decrypt.clone();
        match field {
            "domain" => {
                reveal.statement.domain = PET_BLIND_DECRYPT_RESPONSE_DOMAIN.to_string();
                other_decrypt.statement.domain = PET_BLIND_REVEAL_RESPONSE_DOMAIN.to_string();
            }
            "chain" => {
                reveal.statement.chain_id.push('x');
                other_decrypt.statement.chain_id.push('x');
            }
            "ring" => {
                reveal.statement.ring_id.push('x');
                other_decrypt.statement.ring_id.push('x');
            }
            "key" => {
                reveal.statement.ring_pk.push('x');
                other_decrypt.statement.ring_pk.push('x');
            }
            "state" => {
                reveal.statement.ring_state_sha256.push('x');
                other_decrypt.statement.ring_state_sha256.push('x');
            }
            "version" => {
                reveal.statement.protocol_version += 1;
                other_decrypt.statement.protocol_version += 1;
            }
            _ => unreachable!(),
        }
        // Genuine signatures distinguish a context rejection from signature failure.
        reveal.response_signature = sign_node_message_with_hex_key(
            &fixture.signers[0].secret_hex,
            &reveal.statement.canonical_bytes(),
        )
        .unwrap();
        other_decrypt.response_signature = sign_node_message_with_hex_key(
            &fixture.signers[0].secret_hex,
            &other_decrypt.statement.canonical_bytes(),
        )
        .unwrap();
        assert!(
            matches!(
                build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
                    &other_certificate,
                    &fixture.ring_payload,
                    &fixture.tag,
                    &target,
                    &context,
                ),
                Err(PetError::ProtocolError(_))
            ),
            "cross-context reveal: {field}"
        );
        assert!(
            matches!(
                check_decrypt(&other_decrypt),
                ContributionCheckOutcome::NotAttributable(PetError::ProtocolError(_))
            ),
            "cross-context decrypt is not reportable: {field}"
        );
    }
}

#[test]
fn signed_context_preserves_signature_before_fault_attribution() {
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let target = PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).unwrap();
    let certificate = build_valid_certificate(&fixture, &target);
    let context = fixture_blind_context(&fixture, &certificate.attempt_id);
    let (r, diff) = build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
        &certificate,
        &fixture.ring_payload,
        &fixture.tag,
        &target,
        &context,
    )
    .unwrap();
    let mut reply = decrypt_share(&fixture, &certificate, &r, &diff, 1);
    let polynomial = fixture_pub_poly(&fixture);
    let check = |reply: &PetBlindSignedDecrypt| {
        verify_one_decrypt::<PetImpl>(
            &reply.statement,
            &reply.response_signature,
            &fixture.ring_payload,
            &polynomial,
            certificate.context_digest,
            certificate.certificate_digest(),
            &certificate.attempt_id,
            &reply.statement.aggregate_r,
            &reply.statement.aggregate_diff,
            &context,
        )
    };
    reply.statement.proof.clear();
    assert!(matches!(
        check(&reply),
        ContributionCheckOutcome::NotAttributable(_)
    ));
    reply.response_signature = sign_node_message_with_hex_key(
        &fixture.signers[0].secret_hex,
        &reply.statement.canonical_bytes(),
    )
    .unwrap();
    assert!(matches!(
        check(&reply),
        ContributionCheckOutcome::Invalid(_)
    ));
}

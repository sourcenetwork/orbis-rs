use super::*;
use crate::pet::v0::messages::DecryptRequest;
use crate::unsafe_testing::service::UnsafeTestingServiceImpl;
use proto::unsafe_testing::{
    unsafe_testing_service_server::UnsafeTestingService, SetPetDecryptFaultRequest,
};
use tonic::Request;

#[tokio::test]
#[serial_test::serial]
async fn signed_decrypt_fault_is_ring_scoped_and_preserves_bundle_validation() {
    let db_name = "pet_signed_decrypt_fault";
    let fixture = build_fixture(3, 2, AUDIT_TARGET);
    let coordinator = test_coordinator(db_name, &fixture).await;
    let state = &coordinator.app_state;
    let service = UnsafeTestingServiceImpl::with_app_state(state.clone());
    let context = authorized_pet_context(&fixture);
    let actor = verify_pet_audit_authorization(&*state.authz, &context, None, current_unix_time())
        .await
        .unwrap();
    let blind = build_pet_blind_context(
        state.bulletin.chain_id(),
        &fixture.ring_payload,
        fixture.ring_payload.pet_pk.as_ref().unwrap(),
        0,
        PetImpl::name(),
        &context,
        actor,
        state.node_key.clone(),
        "fault-attempt".into(),
    );
    let target = PetImpl::owner_fingerprint(AUDIT_TARGET.as_bytes()).unwrap();
    let contributions: Vec<_> = [1, 2]
        .into_iter()
        .map(|id| {
            commit(
                &fixture.tag,
                &target,
                &blind.attempt_id,
                blind.context_digest(),
                id,
            )
        })
        .collect();
    let commitments: Vec<_> = contributions
        .iter()
        .map(|c| (c.node_id, c.commitment))
        .collect();
    let certificate = PetBlindCertificate {
        public_polynomial: fixture_polynomial_bytes(&fixture),
        attempt_id: blind.attempt_id.clone(),
        context_digest: blind.context_digest(),
        all_commitments: commitments
            .iter()
            .map(|(id, bytes)| (*id, bytes.to_vec()))
            .collect(),
        reveals: contributions
            .iter()
            .map(|c| {
                reveal(
                    &fixture,
                    &target,
                    &blind.attempt_id,
                    blind.context_digest(),
                    &commitments,
                    c,
                    &fixture.signers[(c.node_id - 1) as usize],
                )
            })
            .collect(),
    };
    let (r, diff) = build_and_verify_pet_blind_certificate::<DkgImpl, PetImpl>(
        &certificate,
        &fixture.ring_payload,
        &fixture.tag,
        &target,
        &blind,
    )
    .unwrap();
    let request = DecryptRequest {
        request_id: "decrypt-fault-attempt".into(),
        attempt_id: blind.attempt_id.clone(),
        from_node_id: 1,
        certificate: certificate.clone(),
        context,
    };
    let peer = PeerId::new(hex::decode(peer_id_hex_for(0)).unwrap());
    let original = RingShareBundle::load_by_pet_ring_key(&state.local_storage, RING_ID).unwrap();
    let verify = |reply| {
        verify_decrypt_response::<PetImpl>(
            reply,
            RING_ID,
            &fixture.ring_payload,
            "fixture-peer",
            &fixture_pub_poly(&fixture),
            blind.context_digest(),
            certificate.certificate_digest(),
            &blind.attempt_id,
            &r.to_bytes().unwrap(),
            &diff.to_bytes().unwrap(),
            &blind,
            &certificate,
            &None,
            &mut HashSet::new(),
        )
    };

    // A different target is unaffected; the selected target signs invalid DLEQ
    // evidence rather than failing its identity signature or mutating the key.
    for (ring, enabled, invalid) in [
        ("other-ring", true, false),
        (RING_ID, true, true),
        (RING_ID, false, false),
    ] {
        service
            .set_pet_decrypt_fault(Request::new(SetPetDecryptFaultRequest {
                ring_id: ring.into(),
                enabled,
            }))
            .await
            .unwrap();
        let response = coordinator
            .handle_decrypt_request(request.clone(), &peer)
            .await
            .unwrap()
            .unwrap();
        let result = verify(response);
        if invalid {
            let PetDecryptResponseVerification::InvalidProof(observation) = result else {
                panic!("fault must produce attributable signed evidence");
            };
            assert_eq!(observation.accused_node_key, state.node_key);
            assert_eq!(observation.pet_blind_certificate, Some(certificate.clone()));
        } else {
            assert!(matches!(
                result,
                PetDecryptResponseVerification::Verified(..)
            ));
        }
        let stored = RingShareBundle::load_by_pet_ring_key(&state.local_storage, RING_ID).unwrap();
        assert!(stored.to_bytes().as_slice() == original.to_bytes().as_slice());
    }

    // Enabling the hook cannot turn an inconsistent stored share into a signed
    // response: the normal atomic-bundle check still runs before injection.
    service
        .set_pet_decrypt_fault(Request::new(SetPetDecryptFaultRequest {
            ring_id: RING_ID.into(),
            enabled: true,
        }))
        .await
        .unwrap();
    let mut corrupt = original.clone();
    let share = PriShare {
        i: 1,
        v: fixture.pet_sk + Fr::from(1u64),
    };
    corrupt.share_bytes = Zeroizing::new(share.to_bytes().unwrap());
    corrupt
        .save_by_pet_ring_key(&state.local_storage, RING_ID)
        .unwrap();
    let error = coordinator
        .handle_decrypt_request(request, &peer)
        .await
        .unwrap_err();
    assert!(matches!(error, PetError::Storage(_)), "{error:?}");
    cleanup_db(&test_db_path(db_name));
}

use crate::dkg::v0::service::DkgServiceImpl;
use crate::helpers::auth::current_unix_time;
use crate::helpers::test_helpers::{
    cleanup_db, create_authenticated_request, create_test_app_state_with_bulletin, test_db_path,
    JwtSigner,
};
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::{RingPayload, UpgradeInfo};
use crypto::DkgImpl;
use proto::v0::dkg::{dkg_service_server::DkgService, StartDkgRequest};
use std::sync::Arc;

/// Verify that a v0 DkgService returns FailedPrecondition when the ring's
/// activation_time has passed and its effective_version is no longer 0.
#[tokio::test]
async fn dkg_service_rejects_migrated_ring() {
    let db_name = test_db_path("upgrade_dkg");
    let bulletin = Arc::new(DummyBulletin::new().await.unwrap());
    let now = current_unix_time().expect("system clock");

    // Ring whose upgrade window has already elapsed: effective_version is now 1.
    bulletin
        .set_ring(
            "ring-1".to_string(),
            RingPayload {
                upgrade_info: UpgradeInfo {
                    current_version: 0,
                    next_version: Some(1),
                    activation_time: Some(now - 1),
                },
                ring_pk: "deadbeef".to_string(),
                peer_node_keys: vec![],
                ..Default::default()
            },
        )
        .unwrap();

    let app_state = create_test_app_state_with_bulletin(None, true, bulletin, &db_name).await;
    let svc = DkgServiceImpl::<DkgImpl>::with_routes(app_state, &network::V0);

    let token = JwtSigner::new().create_dkg_jwt("ring-1").unwrap();
    let request = create_authenticated_request(
        StartDkgRequest {
            ring_id: "ring-1".to_string(),
        },
        &token,
    )
    .unwrap();

    let err = svc.start_dkg(request).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(
        err.message().contains("route_version=0"),
        "expected route_version in error: {}",
        err.message()
    );
    assert!(
        err.message().contains("effective_version=1"),
        "expected effective_version in error: {}",
        err.message()
    );

    cleanup_db(&db_name);
}

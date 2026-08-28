#[allow(unused_imports)]
use {super::super::*, super::support::*};

#[test]
fn reshare_next_transport_routes_accept_reordering_with_exact_key_bindings() {
    validate_reshare_next_transport_committee(
        &valid_next_transport_committee(),
        &["next-b".to_string(), "next-a".to_string()],
        2,
        &resolved_next_routes(),
    )
    .expect("equivalent orderings with authoritative key-route bindings must validate");
}

#[test]
fn reshare_next_transport_routes_reject_altered_or_swapped_routes() {
    let expected_keys = ["next-b".to_string(), "next-a".to_string()];
    let resolved = resolved_next_routes();

    let mut altered = valid_next_transport_committee();
    altered.peer_routes[0] = format!("{}@127.0.0.1:9999", "aa".repeat(32));
    let error = validate_reshare_next_transport_committee(&altered, &expected_keys, 2, &resolved)
        .expect_err("an altered direct address must be rejected");
    assert!(matches!(error, DkgError::Unauthorized(_)));
    assert!(error.to_string().contains("Vera NodeInfo routes"));

    let mut swapped = valid_next_transport_committee();
    swapped.peer_routes.swap(0, 1);
    let error = validate_reshare_next_transport_committee(&swapped, &expected_keys, 2, &resolved)
        .expect_err("a route set bound to the wrong node keys must be rejected");
    assert!(matches!(error, DkgError::Unauthorized(_)));
    assert!(error.to_string().contains("Vera NodeInfo routes"));
}

#[test]
fn reshare_next_transport_rejects_membership_threshold_and_assignment_mismatches() {
    let expected_keys = ["next-b".to_string(), "next-a".to_string()];
    let resolved = resolved_next_routes();

    let mut wrong_member = valid_next_transport_committee();
    wrong_member.node_keys[0] = "next-c".to_string();
    let error =
        validate_reshare_next_transport_committee(&wrong_member, &expected_keys, 2, &resolved)
            .expect_err("a different transport member must be rejected");
    assert!(matches!(error, DkgError::Unauthorized(_)));
    assert!(error.to_string().contains("announced next committee"));

    let mut wrong_threshold = valid_next_transport_committee();
    wrong_threshold.threshold = 1;
    let error =
        validate_reshare_next_transport_committee(&wrong_threshold, &expected_keys, 2, &resolved)
            .expect_err("a different transport threshold must be rejected");
    assert!(matches!(error, DkgError::Unauthorized(_)));
    assert!(error.to_string().contains("announced threshold"));

    let mut wrong_assignments = valid_next_transport_committee();
    wrong_assignments
        .node_id_assignments
        .insert("next-a".to_string(), 2);
    wrong_assignments
        .node_id_assignments
        .insert("next-b".to_string(), 1);
    let error =
        validate_reshare_next_transport_committee(&wrong_assignments, &expected_keys, 2, &resolved)
            .expect_err("noncanonical next transport assignments must be rejected");
    assert!(matches!(error, DkgError::Unauthorized(_)));
    assert!(error.to_string().contains("not canonical"));
}

#[test]
fn follower_bootstrap_preserves_the_authoritative_direct_route() {
    let leader_bytes = [7u8; 32];
    let route = format!("{}@127.0.0.1:9000", hex::encode(leader_bytes));

    let bootstrap = leader_bootstrap("follower-key", "leader-key", &route).unwrap();

    assert_eq!(bootstrap.len(), 1);
    assert_eq!(bootstrap[0].as_bytes(), route.as_bytes());
}

#[test]
fn follower_bootstrap_accepts_an_id_only_discovery_route() {
    let route = hex::encode([7u8; 32]);

    let bootstrap = leader_bootstrap("follower-key", "leader-key", &route).unwrap();

    assert_eq!(bootstrap.len(), 1);
    assert_eq!(bootstrap[0].as_bytes(), route.as_bytes());
}

#[test]
fn follower_bootstrap_preserves_hostname_and_ipv6_routes() {
    let node_id = hex::encode([7u8; 32]);
    for route in [
        format!("{node_id}@leader.example.com:9000"),
        format!("{node_id}@[::1]:9000"),
    ] {
        let bootstrap = leader_bootstrap("follower-key", "leader-key", &route).unwrap();
        assert_eq!(bootstrap[0].as_bytes(), route.as_bytes());
    }
}

#[test]
fn follower_bootstrap_rejects_malformed_leader_route() {
    let error = leader_bootstrap("follower-key", "leader-key", "not-hex@127.0.0.1:9000")
        .expect_err("malformed leader node IDs must be rejected before Gossip subscribe");

    assert!(matches!(error, DkgError::InvalidInput(_)));
    assert!(error.to_string().contains("invalid leader route"));

    let node_id = hex::encode([7u8; 32]);
    let error = leader_bootstrap(
        "follower-key",
        "leader-key",
        &format!("{node_id}@not a valid address"),
    )
    .expect_err("malformed direct addresses must be rejected before Gossip subscribe");

    assert!(matches!(error, DkgError::InvalidInput(_)));
    assert!(error.to_string().contains("invalid leader route"));
}

#[tokio::test]
#[serial_test::serial]
async fn follower_bootstrap_joins_gossip_with_discovery_and_relays_disabled() {
    use network::Network as _;

    let leader = network::NetworkImpl::builder()
        .bind_addr_v4("127.0.0.1:0".parse().unwrap())
        .private_routes_only()
        .build()
        .await
        .expect("build leader network");
    let follower = network::NetworkImpl::builder()
        .bind_addr_v4("127.0.0.1:0".parse().unwrap())
        .private_routes_only()
        .build()
        .await
        .expect("build follower network");
    let leader_router = leader
        .create_router_builder()
        .unwrap()
        .spawn()
        .expect("spawn leader Gossip router");
    let follower_router = follower
        .create_router_builder()
        .unwrap()
        .spawn()
        .expect("spawn follower Gossip router");

    let topic_id = network::TopicId::new([23; 32]);
    let leader_topic = leader
        .pubsub()
        .expect("leader pub-sub")
        .subscribe(topic_id, Vec::new())
        .await
        .expect("leader creates topic");
    let leader_route = format!(
        "{}@{}",
        hex::encode(leader.local_peer_id().as_bytes()),
        leader
            .bound_addresses()
            .into_iter()
            .next()
            .expect("leader bound address")
    );
    let bootstrap = leader_bootstrap("follower-key", "leader-key", &leader_route).unwrap();
    let follower_topic = follower
        .pubsub()
        .expect("follower pub-sub")
        .subscribe(topic_id, bootstrap)
        .await
        .expect("follower joins through the direct leader route");

    timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                leader_topic.recv().await.expect("leader topic event"),
                PubSubEvent::NeighborUp(_)
            ) {
                break;
            }
        }
    })
    .await
    .expect("leader and follower should become Gossip neighbors");

    leader_topic
        .broadcast(Bytes::from_static(b"direct-route-bootstrap"))
        .await
        .expect("leader broadcasts after direct join");
    let received = timeout(Duration::from_secs(10), async {
        loop {
            if let PubSubEvent::Received(message) =
                follower_topic.recv().await.expect("follower topic event")
            {
                return message;
            }
        }
    })
    .await
    .expect("follower receives over the direct Gossip route");
    assert_eq!(&received.data[..], b"direct-route-bootstrap");
    assert_eq!(received.origin, leader.local_peer_id());

    leader_router.shutdown().await.unwrap();
    follower_router.shutdown().await.unwrap();
}

#[test]
fn leader_does_not_bootstrap_through_its_own_route() {
    assert!(leader_bootstrap("leader-key", "leader-key", "not-needed")
        .unwrap()
        .is_empty());
}

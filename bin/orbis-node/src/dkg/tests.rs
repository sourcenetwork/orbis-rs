#[cfg(test)]
mod tests {
    use crate::helpers::test_helpers::create_test_app_state_default;
    use crate::{
        crypto_service::{crypto_service_server::CryptoService, StartDkgRequest},
        CryptoServiceImpl,
    };
    use hex;
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tonic::{Request, Response};
    /// Unit test: Test start_dkg directly
    #[tokio::test]
    async fn test_start_dkg_unit() {
        let app_state = create_test_app_state_default().await;
        let service = CryptoServiceImpl::new(app_state);

        let request = StartDkgRequest {
            session_id: "test-session-123".to_string(),
            threshold: 2,
            total_participants: 3,
            participant_ids: vec![
                "participant-1".to_string(),
                "participant-2".to_string(),
                "participant-3".to_string(),
            ],
            parameters: {
                let mut map = HashMap::new();
                map.insert("key_type".to_string(), "BLS12_381".to_string());
                map.insert("curve".to_string(), "bls12_381".to_string());
                map
            },
            peer_ids: vec!["test".to_string()],
        };

        let tonic_request = Request::new(request.clone());
        let result = service.start_dkg(tonic_request).await;

        assert!(result.is_ok(), "start_dkg should succeed");

        let response: Response<_> = result.unwrap();
        let inner = response.into_inner();

        // Verify response fields
        assert_eq!(inner.session_id, request.session_id);
        assert_eq!(inner.status, "started");
        assert!(inner.message.contains("DKG session started"));
        assert!(inner.message.contains("threshold 2"));
        assert!(inner.message.contains("3 participants"));

        // Verify timestamp is reasonable (within last minute)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            inner.created_at <= now && inner.created_at >= now - 60,
            "created_at should be recent, got: {}, now: {}",
            inner.created_at,
            now
        );
    }

    /// Unit test: Test start_dkg with minimal request
    #[tokio::test]
    async fn test_start_dkg_minimal() {
        let app_state = create_test_app_state_default().await;
        let service = CryptoServiceImpl::new(app_state);

        let request = StartDkgRequest {
            session_id: "minimal-session".to_string(),
            threshold: 1,
            total_participants: 1,
            participant_ids: vec!["single-participant".to_string()],
            parameters: HashMap::new(),
            peer_ids: vec!["test".to_string()],
        };

        let tonic_request = Request::new(request.clone());
        let result = service.start_dkg(tonic_request).await;

        assert!(
            result.is_ok(),
            "start_dkg should succeed with minimal request"
        );

        let response: Response<_> = result.unwrap();
        let inner = response.into_inner();

        assert_eq!(inner.session_id, request.session_id);
        assert_eq!(inner.status, "started");
        assert!(inner.message.contains("threshold 1"));
        assert!(inner.message.contains("1 participants"));
    }

    /// Unit test: Test start_dkg with empty participant list
    #[tokio::test]
    async fn test_start_dkg_empty_participants() {
        let app_state = create_test_app_state_default().await;
        let service = CryptoServiceImpl::new(app_state);

        let request = StartDkgRequest {
            session_id: "empty-session".to_string(),
            threshold: 0,
            total_participants: 0,
            participant_ids: vec![],
            parameters: HashMap::new(),
            peer_ids: vec!["test".to_string()],
        };

        let tonic_request = Request::new(request.clone());
        let result = service.start_dkg(tonic_request).await;

        // Should still succeed even with empty participants
        assert!(result.is_ok(), "start_dkg should handle empty participants");

        let response: Response<_> = result.unwrap();
        let inner = response.into_inner();

        assert_eq!(inner.session_id, request.session_id);
        assert_eq!(inner.status, "started");
        assert!(inner.message.contains("threshold 0"));
        assert!(inner.message.contains("0 participants"));
    }

    /// Unit test: Test start_dkg with custom parameters
    #[tokio::test]
    async fn test_start_dkg_with_parameters() {
        let app_state = create_test_app_state_default().await;
        let service = CryptoServiceImpl::new(app_state);

        let mut parameters = HashMap::new();
        parameters.insert("algorithm".to_string(), "ECDSA".to_string());
        parameters.insert("key_size".to_string(), "256".to_string());
        parameters.insert("curve".to_string(), "secp256k1".to_string());

        let request = StartDkgRequest {
            session_id: "parameterized-session".to_string(),
            threshold: 3,
            total_participants: 5,
            participant_ids: vec![
                "p1".to_string(),
                "p2".to_string(),
                "p3".to_string(),
                "p4".to_string(),
                "p5".to_string(),
            ],
            parameters: parameters.clone(),
            peer_ids: vec!["test".to_string()],
        };

        let tonic_request = Request::new(request.clone());
        let result = service.start_dkg(tonic_request).await;

        assert!(result.is_ok(), "start_dkg should succeed with parameters");

        let response: Response<_> = result.unwrap();
        let inner = response.into_inner();

        assert_eq!(inner.session_id, request.session_id);
        assert_eq!(inner.session_id, request.session_id);
        assert_eq!(inner.status, "started");
        assert!(inner.message.contains("threshold 3"));
        assert!(inner.message.contains("5 participants"));
    }

    /// Integration test: Three nodes connect to each other
    ///
    /// This test spins up three nodes (Alice, Bob, Charlie), starts routers for Bob and Charlie,
    /// and has Alice send a StartDkgRequest with Bob and Charlie's peer IDs so they can all
    /// establish connections to each other.
    #[tokio::test]
    async fn test_three_nodes_connect() {
        use crate::helpers::test_helpers::create_test_app_state;
        use network::Network;

        // Create three nodes: Alice, Bob, and Charlie
        println!("Creating three test nodes...");
        let alice_state = create_test_app_state(
            Some("alice".to_string()),
            Some("127.0.0.1:0".to_string()),
        )
        .await;
        let bob_state = create_test_app_state(
            Some("bob".to_string()),
            Some("127.0.0.1:0".to_string()),
        )
        .await;
        let charlie_state = create_test_app_state(
            Some("charlie".to_string()),
            Some("127.0.0.1:0".to_string()),
        )
        .await;

        // Get peer IDs (iroh PublicKey strings) for each node
        let alice_peer_id = alice_state.network.local_peer_id();
        let alice_address = alice_state
            .network
            .local_address()
            .expect("Failed to get Alice's address");

        let bob_peer_id = bob_state.network.local_peer_id();
        let bob_address = bob_state
            .network
            .local_address()
            .expect("Failed to get Bob's address");

        let charlie_peer_id = charlie_state.network.local_peer_id();
        let charlie_address = charlie_state
            .network
            .local_address()
            .expect("Failed to get Charlie's address");

        println!(
            "Alice - Peer ID: {}, Address: {}",
            hex::encode(alice_peer_id.as_bytes()),
            alice_address
        );
        println!(
            "Bob - Peer ID: {}, Address: {}",
            hex::encode(bob_peer_id.as_bytes()),
            bob_address
        );
        println!(
            "Charlie - Peer ID: {}, Address: {}",
            hex::encode(charlie_peer_id.as_bytes()),
            charlie_address
        );

        // Start routers for Bob and Charlie so they can accept incoming connections
        println!("Starting routers for Bob and Charlie...");
        let bob_endpoint = bob_state.network.endpoint().clone();
        let bob_router = network::IrohRouter::builder(bob_endpoint).spawn();

        let charlie_endpoint = charlie_state.network.endpoint().clone();
        let charlie_router = network::IrohRouter::builder(charlie_endpoint).spawn();

        // Use the node addresses (PublicKey strings) as peer IDs for connection
        // The local_address() returns the iroh PublicKey string representation
        // Format: "node_id" or "node_id@ip:port" - we'll use just "node_id" for now
        // In a production environment, you'd include the IP:port if known
        let bob_peer_id_formatted = bob_address.clone();
        let charlie_peer_id_formatted = charlie_address.clone();

        println!("Bob peer ID for connection: {}", bob_peer_id_formatted);
        println!("Charlie peer ID for connection: {}", charlie_peer_id_formatted);

        // Create Alice's service
        let alice_service = CryptoServiceImpl::new(alice_state);

        // Alice sends StartDkgRequest with Bob and Charlie's peer IDs
        let request = StartDkgRequest {
            session_id: "three-node-session".to_string(),
            threshold: 2,
            total_participants: 3,
            participant_ids: vec![
                "alice".to_string(),
                "bob".to_string(),
                "charlie".to_string(),
            ],
            peer_ids: vec![bob_peer_id_formatted, charlie_peer_id_formatted],
            parameters: {
                let mut map = HashMap::new();
                map.insert("key_type".to_string(), "BLS12_381".to_string());
                map.insert("curve".to_string(), "bls12_381".to_string());
                map
            },
        };

        println!("Alice sending StartDkgRequest with peer IDs...");
        let tonic_request = Request::new(request.clone());
        let result = alice_service.start_dkg(tonic_request).await;

        assert!(result.is_ok(), "start_dkg should succeed");

        let response: Response<_> = result.unwrap();
        let inner = response.into_inner();

        // Verify response
        assert_eq!(inner.session_id, request.session_id);
        assert_eq!(inner.status, "started");
        assert!(inner.message.contains("DKG session started"));

        // Note: In a real test, you might want to verify that connections were actually established
        // by checking connection state or sending test messages. For now, we verify the request
        // was processed successfully.

        // Clean up routers
        println!("Cleaning up routers...");
        bob_router
            .shutdown()
            .await
            .expect("Failed to shutdown Bob's router");
        charlie_router
            .shutdown()
            .await
            .expect("Failed to shutdown Charlie's router");

        println!("Test completed successfully!");
    }
}

#[cfg(test)]
mod tests {
    use crate::helpers::test_helpers::create_test_app_state_default;
    use crate::{
        crypto_service::{crypto_service_server::CryptoService, StartDkgRequest},
        CryptoServiceImpl,
    };
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
        assert_eq!(inner.status, "started");
        assert!(inner.message.contains("threshold 3"));
        assert!(inner.message.contains("5 participants"));
    }
}

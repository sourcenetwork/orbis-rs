//! Node initialization, configuration, and key management tests.

use crate::helpers::test_helpers::TEST_FRESH_DKG_RING_ID;
use crate::{
    constants::{
        GRPC_CONCURRENCY_LIMIT_PER_CONNECTION, GRPC_MAX_CONCURRENT_STREAMS, MAX_SIGN_MESSAGE_BYTES,
        MAX_SIGN_REQUEST_BYTES, MAX_SMALL_GRPC_REQUEST_BYTES, MAX_STORE_SECRET_REQUEST_BYTES,
    },
    dkg::v0::service::DkgServiceImpl,
    helpers::{
        launch::{
            build_node_info_from_args, create_and_store_node_key, derive_secret_key_bytes,
            ensure_node_info, LogLevel,
        },
        test_helpers::{cleanup_db, test_db_path},
    },
    info::InfoServiceImpl,
    init_node,
    pre::v0::service::PreServiceImpl,
    shutdown_bootstrap_after_init,
    sign::v0::service::SignServiceImpl,
    start_bootstrap_info_server,
    store_secret::StoreSecretServiceImpl,
    Args, NodeConfig,
};
use authz::r#trait::Authz;
use authz::AuthzImpl;
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::{Bulletin, BulletinKind, NodeInfo};
use common::blockchain::ChainConfigBuilder;
use crypto::{DkgImpl, PreImpl, SignImpl};
use local_storage::{r#trait::LocalStorage, LocalStorageImpl};
use network::{Network, NetworkImpl};
use proto::{
    info_service::{
        info_service_client::InfoServiceClient, info_service_server::InfoServiceServer,
        GetNodeInfoRequest, GetRingStateRequest, NodeStatus,
    },
    v0::dkg::{
        dkg_service_client::DkgServiceClient, dkg_service_server::DkgServiceServer, StartDkgRequest,
    },
    v0::pre::{
        pre_service_client::PreServiceClient, pre_service_server::PreServiceServer, StartPreRequest,
    },
    v0::sign::{
        sign_service_client::SignServiceClient, sign_service_server::SignServiceServer,
        StartSignRequest,
    },
    v0::store_secret::{
        store_secret_service_client::StoreSecretServiceClient,
        store_secret_service_server::StoreSecretServiceServer, StoreSecretRequest,
    },
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
    task::JoinHandle,
};
use tonic::Code;
use tonic_web::GrpcWebLayer;
use tower_http::cors::CorsLayer;

/// Builds a [`NodeConfig`] for testing, returning it together with the DB path for cleanup.
///
/// `test_name` is used to derive an isolated DB path via [`test_db_path`].
/// `addr` is the gRPC bind address (`"127.0.0.1:0"` lets the OS pick a free port).
/// `password` is the storage password; `None` falls back to `"test-password"`.
async fn make_test_node_config(
    test_name: &str,
    addr: &str,
    password: Option<String>,
) -> (NodeConfig, String) {
    let db_path = test_db_path(test_name);
    let network: Arc<dyn Network> =
        Arc::new(NetworkImpl::new().await.expect("Failed to create network"));
    let authz: Arc<dyn Authz> = Arc::new(
        AuthzImpl::new(ChainConfigBuilder::default())
            .await
            .expect("Failed to initialize Authz"),
    );
    let bulletin: Arc<dyn Bulletin + Send + Sync> = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize bulletin"),
    );
    let config = NodeConfig {
        args: Args {
            addr: addr.to_string(),
            log_level: LogLevel::Info,
            authz_grpc: None,
            bulletin_grpc: None,
            chain_rest: None,
            chain_rpc: None,
            denom: None,
            chain_gas_multiplier: None,
            metrics_addr: None,
            loki_url: None,
            runtime_base_path: None,
            reshare_interval_secs: 0, // disabled in tests
            network_private_routes_only: false,
            node_controller_key: "test-controller-key".to_string(),
            node_peer_id: None,
            node_whitelisted_policy_ids: vec![],
            node_whitelisted_ring_ids: vec![],
            trusted_auth_relay_dids: vec![],
            grpc_concurrency_limit_per_connection: GRPC_CONCURRENCY_LIMIT_PER_CONNECTION,
            grpc_max_concurrent_streams: GRPC_MAX_CONCURRENT_STREAMS,
        },
        node_key: "test-node-key".to_string(),
        network,
        local_storage: LocalStorageImpl::new(
            password.unwrap_or_else(|| "test-password".to_string()),
            db_path.clone(),
        )
        .expect("Failed to create local storage"),
        authz,
        bulletin,
    };
    (config, db_path)
}

async fn make_bootstrap_identity(
    test_name: &str,
) -> (Arc<dyn Network>, LocalStorageImpl, String, String) {
    let db_path = test_db_path(test_name);
    cleanup_db(&db_path);

    let local_storage = LocalStorageImpl::new("test-password".to_string(), db_path.clone())
        .expect("Failed to create local storage");
    let runtime_base_path = project_root::get_project_root().expect("resolve project root");
    let signer = create_and_store_node_key(
        local_storage.clone(),
        ChainConfigBuilder::default().build(),
        &runtime_base_path,
    )
    .expect("Failed to create and store node key");
    let network: Arc<dyn Network> =
        Arc::new(NetworkImpl::new().await.expect("Failed to create network"));

    (network, local_storage, db_path, signer.address())
}

fn node_info_test_args(
    controller_key: &str,
    node_peer_id: Option<String>,
    policy_ids: Vec<&str>,
    ring_ids: Vec<&str>,
) -> Args {
    Args {
        addr: "127.0.0.1:0".to_string(),
        log_level: LogLevel::Info,
        authz_grpc: None,
        bulletin_grpc: None,
        chain_rest: None,
        chain_rpc: None,
        denom: None,
        chain_gas_multiplier: None,
        metrics_addr: None,
        loki_url: None,
        runtime_base_path: None,
        reshare_interval_secs: 0,
        network_private_routes_only: false,
        node_controller_key: controller_key.to_string(),
        node_peer_id,
        node_whitelisted_policy_ids: policy_ids.into_iter().map(str::to_string).collect(),
        node_whitelisted_ring_ids: ring_ids.into_iter().map(str::to_string).collect(),
        trusted_auth_relay_dids: vec![],
        grpc_concurrency_limit_per_connection: GRPC_CONCURRENCY_LIMIT_PER_CONNECTION,
        grpc_max_concurrent_streams: GRPC_MAX_CONCURRENT_STREAMS,
    }
}

fn spawn_full_test_grpc_server(
    node: crate::InitializedNode,
) -> (SocketAddr, oneshot::Sender<()>, JoinHandle<()>) {
    let incoming =
        tonic::transport::server::TcpIncoming::bind(node.grpc_addr).expect("bind full gRPC server");
    let local_addr = incoming.local_addr().expect("full gRPC local addr");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let dkg_service = DkgServiceImpl::<DkgImpl>::with_routes(node.app_state.clone(), &network::V0);
    let pre_service =
        PreServiceImpl::<DkgImpl, PreImpl>::with_routes(node.app_state.clone(), &network::V0);
    let info_service = InfoServiceImpl::<DkgImpl>::new((*node.app_state).clone());
    let store_secret_service = StoreSecretServiceImpl::<DkgImpl, SignImpl>::with_routes(
        node.app_state.clone(),
        &network::V0,
    );
    let sign_service =
        SignServiceImpl::<DkgImpl, SignImpl>::with_routes(node.app_state.clone(), &network::V0);

    let task = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .accept_http1(true)
            .layer(CorsLayer::permissive())
            .layer(GrpcWebLayer::new())
            .add_service(
                DkgServiceServer::new(dkg_service)
                    .max_decoding_message_size(MAX_SMALL_GRPC_REQUEST_BYTES),
            )
            .add_service(
                PreServiceServer::new(pre_service)
                    .max_decoding_message_size(MAX_SMALL_GRPC_REQUEST_BYTES),
            )
            .add_service(
                InfoServiceServer::new(info_service)
                    .max_decoding_message_size(MAX_SMALL_GRPC_REQUEST_BYTES),
            )
            .add_service(
                StoreSecretServiceServer::new(store_secret_service)
                    .max_decoding_message_size(MAX_STORE_SECRET_REQUEST_BYTES),
            )
            .add_service(
                SignServiceServer::new(sign_service)
                    .max_decoding_message_size(MAX_SIGN_REQUEST_BYTES),
            )
            .serve_with_incoming_shutdown(incoming, async {
                let _ = shutdown_rx.await;
            })
            .await;

        let _ = node.router.shutdown().await;
    });

    (local_addr, shutdown_tx, task)
}

async fn send_http1_request(addr: SocketAddr, request: Vec<u8>) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect test HTTP/1 client");
    stream
        .write_all(&request)
        .await
        .expect("write test HTTP/1 request");

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("timed out reading test HTTP/1 response")
        .expect("read test HTTP/1 response");

    String::from_utf8_lossy(&response).into_owned()
}

fn assert_decode_limit_error(status: tonic::Status) {
    assert_eq!(
        status.code(),
        Code::OutOfRange,
        "oversized gRPC request should fail during decode"
    );
    assert!(
        status
            .message()
            .contains("decoded message length too large"),
        "unexpected decode-limit error message: {}",
        status.message()
    );
}

#[test]
fn test_build_node_info_from_args_stores_policy_ids_unchanged() {
    let args = node_info_test_args(
        "controller-key",
        None,
        vec!["team-a", "orbis/team-b", " policy-c ", ""],
        vec!["ring-1", " ring-2 ", ""],
    );

    let node_info = build_node_info_from_args("peer-id".to_string(), "controller-key", &args);
    assert_eq!(node_info.peer_id, "peer-id");
    assert_eq!(node_info.controller_key, "controller-key");
    assert_eq!(
        node_info.whitelisted_policy_ids,
        vec![
            "team-a".to_string(),
            "orbis/team-b".to_string(),
            "policy-c".to_string()
        ]
    );
    assert_eq!(
        node_info.whitelisted_ring_ids,
        vec!["ring-1".to_string(), "ring-2".to_string()]
    );
}

#[tokio::test]
async fn test_ensure_node_info_keeps_existing_whitelists() {
    let network = NetworkImpl::new().await.expect("create network");
    let bulletin = DummyBulletin::new().await.expect("create bulletin");
    let node_key = "node-key-existing";
    let peer_id = hex::encode(network.local_peer_id().as_bytes());
    let existing = NodeInfo {
        peer_id,
        controller_key: "controller-key".to_string(),
        whitelisted_policy_ids: vec!["existing-policy".to_string()],
        whitelisted_ring_ids: vec!["ring-existing".to_string()],
    };
    bulletin
        .set_node_info(node_key.to_string(), existing.clone())
        .expect("seed node info");
    let args = node_info_test_args("controller-key", None, vec!["new-policy"], vec!["new-ring"]);

    ensure_node_info(&bulletin, node_key, &network, &args)
        .await
        .expect("ensure node info");

    let post = bulletin
        .read(node_key.to_string(), BulletinKind::NodeInfo)
        .await
        .expect("read existing node info");
    let node_info = NodeInfo::try_from(post).expect("parse node info");
    assert_eq!(
        node_info.whitelisted_policy_ids,
        existing.whitelisted_policy_ids
    );
    assert_eq!(
        node_info.whitelisted_ring_ids,
        existing.whitelisted_ring_ids
    );
}

#[tokio::test]
async fn test_ensure_node_info_fails_when_existing_peer_mismatches() {
    let network = NetworkImpl::new().await.expect("create network");
    let bulletin = DummyBulletin::new().await.expect("create bulletin");
    let node_key = "node-key-peer-mismatch";
    let existing = NodeInfo {
        peer_id: "different-peer".to_string(),
        controller_key: "controller-key".to_string(),
        whitelisted_policy_ids: vec![],
        whitelisted_ring_ids: vec![],
    };
    bulletin
        .set_node_info(node_key.to_string(), existing)
        .expect("seed node info");
    let args = node_info_test_args("controller-key", None, vec![], vec![]);

    let err = ensure_node_info(&bulletin, node_key, &network, &args)
        .await
        .expect_err("peer mismatch should fail");
    assert!(err.to_string().contains("peer_id"));
}

#[tokio::test]
async fn test_ensure_node_info_fails_when_existing_controller_mismatches() {
    let network = NetworkImpl::new().await.expect("create network");
    let bulletin = DummyBulletin::new().await.expect("create bulletin");
    let node_key = "node-key-controller-mismatch";
    let existing = NodeInfo {
        peer_id: hex::encode(network.local_peer_id().as_bytes()),
        controller_key: "different-controller".to_string(),
        whitelisted_policy_ids: vec![],
        whitelisted_ring_ids: vec![],
    };
    bulletin
        .set_node_info(node_key.to_string(), existing)
        .expect("seed node info");
    let args = node_info_test_args("controller-key", None, vec![], vec![]);

    let err = ensure_node_info(&bulletin, node_key, &network, &args)
        .await
        .expect_err("controller mismatch should fail");
    assert!(err.to_string().contains("controller_key"));
}

#[tokio::test]
async fn test_store_secret_endpoint_accepts_browser_grpc_web_requests() {
    let (config, db_path) = make_test_node_config(
        "test_store_secret_endpoint_accepts_browser_grpc_web_requests",
        "127.0.0.1:0",
        None,
    )
    .await;
    let node = init_node(config).await.expect("initialize test node");
    let (addr, shutdown_tx, task) = spawn_full_test_grpc_server(node);

    let preflight = format!(
        "OPTIONS /store_secret_service.StoreSecretService/StoreSecret HTTP/1.1\r\n\
Host: {addr}\r\n\
Origin: http://localhost:5173\r\n\
Access-Control-Request-Method: POST\r\n\
Access-Control-Request-Headers: content-type,x-grpc-web,authorization\r\n\
Content-Length: 0\r\n\
Connection: close\r\n\
\r\n"
    );
    let preflight_response = send_http1_request(addr, preflight.into_bytes()).await;
    let preflight_headers = preflight_response.to_ascii_lowercase();

    assert!(
        preflight_response.starts_with("HTTP/1.1 200 OK"),
        "unexpected preflight response:\n{preflight_response}"
    );
    assert!(
        preflight_headers.contains("access-control-allow-origin: *"),
        "preflight response did not allow browser origin:\n{preflight_response}"
    );
    assert!(
        preflight_headers.contains("access-control-allow-methods: *"),
        "preflight response did not allow browser method:\n{preflight_response}"
    );
    assert!(
        preflight_headers.contains("access-control-allow-headers: *"),
        "preflight response did not allow browser headers:\n{preflight_response}"
    );

    let mut grpc_web_post = format!(
        "POST /store_secret_service.StoreSecretService/StoreSecret HTTP/1.1\r\n\
Host: {addr}\r\n\
Origin: http://localhost:5173\r\n\
Content-Type: application/grpc-web+proto\r\n\
X-Grpc-Web: 1\r\n\
Content-Length: 5\r\n\
Connection: close\r\n\
\r\n"
    )
    .into_bytes();
    grpc_web_post.extend_from_slice(&[0, 0, 0, 0, 0]);

    let post_response = send_http1_request(addr, grpc_web_post).await;
    let post_headers = post_response.to_ascii_lowercase();

    assert!(
        post_response.starts_with("HTTP/1.1 200 OK"),
        "unexpected gRPC-Web POST response:\n{post_response}"
    );
    assert!(
        post_headers.contains("content-type: application/grpc-web+proto"),
        "POST response was not translated as gRPC-Web:\n{post_response}"
    );
    assert!(
        post_headers.contains("access-control-allow-origin: *"),
        "POST response did not include browser CORS headers:\n{post_response}"
    );

    shutdown_tx.send(()).expect("shutdown full test server");
    task.await.expect("join full test server task");
    cleanup_db(&db_path);
}

#[tokio::test]
async fn test_full_grpc_server_enforces_decode_caps() {
    let (config, db_path) = make_test_node_config(
        "test_full_grpc_server_enforces_decode_caps",
        "127.0.0.1:0",
        None,
    )
    .await;
    let node = init_node(config).await.expect("initialize test node");
    let (addr, shutdown_tx, task) = spawn_full_test_grpc_server(node);
    let endpoint = format!("http://{}", addr);

    let mut dkg_client = DkgServiceClient::connect(endpoint.clone())
        .await
        .expect("connect dkg client");
    let dkg_err = dkg_client
        .start_dkg(StartDkgRequest {
            ring_id: "x".repeat(MAX_SMALL_GRPC_REQUEST_BYTES),
        })
        .await
        .expect_err("oversized dkg request should fail during decode");
    assert_decode_limit_error(dkg_err);

    let mut pre_client = PreServiceClient::connect(endpoint.clone())
        .await
        .expect("connect pre client");
    let pre_err = pre_client
        .start_pre(StartPreRequest {
            rdr_pk: Vec::new(),
            object_id: "object-id".to_string(),
            derivation: Some(vec![0u8; MAX_SMALL_GRPC_REQUEST_BYTES]),
            salt: None,
            valid_window: None,
        })
        .await
        .expect_err("oversized pre request should fail during decode");
    assert_decode_limit_error(pre_err);

    let mut sign_client = SignServiceClient::connect(endpoint.clone())
        .await
        .expect("connect sign client");
    let at_limit_sign_err = sign_client
        .start_sign(StartSignRequest {
            message: vec![0u8; MAX_SIGN_MESSAGE_BYTES],
            derivation_id: "derivation-id".to_string(),
            valid_window: None,
        })
        .await
        .expect_err("sign request at message limit should reach auth");
    assert_eq!(
        at_limit_sign_err.code(),
        Code::Unauthenticated,
        "sign request at message limit should reach the service auth path"
    );

    let sign_decode_err = sign_client
        .start_sign(StartSignRequest {
            message: vec![0u8; MAX_SIGN_REQUEST_BYTES],
            derivation_id: "derivation-id".to_string(),
            valid_window: None,
        })
        .await
        .expect_err("oversized sign request should fail during decode");
    assert_decode_limit_error(sign_decode_err);

    let mut store_secret_client = StoreSecretServiceClient::connect(endpoint)
        .await
        .expect("connect store secret client");
    let store_secret_err = store_secret_client
        .store_secret(StoreSecretRequest {
            encrypted_document: vec![0u8; MAX_STORE_SECRET_REQUEST_BYTES],
            enc_cmt: Vec::new(),
            ring_id: "ring-id".to_string(),
            policy_id: "policy-id".to_string(),
            resource: "resource".to_string(),
            permission: "read".to_string(),
            shared_point: Vec::new(),
            challenge: Vec::new(),
            response: Vec::new(),
            with_proof: false,
            tier: None,
            timestamp: None,
        })
        .await
        .expect_err("oversized store-secret request should fail during decode");
    assert_decode_limit_error(store_secret_err);

    shutdown_tx.send(()).expect("shutdown full test server");
    task.await.expect("join full test server task");
    cleanup_db(&db_path);
}

/// Test that the node initializes successfully with valid configuration
#[tokio::test]
async fn test_init_node_success() {
    let (config, db_path) =
        make_test_node_config("test_init_node_success", "127.0.0.1:0", None).await;

    let result = init_node(config).await;
    assert!(result.is_ok(), "Node initialization should succeed");

    let node = result.unwrap();

    // Verify the node was initialized correctly
    assert!(
        !node.local_address.is_empty(),
        "Local address should be set"
    );

    // Clean up
    node.router
        .shutdown()
        .await
        .expect("Router shutdown failed");
    cleanup_db(&db_path);
}

#[tokio::test]
#[serial_test::serial]
async fn test_bootstrap_info_server_exposes_only_info() {
    let (network, local_storage, db_path, expected_address) =
        make_bootstrap_identity("test_bootstrap_info_server_exposes_only_info").await;
    let bootstrap = start_bootstrap_info_server(
        "127.0.0.1:0".parse().expect("bootstrap bind addr"),
        network,
        local_storage,
    )
    .expect("start bootstrap info server");
    let endpoint = format!("http://{}", bootstrap.local_addr());

    let mut info_client = InfoServiceClient::connect(endpoint.clone())
        .await
        .expect("connect bootstrap info service");
    let node_info = info_client
        .get_node_info(GetNodeInfoRequest {})
        .await
        .expect("get node info during bootstrap")
        .into_inner();

    assert_eq!(node_info.public_address, expected_address);
    assert_eq!(node_info.status, NodeStatus::Bootstrapping as i32);
    assert_eq!(node_info.managed_ring_count, 0);
    assert_eq!(node_info.supported_protocol_versions, vec![0]);
    assert!(!node_info.peer_id.is_empty(), "peer_id should be set");
    assert!(
        node_info
            .p2p_address
            .starts_with(&format!("{}@", node_info.peer_id)),
        "p2p address should include the peer id"
    );

    let ring_err = info_client
        .get_ring_state(GetRingStateRequest {
            ring_pk_hex: String::new(),
        })
        .await
        .expect_err("ring state should be blocked during bootstrap");
    assert_eq!(ring_err.code(), Code::FailedPrecondition);

    let mut dkg_client = DkgServiceClient::connect(endpoint)
        .await
        .expect("connect bootstrap endpoint as dkg client");
    let err = dkg_client
        .start_dkg(StartDkgRequest {
            ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
        })
        .await
        .expect_err("dkg should not be registered during bootstrap");
    assert_eq!(err.code(), Code::Unimplemented);

    bootstrap
        .shutdown()
        .await
        .expect("shutdown bootstrap server");
    cleanup_db(&db_path);
}

#[tokio::test]
#[serial_test::serial]
async fn test_bootstrap_info_server_hands_off_to_full_server_on_same_port() {
    let (network, local_storage, db_path, expected_address) =
        make_bootstrap_identity("test_bootstrap_info_server_hands_off_to_full_server_on_same_port")
            .await;
    let bootstrap = start_bootstrap_info_server(
        "127.0.0.1:0".parse().expect("bootstrap bind addr"),
        network.clone(),
        local_storage.clone(),
    )
    .expect("start bootstrap info server");
    let grpc_addr = bootstrap.local_addr();
    let endpoint = format!("http://{}", grpc_addr);

    let mut bootstrap_dkg_client = DkgServiceClient::connect(endpoint.clone())
        .await
        .expect("connect bootstrap endpoint as dkg client");
    let bootstrap_err = bootstrap_dkg_client
        .start_dkg(StartDkgRequest {
            ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
        })
        .await
        .expect_err("dkg should not be registered during bootstrap");
    assert_eq!(bootstrap_err.code(), Code::Unimplemented);

    let authz: Arc<dyn Authz> = Arc::new(
        AuthzImpl::new(ChainConfigBuilder::default())
            .await
            .expect("Failed to initialize Authz"),
    );
    let bulletin: Arc<dyn Bulletin + Send + Sync> = Arc::new(
        DummyBulletin::new()
            .await
            .expect("Failed to initialize bulletin"),
    );
    let config = NodeConfig {
        args: Args {
            addr: grpc_addr.to_string(),
            log_level: LogLevel::Info,
            authz_grpc: None,
            bulletin_grpc: None,
            chain_rest: None,
            chain_rpc: None,
            denom: None,
            chain_gas_multiplier: None,
            metrics_addr: None,
            loki_url: None,
            runtime_base_path: None,
            reshare_interval_secs: 0,
            network_private_routes_only: false,
            node_controller_key: "test-controller-key".to_string(),
            node_peer_id: None,
            node_whitelisted_policy_ids: vec![],
            node_whitelisted_ring_ids: vec![],
            trusted_auth_relay_dids: vec![],
            grpc_concurrency_limit_per_connection: GRPC_CONCURRENCY_LIMIT_PER_CONNECTION,
            grpc_max_concurrent_streams: GRPC_MAX_CONCURRENT_STREAMS,
        },
        node_key: "test-node-key".to_string(),
        network,
        local_storage,
        authz,
        bulletin,
    };
    let node = init_node(config).await.expect("Node initialization failed");

    bootstrap
        .shutdown()
        .await
        .expect("shutdown bootstrap server");
    let (full_addr, full_shutdown, full_task) = spawn_full_test_grpc_server(node);
    assert_eq!(
        full_addr, grpc_addr,
        "full server should reuse bootstrap port"
    );

    let mut info_client = InfoServiceClient::connect(endpoint.clone())
        .await
        .expect("connect full info service");
    let node_info = info_client
        .get_node_info(GetNodeInfoRequest {})
        .await
        .expect("get node info after full server starts")
        .into_inner();
    assert_eq!(node_info.public_address, expected_address);
    assert_eq!(node_info.status, NodeStatus::Ready as i32);
    assert_eq!(node_info.managed_ring_count, 0);
    assert_eq!(node_info.supported_protocol_versions, vec![0]);

    let channel = tonic::transport::Endpoint::from_shared(endpoint.clone())
        .expect("valid endpoint")
        .connect()
        .await
        .expect("connect raw grpc client");
    let mut raw_client = tonic::client::Grpc::new(channel);
    raw_client.ready().await.expect("raw grpc client ready");
    let old_route_result: Result<tonic::Response<proto::v0::dkg::StartDkgResponse>, tonic::Status> =
        raw_client
            .unary(
                tonic::Request::new(StartDkgRequest {
                    ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
                }),
                tonic::codegen::http::uri::PathAndQuery::from_static(
                    "/dkg_service.DkgService/StartDkg",
                ),
                tonic_prost::ProstCodec::default(),
            )
            .await;
    assert_eq!(
        old_route_result
            .expect_err("old unversioned route must be absent")
            .code(),
        Code::Unimplemented
    );

    let mut full_dkg_client = DkgServiceClient::connect(endpoint)
        .await
        .expect("connect full endpoint as dkg client");
    let full_err = full_dkg_client
        .start_dkg(StartDkgRequest {
            ring_id: TEST_FRESH_DKG_RING_ID.to_string(),
        })
        .await
        .expect_err("unauthenticated dkg should fail after reaching the service");
    assert_ne!(full_err.code(), Code::Unimplemented);

    let _ = full_shutdown.send(());
    full_task.await.expect("full server task join");
    cleanup_db(&db_path);
}

#[tokio::test]
#[serial_test::serial]
async fn test_bootstrap_info_server_shutdown_on_init_error() {
    let (network, local_storage, db_path, _) =
        make_bootstrap_identity("test_bootstrap_info_server_shutdown_on_init_error").await;
    let bootstrap = start_bootstrap_info_server(
        "127.0.0.1:0".parse().expect("bootstrap bind addr"),
        network,
        local_storage,
    )
    .expect("start bootstrap info server");
    let grpc_addr = bootstrap.local_addr();

    let init_error = std::io::Error::other("synthetic init failure");
    let err = match shutdown_bootstrap_after_init(bootstrap, Err(Box::new(init_error))).await {
        Ok(_) => panic!("synthetic init failure should be returned"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("synthetic init failure"));

    let incoming = tonic::transport::server::TcpIncoming::bind(grpc_addr)
        .expect("bootstrap port should be released after init failure");
    drop(incoming);

    cleanup_db(&db_path);
}

/// Test that the node fails with invalid address
#[tokio::test]
async fn test_init_node_invalid_address() {
    let (config, db_path) = make_test_node_config(
        "test_init_node_invalid_address",
        "not-a-valid-address",
        None,
    )
    .await;

    let result = init_node(config).await;
    assert!(
        result.is_err(),
        "Node initialization should fail with invalid address"
    );
    cleanup_db(&db_path);
}

/// Test that AppState is properly configured after initialization
#[tokio::test]
async fn test_init_node_app_state_configuration() {
    let (config, db_path) = make_test_node_config(
        "test_init_node_app_state_configuration",
        "127.0.0.1:0",
        None,
    )
    .await;

    let node = init_node(config).await.expect("Node initialization failed");

    // Verify no sessions exist initially
    assert_eq!(
        node.app_state.dkg_session_state.session_count().await,
        0,
        "Should have no sessions initially"
    );

    // Clean up
    node.router
        .shutdown()
        .await
        .expect("Router shutdown failed");
    cleanup_db(&db_path);
}

/// Test that multiple nodes can be initialized concurrently
#[tokio::test]
async fn test_init_multiple_nodes() {
    let (config1, db_path1) =
        make_test_node_config("test_init_multiple_nodes_1", "127.0.0.1:0", None).await;
    let (config2, db_path2) =
        make_test_node_config("test_init_multiple_nodes_2", "127.0.0.1:0", None).await;

    let node1 = init_node(config1)
        .await
        .expect("Node 1 initialization failed");
    let node2 = init_node(config2)
        .await
        .expect("Node 2 initialization failed");

    // Verify both nodes have different addresses
    assert_ne!(
        node1.local_address, node2.local_address,
        "Nodes should have different P2P addresses"
    );

    // Clean up
    node1
        .router
        .shutdown()
        .await
        .expect("Router 1 shutdown failed");
    node2
        .router
        .shutdown()
        .await
        .expect("Router 2 shutdown failed");
    cleanup_db(&db_path1);
    cleanup_db(&db_path2);
}

/// ThresholdDealer::name() reflects the compiled crypto backend (elgamal/decaf377 vs elgamal/bls12_381).
#[test]
fn test_pre_impl_name_matches_backend() {
    use crypto::r#trait::ThresholdDealer;
    use crypto::PreImpl;

    #[cfg(feature = "decaf377")]
    assert_eq!(
        PreImpl::name(),
        "elgamal/decaf377",
        "decaf377 build should report elgamal/decaf377"
    );
    #[cfg(feature = "bls12-381")]
    assert_eq!(
        PreImpl::name(),
        "elgamal/bls12_381",
        "bls12-381 build should report elgamal/bls12_381"
    );
}

/// Test that encrypted storage works with the node
#[tokio::test]
#[serial_test::serial]
async fn test_init_node_with_encrypted_storage() {
    let (config, db_path) = make_test_node_config(
        "test_init_node_with_encrypted_storage",
        "127.0.0.1:0",
        Some("test-password-123".to_string()),
    )
    .await;

    let result = init_node(config).await;
    assert!(
        result.is_ok(),
        "Node should initialize with encrypted storage"
    );

    let node = result.unwrap();
    node.router
        .shutdown()
        .await
        .expect("Router shutdown failed");
    cleanup_db(&db_path);
}

// ============================================================================
// derive_secret_key_bytes tests
// ============================================================================

#[test]
fn test_valid_hex_input() {
    // 64-char hex (32 bytes) should be decoded directly
    let hex_input = "a".repeat(64);
    let result = derive_secret_key_bytes(&hex_input);
    assert!(result.is_ok());

    let bytes = result.unwrap();
    assert_eq!(bytes, [0xaa; 32]);
}

#[test]
fn test_valid_passphrase() {
    // 16+ char passphrase should be hashed
    let passphrase = "this-is-a-valid-passphrase";
    let result = derive_secret_key_bytes(passphrase);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 32);
}

#[test]
fn test_short_passphrase_rejected() {
    // Less than 16 chars should fail
    let short = "tooshort";
    let result = derive_secret_key_bytes(short);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("at least 16 characters"));
}

#[test]
fn test_deterministic_output() {
    // Same input should always produce same output
    let input = "my-deterministic-secret";
    let result1 = derive_secret_key_bytes(input).unwrap();
    let result2 = derive_secret_key_bytes(input).unwrap();
    assert_eq!(result1, result2);
}

#[tokio::test]
async fn test_deterministic_peer_id_from_secret() {
    // Same secret should produce same peer ID across network instances
    let secret = "my-deterministic-node-identity";
    let secret_key_bytes = derive_secret_key_bytes(secret).unwrap();

    // Create first network with secret key
    let secret_key1 = network::SecretKey::from_bytes(&secret_key_bytes);
    let network1 = NetworkImpl::builder()
        .secret_key(secret_key1)
        .build()
        .await
        .expect("Failed to create first network");
    let peer_id1 = network1.local_peer_id();

    // Create second network with same secret key
    let secret_key2 = network::SecretKey::from_bytes(&secret_key_bytes);
    let network2 = NetworkImpl::builder()
        .secret_key(secret_key2)
        .build()
        .await
        .expect("Failed to create second network");
    let peer_id2 = network2.local_peer_id();

    // Peer IDs should be identical
    assert_eq!(
        peer_id1.as_bytes(),
        peer_id2.as_bytes(),
        "Same secret should produce same peer ID"
    );
}

// ============================================================================
// create_and_store_node_key tests
// ============================================================================

#[test]
#[serial_test::serial]
fn test_create_and_store_node_key() {
    use common::blockchain::ChainConfig;

    let db_path = test_db_path("test_create_and_store_node_key");
    let local_storage = LocalStorageImpl::new("test-password".to_string(), db_path.clone())
        .expect("Failed to create local storage");

    let config = ChainConfig::local();
    let runtime_base_path = project_root::get_project_root().expect("resolve project root");

    // First call should create a new key
    let result =
        create_and_store_node_key(local_storage.clone(), config.clone(), &runtime_base_path);
    assert!(
        result.is_ok(),
        "Should create key successfully: {:?}",
        result.err()
    );

    let signer1 = result.unwrap();
    let address1 = signer1.address();
    assert!(
        address1.starts_with("source1"),
        "Address should be bech32 with source1 prefix, got: {}",
        address1
    );

    // Second call should return the same address (idempotent)
    let result2 = create_and_store_node_key(local_storage.clone(), config, &runtime_base_path);
    assert!(result2.is_ok(), "Second call should succeed");

    let signer2 = result2.unwrap();
    let address2 = signer2.address();
    assert_eq!(
        address1, address2,
        "Same key should be returned on subsequent calls"
    );

    cleanup_db(&db_path);
}

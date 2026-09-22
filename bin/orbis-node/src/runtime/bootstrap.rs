//! The info-only gRPC server that runs while the node waits for chain funding
//! and bulletin initialization, before the full node is ready to serve.

use super::{wait_for_shutdown, InitializedNode};
use crate::constants;
use crate::helpers::launch::CorsPolicy;
use crate::info::BootstrapInfoServiceImpl;
use local_storage::LocalStorageImpl;
use network::Network;
use proto::info_service::{info_service_server::InfoServiceServer, NodeStatus};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicI32, Ordering},
    Arc,
};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use tonic_web::GrpcWebLayer;

/// Running info-only gRPC server used while the node waits for chain funding.
#[derive(Clone)]
pub(crate) struct BootstrapStatus(Arc<AtomicI32>);

impl BootstrapStatus {
    fn new(status: NodeStatus) -> Self {
        Self(Arc::new(AtomicI32::new(status as i32)))
    }

    pub(crate) fn set_status(&self, status: NodeStatus) {
        self.0.store(status as i32, Ordering::SeqCst);
    }

    fn shared(&self) -> Arc<AtomicI32> {
        self.0.clone()
    }
}

pub(crate) struct BootstrapInfoServer {
    local_addr: SocketAddr,
    status: BootstrapStatus,
    shutdown_tx: oneshot::Sender<()>,
    task: JoinHandle<Result<(), tonic::transport::Error>>,
}

impl BootstrapInfoServer {
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(crate) fn status(&self) -> BootstrapStatus {
        self.status.clone()
    }

    pub(crate) async fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.shutdown_tx.send(());
        self.task.await??;
        Ok(())
    }
}

/// Start an info-only gRPC server before the full node is ready.
pub(crate) fn start_bootstrap_info_server(
    grpc_addr: SocketAddr,
    network: Arc<dyn Network>,
    local_storage: LocalStorageImpl,
    cors_policy: CorsPolicy,
) -> Result<BootstrapInfoServer, Box<dyn std::error::Error>> {
    let incoming = tonic::transport::server::TcpIncoming::bind(grpc_addr)?;
    let local_addr = incoming.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let status = BootstrapStatus::new(NodeStatus::Bootstrapping);
    let info_service = BootstrapInfoServiceImpl::new(network, local_storage, status.shared());

    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .accept_http1(true)
            .layer(cors_policy.layer())
            .layer(GrpcWebLayer::new())
            .add_service(
                InfoServiceServer::new(info_service)
                    .max_decoding_message_size(constants::MAX_SMALL_GRPC_REQUEST_BYTES),
            )
            .serve_with_incoming_shutdown(incoming, async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    Ok(BootstrapInfoServer {
        local_addr,
        status,
        shutdown_tx,
        task,
    })
}

pub(crate) async fn shutdown_bootstrap_after_init(
    bootstrap_info_server: BootstrapInfoServer,
    init_result: Result<InitializedNode, Box<dyn std::error::Error>>,
) -> Result<InitializedNode, Box<dyn std::error::Error>> {
    if init_result.is_ok() {
        tracing::info!(
            "Funding and bulletin initialization complete; stopping bootstrap info service"
        );
    } else {
        tracing::info!("Node initialization failed; stopping bootstrap info service");
    }

    let shutdown_result = bootstrap_info_server.shutdown().await;

    match (init_result, shutdown_result) {
        (Ok(node), Ok(())) => Ok(node),
        (Err(init_err), Ok(())) => Err(init_err),
        (Ok(_), Err(shutdown_err)) => Err(shutdown_err),
        (Err(init_err), Err(shutdown_err)) => {
            tracing::error!(
                error = %shutdown_err,
                "Bootstrap info service shutdown failed while handling initialization error"
            );
            Err(init_err)
        }
    }
}

/// Wait for node initialization or stop it promptly when process shutdown is requested.
pub(crate) async fn complete_initialization_or_shutdown<F>(
    bootstrap_info_server: BootstrapInfoServer,
    init_result: F,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<Option<InitializedNode>, Box<dyn std::error::Error>>
where
    F: Future<Output = Result<InitializedNode, Box<dyn std::error::Error>>>,
{
    tokio::pin!(init_result);

    tokio::select! {
        init_result = &mut init_result => {
            shutdown_bootstrap_after_init(bootstrap_info_server, init_result)
                .await
                .map(Some)
        }
        _ = wait_for_shutdown(shutdown_rx) => {
            tracing::info!("Shutdown requested during node initialization; stopping bootstrap info service");
            bootstrap_info_server.shutdown().await?;
            Ok(None)
        }
    }
}

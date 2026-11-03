use super::*;
use ark_ec::AffineRepr;
use crypto::r#trait::CryptoSerialize;
use proto::v0::sign::{
    sign_service_server::{SignService, SignServiceServer},
    StartSignRequest, StartSignResponse,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

struct DeniedSigner(Arc<AtomicUsize>);

#[tonic::async_trait]
impl SignService for DeniedSigner {
    async fn start_sign(
        &self,
        request: Request<StartSignRequest>,
    ) -> Result<Response<StartSignResponse>, Status> {
        assert_eq!(request.into_inner().message, b"message");
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(Status::unauthenticated("signing permission revoked"))
    }
}

#[tokio::test]
async fn async_signing_reaches_service_from_current_thread_runtime() {
    let calls = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let service = DeniedSigner(Arc::clone(&calls));
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(SignServiceServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let identity = Arc::new(
        defra_identity::RawIdentity::from_ed25519(
            defra_crypto::Ed25519PrivateKey::from_bytes(
                &defra_crypto::ed25519_key_from_seed(&[3; 32]).unwrap(),
            )
            .unwrap(),
        )
        .unwrap(),
    );
    let signer = Arc::new(Signer::new(
        defra_orbis::OrbisClient::new(
            endpoint,
            "a".repeat(64),
            crypto::GroupAffine::generator().to_bytes().unwrap(),
            identity,
            defra_edge::on_demand().unwrap().clone(),
        )
        .await
        .unwrap(),
    ));
    let blocking_signer = Arc::clone(&signer);
    let error = tokio::task::spawn_blocking(move || blocking_signer.sign_sync(b"message", None))
        .await
        .unwrap()
        .unwrap_err();
    assert!(error.contains("single-threaded executor"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let error = signer.sign(b"message").await.unwrap_err();
    assert!(error.message.contains("signing permission revoked"));
    assert!(!error.transient);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    server.abort();
    let _ = server.await;
}

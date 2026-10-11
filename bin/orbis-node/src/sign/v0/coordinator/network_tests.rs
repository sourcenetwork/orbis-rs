use super::*;
use async_trait::async_trait;
use network::{Connection, NetworkError, PeerConnection, ProtocolHandler, RouterBuilder};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, Notify};

const PEER: &str = "peer";
const PROTOCOL: &[u8] = b"orbis/sign/0";

#[derive(Clone, Copy)]
enum Behavior {
    Healthy,
    OpenPending,
    ReceivePending,
    SendFailure,
}

struct State {
    closed: AtomicBool,
    sends: AtomicUsize,
    receiving: Notify,
}

#[derive(Clone)]
struct ScriptedPeer {
    peer: PeerId,
    behavior: Behavior,
    state: Arc<State>,
}

impl ScriptedPeer {
    fn new(behavior: Behavior) -> Self {
        Self {
            peer: PeerId::from_bytes(PEER.as_bytes()),
            behavior,
            state: Arc::new(State {
                closed: AtomicBool::new(false),
                sends: AtomicUsize::new(0),
                receiving: Notify::new(),
            }),
        }
    }
}

#[async_trait]
impl PeerConnection for ScriptedPeer {
    async fn open_stream(&self) -> network::Result<Box<dyn Connection>> {
        if matches!(self.behavior, Behavior::OpenPending) {
            std::future::pending().await
        } else {
            Ok(Box::new(self.clone()))
        }
    }

    fn peer_id(&self) -> &PeerId {
        &self.peer
    }

    async fn close(&self) -> network::Result<()> {
        self.state.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[async_trait]
impl Connection for ScriptedPeer {
    async fn send(&self, _: NetworkMessage) -> network::Result<()> {
        self.state.sends.fetch_add(1, Ordering::SeqCst);
        if matches!(self.behavior, Behavior::SendFailure) {
            Err(NetworkError::Io(std::io::Error::from(
                std::io::ErrorKind::BrokenPipe,
            )))
        } else {
            Ok(())
        }
    }

    async fn recv(&self) -> network::Result<NetworkMessage> {
        self.state.receiving.notify_one();
        if matches!(self.behavior, Behavior::ReceivePending) {
            std::future::pending().await
        } else {
            Ok(NetworkMessage::new(b"response".to_vec(), PROTOCOL))
        }
    }

    fn peer_id(&self) -> &PeerId {
        &self.peer
    }
}

struct ScriptedNetwork {
    peers: Mutex<VecDeque<ScriptedPeer>>,
    connects: AtomicUsize,
}

impl ScriptedNetwork {
    fn new(peers: &[ScriptedPeer]) -> Arc<Self> {
        Arc::new(Self {
            peers: Mutex::new(peers.iter().cloned().collect()),
            connects: AtomicUsize::new(0),
        })
    }
}

#[async_trait]
impl Network for ScriptedNetwork {
    async fn connect(&self, _: &PeerId, _: &[u8]) -> network::Result<Box<dyn PeerConnection>> {
        self.connects.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(
            self.peers
                .lock()
                .await
                .pop_front()
                .expect("scripted connection"),
        ))
    }

    async fn listen(&mut self, _: &[u8], _: Box<dyn ProtocolHandler>) -> network::Result<()> {
        Err(NetworkError::InvalidConfig(
            "no listener in transport test".into(),
        ))
    }

    fn local_peer_id(&self) -> PeerId {
        PeerId::from_bytes(b"coordinator")
    }

    fn local_address(&self) -> network::Result<String> {
        Err(NetworkError::InvalidAddress(
            "no local address in transport test".into(),
        ))
    }

    fn create_router_builder(&self) -> network::Result<Box<dyn RouterBuilder>> {
        Err(NetworkError::InvalidConfig(
            "no router in transport test".into(),
        ))
    }
}

async fn request(
    pool: &PeerConnectionPool,
    network: &Arc<dyn Network>,
    timeout: Duration,
) -> Result<NetworkMessage> {
    peer_exchange(
        pool,
        network,
        PEER,
        PROTOCOL,
        NetworkMessage::new(b"request".to_vec(), PROTOCOL),
        Instant::now() + timeout,
        |response, _| async move { Ok(response) },
    )
    .await
}

async fn failed_request_reconnects(behavior: Behavior, phase: &str) {
    let pool = PeerConnectionPool::new();
    let failed = ScriptedPeer::new(behavior);
    let healthy = ScriptedPeer::new(Behavior::Healthy);
    let scripted = ScriptedNetwork::new(&[failed.clone(), healthy.clone()]);
    let network: Arc<dyn Network> = scripted.clone();
    let error = request(&pool, &network, Duration::from_millis(50))
        .await
        .unwrap_err();
    if matches!(behavior, Behavior::SendFailure) {
        assert!(matches!(error, SignError::NetworkCommunication(_)));
    } else {
        assert!(matches!(error, SignError::Timeout(ref detail) if detail.contains(phase)));
    }
    assert!(failed.state.closed.load(Ordering::SeqCst));
    assert!(pool.get(PEER, PROTOCOL).await.is_none());
    assert_eq!(scripted.connects.load(Ordering::SeqCst), 1);
    assert_eq!(
        failed.state.sends.load(Ordering::SeqCst),
        usize::from(!matches!(behavior, Behavior::OpenPending))
    );
    assert_eq!(
        request(&pool, &network, Duration::from_secs(1))
            .await
            .unwrap()
            .data
            .as_ref(),
        b"response"
    );
    assert_eq!(scripted.connects.load(Ordering::SeqCst), 2);
    assert_eq!(healthy.state.sends.load(Ordering::SeqCst), 1);
    assert!(!healthy.state.closed.load(Ordering::SeqCst));
}

#[tokio::test]
async fn timed_out_receive_retires_connection_without_replaying_request() {
    failed_request_reconnects(Behavior::ReceivePending, "receiving").await;
}

#[tokio::test]
async fn timed_out_stream_open_retires_connection_before_next_request() {
    failed_request_reconnects(Behavior::OpenPending, "opening").await;
}

#[tokio::test]
async fn failed_send_retires_connection_without_replaying_request() {
    failed_request_reconnects(Behavior::SendFailure, "sending").await;
}

#[tokio::test]
async fn successful_exchanges_reuse_connection() {
    let pool = PeerConnectionPool::new();
    let healthy = ScriptedPeer::new(Behavior::Healthy);
    let scripted = ScriptedNetwork::new(&[healthy.clone()]);
    let network: Arc<dyn Network> = scripted.clone();
    for _ in 0..2 {
        request(&pool, &network, Duration::from_secs(1))
            .await
            .unwrap();
    }
    assert_eq!(scripted.connects.load(Ordering::SeqCst), 1);
    assert_eq!(healthy.state.sends.load(Ordering::SeqCst), 2);
    assert!(!healthy.state.closed.load(Ordering::SeqCst));
}

#[tokio::test]
async fn response_validation_failure_does_not_retire_transport() {
    let pool = PeerConnectionPool::new();
    let healthy = ScriptedPeer::new(Behavior::Healthy);
    let scripted = ScriptedNetwork::new(&[healthy.clone()]);
    let network: Arc<dyn Network> = scripted.clone();
    let error = peer_exchange(
        &pool,
        &network,
        PEER,
        PROTOCOL,
        NetworkMessage::new(b"request".to_vec(), PROTOCOL),
        Instant::now() + Duration::from_secs(1),
        |_, _| async { Err::<(), _>(SignError::ProtocolError("invalid response".into())) },
    )
    .await
    .unwrap_err();
    assert!(matches!(error, SignError::ProtocolError(_)));
    assert!(!healthy.state.closed.load(Ordering::SeqCst));
    request(&pool, &network, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(scripted.connects.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn late_timeout_preserves_replacement_connection() {
    let pool = PeerConnectionPool::new();
    let failed = ScriptedPeer::new(Behavior::ReceivePending);
    let healthy = ScriptedPeer::new(Behavior::Healthy);
    let scripted = ScriptedNetwork::new(&[failed.clone(), healthy.clone()]);
    let network: Arc<dyn Network> = scripted.clone();
    let pending = request(&pool, &network, Duration::from_secs(1));
    let reconnect = async {
        failed.state.receiving.notified().await;
        let old = pool.get(PEER, PROTOCOL).await.unwrap();
        assert!(pool.invalidate_if_same(PEER, PROTOCOL, &old).await);
        request(&pool, &network, Duration::from_secs(1))
            .await
            .unwrap();
    };
    let (result, ()) = tokio::join!(pending, reconnect);
    assert!(matches!(result, Err(SignError::Timeout(_))));
    assert!(!healthy.state.closed.load(Ordering::SeqCst));
    assert!(pool.get(PEER, PROTOCOL).await.is_some());
    assert_eq!(scripted.connects.load(Ordering::SeqCst), 2);
}

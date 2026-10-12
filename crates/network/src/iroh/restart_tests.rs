use super::*;
use std::{
    fs::OpenOptions,
    net::{Ipv4Addr, UdpSocket},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

const PROTOCOL: &[u8] = b"orbis/restart-transport";
const CHILD: &str = "iroh::tests::restart::transport_server_child";
const DEADLINE: Duration = Duration::from_secs(10);

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Server {
    fn start(directory: &Path, port: u16) -> Self {
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(directory.join("server.private.log"))
            .unwrap();
        Self(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    CHILD,
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("ORBIS_IROH_RESTART_DIRECTORY", directory)
                .env("ORBIS_IROH_RESTART_PORT", port.to_string())
                .stdout(Stdio::from(log.try_clone().unwrap()))
                .stderr(Stdio::from(log))
                .spawn()
                .unwrap(),
        )
    }

    async fn ready(&mut self, path: &Path) -> PeerId {
        tokio::time::timeout(DEADLINE, async {
            loop {
                assert!(
                    self.0.try_wait().unwrap().is_none(),
                    "transport child exited"
                );
                if let Ok(bytes) = std::fs::read(path) {
                    if !bytes.is_empty() {
                        return PeerId::from_bytes(&bytes);
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("transport child ready")
    }

    fn crash(&mut self) {
        self.0.kill().unwrap();
        let status = self.0.wait().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
    }
}

fn ports() -> (u16, u16) {
    let first = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let second = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    (
        first.local_addr().unwrap().port(),
        second.local_addr().unwrap().port(),
    )
}

async fn client(port: u16) -> IrohNetwork {
    IrohNetwork::builder()
        .secret_key(SecretKey::from_bytes(&[1; 32]))
        .bind_addr_v4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
        .private_routes_only()
        .build()
        .await
        .unwrap()
}

async fn echo(network: &IrohNetwork, peer: &PeerId) {
    let connection = tokio::time::timeout(DEADLINE, network.connect(peer, PROTOCOL))
        .await
        .expect("cold peer connection deadline")
        .unwrap();
    let stream = connection.open_stream().await.unwrap();
    stream
        .send(Message::new(b"restart-check".as_slice(), PROTOCOL))
        .await
        .unwrap();
    let response = tokio::time::timeout(DEADLINE, stream.recv())
        .await
        .expect("echo deadline")
        .unwrap();
    assert_eq!(response.data.as_ref(), b"restart-check");
    connection.close().await.unwrap();
}

#[tokio::test]
#[ignore = "subprocess helper for the transport crash test"]
async fn transport_server_child() {
    let directory = PathBuf::from(std::env::var_os("ORBIS_IROH_RESTART_DIRECTORY").unwrap());
    let port = std::env::var("ORBIS_IROH_RESTART_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let network = IrohNetwork::builder()
        .secret_key(SecretKey::from_bytes(&[2; 32]))
        .bind_addr_v4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
        .private_routes_only()
        .build()
        .await
        .unwrap();
    let _router = network
        .create_router_builder()
        .unwrap()
        .accept(PROTOCOL.to_vec(), Arc::new(trait_tests::EchoHandler))
        .spawn()
        .unwrap();
    let route = format!("{}@127.0.0.1:{port}", network.local_address().unwrap());
    use std::io::Write;
    let mut ready = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(directory.join("ready.tmp"))
        .unwrap();
    ready.write_all(route.as_bytes()).unwrap();
    drop(ready);
    std::fs::rename(directory.join("ready.tmp"), directory.join("ready")).unwrap();
    std::future::pending::<()>().await;
}

#[tokio::test]
#[serial_test::serial]
async fn cold_dial_reconnects_after_same_key_and_socket_peer_crashes() {
    let directory = tempfile::tempdir().unwrap();
    let ready = directory.path().join("ready");
    let (server_port, client_port) = ports();
    let mut server = Server::start(directory.path(), server_port);
    let peer = server.ready(&ready).await;
    let network = client(client_port).await;
    echo(&network, &peer).await;
    network.endpoint().close().await;
    drop(network);
    for _ in 0..2 {
        server.crash();
        std::fs::remove_file(&ready).unwrap();
        server = Server::start(directory.path(), server_port);
        assert_eq!(server.ready(&ready).await, peer);
        let network = client(client_port).await;
        echo(&network, &peer).await;
        network.endpoint().close().await;
        drop(network);
    }
    println!(
        "iroh_restart_transport={{\"peer_crashes\":2,\"fresh_client_dials\":3,\"echoes\":3,\"loopback_only\":true}}"
    );
}

use std::num::NonZeroU16;

use async_trait::async_trait;
use base64::Engine;
use reqwest::{Client as HttpClient, Url};
use tendermint_rpc::{client::Client, response::Response, Error, SimpleRequest};

use super::client::{RPC_POOL_IDLE_TIMEOUT, RPC_REQUEST_TIMEOUT};
use crate::blockchain::{BlockchainError, Result};

pub(super) struct TendermintClient {
    client: HttpClient,
    url: Url,
}

impl TendermintClient {
    pub(super) fn new(raw_url: &str) -> Result<Self> {
        let url = Url::parse(raw_url)
            .map_err(|error| BlockchainError::Config(format!("Invalid RPC URL: {error}")))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(BlockchainError::Config(
                "RPC URL must be HTTP or HTTPS with a host".into(),
            ));
        }
        let client = HttpClient::builder()
            .timeout(RPC_REQUEST_TIMEOUT)
            .pool_idle_timeout(RPC_POOL_IDLE_TIMEOUT)
            .build()
            .map_err(|error| {
                BlockchainError::Config(format!("Failed to create RPC client: {error}"))
            })?;
        Ok(Self { client, url })
    }
}

#[async_trait]
impl Client for TendermintClient {
    async fn perform<R>(&self, request: R) -> std::result::Result<R::Output, Error>
    where
        R: SimpleRequest,
    {
        let mut url = self.url.clone();
        let credentials = url
            .authority()
            .split_once('@')
            .map(|(value, _)| value.to_owned());
        url.set_username("")
            .map_err(|_| Error::client_internal("invalid RPC username".into()))?;
        url.set_password(None)
            .map_err(|_| Error::client_internal("invalid RPC password".into()))?;
        let mut request = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(request.into_json());
        if let Some(credentials) = credentials {
            let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
            request = request.header(reqwest::header::AUTHORIZATION, format!("Basic {encoded}"));
        }
        let response = request
            .send()
            .await
            .map_err(|error| Error::io(std::io::Error::other(error)))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::http_request_failed(
                NonZeroU16::new(response.status().as_u16()).expect("valid HTTP status"),
            ));
        }
        let body = response
            .bytes()
            .await
            .map_err(|error| Error::io(std::io::Error::other(error)))?;
        R::Response::from_string(&body).map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn sends_json_rpc_with_basic_auth_and_decodes_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server =
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut data = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let count = stream.read(&mut chunk).await.unwrap();
                    assert_ne!(count, 0);
                    data.extend_from_slice(&chunk[..count]);
                    if let Some(end) = data.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&data[..end]).unwrap();
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap();
                        if data.len() < end + 4 + length {
                            continue;
                        }
                        assert!(headers
                            .lines()
                            .any(|line| line
                                .eq_ignore_ascii_case("authorization: Basic dXNlcjpwYXNz")));
                        let request: serde_json::Value =
                            serde_json::from_slice(&data[end + 4..end + 4 + length]).unwrap();
                        assert_eq!(request["method"], "health");
                        let body =
                            serde_json::json!({"jsonrpc":"2.0", "id":request["id"], "result":{}})
                                .to_string();
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        stream.write_all(response.as_bytes()).await.unwrap();
                        break;
                    }
                }
            });
        TendermintClient::new(&format!("http://user:pass@{address}"))
            .unwrap()
            .health()
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn broadcasts_transaction_with_expected_wire_format() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut data = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let count = stream.read(&mut chunk).await.unwrap();
                assert_ne!(count, 0);
                data.extend_from_slice(&chunk[..count]);
                if let Some(end) = data.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&data[..end]).unwrap();
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    if data.len() < end + 4 + length {
                        continue;
                    }
                    let request: serde_json::Value =
                        serde_json::from_slice(&data[end + 4..end + 4 + length]).unwrap();
                    assert_eq!(request["method"], "broadcast_tx_sync");
                    assert_eq!(request["params"]["tx"], "AQID");
                    let body = serde_json::json!({"jsonrpc":"2.0", "id":request["id"], "result": {
                        "codespace":"", "code":0, "data":"", "log":"", "hash":"11".repeat(32)
                    }})
                    .to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                    break;
                }
            }
        });
        let response = TendermintClient::new(&format!("http://{address}"))
            .unwrap()
            .broadcast_tx_sync(vec![1, 2, 3])
            .await
            .unwrap();
        assert!(response.code.is_ok());
        assert_eq!(response.hash.to_string(), "11".repeat(32));
        server.await.unwrap();
    }

    async fn health_response(status: &str, body: &str) -> Error {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            assert_ne!(stream.read(&mut buffer).await.unwrap(), 0);
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let error = TendermintClient::new(&format!("http://{address}"))
            .unwrap()
            .health()
            .await
            .unwrap_err();
        server.await.unwrap();
        error
    }

    #[tokio::test]
    async fn reports_http_and_json_rpc_errors() {
        let http = health_response("503 Service Unavailable", "unavailable").await;
        assert!(http.to_string().contains("503"));
        let rpc = health_response(
            "200 OK",
            r#"{"jsonrpc":"2.0","id":"1","error":{"code":-32601,"message":"Method not found"}}"#,
        )
        .await;
        assert!(matches!(
            rpc.detail(),
            tendermint_rpc::error::ErrorDetail::Response(_)
        ));
        let malformed = health_response("200 OK", "not json").await;
        assert!(malformed.to_string().contains("serde"));
    }

    #[tokio::test]
    async fn tls_rejects_untrusted_certificates_and_accepts_configured_roots() {
        use std::sync::Arc;
        use tokio_rustls::rustls::{pki_types::PrivatePkcs8KeyDer, ServerConfig};
        use tokio_rustls::TlsAcceptor;

        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let certificate = cert.der().clone();
        let private_key = PrivatePkcs8KeyDer::from(signing_key.serialize_der());
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key.into())
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            assert!(acceptor.accept(stream).await.is_err());
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut data = [0u8; 4096];
            assert_ne!(stream.read(&mut data).await.unwrap(), 0);
            let body = r#"{"jsonrpc":"2.0","id":"1","result":{}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let endpoint = format!("https://localhost:{}", address.port());
        let untrusted = TendermintClient::new(&endpoint).unwrap();
        assert!(untrusted.health().await.is_err());
        let mut trusted = TendermintClient::new(&endpoint).unwrap();
        trusted.client = HttpClient::builder()
            .add_root_certificate(reqwest::Certificate::from_der(certificate.as_ref()).unwrap())
            .timeout(RPC_REQUEST_TIMEOUT)
            .build()
            .unwrap();
        trusted.health().await.unwrap();
        server.await.unwrap();
    }

    #[test]
    fn rejects_non_http_rpc_url() {
        assert!(TendermintClient::new("file:///tmp/test").is_err());
    }
}

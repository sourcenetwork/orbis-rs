use anyhow::{anyhow, bail, Context, Result};
use authn::{create_authenticated_request, JwtSigner};
use common::blockchain::VeraClient;
use crypto::r#trait::{Secret, ThresholdDealer, ThresholdSigner};
use crypto::{CryptoDeserialize, GroupAffine, PreImpl, ScalarField, SignImpl};
use did_key::{generate, Ed25519KeyPair as DidEd25519KeyPair, PatchedKeyPair};
use proto::info_service::{
    info_service_client::InfoServiceClient, GetNodeInfoRequest, GetNodeInfoResponse,
    GetRingStateRequest, GetRingStateResponse, NodeStatus,
};
use proto::v0::dkg::{dkg_service_client::DkgServiceClient, StartDkgRequest};
use proto::v0::pre::{pre_service_client::PreServiceClient, StartPreRequest};
use proto::v0::sign::{sign_service_client::SignServiceClient, StartSignRequest};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::Duration;
use tokio::time::{sleep, timeout, Instant};
use tonic::transport::Channel;

#[derive(Clone, Debug)]
pub struct NodeEndpoint {
    pub index: usize,
    pub service: String,
    pub grpc_url: String,
    pub metrics_url: String,
}

#[derive(Clone, Debug)]
pub struct NodeIdentity {
    pub endpoint: NodeEndpoint,
    pub public_address: String,
    pub peer_id: String,
    pub p2p_address: String,
    pub node_key: String,
}

impl NodeIdentity {
    pub fn docker_p2p_address(&self) -> Result<String> {
        let (peer, address) = self
            .p2p_address
            .split_once('@')
            .ok_or_else(|| anyhow!("invalid Iroh address {:?}", self.p2p_address))?;
        let (_, port) = address
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("invalid Iroh socket {:?}", self.p2p_address))?;
        Ok(format!("{peer}@{}:{port}", self.endpoint.service))
    }
}

pub async fn discover_node_identity(
    endpoint: NodeEndpoint,
    deadline: Duration,
) -> Result<NodeIdentity> {
    let response = timeout(deadline, async {
        loop {
            match InfoServiceClient::connect(endpoint.grpc_url.clone()).await {
                Ok(mut client) => match client.get_node_info(GetNodeInfoRequest {}).await {
                    Ok(response) => return Ok::<_, anyhow::Error>(response.into_inner()),
                    Err(_) => sleep(Duration::from_millis(250)).await,
                },
                Err(_) => sleep(Duration::from_millis(250)).await,
            }
        }
    })
    .await
    .context("timed out waiting for bootstrap Info service")??;
    identity_from_response(endpoint, response)
}

fn identity_from_response(
    endpoint: NodeEndpoint,
    response: GetNodeInfoResponse,
) -> Result<NodeIdentity> {
    if response.node_key.is_empty() || response.public_address.is_empty() {
        bail!(
            "node {} bootstrap info omitted its signing identity",
            endpoint.index
        );
    }
    Ok(NodeIdentity {
        endpoint,
        public_address: response.public_address,
        peer_id: response.peer_id,
        p2p_address: response.p2p_address,
        node_key: response.node_key,
    })
}

pub async fn wait_nodes_ready(
    nodes: &[NodeEndpoint],
    deadline: Duration,
) -> Result<Vec<NodeIdentity>> {
    timeout(deadline, async {
        loop {
            let mut identities = Vec::with_capacity(nodes.len());
            let mut all_ready = true;
            for endpoint in nodes {
                let response = match InfoServiceClient::connect(endpoint.grpc_url.clone()).await {
                    Ok(mut client) => client.get_node_info(GetNodeInfoRequest {}).await.ok(),
                    Err(_) => None,
                };
                let Some(response) = response.map(tonic::Response::into_inner) else {
                    all_ready = false;
                    break;
                };
                if response.status != NodeStatus::Ready as i32 {
                    all_ready = false;
                    break;
                }
                identities.push(identity_from_response(endpoint.clone(), response)?);
            }
            if all_ready {
                return Ok::<_, anyhow::Error>(identities);
            }
            sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .context("timed out waiting for all nodes to become ready")?
}

pub struct DirectClients {
    info_urls: Vec<String>,
    info: Vec<InfoServiceClient<Channel>>,
    dkg: Vec<DkgServiceClient<Channel>>,
    pre: Vec<PreServiceClient<Channel>>,
    sign: Vec<SignServiceClient<Channel>>,
}

impl DirectClients {
    pub async fn connect(nodes: &[NodeEndpoint]) -> Result<Self> {
        let mut info_urls = Vec::with_capacity(nodes.len());
        let mut info = Vec::with_capacity(nodes.len());
        let mut dkg = Vec::with_capacity(nodes.len());
        let mut pre = Vec::with_capacity(nodes.len());
        let mut sign = Vec::with_capacity(nodes.len());
        for node in nodes {
            let channel = Channel::from_shared(node.grpc_url.clone())?
                .connect()
                .await
                .with_context(|| format!("connect persistent gRPC channel to {}", node.grpc_url))?;
            info_urls.push(node.grpc_url.clone());
            info.push(InfoServiceClient::new(channel.clone()));
            dkg.push(DkgServiceClient::new(channel.clone()));
            pre.push(PreServiceClient::new(channel.clone()));
            sign.push(SignServiceClient::new(channel));
        }
        Ok(Self {
            info_urls,
            info,
            dkg,
            pre,
            sign,
        })
    }

    pub async fn start_dkg(
        &mut self,
        initiator: usize,
        ring_id: &str,
    ) -> Result<DkgAcknowledgement> {
        let signer = JwtSigner::new();
        let token = signer.create_dkg_jwt(ring_id)?;
        let request = create_authenticated_request(
            StartDkgRequest {
                ring_id: ring_id.to_string(),
            },
            &token,
        )?;
        let started = Instant::now();
        let response = self
            .dkg
            .get_mut(initiator)
            .ok_or_else(|| anyhow!("DKG initiator {initiator} is outside the network"))?
            .start_dkg(request)
            .await?
            .into_inner();
        Ok(DkgAcknowledgement {
            acknowledgement_ms: started.elapsed().as_secs_f64() * 1000.0,
            session_id: response.session_id,
            status: response.status,
        })
    }

    pub async fn pre(&mut self, initiator: usize, fixture: &PreFixture) -> Result<PreMeasurement> {
        pre_call(
            self.pre
                .get_mut(initiator)
                .ok_or_else(|| anyhow!("PRE initiator {initiator} is outside the network"))?,
            fixture,
        )
        .await
    }

    pub async fn sign(
        &mut self,
        initiator: usize,
        fixture: &SignFixture,
        message: Vec<u8>,
    ) -> Result<SignMeasurement> {
        sign_call(
            self.sign
                .get_mut(initiator)
                .ok_or_else(|| anyhow!("SIGN initiator {initiator} is outside the network"))?,
            fixture,
            message,
        )
        .await
    }

    pub fn pre_client(&self, initiator: usize) -> Result<PreServiceClient<Channel>> {
        self.pre
            .get(initiator)
            .cloned()
            .ok_or_else(|| anyhow!("PRE initiator {initiator} is outside the network"))
    }

    pub fn sign_client(&self, initiator: usize) -> Result<SignServiceClient<Channel>> {
        self.sign
            .get(initiator)
            .cloned()
            .ok_or_else(|| anyhow!("SIGN initiator {initiator} is outside the network"))
    }

    pub async fn ring_states(
        &self,
        members: &[usize],
        ring_pk: &str,
    ) -> Result<Vec<GetRingStateResponse>> {
        let requests = members.iter().map(|member| {
            let member_index = member.saturating_sub(1);
            let client = self
                .info
                .get(member_index)
                .cloned()
                .ok_or_else(|| anyhow!("ring member {member} is outside the network"));
            let info_url = self
                .info_urls
                .get(member_index)
                .cloned()
                .ok_or_else(|| anyhow!("ring member {member} has no info endpoint"));
            let ring_pk = ring_pk.to_string();
            async move {
                let mut client = client?;
                let request = || GetRingStateRequest {
                    ring_pk_hex: ring_pk.clone(),
                };
                match timeout(Duration::from_secs(3), client.get_ring_state(request())).await {
                    Ok(Ok(response)) => Ok(response.into_inner()),
                    first_attempt => {
                        let info_url = info_url?;
                        let mut fresh = timeout(
                            Duration::from_secs(3),
                            InfoServiceClient::connect(info_url.clone()),
                        )
                        .await
                        .with_context(|| format!("connect timeout for ring member {member}"))?
                        .with_context(|| format!("reconnect ring member {member} at {info_url}"))?;
                        timeout(Duration::from_secs(3), fresh.get_ring_state(request()))
                            .await
                            .with_context(|| {
                                format!(
                                    "GetRingState timeout for ring member {member} after persistent attempt {first_attempt:?}"
                                )
                            })?
                            .map(tonic::Response::into_inner)
                            .map_err(anyhow::Error::from)
                    }
                }
            }
        });
        futures::future::join_all(requests)
            .await
            .into_iter()
            .collect()
    }

    pub async fn wait_ring_finalized_everywhere(
        &self,
        vera: &VeraClient,
        ring_id: &str,
        members: &[usize],
        deadline: Duration,
    ) -> Result<String> {
        timeout(deadline, async {
            let mut last_progress = Instant::now()
                .checked_sub(Duration::from_secs(10))
                .unwrap_or_else(Instant::now);
            loop {
                let ring = match crate::runner::read_ring_with_retry(vera, ring_id).await {
                    Ok(ring) => ring,
                    Err(error) => {
                        if last_progress.elapsed() >= Duration::from_secs(10) {
                            eprintln!(
                                "ring {ring_id}: Vera read failed, retrying until timeout: {error:#}"
                            );
                            last_progress = Instant::now();
                        }
                        sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                };
                if let Some(ring) = ring.filter(|ring| !ring.ring_pk.is_empty()) {
                    match self.ring_states(members, &ring.ring_pk).await {
                        Ok(states) => {
                            let expected_polynomial = states
                                .first()
                                .map(|state| state.public_polynomial.as_str())
                                .filter(|polynomial| !polynomial.is_empty());
                            if expected_polynomial.is_some()
                                && states.iter().all(|state| {
                                    Some(state.public_polynomial.as_str()) == expected_polynomial
                                })
                            {
                                return Ok::<_, anyhow::Error>(ring.ring_pk);
                            }
                            if last_progress.elapsed() >= Duration::from_secs(10) {
                                eprintln!(
                                    "ring {ring_id}: on-chain finalization observed; waiting for matching local state on {} committee nodes",
                                    members.len()
                                );
                                last_progress = Instant::now();
                            }
                        }
                        Err(error) => {
                            if last_progress.elapsed() >= Duration::from_secs(10) {
                                eprintln!(
                                    "ring {ring_id}: on-chain finalization observed; local-state verification pending: {error:#}"
                                );
                                last_progress = Instant::now();
                            }
                        }
                    }
                } else if last_progress.elapsed() >= Duration::from_secs(10) {
                    eprintln!("ring {ring_id}: waiting for Vera finalization");
                    last_progress = Instant::now();
                }
                sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .with_context(|| {
            format!("ring {ring_id} did not finalize on-chain and on every committee node")
        })?
    }

    pub async fn wait_pss_refresh(
        &self,
        members: &[usize],
        ring_pk: &str,
        baseline: &[GetRingStateResponse],
        due_at_unix_secs: u64,
        deadline: Duration,
    ) -> Result<PssMeasurement> {
        let due_at_unix_ms = u128::from(due_at_unix_secs) * 1_000;
        let wait_until_due_ms = due_at_unix_ms.saturating_sub(unix_ms());
        if wait_until_due_ms > 0 {
            sleep(Duration::from_millis(
                wait_until_due_ms.min(u128::from(u64::MAX)) as u64,
            ))
            .await;
        }
        let due_started = Instant::now();
        let result = timeout(deadline, async {
            loop {
                if let Ok(current) = self.ring_states(members, ring_pk).await {
                    let expected_polynomial = current
                        .first()
                        .map(|state| state.public_polynomial.as_str())
                        .filter(|polynomial| !polynomial.is_empty());
                    let changed = current.len() == baseline.len()
                        && expected_polynomial.is_some()
                        && current.iter().zip(baseline).all(|(state, before)| {
                            state.last_pss > before.last_pss
                                && state.public_polynomial != before.public_polynomial
                                && Some(state.public_polynomial.as_str()) == expected_polynomial
                        });
                    if changed {
                        return Ok::<_, anyhow::Error>(PssMeasurement {
                            scheduler_delay_ms: 0.0,
                            ceremony_ms: due_started.elapsed().as_secs_f64() * 1_000.0,
                            states: current,
                        });
                    }
                }
                sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .map_err(|_| PssRefreshTimeout)?;
        result
    }
}

#[derive(Clone, Debug)]
pub struct DkgAcknowledgement {
    pub acknowledgement_ms: f64,
    pub session_id: String,
    pub status: String,
}

#[derive(Debug)]
pub struct PssRefreshTimeout;

impl fmt::Display for PssRefreshTimeout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PSS refresh did not update every committee node before the timeout")
    }
}

impl std::error::Error for PssRefreshTimeout {}

#[derive(Clone, Debug)]
pub struct PssMeasurement {
    pub scheduler_delay_ms: f64,
    pub ceremony_ms: f64,
    pub states: Vec<GetRingStateResponse>,
}

#[derive(Clone, Debug)]
pub struct PreFixture {
    pub ring_pk: String,
    pub reader_pk: Vec<u8>,
    pub reader_sk: ScalarField,
    pub object_id: String,
    pub reader_identity: String,
    pub derivation: Option<Vec<u8>>,
    pub salt: Option<String>,
    pub expected_plaintext: Vec<u8>,
}

#[derive(Deserialize)]
struct PreResponse {
    xnc_cmt: String,
    secret: Secret,
}

#[derive(Clone, Debug)]
pub struct PreMeasurement {
    pub total_ms: f64,
    pub rpc_ms: f64,
    pub decrypt_ms: f64,
}

pub async fn pre_call(
    client: &mut PreServiceClient<Channel>,
    fixture: &PreFixture,
) -> Result<PreMeasurement> {
    let signer = JwtSigner::from_key_pair(did_key_pair(&fixture.reader_identity));
    let token = signer.create_pre_jwt(
        fixture.reader_pk.clone(),
        &fixture.object_id,
        fixture.derivation.clone(),
        fixture.salt.clone(),
    )?;
    let total_started = Instant::now();
    let request = create_authenticated_request(
        StartPreRequest {
            rdr_pk: fixture.reader_pk.clone(),
            object_id: fixture.object_id.clone(),
            derivation: fixture.derivation.clone(),
            salt: fixture.salt.clone(),
            valid_window: None,
            document: None,
        },
        &token,
    )?;
    let rpc_started = Instant::now();
    let response = client.start_pre(request).await?.into_inner();
    let rpc_ms = rpc_started.elapsed().as_secs_f64() * 1000.0;
    if response.encrypted_secret.is_empty() {
        bail!(
            "PRE response contained no encrypted secret: {}",
            response.message
        );
    }
    let decrypt_started = Instant::now();
    let response: PreResponse = serde_json::from_slice(&response.encrypted_secret)?;
    let xnc_cmt = GroupAffine::from_bytes(&hex::decode(response.xnc_cmt)?)?;
    let ring_pk = GroupAffine::from_bytes(&hex::decode(&fixture.ring_pk)?)?;
    let effective_pk = match &fixture.derivation {
        Some(derivation) => PreImpl::derive_public_key(&ring_pk, derivation)?,
        None => ring_pk,
    };
    let plaintext = PreImpl::decrypt_secret(
        &effective_pk,
        &xnc_cmt,
        &fixture.reader_sk,
        &response.secret,
    )?;
    let decrypt_ms = decrypt_started.elapsed().as_secs_f64() * 1000.0;
    if plaintext != fixture.expected_plaintext {
        bail!("PRE correctness failure: recovered plaintext does not match input");
    }
    Ok(PreMeasurement {
        total_ms: total_started.elapsed().as_secs_f64() * 1000.0,
        rpc_ms,
        decrypt_ms,
    })
}

#[derive(Clone, Debug)]
pub struct SignFixture {
    pub derivation_id: String,
    pub derived_public_key: String,
    pub reader_identity: String,
}

#[derive(Clone, Debug)]
pub struct SignMeasurement {
    pub total_ms: f64,
    pub rpc_ms: f64,
    pub verification_ms: f64,
}

pub async fn sign_call(
    client: &mut SignServiceClient<Channel>,
    fixture: &SignFixture,
    message: Vec<u8>,
) -> Result<SignMeasurement> {
    let signer = JwtSigner::from_key_pair(did_key_pair(&fixture.reader_identity));
    let token = signer.create_sign_jwt(&fixture.derivation_id, &message)?;
    let total_started = Instant::now();
    let request = create_authenticated_request(
        StartSignRequest {
            message: message.clone(),
            derivation_id: fixture.derivation_id.clone(),
            valid_window: None,
        },
        &token,
    )?;
    let rpc_started = Instant::now();
    let response = client.start_sign(request).await?.into_inner();
    let rpc_ms = rpc_started.elapsed().as_secs_f64() * 1000.0;
    let verification_started = Instant::now();
    let signature_bytes = hex::decode(&response.signature)?;
    let signature = <SignImpl as ThresholdSigner>::Signature::from_bytes(&signature_bytes)?;
    let public_key = GroupAffine::from_bytes(&hex::decode(&fixture.derived_public_key)?)?;
    SignImpl::new().verify(&public_key, &message, &signature)?;
    let verification_ms = verification_started.elapsed().as_secs_f64() * 1000.0;
    Ok(SignMeasurement {
        total_ms: total_started.elapsed().as_secs_f64() * 1000.0,
        rpc_ms,
        verification_ms,
    })
}

fn did_key_pair(identity: &str) -> PatchedKeyPair {
    let seed: [u8; 32] = Sha256::digest(identity.as_bytes()).into();
    generate::<DidEd25519KeyPair>(Some(&seed))
}

fn unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_only_the_host_part_of_an_iroh_address() {
        let identity = NodeIdentity {
            endpoint: NodeEndpoint {
                index: 7,
                service: "node-007".into(),
                grpc_url: "http://127.0.0.1:1".into(),
                metrics_url: "http://127.0.0.1:2/metrics".into(),
            },
            public_address: "source1...".into(),
            peer_id: "peer".into(),
            p2p_address: "abcdef@0.0.0.0:4242".into(),
            node_key: "key".into(),
        };
        assert_eq!(
            identity.docker_p2p_address().unwrap(),
            "abcdef@node-007:4242"
        );
    }
}

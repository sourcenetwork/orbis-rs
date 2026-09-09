//! Native threshold metadata with durable submission and certified reads.

mod backend;
mod config;
pub use backend::NativeBulletin;
pub use config::NativeConfig;

use std::path::Path;

use alloy_primitives::{Bytes, B256};
use hub_client::{
    nodes::{encode_node_request, sign_node_request, NodeRead, NodeRequest},
    threshold_objects::{
        encode_threshold_object, EncryptedDocument, KeyDerivation, ThresholdObject,
    },
    ClientError, ExecutionReceipt, HubClient, NativeWorker, HUB_ADDRESS,
};
use hub_domain::{ConsensusPublicKey, NativeTx};
use k256::ecdsa::SigningKey;
use local_storage::{
    r#trait::{LocalStorage, LocalStorageKeys},
    redb::RedbStorage,
};
use zeroize::Zeroizing;

use crate::r#trait::{
    BulletinPost, BulletinReportSubmission, DemeritConfig, DocumentPayload, NodeInfo,
    ReportingConfig, RingFinalizationStatus, RingPayload, UpgradeInfo,
};
pub use hub_client::nodes::{NodeCommand, NodeTarget};
use hub_client::rings::{
    encode_ring_command, encode_ring_participant_request, encode_ring_report, encode_ring_reshare,
    sign_ring_participant_request, RingRead, RingRecord, RingState,
};
pub use hub_client::rings::{
    ReshareTarget, RingCommand, RingConfig, RingParticipantCommand, RingParticipantRequest,
    RingReshareRequest, RingSettings, RingUpdate, ScheduledUpgrade, ThresholdScheme,
};
pub use hub_client::threshold_objects::ObjectKind;

/// Native service client backed by an encrypted worker key and durable submission journal.
/// Prepare, submit and confirm are separate so an uncertain response never allocates a new request.
pub struct NativeVeraClient {
    client: HubClient,
    trusted: ConsensusPublicKey,
    deployment_root: [u8; 32],
    authority: SigningKey,
    worker: NativeWorker,
}

/// Decode the raw key used by early native clients or the encrypted hex used by node startup.
pub fn decode_node_signing_key(bytes: &[u8]) -> Result<SigningKey, ClientError> {
    if bytes.len() == 32 {
        return SigningKey::from_slice(bytes).map_err(|e| ClientError::Signing(e.to_string()));
    }
    let encoded = std::str::from_utf8(bytes)
        .map_err(|_| ClientError::Signing("invalid node signing key encoding".into()))?;
    let encoded = encoded.strip_prefix("0x").unwrap_or(encoded);
    if encoded.len() != 64 {
        return Err(ClientError::Signing(
            "invalid node signing key length".into(),
        ));
    }
    let decoded = Zeroizing::new(
        hex::decode(encoded)
            .map_err(|_| ClientError::Signing("invalid node signing key encoding".into()))?,
    );
    SigningKey::from_slice(&decoded).map_err(|e| ClientError::Signing(e.to_string()))
}

impl NativeVeraClient {
    /// Open the journal using Orbis's existing encrypted store and node signing identity.
    /// The caller provisions the deployment root and consensus key independently of the endpoint.
    pub fn open(
        client: HubClient,
        trusted: ConsensusPublicKey,
        deployment_root: [u8; 32],
        deployment_id: u64,
        directory: &Path,
        storage: &RedbStorage,
    ) -> Result<Self, ClientError> {
        let bytes = storage
            .get_encrypted(LocalStorageKeys::NodeSigningKey)
            .map_err(|e| ClientError::Signing(e.to_string()))?
            .ok_or_else(|| ClientError::Signing("node signing key is missing".into()))?;
        let authority = decode_node_signing_key(&bytes)?;
        let worker = NativeWorker::open(
            directory,
            deployment_id,
            |name| {
                storage
                    .get_encrypted(LocalStorageKeys::NativeWorkerKey(name.into()))
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| "native worker key is missing".to_owned())
            },
            |name, bytes| {
                storage.set_encrypted(
                    LocalStorageKeys::NativeWorkerKey(name.into()),
                    Zeroizing::new(bytes.to_vec()),
                )
            },
        )?;
        Ok(Self {
            client,
            trusted,
            deployment_root,
            authority,
            worker,
        })
    }

    pub fn node_key(&self) -> String {
        hex::encode(self.authority.verifying_key().to_sec1_bytes())
    }

    /// Persist a registration before submitting anything. Allow lists are canonicalized as sets.
    pub fn prepare_node_registration(
        &mut self,
        info: NodeInfo,
        expires_at: u64,
    ) -> Result<B256, ClientError> {
        let mut info = hub_client::nodes::NodeInfo {
            peer_id: info.peer_id,
            controller_key: info.controller_key,
            allowed_policy_ids: info.whitelisted_policy_ids,
            allowed_ring_ids: info.whitelisted_ring_ids,
        };
        info.allowed_policy_ids.sort();
        info.allowed_ring_ids.sort();
        info.validate()
            .map_err(|e| ClientError::Signing(e.to_string()))?;
        self.prepare_node_command(self.node_key(), 0, NodeCommand::Register(info), expires_at)
    }

    /// Persist a command signed by this store's authority. Obtain the node sequence from a certified read.
    /// A pending command can only be prepared again with identical arguments, including expiry.
    pub fn prepare_node_command(
        &mut self,
        node_key: String,
        sequence: u64,
        command: NodeCommand,
        expires_at: u64,
    ) -> Result<B256, ClientError> {
        let signed = sign_node_request(
            NodeRequest {
                deployment_root: self.deployment_root,
                deployment_id: self.worker.deployment_id(),
                node_key,
                sequence,
                command,
                expires_at,
            },
            &self.authority,
        )?;
        self.prepare_call(encode_node_request(&signed)?)
    }

    fn prepare_call(&mut self, calldata: Bytes) -> Result<B256, ClientError> {
        let wire = self.worker.prepare(HUB_ADDRESS, calldata)?;
        Ok(NativeTx::decode_wire(wire)
            .map_err(|e| ClientError::Signing(e.to_string()))?
            .tx_id()
            .0)
    }

    /// Identity to which an actor delegates native service commands.
    pub fn worker_did(&self) -> &str {
        self.worker.did()
    }

    /// Persist an ACP-authorized ring command before submission.
    pub fn prepare_ring_command(
        &mut self,
        command: &RingCommand,
        token: &str,
    ) -> Result<B256, ClientError> {
        self.prepare_call(encode_ring_command(command, token)?)
    }

    /// Persist a fresh-DKG confirmation or cancellation signed by the node identity.
    pub fn prepare_ring_participant_request(
        &mut self,
        ring_id: String,
        command: RingParticipantCommand,
        expires_at: u64,
    ) -> Result<B256, ClientError> {
        let signed = sign_ring_participant_request(
            RingParticipantRequest {
                deployment_root: self.deployment_root,
                deployment_id: self.worker.deployment_id(),
                ring_id,
                node_key: self.node_key(),
                command,
                expires_at,
            },
            &self.authority,
        )?;
        self.prepare_call(encode_ring_participant_request(&signed)?)
    }

    /// Deployment namespace used by the existing Orbis reshare signing document.
    pub fn deployment_label(&self) -> String {
        hub_client::rings::ring_deployment_label(self.deployment_root, self.worker.deployment_id())
    }

    /// Persist aggregate authorization produced by the existing ring's threshold signers.
    pub fn prepare_ring_reshare(
        &mut self,
        ring_id: String,
        expected_sequence: u64,
        scheme: ThresholdScheme,
        signature: String,
    ) -> Result<B256, ClientError> {
        self.prepare_call(encode_ring_reshare(&RingReshareRequest {
            deployment_root: self.deployment_root,
            deployment_id: self.worker.deployment_id(),
            ring_id,
            expected_sequence,
            scheme,
            signature,
        })?)
    }

    /// Persist an encrypted document under the actor's scoped delegation.
    pub fn prepare_document(
        &mut self,
        document: DocumentPayload,
        token: &str,
    ) -> Result<B256, ClientError> {
        let object = ThresholdObject::Document(EncryptedDocument {
            ring_id: document.ring_id,
            document: document.document,
            proof: document.proof,
            policy_id: document.policy_id,
            resource: document.resource,
            permission: document.permission,
            tier: document.tier,
            timestamp: document.timestamp,
        });
        self.prepare_call(encode_threshold_object(&object, token)?)
    }

    /// Persist a signing derivation and its policy binding under scoped delegation.
    pub fn prepare_key_derivation(
        &mut self,
        derivation: crate::r#trait::KeyDerivation,
        token: &str,
    ) -> Result<B256, ClientError> {
        let object = ThresholdObject::KeyDerivation(KeyDerivation {
            ring_id: derivation.ring_id,
            derivation: derivation.derivation,
            policy_id: derivation.policy_id,
            resource: derivation.resource,
            permission: derivation.permission,
        });
        self.prepare_call(encode_threshold_object(&object, token)?)
    }

    /// Adapt a certified document or derivation to the payload consumed by Orbis protocols.
    pub async fn read_object(
        &self,
        kind: ObjectKind,
        id: &str,
        minimum_revision: u64,
    ) -> crate::error::Result<BulletinPost> {
        let response = self
            .client
            .read_threshold_object(kind, id, minimum_revision, &self.trusted)
            .await
            .map_err(|e| crate::error::BulletinError::NativeError(e.to_string()))?;
        let record = response
            .record
            .ok_or_else(|| crate::error::BulletinError::NotFound { id: id.into() })?;
        if record.deployment_root != self.deployment_root {
            return Err(crate::error::BulletinError::NativeError(
                "object deployment mismatch".into(),
            ));
        }
        object_post(record)
    }

    /// Persist an aggregate-signed report without changing the signed envelope.
    pub fn prepare_ring_report(
        &mut self,
        submission: BulletinReportSubmission,
    ) -> Result<B256, ClientError> {
        if submission.chain_id != self.deployment_label() {
            return Err(ClientError::Signing("report deployment mismatch".into()));
        }
        self.prepare_call(encode_ring_report(&native_report(submission))?)
    }

    pub async fn read_ring(
        &self,
        id: &str,
        minimum_revision: u64,
    ) -> Result<RingRead, ClientError> {
        self.client
            .read_threshold_ring(id, minimum_revision, &self.trusted)
            .await
    }

    /// Adapt a certified ring to the existing Orbis DKG payload.
    pub async fn read_ring_info(
        &self,
        id: &str,
        minimum_revision: u64,
    ) -> crate::error::Result<BulletinPost> {
        ring_post(
            self.read_ring(id, minimum_revision)
                .await
                .map_err(|e| crate::error::BulletinError::NativeError(e.to_string()))?
                .record
                .ok_or_else(|| crate::error::BulletinError::NotFound { id: id.into() })?,
        )
    }

    pub async fn ring_finalization_status(
        &self,
        id: &str,
        minimum_revision: u64,
    ) -> crate::error::Result<RingFinalizationStatus> {
        let record = self
            .read_ring(id, minimum_revision)
            .await
            .map_err(|e| crate::error::BulletinError::NativeError(e.to_string()))?
            .record
            .ok_or_else(|| crate::error::BulletinError::NotFound { id: id.into() })?;
        ring_status(&record)
    }

    /// Local submission identity, also available after reopening an interrupted request.
    pub fn pending_id(&self) -> Result<Option<B256>, ClientError> {
        self.worker
            .pending()
            .map(|wire| {
                NativeTx::decode_wire(wire)
                    .map(|tx| tx.tx_id().0)
                    .map_err(|e| ClientError::Signing(e.to_string()))
            })
            .transpose()
    }

    fn pending_call(&self) -> Result<Option<Bytes>, ClientError> {
        self.worker
            .pending()
            .map(|wire| {
                let request =
                    NativeTx::decode_wire(wire).map_err(|e| ClientError::Worker(e.to_string()))?;
                if request.target != HUB_ADDRESS {
                    return Err(ClientError::Worker(
                        "unexpected native bulletin target".into(),
                    ));
                }
                Ok(request.calldata)
            })
            .transpose()
    }

    /// Send the exact journaled bytes. Errors retain the request for receipt lookup or resubmission.
    pub async fn submit_pending(&self) -> Result<B256, ClientError> {
        let expected = self
            .pending_id()?
            .ok_or_else(|| ClientError::Worker("no pending request".into()))?;
        let submitted = self
            .client
            .send_native_tx(self.worker.pending().expect("pending request"))
            .await?;
        if submitted != expected {
            return Err(ClientError::InvalidResponse(
                "node submission identifier mismatch",
            ));
        }
        Ok(expected)
    }

    /// Release the worker only with a certified receipt; inspect its success before treating a command as applied.
    pub async fn confirm_pending(&mut self) -> Result<Option<ExecutionReceipt>, ClientError> {
        let Some(id) = self.pending_id()? else {
            return Ok(None);
        };
        let Some(proof) = self.client.read_receipt(id, &self.trusted).await? else {
            return Ok(None);
        };
        self.worker.acknowledge(&proof, &self.trusted).map(Some)
    }

    /// Read a node's next command sequence and metadata from certified state.
    pub async fn read(
        &self,
        node_key: &str,
        minimum_revision: u64,
    ) -> Result<NodeRead, ClientError> {
        self.client
            .read_threshold_node(node_key, minimum_revision, &self.trusted)
            .await
    }

    /// Adapt certified metadata to the payload consumed by Orbis peer routing.
    pub async fn read_node_info(
        &self,
        node_key: &str,
        minimum_revision: u64,
    ) -> crate::error::Result<BulletinPost> {
        let response = self
            .read(node_key, minimum_revision)
            .await
            .map_err(|e| crate::error::BulletinError::NativeError(e.to_string()))?;
        let record = response
            .record
            .ok_or_else(|| crate::error::BulletinError::NotFound {
                id: node_key.into(),
            })?;
        let info = NodeInfo {
            peer_id: record.info.peer_id,
            controller_key: record.info.controller_key,
            whitelisted_policy_ids: record.info.allowed_policy_ids,
            whitelisted_ring_ids: record.info.allowed_ring_ids,
        };
        Ok(BulletinPost {
            id: node_key.into(),
            payload: info.try_into()?,
        })
    }
}

fn object_post(
    record: hub_client::threshold_objects::ObjectRecord,
) -> crate::error::Result<BulletinPost> {
    let payload = match record.object {
        ThresholdObject::Document(d) => serde_json::to_vec(&d),
        ThresholdObject::KeyDerivation(d) => serde_json::to_vec(&d),
    }
    .map_err(|e| crate::error::BulletinError::NativeError(e.to_string()))?;
    Ok(BulletinPost {
        id: record.id,
        payload,
    })
}

fn native_report(s: BulletinReportSubmission) -> hub_client::rings::SignedReport {
    hub_client::rings::SignedReport {
        report: hub_client::rings::ReportEnvelope {
            domain: s.domain,
            report_type: s.report_type,
            chain_id: s.chain_id,
            ring_id: s.ring_id,
            ring_pk: s.ring_pk,
            ring_state_sha256: s.ring_state_sha256,
            reporter_node_key: s.reporter_node_key,
            accused_node_key: s.accused_node_key,
            accused_peer_id: s.accused_peer_id,
            observed_at: s.observed_at,
            expires_at: s.expires_at,
            payload: s.payload,
            session_id: s.session_id,
        },
        report_id: s.report_id,
        signature_scheme: s.signature_scheme,
        signature: hex::encode(s.signature),
    }
}

fn ring_status(record: &RingRecord) -> crate::error::Result<RingFinalizationStatus> {
    match &record.state {
        RingState::Pending { confirmations, .. } => Ok(RingFinalizationStatus {
            ring_pk: String::new(),
            confirmation_node_keys: Some(confirmations.clone()),
        }),
        RingState::Active { public_key } => Ok(RingFinalizationStatus {
            ring_pk: public_key.clone(),
            confirmation_node_keys: Some(Vec::new()),
        }),
        RingState::Cancelled { .. } | RingState::Conflict { .. } => {
            Err(crate::error::BulletinError::NotFound {
                id: record.id.clone(),
            })
        }
    }
}

fn ring_post(record: RingRecord) -> crate::error::Result<BulletinPost> {
    let status = ring_status(&record)?;
    let settings = record.current_settings();
    let (new_peer_node_keys, new_threshold) =
        settings.pending_reshare.map_or((None, None), |target| {
            (Some(target.peer_node_keys), Some(target.threshold))
        });
    let (next_version, activation_time) =
        settings.scheduled_upgrade.map_or((None, None), |upgrade| {
            (Some(upgrade.version), Some(upgrade.activates_at))
        });
    let ring = RingPayload {
        ring_pk: status.ring_pk,
        new_peer_node_keys,
        new_threshold,
        peer_node_keys: settings.peer_node_keys,
        threshold: settings.threshold,
        pss_interval: settings.pss_interval,
        block_number_nonce: record.sequence,
        policy_id: Some(record.config.policy_id),
        trusted_auth_relay_dids: settings.trusted_auth_relay_dids,
        upgrade_info: UpgradeInfo {
            current_version: settings.current_version,
            next_version,
            activation_time,
        },
        reporting: ReportingConfig {
            demerit_config: DemeritConfig {
                node_offline_demerits: settings.reporting.node_offline_demerits,
                reset_interval_seconds: settings.reporting.reset_interval_seconds,
                invalid_crypto_response_demerits: settings
                    .reporting
                    .invalid_crypto_response_demerits,
                unauthorized_request_demerits: settings.reporting.unauthorized_request_demerits,
            },
            backup_node_keys: settings.reporting.backup_node_keys,
            kick_threshold: settings.reporting.kick_threshold,
        },
    };
    Ok(BulletinPost {
        id: record.id,
        payload: serde_json::to_vec(&ring)
            .map_err(|e| crate::error::BulletinError::ParseError(e.to_string()))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_math::algebra::CryptoGroup;

    #[test]
    fn native_objects_preserve_current_consumer_ids_and_payloads() {
        let document = EncryptedDocument {
            ring_id: "11".repeat(32),
            document:
                r#"{"enc_cmt":[1,2,3],"encrypted_data":[4,5,6],"nonce":[0,0,0,0,0,0,0,0,0,0,0,0]}"#
                    .into(),
            proof: r#"{"challenge":[7,8],"response":[9,10]}"#.into(),
            policy_id: "22".repeat(32),
            resource: "document".into(),
            permission: "read".into(),
            tier: Some("gold".into()),
            timestamp: Some(1_700_000_000),
        };
        let expected = common::blockchain::orbis::generate_document_id(
            &document.ring_id,
            &document.document,
            &document.proof,
            &document.policy_id,
            &document.resource,
            &document.permission,
            document.tier.as_deref(),
            document.timestamp,
        )
        .unwrap();
        let derivation = KeyDerivation {
            ring_id: document.ring_id.clone(),
            derivation: "tenant/key".into(),
            policy_id: document.policy_id.clone(),
            resource: "document".into(),
            permission: "sign".into(),
        };
        let derivation_id = common::blockchain::orbis::generate_key_derivation_id(
            &derivation.ring_id,
            &derivation.derivation,
            &derivation.policy_id,
            &derivation.resource,
            &derivation.permission,
        );
        let make_post = |object: ThresholdObject| {
            object.validate().unwrap();
            object_post(hub_client::threshold_objects::ObjectRecord {
                id: object.id().unwrap(),
                deployment_root: [7; 32],
                creator: "did:key:actor".into(),
                revision: Default::default(),
                object,
            })
            .unwrap()
        };
        let post = make_post(ThresholdObject::Document(document.clone()));
        assert_eq!(post.id, expected);
        let restored: DocumentPayload = post.try_into().unwrap();
        assert_eq!(restored.document, document.document);
        assert_eq!(restored.proof, document.proof);
        assert_eq!(restored.tier, document.tier);
        assert_eq!(restored.timestamp, document.timestamp);
        let post = make_post(ThresholdObject::KeyDerivation(derivation.clone()));
        assert_eq!(post.id, derivation_id);
        let restored: crate::r#trait::KeyDerivation = post.try_into().unwrap();
        assert_eq!(restored.derivation, derivation.derivation);
        assert_eq!(restored.policy_id, derivation.policy_id);
    }

    #[test]
    fn native_report_conversion_preserves_the_existing_golden_id() {
        let expected = "954c67cd1885283a0d22a074b0b6db7eb412bad414d4fcfb5ff59cd1719e6dc0";
        let report = native_report(BulletinReportSubmission {
            domain: "orbis-mpc-fault-report".into(),
            report_type: "node_offline".into(),
            chain_id: "vera-test".into(),
            ring_id: "ring-1".into(),
            ring_pk: "aabb".into(),
            ring_state_sha256: "11".repeat(32),
            reporter_node_key: "reporter".into(),
            accused_node_key: "accused".into(),
            accused_peer_id: "22".repeat(32),
            observed_at: 1_700_000_000,
            expires_at: 1_700_000_120,
            payload: orbis_reporting::NodeOffline {
                origin_protocol: "pre".into(),
                origin_protocol_version: 0,
                accused_committee_scope: orbis_reporting::CommitteeScope::Current,
                signing_committee_scope: orbis_reporting::CommitteeScope::Current,
            }
            .canonical_bytes(),
            session_id: "pre-request-1".into(),
            report_id: expected.into(),
            signature_scheme: "decaf377_frost".into(),
            signature: vec![3; 64],
        });
        assert_eq!(report.report.report_id(), expected);
        assert_eq!(report.report_id, expected);
        assert_eq!(report.signature, "03".repeat(64));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["report"]["deployment"], "vera-test");
        assert!(json["report"].get("chain_id").is_none());
        let restored: hub_client::rings::SignedReport = serde_json::from_value(json).unwrap();
        assert_eq!(
            restored.report.canonical_bytes(),
            report.report.canonical_bytes()
        );
    }

    #[test]
    fn encrypted_worker_and_exact_request_survive_reopen() {
        let root = tempfile::tempdir().unwrap();
        let storage = RedbStorage::new(
            "test".into(),
            root.path().join("keys.redb").to_string_lossy().into_owned(),
        )
        .unwrap();
        let directory = root.path().join("worker");
        let open = |deployment| {
            NativeVeraClient::open(
                HubClient::new("http://127.0.0.1:1"),
                ConsensusPublicKey::generator(),
                [7; 32],
                deployment,
                &directory,
                &storage,
            )
        };
        assert!(open(9001).is_err());
        storage
            .set_encrypted(
                LocalStorageKeys::NodeSigningKey,
                Zeroizing::new(vec![31; 32]),
            )
            .unwrap();
        let mut registry = open(9001).unwrap();
        let info = NodeInfo {
            peer_id: "peer1".into(),
            controller_key: registry.node_key(),
            whitelisted_policy_ids: vec!["policy2".into(), "policy1".into()],
            whitelisted_ring_ids: vec![],
        };
        let id = registry
            .prepare_node_registration(info.clone(), 100)
            .unwrap();
        assert_eq!(registry.pending_id().unwrap(), Some(id));
        assert!(open(9001).is_err());
        let node_key = registry.node_key();
        drop(registry);
        storage
            .set_encrypted(
                LocalStorageKeys::NodeSigningKey,
                Zeroizing::new(hex::encode([31; 32]).into_bytes()),
            )
            .unwrap();
        let mut registry = open(9001).unwrap();
        assert_eq!(registry.node_key(), node_key);
        assert_eq!(registry.pending_id().unwrap(), Some(id));
        assert_eq!(
            registry
                .prepare_node_registration(info.clone(), 100)
                .unwrap(),
            id
        );
        assert!(registry.prepare_node_registration(info, 101).is_err());
        assert_eq!(registry.pending_id().unwrap(), Some(id));
        drop(registry);
        assert!(open(9002).is_err());
        let journal: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.join("state.json")).unwrap()).unwrap();
        storage
            .delete(LocalStorageKeys::NativeWorkerKey(
                journal["key_name"].as_str().unwrap().into(),
            ))
            .unwrap();
        assert!(open(9001).is_err());
        let ring_directory = root.path().join("ring-worker");
        let open_ring = || {
            NativeVeraClient::open(
                HubClient::new("http://127.0.0.1:1"),
                ConsensusPublicKey::generator(),
                [7; 32],
                9001,
                &ring_directory,
                &storage,
            )
        };
        let mut client = open_ring().unwrap();
        let id = client
            .prepare_ring_participant_request(
                "11".repeat(32),
                RingParticipantCommand::Confirm("aabb".into()),
                100,
            )
            .unwrap();
        drop(client);
        let mut client = open_ring().unwrap();
        assert_eq!(client.pending_id().unwrap(), Some(id));
        assert_eq!(
            client
                .prepare_ring_participant_request(
                    "11".repeat(32),
                    RingParticipantCommand::Confirm("aabb".into()),
                    100
                )
                .unwrap(),
            id
        );
        assert!(client
            .prepare_ring_participant_request("11".repeat(32), RingParticipantCommand::Cancel, 100)
            .is_err());
    }

    #[test]
    fn ring_metadata_preserves_dkg_configuration_and_terminal_outcomes() {
        let key = SigningKey::from_slice(&[31; 32]).unwrap();
        let node = hex::encode(key.verifying_key().to_sec1_bytes());
        let second = SigningKey::from_slice(&[32; 32]).unwrap();
        let mut peers = vec![
            node.clone(),
            hex::encode(second.verifying_key().to_sec1_bytes()),
        ];
        peers.sort();
        let config = RingConfig {
            policy_id: "11".repeat(32),
            peer_node_keys: peers.clone(),
            threshold: 2,
            pss_interval: 90000,
            current_version: 0,
            nonce: [9; 32],
            trusted_auth_relay_dids: Some(vec![
                "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".into(),
            ]),
            reporting: hub_client::rings::ReportingConfig {
                kick_threshold: 7,
                ..Default::default()
            },
        };
        let creator = "did:key:creator".to_string();
        let mut record = RingRecord {
            id: config.id([7; 32], &creator).unwrap(),
            creator,
            deployment_root: [7; 32],
            config: config.clone(),
            settings: None,
            sequence: 2,
            state: RingState::Pending {
                public_key: Some("aabb".into()),
                confirmations: vec![node.clone()],
            },
            revision: serde_json::from_value(
                serde_json::json!({"seconds": 100, "block_height": 2}),
            )
            .unwrap(),
        };
        let status = ring_status(&record).unwrap();
        assert_eq!(status.confirmation_node_keys, Some(vec![node]));
        assert!(status.ring_pk.is_empty());
        let payload = RingPayload::try_from(ring_post(record.clone()).unwrap()).unwrap();
        assert_eq!(payload.peer_node_keys, peers);
        assert_eq!(payload.threshold, 2);
        assert_eq!(payload.pss_interval, 90000);
        assert_eq!(payload.reporting.kick_threshold, 7);
        assert_eq!(
            payload.trusted_auth_relay_dids,
            config.trusted_auth_relay_dids
        );
        assert_eq!(payload.policy_id, Some(config.policy_id));
        assert!(payload.new_peer_node_keys.is_none());
        assert!(payload.new_threshold.is_none());
        record.state = RingState::Active {
            public_key: "aabb".into(),
        };
        assert_eq!(
            RingPayload::try_from(ring_post(record.clone()).unwrap())
                .unwrap()
                .ring_pk,
            "aabb"
        );
        let mut settings = record.current_settings();
        settings.pss_interval = 100000;
        settings.reporting.kick_threshold = 8;
        settings.trusted_auth_relay_dids = Some(vec![]);
        settings.scheduled_upgrade = Some(hub_client::rings::ScheduledUpgrade {
            version: 1,
            activates_at: 700,
        });
        settings.pending_reshare = Some(hub_client::rings::ReshareTarget {
            peer_node_keys: peers.clone(),
            threshold: 1,
        });
        record.settings = Some(settings);
        record.sequence = 3;
        record.validate(&record.id).unwrap();
        let payload = RingPayload::try_from(ring_post(record.clone()).unwrap()).unwrap();
        assert_eq!(payload.peer_node_keys, peers);
        assert_eq!(payload.threshold, 2);
        assert_eq!(payload.new_peer_node_keys, Some(peers));
        assert_eq!(payload.new_threshold, Some(1));
        assert_eq!(payload.block_number_nonce, 3);
        assert_eq!(payload.pss_interval, 100000);
        assert_eq!(payload.reporting.kick_threshold, 8);
        assert_eq!(payload.trusted_auth_relay_dids, Some(vec![]));
        assert_eq!(payload.upgrade_info.current_version, 0);
        assert_eq!(payload.upgrade_info.next_version, Some(1));
        assert_eq!(payload.upgrade_info.activation_time, Some(700));
        use common::blockchain::orbis::{
            ring_reshare_finalize_sign_bytes, ring_reshare_sign_state_hash, RingReshareSignState,
        };
        let payload = RingPayload::try_from(ring_post(record.clone()).unwrap()).unwrap();
        assert_eq!(
            record.report_state_hash().unwrap(),
            crate::reporting::ring_state_sha256(&payload)
        );
        let mut state = RingReshareSignState {
            ring_pk: payload.ring_pk.clone(),
            peer_node_keys: payload.peer_node_keys,
            threshold: payload.threshold,
            new_peer_node_keys: payload.new_peer_node_keys.unwrap(),
            new_threshold: payload.new_threshold,
            block_number_nonce: payload.block_number_nonce,
            policy_id: payload.policy_id.unwrap(),
            allow_trusted_auth_relays: payload.trusted_auth_relay_dids.is_some(),
            trusted_auth_relay_dids: payload.trusted_auth_relay_dids.unwrap_or_default(),
        };
        let current = ring_reshare_sign_state_hash(&state);
        state.peer_node_keys = std::mem::take(&mut state.new_peer_node_keys);
        state.threshold = state.new_threshold.take().unwrap();
        let finalized = ring_reshare_sign_state_hash(&state);
        let orbis_bytes = ring_reshare_finalize_sign_bytes(
            &hub_client::rings::ring_deployment_label(record.deployment_root, 9001),
            &record.id,
            &payload.ring_pk,
            current.to_vec(),
            finalized.to_vec(),
            record.sequence,
        )
        .unwrap();
        assert_eq!(record.reshare_signing_bytes(9001).unwrap(), orbis_bytes);
        record.settings = None;
        record.state = RingState::Cancelled {
            by: record.creator.clone(),
        };
        assert!(matches!(
            ring_post(record.clone()),
            Err(crate::error::BulletinError::NotFound { .. })
        ));
        record.state = RingState::Conflict {
            first_key: "aabb".into(),
            conflicting_key: "ccdd".into(),
            by: record.config.peer_node_keys[0].clone(),
        };
        assert!(matches!(
            ring_status(&record),
            Err(crate::error::BulletinError::NotFound { .. })
        ));
    }
}

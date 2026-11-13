//! The native (Commonware / vera.rs) client: signing-key decoding, the
//! durable submission journal, transaction prepare/submit/confirm, and
//! certified reads. Shared by `authz::native` and `bulletin::native` — the
//! latter layers bulletin-trait-type conversions on top of this via its own
//! extension trait, since the wire shapes here are generic to native, not
//! bulletin-specific.

use std::path::Path;

use alloy_primitives::{Bytes, B256};
use local_storage::r#trait::{LocalStorage, LocalStorageKeys};
use vera_client::nodes::{
    encode_node_request, sign_node_request, NodeCommand, NodeRead, NodeRequest,
};
use vera_client::rings::{
    encode_ring_command, encode_ring_participant_request, encode_ring_reshare,
    sign_ring_participant_request, RingCommand, RingParticipantCommand, RingParticipantRequest,
    RingRead, RingRecord, RingReshareRequest, RingState, ThresholdScheme,
};
use vera_client::{
    ClientError, ExecutionReceipt, NativeWorker, Secp256k1SigningKey as SigningKey, VeraClient,
    VERA_ADDRESS,
};
use vera_domain::{ConsensusPublicKey, NativeTx};
use zeroize::Zeroizing;

/// Native service client backed by an encrypted worker key and durable
/// submission journal. Prepare, submit and confirm are separate so an
/// uncertain response never allocates a new request.
pub struct NativeVeraClient {
    pub client: VeraClient,
    pub trusted: ConsensusPublicKey,
    pub deployment_root: [u8; 32],
    pub authority: SigningKey,
    pub worker: NativeWorker,
}

/// Decode the hex signing key stored by node startup.
pub fn decode_node_signing_key(bytes: &[u8]) -> Result<SigningKey, ClientError> {
    let encoded = std::str::from_utf8(bytes)
        .map_err(|_| ClientError::Signing("invalid node signing key encoding".into()))?;
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
    /// Open the journal using the caller's encrypted store and node signing identity.
    /// The caller provisions the deployment root and consensus key independently of the endpoint.
    pub fn open(
        client: VeraClient,
        trusted: ConsensusPublicKey,
        deployment_root: [u8; 32],
        deployment_id: u64,
        directory: &Path,
        storage: &(impl LocalStorage + ?Sized),
    ) -> Result<Self, ClientError> {
        let bytes = storage
            .get_encrypted(LocalStorageKeys::NodeSigningKey)
            .map_err(|e| ClientError::Signing(e.to_string()))?
            .ok_or_else(|| ClientError::Signing("node signing key is missing".into()))?;
        let authority = decode_node_signing_key(&bytes)?;
        let worker = super::open_native_worker(storage, directory, deployment_root, deployment_id)?;
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

    pub fn prepare_call(&mut self, calldata: Bytes) -> Result<B256, ClientError> {
        let wire = self.worker.prepare(VERA_ADDRESS, calldata)?;
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
        vera_client::rings::ring_deployment_label(self.deployment_root, self.worker.deployment_id())
    }

    /// Verify authorization against the selected ring state before journaling it.
    pub fn prepare_ring_reshare(
        &mut self,
        record: &RingRecord,
        scheme: ThresholdScheme,
        signature: &[u8],
    ) -> Result<B256, ClientError> {
        if record.deployment_root != self.deployment_root {
            return Err(ClientError::Signing("reshare deployment mismatch".into()));
        }
        let message = record
            .reshare_signing_bytes(self.worker.deployment_id())
            .map_err(|e| ClientError::Signing(e.to_string()))?;
        let RingState::Active { keys } = &record.state else {
            return Err(ClientError::Signing("ring is not active".into()));
        };
        let public_key =
            hex::decode(&keys.public_key).map_err(|e| ClientError::Signing(e.to_string()))?;
        vera_crypto::threshold::verify(scheme, &public_key, &message, signature)
            .map_err(|e| ClientError::Signing(e.to_string()))?;
        self.prepare_call(encode_ring_reshare(&RingReshareRequest {
            deployment_root: self.deployment_root,
            deployment_id: self.worker.deployment_id(),
            ring_id: record.id.clone(),
            expected_sequence: record.sequence,
            scheme,
            signature: hex::encode(signature),
        })?)
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

    pub fn pending_call(&self) -> Result<Option<Bytes>, ClientError> {
        self.worker
            .pending()
            .map(|wire| {
                let request =
                    NativeTx::decode_wire(wire).map_err(|e| ClientError::Worker(e.to_string()))?;
                if request.target != VERA_ADDRESS {
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
}

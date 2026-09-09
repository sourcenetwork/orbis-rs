//! Bulletin operations over the durable native worker and certified reads.

use super::*;
use crate::{
    error::{BulletinError, Result},
    r#trait::{
        Bulletin, BulletinKind, BulletinWriteKind, RingCancellationPayload, RingFinalizationPayload,
    },
};
use async_trait::async_trait;
use hub_client::{create_scoped_bearer_token, DelegationScope, ExecutionReceipt};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

#[cfg(test)]
mod tests;

pub struct NativeBulletin {
    reader: HubClient,
    trusted: ConsensusPublicKey,
    writer: Mutex<NativeVeraClient>,
    namespace: String,
    minimum: AtomicU64,
    maximum_age: u64,
    timeout: Duration,
}

fn error(cause: impl std::fmt::Display) -> BulletinError {
    BulletinError::NativeError(cause.to_string())
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(error)
}

impl NativeBulletin {
    /// Readers remain available while one durable writer waits for finality.
    pub async fn connect(
        writer: NativeVeraClient,
        reader: HubClient,
        maximum_age: u64,
        timeout: Duration,
    ) -> Result<Self> {
        if maximum_age == 0 || timeout.is_zero() {
            return Err(error("invalid freshness bound or request timeout"));
        }
        let first = reader
            .read_finalized_revision(1, &writer.trusted)
            .await
            .map_err(error)?;
        if first
            .parent_hash
            .strip_prefix("0x")
            .unwrap_or(&first.parent_hash)
            != hex::encode(writer.deployment_root)
        {
            return Err(error(
                "consensus proof does not bind the configured deployment",
            ));
        }
        Ok(Self {
            namespace: writer.deployment_label(),
            trusted: writer.trusted,
            reader,
            writer: Mutex::new(writer),
            minimum: AtomicU64::new(1),
            maximum_age,
            timeout,
        })
    }

    fn observe(&self, height: u64, timestamp: u64) -> Result<()> {
        let now = now()?;
        if timestamp > now.saturating_add(15) || now.saturating_sub(timestamp) > self.maximum_age {
            return Err(error("bulletin evidence is stale or from the future"));
        }
        if height < self.minimum.fetch_max(height, Ordering::AcqRel) {
            return Err(error("bulletin revision regressed"));
        }
        Ok(())
    }

    async fn ring(&self, id: &str) -> Result<RingRecord> {
        let response = self
            .reader
            .read_threshold_ring(id, self.minimum.load(Ordering::Acquire), &self.trusted)
            .await
            .map_err(error)?;
        self.observe(response.revision, response.timestamp)?;
        response
            .record
            .ok_or_else(|| BulletinError::NotFound { id: id.into() })
    }

    async fn object(
        &self,
        kind: ObjectKind,
        id: &str,
    ) -> Result<Option<hub_client::threshold_objects::ObjectRecord>> {
        let response = self
            .reader
            .read_threshold_object(
                kind,
                id,
                self.minimum.load(Ordering::Acquire),
                &self.trusted,
            )
            .await
            .map_err(error)?;
        self.observe(response.revision, response.timestamp)?;
        Ok(response.record)
    }

    async fn completion(
        &self,
        writer: &NativeVeraClient,
    ) -> Result<Option<hub_client::ReceiptResponse>> {
        let Some(id) = writer.pending_id().map_err(error)? else {
            return Ok(None);
        };
        let mut sent = false;
        loop {
            if let Some(proof) = self
                .reader
                .read_receipt(id, &self.trusted)
                .await
                .map_err(error)?
            {
                return Ok(Some(proof));
            }
            if !sent {
                // A transport error can follow acceptance; only certified execution clears the journal.
                sent = writer.submit_pending().await.is_ok();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Advance the reserved sequence only after certifying its execution.
    async fn settle(&self, writer: &mut NativeVeraClient) -> Result<Option<ExecutionReceipt>> {
        self.completion(writer)
            .await?
            .map(|proof| {
                let receipt = writer
                    .worker
                    .acknowledge(&proof, &self.trusted)
                    .map_err(error)?;
                self.minimum
                    .fetch_max(proof.revision.height, Ordering::AcqRel);
                Ok(receipt)
            })
            .transpose()
    }

    /// Keep the exact request until the next distinct write, so a lost reply can be recovered.
    async fn finish_retained(&self, writer: &NativeVeraClient) -> Result<()> {
        let id = writer
            .pending_id()
            .map_err(error)?
            .ok_or_else(|| error("native bulletin command is missing"))?;
        let proof = self
            .completion(writer)
            .await?
            .ok_or_else(|| error("native bulletin completion is missing"))?;
        let success = proof.verify(id, &self.trusted).map_err(error)?.success();
        self.minimum
            .fetch_max(proof.revision.height, Ordering::AcqRel);
        if success {
            Ok(())
        } else {
            Err(error("native bulletin command was rejected"))
        }
    }

    async fn finish(&self, writer: &mut NativeVeraClient) -> Result<()> {
        match self.settle(writer).await? {
            Some(receipt) if receipt.success() => Ok(()),
            _ => Err(error("native bulletin command was rejected")),
        }
    }

    async fn post_inner(&self, kind: BulletinWriteKind, payload: &[u8]) -> Result<String> {
        if payload.len() > 512 << 10 {
            return Err(error("bulletin request exceeds byte limit"));
        }
        let mut writer = self.writer.lock().await;
        self.settle(&mut writer).await?;
        let expiry = now()?
            .checked_add(120)
            .ok_or_else(|| error("request expiry overflow"))?;
        let id = match kind {
            BulletinWriteKind::Finalize => {
                let request: RingFinalizationPayload =
                    serde_json::from_slice(payload).map_err(error)?;
                let ring = self.ring(&request.ring_id).await?;
                match &ring.state {
                    RingState::Active { public_key } if public_key == &request.ring_pk => {
                        return Ok(request.ring_id)
                    }
                    RingState::Pending {
                        public_key,
                        confirmations,
                    } if public_key.as_ref() == Some(&request.ring_pk)
                        && confirmations.contains(&writer.node_key()) =>
                    {
                        return Ok(request.ring_id)
                    }
                    _ => {}
                }
                writer
                    .prepare_ring_participant_request(
                        request.ring_id.clone(),
                        RingParticipantCommand::Confirm(request.ring_pk),
                        expiry,
                    )
                    .map_err(error)?;
                request.ring_id
            }
            BulletinWriteKind::CancelPendingRing => {
                let request: RingCancellationPayload =
                    serde_json::from_slice(payload).map_err(error)?;
                if matches!(
                    self.ring(&request.ring_id).await?.state,
                    RingState::Cancelled { .. }
                ) {
                    return Ok(request.ring_id);
                }
                writer
                    .prepare_ring_participant_request(
                        request.ring_id.clone(),
                        RingParticipantCommand::Cancel,
                        expiry,
                    )
                    .map_err(error)?;
                request.ring_id
            }
            BulletinWriteKind::NodeInfo => {
                let mut info: NodeInfo = serde_json::from_slice(payload).map_err(error)?;
                info.whitelisted_policy_ids.sort();
                info.whitelisted_ring_ids.sort();
                let id = writer.node_key();
                let current = self
                    .reader
                    .read_threshold_node(&id, self.minimum.load(Ordering::Acquire), &self.trusted)
                    .await
                    .map_err(error)?;
                self.observe(current.revision, current.timestamp)?;
                if let Some(record) = current.record {
                    if record.info.peer_id == info.peer_id
                        && record.info.controller_key == info.controller_key
                        && record.info.allowed_policy_ids == info.whitelisted_policy_ids
                        && record.info.allowed_ring_ids == info.whitelisted_ring_ids
                    {
                        return Ok(id);
                    }
                    return Err(error("node info already exists with different settings"));
                }
                writer
                    .prepare_node_registration(info, expiry)
                    .map_err(error)?;
                id
            }
            BulletinWriteKind::Document | BulletinWriteKind::KeyDerivation => {
                let object = if kind == BulletinWriteKind::Document {
                    ThresholdObject::Document(serde_json::from_slice(payload).map_err(error)?)
                } else {
                    ThresholdObject::KeyDerivation(serde_json::from_slice(payload).map_err(error)?)
                };
                object.validate().map_err(error)?;
                let id = object.id().map_err(error)?;
                if self.object(object.kind(), &id).await?.is_some() {
                    return Ok(id);
                }
                let token = create_scoped_bearer_token(
                    &writer.authority,
                    writer.worker.did(),
                    writer.worker.deployment_id(),
                    now()?,
                    expiry,
                    DelegationScope::StoreThresholdObject,
                )
                .map_err(error)?;
                writer
                    .prepare_call(encode_threshold_object(&object, &token).map_err(error)?)
                    .map_err(error)?;
                id
            }
        };
        self.finish(&mut writer).await?;
        Ok(id)
    }
}

#[async_trait]
impl Bulletin for NativeBulletin {
    async fn post(&self, kind: BulletinWriteKind, payload: Vec<u8>) -> Result<String> {
        tokio::time::timeout(self.timeout, self.post_inner(kind, &payload))
            .await
            .map_err(|_| {
                error("native bulletin deadline exceeded; any pending submission remains durable")
            })?
    }

    async fn update(&self, id: String, signature_scheme: String, signature: Vec<u8>) -> Result<()> {
        tokio::time::timeout(self.timeout, async {
            let mut writer = self.writer.lock().await;
            let scheme = serde_json::from_value(serde_json::Value::String(signature_scheme))
                .map_err(error)?;
            let signature = hex::encode(signature);
            if let Some(call) = writer.pending_call().map_err(error)? {
                if let Some(previous) =
                    hub_client::rings::decode_ring_reshare(&call).map_err(error)?
                {
                    if previous.ring_id == id
                        && previous.scheme == scheme
                        && previous.signature == signature
                    {
                        return self.finish_retained(&writer).await;
                    }
                }
            }
            self.settle(&mut writer).await?;
            let record = self.ring(&id).await?;
            writer
                .prepare_ring_reshare(id, record.sequence, scheme, signature)
                .map_err(error)?;
            self.finish_retained(&writer).await
        })
        .await
        .map_err(|_| {
            error("native reshare deadline exceeded; any pending submission remains durable")
        })?
    }

    async fn submit_report(&self, report: BulletinReportSubmission) -> Result<()> {
        tokio::time::timeout(self.timeout, async {
            if report.chain_id != self.namespace {
                return Err(error("report deployment mismatch"));
            }
            let call = encode_ring_report(&native_report(report)).map_err(error)?;
            let mut writer = self.writer.lock().await;
            if writer.pending_call().map_err(error)?.as_ref() == Some(&call) {
                return self.finish_retained(&writer).await;
            }
            self.settle(&mut writer).await?;
            writer.prepare_call(call).map_err(error)?;
            self.finish_retained(&writer).await
        })
        .await
        .map_err(|_| {
            error("native report deadline exceeded; any pending submission remains durable")
        })?
    }

    async fn read(&self, id: String, kind: BulletinKind) -> Result<BulletinPost> {
        match kind {
            BulletinKind::Ring => ring_post(self.ring(&id).await?),
            BulletinKind::Document | BulletinKind::KeyDerivation => {
                let kind = if kind == BulletinKind::Document {
                    ObjectKind::Document
                } else {
                    ObjectKind::KeyDerivation
                };
                object_post(
                    self.object(kind, &id)
                        .await?
                        .ok_or(BulletinError::NotFound { id })?,
                )
            }
            BulletinKind::NodeInfo => {
                let current = self
                    .reader
                    .read_threshold_node(&id, self.minimum.load(Ordering::Acquire), &self.trusted)
                    .await
                    .map_err(error)?;
                self.observe(current.revision, current.timestamp)?;
                let record = current
                    .record
                    .ok_or_else(|| BulletinError::NotFound { id: id.clone() })?;
                let info = NodeInfo {
                    peer_id: record.info.peer_id,
                    controller_key: record.info.controller_key,
                    whitelisted_policy_ids: record.info.allowed_policy_ids,
                    whitelisted_ring_ids: record.info.allowed_ring_ids,
                };
                Ok(BulletinPost {
                    id,
                    payload: info.try_into()?,
                })
            }
        }
    }

    async fn ring_finalization_status(&self, id: String) -> Result<RingFinalizationStatus> {
        ring_status(&self.ring(&id).await?)
    }
    fn chain_id(&self) -> String {
        self.namespace.clone()
    }
    fn ring_reshare_finalize_sign_bytes(
        &self,
        chain_id: &str,
        ring_id: &str,
        ring_pk: &str,
        current_ring_sha256: Vec<u8>,
        finalized_ring_sha256: Vec<u8>,
        sequence: u64,
    ) -> Result<Vec<u8>> {
        if chain_id != self.namespace {
            return Err(error("reshare deployment mismatch"));
        }
        common::blockchain::orbis::ring_reshare_finalize_sign_bytes(
            chain_id,
            ring_id,
            ring_pk,
            current_ring_sha256,
            finalized_ring_sha256,
            sequence,
        )
        .map_err(error)
    }
}

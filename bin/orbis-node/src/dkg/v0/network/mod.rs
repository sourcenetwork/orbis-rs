//! The sole network transport for DKG-backed ceremonies.
//!
//! Control messages and private shares use authenticated direct QUIC streams.
//! Public contributions are individually endpoint-signed, collected by the
//! canonical leader, and relayed in canonical batches over a transient Gossip
//! topic. Fresh DKG, refresh, and reshare all use this transport.

use async_trait::async_trait;
use bytes::Bytes;
use futures::{stream::FuturesUnordered, StreamExt};
use network::{Connection, Message, PeerId, ProtocolHandler, PubSubEvent, SignedPayload, Topic};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Weak};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout, Duration, Instant};

use crate::app_state::{AppState, DkgOfflineRelayReceipt};
use crate::constants::{
    DKG_FORWARDED_START_RESPONSE_GRACE, DKG_GOSSIP_ISOLATION_GRACE, DKG_MAX_REPAIR_BACKOFF,
    DKG_PREPARATION_RETRY_MAX_BACKOFF, DKG_PREPARATION_TIMEOUT, DKG_REPAIR_STALL_INTERVAL,
    DKG_TOPOLOGY_PROBE_INTERVAL, MAX_DKG_COMMITTEE_SIZE, PEER_RESPONSE_TIMEOUT,
    PSS_GRACE_PERIOD_SECS,
};
use crate::dkg::v0::coordinator::evidence::{
    commitments_prove_equivocation, handle_control_message_fault_evidence_relay,
    handle_invalid_commitment_evidence_relay, handle_invalid_share_evidence_relay,
    handle_leader_batch_mismatch_evidence_relay, handle_leader_equivocation_evidence_relay,
    handle_leader_public_fault_evidence_relay, handle_public_origin_fault_evidence_relay,
    now_unix_secs, queue_or_relay_control_message_fault, queue_or_relay_equivocation,
    queue_or_relay_leader_batch_mismatch, queue_or_relay_leader_equivocation,
    queue_or_relay_leader_public_fault, queue_or_relay_public_origin_fault,
    report_leader_prepare_fault_best_effort, sign_control_message, verify_commitment_evidence,
    verify_control_signature,
};
use crate::dkg::v0::coordinator::message_handlers::{
    drive_accepted_share, handle_commitment_audit_message, handle_commitment_hash_message,
    handle_commitment_message, handle_reshare_participant_set, handle_reshare_share_ack,
    handle_session_init, preflight_commitment_audit_message, preflight_commitment_hash_message,
    preflight_reshare_participant_set, prepare_commitment_message,
};
use crate::dkg::v0::coordinator::refresh_health_check::{handle_result, preflight_result};
use crate::dkg::v0::coordinator::reporting::{
    spawn_pss_offline_observations, PssOfflineObservationSeed,
};
use crate::dkg::v0::coordinator::types::{CoordinatorDkg, CoordinatorReportSigner};
use crate::dkg::v0::coordinator::DkgCoordinator;
use crate::dkg::v0::error::{DkgError, Result};
use crate::dkg::v0::helpers::{
    derive_fresh_dkg_session_id, derive_refresh_session_id, derive_reshare_session_id,
    ring_payload_matches_ring_key, validate_fresh_dkg_ring_payload,
};
use crate::dkg::v0::messages::{
    ControlSignature, SessionKind, SignedDkgCommitment, SignedDkgShare,
};
#[cfg(test)]
use crate::dkg::v0::session_state::CreateSessionOutcome;
use crate::dkg::v0::session_state::{
    DkgFailureStage, DkgPhase, FailedDkgSessionRecord, MessageProcessingClaim,
    MissingDkgParticipant, PublicBatchRecordOutcome, PublicContributionRecordOutcome,
    PublicRepairClaimOutcome, TopicTaskDisposition, TopologyAckRecordOutcome,
    TransportActivationOutcome, TransportBeginOutcome, TransportConfigureOutcome,
};
use crate::dkg::v0::transport::{
    self, AttemptId, AttemptKey, CeremonyConfig, CeremonyId, CommitteeConfig, CommitteeScope,
    DkgControlMessage, DkgPrivateMessage, DkgPublicContribution, DkgPublicMessage,
    DkgPublicPayload, MessageId, ParticipantRef, PhaseManifest, PrepareSession, PssOfflineStage,
    PublicPhase, PUBLIC_CONTRIBUTION_SIGNING_DOMAIN,
};
use crate::helpers::auth::current_unix_time;
use crate::helpers::identity::{extract_node_part, is_self_peer_id, validate_peer_id};
use crate::helpers::node_routes::{
    canonical_node_id_assignments_from_node_keys, peer_ids_from_routes, resolve_node_routes,
    validate_node_route_bindings, NodeRoute,
};
use crate::helpers::protocol_version::read_ring_for_route;
#[cfg(test)]
use crate::helpers::test_helpers::{
    create_test_app_state_default, create_test_app_state_with_bulletin, TEST_FRESH_DKG_RING_ID,
};
use crate::metrics::{DkgCeremonyKind, PrivatePairMetricsGuard};
use crate::reporting::v0::types::{
    ControlMessageArtifact, DkgControlMessageFaultKind, DkgLeaderPublicFaultKind,
    DkgPublicOriginFaultKind,
};
use crate::ring_state::RingShareBundle;
#[cfg(test)]
use bulletin::dummy::DummyBulletin;
use bulletin::r#trait::RingPayload;
use crypto::SignImpl;

mod ceremony_start;
mod common;
mod control_client;
mod control_handler;
mod evidence_relay;
mod fault_report;
mod gossip_listener;
mod prepare;
mod prepare_participant;
mod private;
mod pss_offline;
mod public_batch;
mod public_contribution;
mod public_publish;
mod public_repair;

#[cfg(test)]
mod stability_tests;

// Internal cross-submodule glue: every submodule item shared across a module
// boundary is `pub(super)`; these globs flatten them so a sibling's `use super::*`
// resolves them (and they remain reachable as `crate::dkg::v0::network::<item>`).
#[allow(unused_imports)]
use self::{
    ceremony_start::*, common::*, control_client::*, control_handler::*, evidence_relay::*,
    fault_report::*, gossip_listener::*, prepare::*, prepare_participant::*, private::*,
    pss_offline::*, public_batch::*, public_contribution::*, public_publish::*, public_repair::*,
};

pub use ceremony_start::{fetch_dkg_session_status, start_fresh};
pub use control_handler::DkgControlHandler;
pub use private::DkgPrivateHandler;

pub(crate) use ceremony_start::{
    start_refresh, start_reshare, RefreshStartOutcome, ReshareStartOutcome,
};
// Only `unsafe_testing` drives the leader broadcast path directly; gating the
// re-export keeps it out of non-`unsafe-testing` builds without an unused import.
#[cfg(feature = "unsafe-testing")]
pub(crate) use ceremony_start::coordinate_refresh_as_claimed_leader;
pub(crate) use evidence_relay::{
    relay_control_message_fault_evidence, relay_invalid_commitment_evidence,
    relay_invalid_share_evidence, relay_leader_batch_mismatch_evidence,
    relay_leader_equivocation_evidence, relay_leader_public_fault_evidence,
    relay_pss_offline_candidates, relay_public_origin_fault_evidence, send_reshare_share_ack,
};
pub(crate) use prepare::broadcast_attempt_abort;
pub(crate) use private::exchange_private_shares;
pub(crate) use pss_offline::{spawn_pss_offline_for_attempt, PeerDeliveryFailure};
pub(crate) use public_contribution::contribution_ids;
pub(crate) use public_publish::submit_public_contribution;

#[cfg(test)]
pub(crate) use control_handler::handle_control_for_test;
#[cfg(test)]
pub(crate) use fault_report::{
    queue_public_commitment_equivocation_for_test, record_control_ack_best_effort_for_test,
};
#[cfg(test)]
pub(crate) use public_contribution::record_public_contribution_at_leader_for_test;

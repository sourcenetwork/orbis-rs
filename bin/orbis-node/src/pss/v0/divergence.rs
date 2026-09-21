//! Multi-ring protocol-version divergence detection and warning.
//!
//! Protocol versions are controlled per-ring (see `UPGRADING.md`): every ring
//! schedules its own upgrades independently, so a node that sits in several
//! rings can be forced to run one binary that serves several versions at once
//! and to migrate local storage per-ring. This module classifies that
//! situation and throttles/de-duplicates the operator-facing log line for it.

use crate::app_state::AppState;
use crate::constants::PROTOCOL_DIVERGENCE_CHECK_INTERVAL_SECS;
use crate::helpers::auth::current_unix_time;
use crate::helpers::protocol_version::{effective_protocol_version, installed_versions_label};
use crate::ring_state::RingIndexEntry;
use bulletin::r#trait::{BulletinKind, RingPayload};
use crypto::r#trait::Dkg;
use crypto::{GroupAffine, PolynomialCommitmentImpl, PubPolyImpl, ScalarField as Fr};
use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, OnceLock};

/// Throttling + de-duplication state for [`warn_on_protocol_version_divergence`].
pub(super) struct DivergenceReportState {
    /// Unix time of the last check that ran (i.e. was not skipped by the
    /// [`PROTOCOL_DIVERGENCE_CHECK_INTERVAL_SECS`] throttle).
    pub(super) last_check_secs: u64,
    /// Fingerprint of the last `(ring_id, effective_version, pending_version)`
    /// list that was actually logged. `None` means nothing has been logged yet;
    /// it is also reset to `None` whenever the node is not in a multi-ring
    /// situation, so a later re-entry re-logs.
    pub(super) last_fingerprint: Option<u64>,
}

static DIVERGENCE_REPORT: OnceLock<Mutex<DivergenceReportState>> = OnceLock::new();

fn divergence_report_state() -> &'static Mutex<DivergenceReportState> {
    DIVERGENCE_REPORT.get_or_init(|| {
        Mutex::new(DivergenceReportState {
            last_check_secs: 0,
            last_fingerprint: None,
        })
    })
}

/// Outcome of classifying this node's multi-ring protocol-version situation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DivergenceReport {
    /// Fewer than two member rings — nothing to report.
    Silent,
    /// Two or more member rings that share a single `(effective, pending)`
    /// protocol trajectory — aligned, even when that shared trajectory carries a
    /// scheduled upgrade that has not activated yet.
    MultiRingSingleVersion,
    /// Two or more member rings whose `(effective, pending)` trajectories are not
    /// all identical: they sit on different effective versions, or a
    /// scheduled-but-not-yet-active upgrade applies to some rings and not others.
    Divergent,
}

/// Distinct protocol versions across `member_rings`, effective plus any pending.
/// Feeds the human-readable `versions=` log field only; classification uses
/// [`divergence_trajectories`].
fn divergence_versions(member_rings: &[(String, u64, Option<u64>)]) -> BTreeSet<u64> {
    member_rings
        .iter()
        .flat_map(|(_, effective, pending)| std::iter::once(*effective).chain(*pending))
        .collect()
}

/// Distinct `(effective_version, pending_next_version)` trajectories across
/// `member_rings`. Rings sharing an identical trajectory — same effective
/// version and the same (or no) scheduled upgrade — are aligned, not divergent,
/// even when that shared trajectory has a pending version bump.
fn divergence_trajectories(
    member_rings: &[(String, u64, Option<u64>)],
) -> BTreeSet<(u64, Option<u64>)> {
    member_rings
        .iter()
        .map(|(_, effective, pending)| (*effective, *pending))
        .collect()
}

/// Classify a caller-built list of member rings. Order-independent.
pub(super) fn classify_divergence(member_rings: &[(String, u64, Option<u64>)]) -> DivergenceReport {
    if member_rings.len() < 2 {
        return DivergenceReport::Silent;
    }
    if divergence_trajectories(member_rings).len() > 1 {
        DivergenceReport::Divergent
    } else {
        DivergenceReport::MultiRingSingleVersion
    }
}

fn divergence_fingerprint(member_rings: &[(String, u64, Option<u64>)]) -> u64 {
    let mut hasher = DefaultHasher::new();
    member_rings.hash(&mut hasher);
    hasher.finish()
}

/// Extract `(ring_id, effective_version, pending_next_version)` for every ring in
/// `payloads` that `node_key` is a current, finalized member of. Rings with a
/// malformed `upgrade_info` are skipped. A `next_version` is reported as pending
/// only while its `activation_time` is still in the future. Result is sorted so
/// the fingerprint is stable across ticks.
pub(super) fn member_ring_versions(
    payloads: &[(String, RingPayload)],
    node_key: &str,
    now_secs: u64,
) -> Vec<(String, u64, Option<u64>)> {
    let mut member_rings: Vec<(String, u64, Option<u64>)> = Vec::new();
    for (ring_id, ring_payload) in payloads {
        let is_current_member = ring_payload
            .peer_node_keys
            .iter()
            .any(|candidate| candidate == node_key);
        if ring_payload.ring_pk.is_empty() || !is_current_member {
            continue;
        }

        let effective = match effective_protocol_version(&ring_payload.upgrade_info, now_secs) {
            Ok(version) => version,
            Err(error) => {
                tracing::debug!(ring_id = %ring_id, %error, "PSS: divergence check: malformed upgrade_info");
                continue;
            }
        };
        let pending_next = match (
            ring_payload.upgrade_info.next_version,
            ring_payload.upgrade_info.activation_time,
        ) {
            (Some(next), Some(activation)) if activation > now_secs && next != effective => {
                Some(next)
            }
            _ => None,
        };
        member_rings.push((ring_id.clone(), effective, pending_next));
    }
    member_rings.sort();
    member_rings
}

/// Fold classify + fingerprint + change-detection into one step, updating `state`.
///
/// Assumes the caller has already applied the
/// [`PROTOCOL_DIVERGENCE_CHECK_INTERVAL_SECS`] throttle; always advances
/// `last_check_secs`. Returns `Some(report)` when a fresh INFO/WARN line should be
/// emitted now, and `None` when the situation is `Silent` or unchanged since the
/// last logged line.
pub(super) fn divergence_log_decision(
    now_secs: u64,
    member_rings: &[(String, u64, Option<u64>)],
    state: &mut DivergenceReportState,
) -> Option<DivergenceReport> {
    state.last_check_secs = now_secs;

    let report = classify_divergence(member_rings);
    if report == DivergenceReport::Silent {
        state.last_fingerprint = None;
        return None;
    }

    let fingerprint = divergence_fingerprint(member_rings);
    if state.last_fingerprint == Some(fingerprint) {
        return None;
    }
    state.last_fingerprint = Some(fingerprint);
    Some(report)
}

/// Warn the operator when this node is a current member of more than one ring.
///
/// Protocol versions are controlled per-ring (see `UPGRADING.md`): every ring
/// schedules its own upgrades independently, so a node that sits in several rings
/// can be forced to run one binary that serves several versions at once and to
/// migrate local storage per-ring. This surfaces that situation in the node log.
///
/// Runs at most once per [`PROTOCOL_DIVERGENCE_CHECK_INTERVAL_SECS`] and logs at
/// INFO/WARN only when the observed set of `(ring, version)` pairs changes. Never
/// returns an error — a divergence warning must not disrupt the PSS tick.
pub(super) async fn warn_on_protocol_version_divergence<D>(
    app_state: &Arc<AppState<D>>,
    ring_index: &[RingIndexEntry],
) where
    D: Dkg<
            ShareValue = Fr,
            PublicKey = GroupAffine,
            PolynomialCommitment = PolynomialCommitmentImpl,
            PubPoly = PubPolyImpl,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    let now_secs = match current_unix_time() {
        Ok(secs) => secs,
        Err(error) => {
            tracing::debug!(%error, "PSS: divergence check skipped (system clock)");
            return;
        }
    };

    // Cheap pre-read gate: skip the per-ring bulletin reads entirely if the check
    // ran recently. Reserve the interval — advance `last_check_secs` while still
    // holding the lock — so overlapping scheduler tasks (e.g. several in-process
    // nodes in a test sharing this process-global state) cannot both pass the
    // gate and each run the bulletin read batch. The lock is never held across an
    // `.await`. `divergence_log_decision` re-stamps `last_check_secs` with the
    // same `now_secs` after the reads; that is redundant here but keeps that
    // function self-contained for its own unit tests.
    {
        let mut state = divergence_report_state()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if now_secs.saturating_sub(state.last_check_secs) < PROTOCOL_DIVERGENCE_CHECK_INTERVAL_SECS
        {
            return;
        }
        state.last_check_secs = now_secs;
    }

    let mut payloads: Vec<(String, RingPayload)> = Vec::with_capacity(ring_index.len());
    for entry in ring_index {
        let post_id = &entry.bulletin_post_id;
        match app_state
            .bulletin
            .read(post_id.clone(), BulletinKind::Ring)
            .await
            .map_err(|error| error.to_string())
            .and_then(|post| RingPayload::try_from(post).map_err(|error| error.to_string()))
        {
            Ok(payload) => payloads.push((post_id.clone(), payload)),
            Err(error) => {
                tracing::debug!(ring_id = %post_id, %error, "PSS: divergence check: ring read failed");
            }
        }
    }

    let member_rings = member_ring_versions(&payloads, &app_state.node_key, now_secs);

    let decision = {
        let mut state = divergence_report_state()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        divergence_log_decision(now_secs, &member_rings, &mut state)
    };
    let Some(report) = decision else {
        return;
    };

    let rings_label = member_rings
        .iter()
        .map(|(ring_id, effective, pending)| match pending {
            Some(next) => format!("{ring_id}=v{effective}(pending v{next})"),
            None => format!("{ring_id}=v{effective}"),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let versions_label = divergence_versions(&member_rings)
        .iter()
        .map(|version| format!("v{version}"))
        .collect::<Vec<_>>()
        .join(", ");

    match report {
        DivergenceReport::Divergent => tracing::warn!(
            ring_count = member_rings.len(),
            versions = %versions_label,
            installed_versions = %installed_versions_label(),
            rings = %rings_label,
            "This node is a member of multiple rings whose protocol versions differ. \
             Protocol versions are set per-ring and each ring upgrades independently, so \
             this binary must keep serving every version its rings use, and a version gap \
             may require per-ring local storage migration. See UPGRADING.md."
        ),
        DivergenceReport::MultiRingSingleVersion => tracing::info!(
            ring_count = member_rings.len(),
            versions = %versions_label,
            rings = %rings_label,
            "This node is a member of multiple rings. Protocol versions are set per-ring \
             and each ring upgrades independently: a future upgrade to any one ring can \
             force this node to run several versions at once and to migrate local storage \
             per-ring. See UPGRADING.md."
        ),
        DivergenceReport::Silent => {}
    }
}

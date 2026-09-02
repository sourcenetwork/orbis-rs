#[allow(unused_imports)]
use {super::super::*, super::support::*};

#[test]
fn private_busy_retries_honor_hint_and_desynchronize_pairs() {
    let backoff = Duration::from_secs(1);
    let busy_hint = Duration::from_millis(250);
    let remaining = Duration::from_secs(30);
    let first = private_retry_delay(MessageId([1; 32]), 0, backoff, Some(busy_hint), remaining);
    let second_pair =
        private_retry_delay(MessageId([2; 32]), 0, backoff, Some(busy_hint), remaining);
    let next_attempt =
        private_retry_delay(MessageId([1; 32]), 1, backoff, Some(busy_hint), remaining);

    assert!(first >= busy_hint);
    assert!(first <= busy_hint + backoff);
    assert_ne!(first, second_pair);
    assert_ne!(first, next_attempt);
}

#[test]
fn private_retry_delay_never_exceeds_deadline_or_global_cap() {
    let remaining = Duration::from_millis(17);
    assert_eq!(
        private_retry_delay(
            MessageId([3; 32]),
            99,
            DKG_MAX_REPAIR_BACKOFF,
            Some(Duration::from_secs(300)),
            remaining,
        ),
        remaining
    );
}

// =========================================================================
// GossipNeighborTracker
// =========================================================================

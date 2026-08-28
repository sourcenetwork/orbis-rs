#[allow(unused_imports)]
use {super::super::*, super::support::*};

#[test]
fn neighbor_churn_only_schedules_rejoin_after_sustained_full_isolation() {
    let peer_a = PeerId::from_bytes(b"peer-a");
    let peer_b = PeerId::from_bytes(b"peer-b");
    let now = Instant::now();
    let mut tracker = GossipNeighborTracker::default();

    tracker.neighbor_up(&peer_a);
    tracker.neighbor_up(&peer_b);
    assert!(tracker.neighbor_down(&peer_a, now));
    assert_eq!(tracker.neighbor_count(), 1);
    assert_eq!(tracker.isolation_deadline(), None);

    assert!(tracker.neighbor_down(&peer_b, now));
    assert!(tracker.is_isolated());
    assert_eq!(
        tracker.isolation_deadline(),
        Some(now + DKG_GOSSIP_ISOLATION_GRACE)
    );

    tracker.neighbor_up(&peer_a);
    assert!(!tracker.is_isolated());
    assert_eq!(tracker.isolation_deadline(), None);
}

#[test]
fn rejoin_reset_does_not_treat_initial_empty_topic_as_isolated() {
    let peer = PeerId::from_bytes(b"peer");
    let mut tracker = GossipNeighborTracker::default();
    tracker.neighbor_up(&peer);
    tracker.neighbor_down(&peer, Instant::now());
    assert!(tracker.is_isolated());

    tracker.reset_after_rejoin();
    assert!(!tracker.is_isolated());
    assert_eq!(tracker.neighbor_count(), 0);
    assert_eq!(tracker.isolation_deadline(), None);
}

#[test]
fn gossip_neighbor_tracker_is_not_isolated_before_any_neighbor() {
    let mut tracker = GossipNeighborTracker::default();
    assert!(!tracker.is_isolated());
    assert_eq!(tracker.neighbor_count(), 0);
    // A down event for a peer that was never a neighbor is a no-op and
    // must not arm isolation before any neighbor was ever seen.
    assert!(!tracker.neighbor_down(&tracker_peer(1), Instant::now()));
    assert!(!tracker.is_isolated());
    assert!(tracker.isolation_deadline().is_none());
}

#[test]
fn gossip_neighbor_tracker_arms_isolation_only_after_last_neighbor_leaves() {
    let mut tracker = GossipNeighborTracker::default();
    let peer_a = tracker_peer(1);
    let peer_b = tracker_peer(2);

    tracker.neighbor_up(&peer_a);
    tracker.neighbor_up(&peer_b);
    assert_eq!(tracker.neighbor_count(), 2);
    assert!(!tracker.is_isolated());

    // One neighbor leaving while another remains must not arm isolation.
    assert!(tracker.neighbor_down(&peer_a, Instant::now()));
    assert_eq!(tracker.neighbor_count(), 1);
    assert!(!tracker.is_isolated());
    assert!(tracker.isolation_deadline().is_none());

    // The last neighbor leaving arms isolation with a grace deadline.
    let now = Instant::now();
    assert!(tracker.neighbor_down(&peer_b, now));
    assert_eq!(tracker.neighbor_count(), 0);
    assert!(tracker.is_isolated());
    let deadline = tracker
        .isolation_deadline()
        .expect("isolation deadline must be armed once every neighbor is gone");
    assert!(deadline >= now);
}

#[test]
fn gossip_neighbor_tracker_rejoin_clears_isolation() {
    let mut tracker = GossipNeighborTracker::default();
    let peer_a = tracker_peer(1);

    tracker.neighbor_up(&peer_a);
    tracker.neighbor_down(&peer_a, Instant::now());
    assert!(tracker.is_isolated());
    assert!(tracker.isolation_deadline().is_some());

    // A fresh neighbor coming up must clear isolation immediately.
    tracker.neighbor_up(&tracker_peer(2));
    assert!(!tracker.is_isolated());
    assert!(tracker.isolation_deadline().is_none());
}

#[test]
fn gossip_neighbor_tracker_reset_after_rejoin_returns_to_initial_state() {
    let mut tracker = GossipNeighborTracker::default();
    let peer_a = tracker_peer(1);
    tracker.neighbor_up(&peer_a);
    tracker.neighbor_down(&peer_a, Instant::now());
    assert!(tracker.is_isolated());

    tracker.reset_after_rejoin();
    assert!(!tracker.is_isolated());
    assert_eq!(tracker.neighbor_count(), 0);
    assert!(tracker.isolation_deadline().is_none());
    // A subsequent down-event on an unrelated peer must not arm
    // isolation, exactly like the pre-any-neighbor state, since
    // `ever_had_neighbor` was cleared by the reset.
    assert!(!tracker.neighbor_down(&tracker_peer(3), Instant::now()));
    assert!(!tracker.is_isolated());
}

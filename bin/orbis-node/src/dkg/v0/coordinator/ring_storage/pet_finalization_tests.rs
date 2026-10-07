use super::*;
use bulletin::error::BulletinError;
use bulletin::r#trait::{BulletinPost, BulletinReportSubmission, RingFinalizationStatus};
use std::sync::atomic::{AtomicUsize, Ordering};

struct ReadbackBulletin {
    ring: RingPayload,
    lost_post_reply: bool,
    read_failures: usize,
    stalled_read: bool,
    pending_statuses: usize,
    posts: AtomicUsize,
    reads: AtomicUsize,
    status_reads: AtomicUsize,
}

impl Default for ReadbackBulletin {
    fn default() -> Self {
        Self {
            ring: RingPayload {
                ring_pk: "pk".into(),
                requires_pet: true,
                pet_pk: Some("pet-pk".into()),
                ..Default::default()
            },
            lost_post_reply: false,
            read_failures: 0,
            stalled_read: false,
            pending_statuses: 0,
            posts: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            status_reads: AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl Bulletin for ReadbackBulletin {
    async fn post(
        &self,
        kind: BulletinWriteKind,
        _payload: Vec<u8>,
    ) -> bulletin::error::Result<String> {
        assert_eq!(kind, BulletinWriteKind::Finalize);
        self.posts.fetch_add(1, Ordering::SeqCst);
        if self.lost_post_reply {
            Err(BulletinError::ChainError(
                "finalization reply was lost".into(),
            ))
        } else {
            Ok("ring".into())
        }
    }

    async fn read(&self, id: String, kind: BulletinKind) -> bulletin::error::Result<BulletinPost> {
        assert!(matches!(kind, BulletinKind::Ring));
        let attempt = self.reads.fetch_add(1, Ordering::SeqCst);
        if self.stalled_read {
            std::future::pending::<()>().await;
        }
        if attempt < self.read_failures {
            return Err(BulletinError::ChainError("temporary read failure".into()));
        }
        Ok(BulletinPost {
            id,
            payload: serde_json::to_vec(&self.ring).unwrap(),
        })
    }

    async fn ring_finalization_status(
        &self,
        _id: String,
    ) -> bulletin::error::Result<RingFinalizationStatus> {
        let read = self.status_reads.fetch_add(1, Ordering::SeqCst);
        Ok(RingFinalizationStatus {
            ring_pk: if read < self.pending_statuses {
                String::new()
            } else {
                "pk".into()
            },
            confirmation_node_keys: None,
        })
    }

    async fn update(
        &self,
        _id: String,
        _signature_scheme: String,
        _signature: Vec<u8>,
    ) -> bulletin::error::Result<()> {
        unreachable!()
    }

    async fn submit_report(
        &self,
        _submission: BulletinReportSubmission,
    ) -> bulletin::error::Result<()> {
        unreachable!()
    }

    async fn accepted_report_session(
        &self,
        _ring_id: &str,
        _report_type: &str,
        _origin_protocol: &str,
        _accused_node_key: &str,
        _session_id: &str,
    ) -> bulletin::error::Result<bool> {
        unreachable!()
    }

    fn chain_id(&self) -> String {
        unreachable!()
    }

    fn ring_reshare_finalize_sign_bytes(
        &self,
        _chain_id: &str,
        _ring_id: &str,
        _ring_pk: &str,
        _current_ring_sha256: Vec<u8>,
        _finalized_ring_sha256: Vec<u8>,
        _block_number_nonce: u64,
    ) -> bulletin::error::Result<Vec<u8>> {
        unreachable!()
    }
}

async fn finalize(bulletin: &ReadbackBulletin, pet_pk: Option<&str>) -> Result<usize> {
    let payload = RingFinalizationPayload {
        ring_id: "ring".into(),
        ring_pk: "pk".into(),
        pet_pk: pet_pk.map(str::to_string),
    };
    post_and_verify_fresh_ring_finalization(
        bulletin,
        "node-key",
        "ring",
        "pk",
        pet_pk,
        payload.try_into().unwrap(),
    )
    .await
}

#[tokio::test]
async fn matching_pair_recovers_a_lost_finalization_reply() {
    let bulletin = ReadbackBulletin {
        lost_post_reply: true,
        ..Default::default()
    };
    assert_eq!(finalize(&bulletin, Some("pet-pk")).await.unwrap(), 0);
    assert_eq!(bulletin.posts.load(Ordering::SeqCst), 1);
    assert_eq!(bulletin.reads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn matching_main_key_does_not_acknowledge_a_different_pet_state() {
    for (main_pk, requires_pet, pet_pk) in [
        ("pk", true, Some("other-pet-pk")),
        ("pk", true, None),
        ("pk", false, Some("pet-pk")),
        ("other-main-pk", true, Some("pet-pk")),
    ] {
        let bulletin = ReadbackBulletin {
            ring: RingPayload {
                ring_pk: main_pk.into(),
                requires_pet,
                pet_pk: pet_pk.map(str::to_string),
                ..Default::default()
            },
            lost_post_reply: true,
            ..Default::default()
        };
        let error = finalize(&bulletin, Some("pet-pk")).await.unwrap_err();
        assert!(error.to_string().contains("expected main and PET key pair"));
        assert_eq!(bulletin.posts.load(Ordering::SeqCst), 1);
        assert_eq!(bulletin.reads.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn transient_pet_read_failure_uses_the_existing_retry_path() {
    let bulletin = ReadbackBulletin {
        read_failures: 1,
        ..Default::default()
    };
    assert_eq!(finalize(&bulletin, Some("pet-pk")).await.unwrap(), 0);
    assert_eq!(bulletin.posts.load(Ordering::SeqCst), 1);
    assert_eq!(bulletin.reads.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn persistent_pet_read_failure_stops_at_the_existing_retry_limit() {
    let bulletin = ReadbackBulletin {
        read_failures: usize::MAX,
        ..Default::default()
    };
    let error = finalize(&bulletin, Some("pet-pk")).await.unwrap_err();
    assert!(error.to_string().contains("temporary read failure"));
    assert_eq!(bulletin.posts.load(Ordering::SeqCst), 1);
    assert_eq!(
        bulletin.reads.load(Ordering::SeqCst),
        FINALIZATION_PERSISTENCE_RETRY_LIMIT + 1
    );
}

#[tokio::test(start_paused = true)]
async fn stalled_pet_read_respects_the_existing_completion_deadline() {
    let bulletin = ReadbackBulletin {
        stalled_read: true,
        ..Default::default()
    };
    let error = finalize(&bulletin, Some("pet-pk")).await.unwrap_err();
    assert!(error
        .to_string()
        .contains("Timed out verifying finalized PET key"));
    assert_eq!(bulletin.reads.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn pet_waits_for_finalization_without_confirmation_counts() {
    let bulletin = ReadbackBulletin {
        pending_statuses: 1,
        ..Default::default()
    };
    assert_eq!(finalize(&bulletin, Some("pet-pk")).await.unwrap(), 0);
    assert_eq!(bulletin.status_reads.load(Ordering::SeqCst), 2);
    assert_eq!(bulletin.reads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ordinary_finalization_does_not_read_the_full_ring() {
    let bulletin = ReadbackBulletin {
        lost_post_reply: true,
        read_failures: usize::MAX,
        ..Default::default()
    };
    assert_eq!(finalize(&bulletin, None).await.unwrap(), 0);
    assert_eq!(bulletin.posts.load(Ordering::SeqCst), 1);
    assert_eq!(bulletin.reads.load(Ordering::SeqCst), 0);
}

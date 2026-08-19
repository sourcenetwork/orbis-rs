//! Test fixtures shared by `dkg.rs`, `refresh.rs`, and `reshare.rs` — all three
//! previously carried identical copies of this type and helper.

use crate::dkg::v0::{
    coordinator::{message_handlers::handle_session_init, DkgCoordinator},
    error::Result,
    messages::SessionKind,
    transport::AttemptKey,
};
use crypto::DkgImpl;
use network::PeerId;

#[derive(Clone)]
pub(super) struct TestSessionInit {
    pub session_id: u128,
    pub threshold: u32,
    pub total_participants: u32,
    pub peer_ids: Vec<String>,
    pub peer_node_keys: Vec<String>,
    pub node_id_assignments: std::collections::HashMap<String, u32>,
    pub token_string: String,
    pub kind: SessionKind,
    pub pss_interval: u64,
    pub policy_id: Option<String>,
    pub ring_id: String,
}

pub(super) async fn invoke_session_init(
    coordinator: &DkgCoordinator<DkgImpl>,
    init: TestSessionInit,
    sender: &PeerId,
) -> Result<()> {
    handle_session_init(
        coordinator,
        AttemptKey::test(init.session_id),
        init.threshold,
        init.total_participants,
        &init.peer_ids,
        &init.peer_node_keys,
        &init.node_id_assignments,
        &init.token_string,
        &init.kind,
        init.pss_interval,
        init.policy_id,
        init.ring_id,
        sender,
        None,
    )
    .await
}

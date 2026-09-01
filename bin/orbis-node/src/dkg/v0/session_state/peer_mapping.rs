use super::*;

impl<D: Dkg + 'static> SessionStateManager<D> {
    /// Set node_id to peer_id mappings for efficient routing
    #[cfg(test)]
    pub async fn set_node_peer_mappings(
        &self,
        session_id: &u128,
        node_id_to_peer_id: HashMap<u32, String>,
    ) {
        let (node_to_peer, peer_to_node) = bidirectional_node_peer_maps(node_id_to_peer_id);
        self.with_state_mut(session_id, |state| {
            state.routing.node_id_to_peer_id = node_to_peer;
            state.routing.peer_id_to_node_id = peer_to_node;
        })
        .await;
    }

    /// Get peer_id for a node_id
    pub async fn get_peer_id_for_node(&self, session_id: &u128, node_id: u32) -> Option<String> {
        self.with_state(session_id, |s| {
            s.routing.node_id_to_peer_id.get(&node_id).cloned()
        })
        .await
        .flatten()
    }

    pub(crate) async fn peer_id_for_participant(
        &self,
        session_id: &u128,
        participant: ParticipantRef,
    ) -> Option<String> {
        self.with_state(session_id, |state| match participant.scope {
            CommitteeScope::Current => state
                .routing
                .node_id_to_peer_id
                .get(&participant.node_id)
                .cloned(),
            CommitteeScope::Next => state
                .routing
                .reshare_new_node_id_to_peer_id
                .get(&participant.node_id)
                .cloned(),
        })
        .await
        .flatten()
    }
}

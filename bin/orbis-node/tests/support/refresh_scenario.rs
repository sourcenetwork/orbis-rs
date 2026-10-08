//! Shared PSS-refresh continuation contract.
//!
//! Each backend owns only the mechanism for causing or observing its local
//! share rotation. The common scenario owns the externally-visible promise:
//! objects and derivations created before refresh must continue to work with
//! the same certified ring public key.

use super::{pet_dkg_contract::Keys, pre_scenario, sign_scenario};

pub(super) trait Backend: sign_scenario::Backend {
    /// Rotate every member's local share and assert that the backend's
    /// certified ring record/public identity did not change.
    async fn rotate_local_shares(
        &mut self,
        keys: &Keys,
        baseline: &<Self as super::pet_dkg_contract::Backend>::LocalState,
    );
}

pub(super) async fn run<B: Backend>(
    backend: &mut B,
    keys: &Keys,
    baseline: &<B as super::pet_dkg_contract::Backend>::LocalState,
    pre: &pre_scenario::Outcome,
    sign: &sign_scenario::Outcome,
) {
    backend.rotate_local_shares(keys, baseline).await;
    pre_scenario::verify_existing(backend, keys, pre).await;
    sign_scenario::verify_existing(backend, keys, sign).await;
}

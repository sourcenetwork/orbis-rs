//! Shared committee-reshare continuation contract.

use super::{pet_dkg_contract::Keys, pre_scenario, refresh_scenario, sign_scenario};

pub(super) trait Backend: refresh_scenario::Backend {
    /// Replace the current committee, wait for the new local generation, and
    /// assert that the ring and public key identities remain stable.
    async fn reshare_committee(&mut self, keys: &Keys);
}

pub(super) async fn run<B: Backend>(
    backend: &mut B,
    keys: &Keys,
    pre: &pre_scenario::Outcome,
    sign: &sign_scenario::Outcome,
) {
    backend.reshare_committee(keys).await;
    pre_scenario::verify_existing(backend, keys, pre).await;
    sign_scenario::verify_existing(backend, keys, sign).await;
}

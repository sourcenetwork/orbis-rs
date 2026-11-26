//! DKG's claims type — but *not* an [`super::EndpointAuth`] impl.
//!
//! `start_dkg` has no per-caller authentication at all, by deliberate
//! design: ring authorization already happened on-chain at ring creation
//! and node whitelisting, so DKG is just a "kick it off" trigger with
//! nothing left to check per caller. There is no existing JWT boundary to
//! extend with WebAuthn here, unlike Sign/PRE/StoreSecret — so this module
//! holds only the claims shape `JwtSigner::create_dkg_jwt` can mint, for
//! whatever caller still wants a self-contained DKG-scoped token, without
//! implying DKG participates in the generic dispatch.

use serde::{Deserialize, Serialize};

/// Claims for DKG endpoints
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DkgClaims {
    /// Pre-created blank ring entry targeted by this DKG.
    pub ring_id: String,
}

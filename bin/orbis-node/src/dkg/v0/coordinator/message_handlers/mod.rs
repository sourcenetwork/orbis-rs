use crate::constants::{
    JWT_CLOCK_SKEW_LEEWAY_SECS, MAX_COMMITMENT_COEFFICIENTS, MAX_JWT_BYTES, MAX_TOKEN_LIFETIME_SECS,
};
use crate::dkg::v0::error::{DkgError, Result};
use crate::dkg::v0::helpers::{
    build_reshare_params, derive_refresh_session_id, derive_reshare_session_id,
    effective_new_peer_node_keys, serialize_commitment_coefficients, session_not_found,
    validate_dkg_claims, validate_dkg_node_authorization_for_committee,
    validate_fresh_dkg_ring_payload, validate_fresh_session_init_params,
    validate_refresh_session_init_for_version, validate_reshare_session_init_for_version,
};
use crate::dkg::v0::messages::{DkgMessage, SessionKind};
use crate::dkg::v0::session_state::RingPssClaimOutcome;
use crate::helpers::helpers::is_self_peer_id;
use crate::helpers::node_routes::{
    canonical_node_id_assignments_from_node_keys, node_id_to_peer_id_from_routes,
    node_key_for_peer, peer_ids_from_routes, resolve_node_routes,
};
use crate::ring_state::RingShareBundle;

use authn::{resolve_jwt_did, BearerToken, DkgClaims};
use crypto::r#trait::{DistributedShare, DkgRole};
use crypto::{
    CryptoDeserialize, PolynomialCommitmentImpl as PolynomialCommitment,
    GROUP_POINT_SIZE as G1_COMPRESSED_SIZE, SCALAR_SIZE as FR_COMPRESSED_SIZE,
};
use network::PeerId;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{peers, phases, state_machine::DkgEvent, types::CoordinatorDkg, DkgCoordinator};

mod commitment;
mod session_init;
mod share;

pub(in crate::dkg::v0::coordinator) use crate::dkg::v0::coordinator::reshare::selection::{
    handle_reshare_participant_set, handle_reshare_share_ack,
};
pub(in crate::dkg::v0::coordinator) use commitment::handle_commitment_message;
pub(in crate::dkg::v0::coordinator) use session_init::handle_session_init;
pub(in crate::dkg::v0::coordinator) use share::handle_share_message;

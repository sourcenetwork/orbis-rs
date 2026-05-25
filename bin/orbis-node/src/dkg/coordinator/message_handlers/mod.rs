use crate::constants::{
    JWT_CLOCK_SKEW_LEEWAY_SECS, MAX_COMMITMENT_COEFFICIENTS, MAX_JWT_BYTES, MAX_TOKEN_LIFETIME_SECS,
};
use crate::dkg::error::{DkgError, Result};
use crate::dkg::helpers::{
    build_reshare_params, derive_refresh_session_id, derive_reshare_session_id,
    load_reshare_ring_payload, serialize_commitment_coefficients, session_not_found,
    validate_dkg_claims, validate_fresh_dkg_node_authorization, validate_refresh_session_init,
    validate_reshare_session_init,
};
use crate::dkg::messages::{DkgMessage, SessionKind};
use crate::dkg::session_state::RingPssClaimOutcome;
use crate::helpers::helpers::{extract_node_part, is_self_peer_id};
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

pub(in crate::dkg::coordinator) use crate::dkg::coordinator::reshare::selection::{
    handle_reshare_participant_set, handle_reshare_share_ack,
};
pub(in crate::dkg::coordinator) use commitment::handle_commitment_message;
pub(in crate::dkg::coordinator) use session_init::handle_session_init;
pub(in crate::dkg::coordinator) use share::handle_share_message;

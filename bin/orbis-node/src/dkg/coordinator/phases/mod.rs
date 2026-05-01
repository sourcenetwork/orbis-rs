use crate::dkg::error::{DkgError, Result};
use crate::dkg::helpers::{
    persist_ring_bundle, serialize_commitment_coefficients, session_not_found,
};
use crate::dkg::messages::{DkgMessage, SessionKind};
use crate::dkg::session_state::DkgPhase;
use crate::helpers::helpers::is_self_peer_id;
use crate::metrics;
use crypto::r#trait::{DistKeyShare, DkgRole, PubShare, ThresholdSigner};
use crypto::{
    CryptoSerialize, GroupAffine as G1Affine, ScalarField as Fr, SigShareInner, SignImpl,
    SignaturePoint,
};
use std::time::{SystemTime, UNIX_EPOCH};

use super::reshare::selection::record_and_ack_valid_reshare_share;
use super::types::CoordinatorDkg;
use super::{reshare, ring_storage, DkgCoordinator};

mod phase1;
mod phase2;
mod phase4;

pub(in crate::dkg::coordinator) use phase1::{
    check_and_trigger_phase2, initiate_phase1_commitments,
};
pub(in crate::dkg::coordinator) use phase2::initiate_phase2_shares;
pub(in crate::dkg::coordinator) use phase4::{
    check_and_trigger_phase4, initiate_phase4_completion,
};

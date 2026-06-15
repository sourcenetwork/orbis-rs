use crate::dkg::v0::error::{DkgError, Result};
use crate::dkg::v0::helpers::session_not_found;
use crate::dkg::v0::messages::{DkgMessage, SessionKind};
use crate::helpers::helpers::is_self_peer_id;
use crypto::r#trait::DkgRole;
use std::collections::HashSet;
use std::time::Duration;

use super::phases;
use super::state_machine::DkgEvent;
use super::types::CoordinatorDkg;
use super::DkgCoordinator;

const RESHARE_PARTICIPANT_SET_SEND_ATTEMPTS: usize = 3;
const RESHARE_PARTICIPANT_SET_RETRY_DELAY: Duration = Duration::from_millis(100);
const RESHARE_SHARE_ACK_RETRY_DELAY: Duration = Duration::from_millis(500);

pub(in crate::dkg::v0::coordinator) mod bulletin_update;
pub(in crate::dkg::v0::coordinator) mod cleanup;
pub(in crate::dkg::v0::coordinator) mod selection;

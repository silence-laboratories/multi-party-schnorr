// mod dsg;
mod types;

/// Messages used in the signing protocol
pub mod messages;

mod shared_rounds;
use std::collections::HashSet;

pub use shared_rounds::*;

/// Taproot signing protocol
#[cfg(any(feature = "taproot", test))]
// #[cfg(feature = "taproot")]
pub mod taproot;

/// EdDSA signing protocol using Curve25519
#[cfg(any(feature = "eddsa", test))]
pub mod eddsa;

pub use types::*;

use crate::common::utils::BaseMessage;

pub(crate) fn validate_input_messages<M: BaseMessage>(
    mut msgs: Vec<M>,
    party_id_list: &[u8],
) -> Result<Vec<M>, SignError> {
    if msgs.len() != party_id_list.len() {
        return Err(SignError::InvalidMsgCount);
    }

    let party_ids = msgs
        .iter()
        .map(|msg| msg.party_id())
        .collect::<HashSet<u8>>();

    if party_ids.len() != party_id_list.len() {
        return Err(SignError::DuplicatePartyId);
    }

    for pid in party_id_list {
        if !party_ids.contains(pid) {
            return Err(SignError::InvalidMsgPartyId);
        }
    }
    msgs.sort_by_key(BaseMessage::party_id);
    Ok(msgs)
}

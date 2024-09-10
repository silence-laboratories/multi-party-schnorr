// mod dsg;
mod types;

/// Messages used in the signing protocol
pub mod messages;

mod presign;
use std::collections::HashSet;

pub use presign::*;

/// Taproot signing protocol
#[cfg(any(feature = "taproot", test))]
pub mod taproot;

/// EdDSA signing protocol using Curve25519
#[cfg(any(feature = "eddsa", test))]
pub mod eddsa;

pub use types::*;

use crate::common::utils::BaseMessage;

pub(crate) fn validate_input_messages<M: BaseMessage>(
    mut msgs: Vec<M>,
    threshold: u8,
    party_id_list: &[u8],
) -> Result<Vec<M>, SignError> {
    if msgs.len() as u8 != threshold {
        return Err(SignError::InvalidMsgCount);
    }

    let party_ids = msgs
        .iter()
        .map(|msg| msg.party_id())
        .collect::<HashSet<u8>>();

    if party_ids.len() as u8 != threshold {
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

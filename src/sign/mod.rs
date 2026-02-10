// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::collections::HashSet;

mod types;

#[cfg(any(feature = "taproot", feature = "eddsa", feature = "redpallas"))]
/// Messages used in the signing protocol
pub mod messages;

#[cfg(any(feature = "taproot", feature = "eddsa", feature = "redpallas"))]
mod shared_rounds;

#[cfg(any(feature = "taproot", feature = "eddsa", feature = "redpallas"))]
pub use shared_rounds::*;

#[cfg(feature = "taproot")]
/// Taproot signing protocol
pub mod taproot;

#[cfg(feature = "eddsa")]
/// EdDSA signing protocol using Curve25519
pub mod eddsa;

#[cfg(feature = "redpallas")]
/// RedDSA signing protocol using RedPallas (compatible with Zcash reddsa)
pub mod reddsa;

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

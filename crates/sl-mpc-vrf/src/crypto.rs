// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::collections::HashSet;

use curve25519_dalek::RistrettoPoint;
use sha2::{digest::Update, Digest, Sha256};

use crate::{
    messages::VrfMsg1,
    types::{SessionId, VrfError},
};

/// Final session id from `(party_id, session_id)` pairs sorted by `party_id`.
pub fn calculate_final_session_id_pairs(
    mut party_session_pairs: Vec<(u8, SessionId)>,
    extra: &[&[u8]],
) -> SessionId {
    party_session_pairs.sort_unstable_by_key(|(pid, _)| *pid);
    let mut hasher = Sha256::new();
    for e in extra {
        hasher = hasher.chain(e);
    }
    for (pid, sid) in &party_session_pairs {
        hasher = hasher
            .chain(u32::from(*pid).to_be_bytes())
            .chain(sid.as_slice());
    }
    hasher.finalize().into()
}

pub(crate) fn validate_input_messages(
    mut msgs: Vec<VrfMsg1>,
    party_id_list: &[u8],
) -> Result<Vec<VrfMsg1>, VrfError> {
    if msgs.len() != party_id_list.len() {
        return Err(VrfError::InvalidMsgCount);
    }

    let party_ids: HashSet<u8> = msgs.iter().map(|m| m.from_party).collect();
    if party_ids.len() != party_id_list.len() {
        return Err(VrfError::DuplicatePartyId);
    }

    for pid in party_id_list {
        if !party_ids.contains(pid) {
            return Err(VrfError::InvalidMsgPartyId);
        }
    }

    msgs.sort_by_key(|msg| msg.from_party);
    Ok(msgs)
}

pub(crate) fn hash_consistency(
    public_key: &RistrettoPoint,
    party_shares: &[RistrettoPoint],
    message: &[u8],
    output_bits: usize,
) -> [u8; 32] {
    let mut hasher = Sha256::new()
        .chain(b"SL-VRF-CONSISTENCY")
        .chain(public_key.compress().as_bytes())
        .chain((party_shares.len() as u64).to_be_bytes());
    for share in party_shares {
        hasher = hasher.chain(share.compress().as_bytes());
    }
    hasher
        .chain((message.len() as u64).to_be_bytes())
        .chain(message)
        .chain((output_bits as u64).to_be_bytes())
        .finalize()
        .into()
}

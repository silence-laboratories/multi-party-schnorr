use curve25519_dalek::{EdwardsPoint, Scalar};
use ed25519_dalek::{Signature, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    common::{traits::PersistentObj, utils::SessionId, DLogProof},
    impl_basemessage,
};

/// Type for the sign gen message 1.
#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SignMsg1 {
    /// Participant Id of the sender
    pub from_party: u8,
    /// The index of the party in the public key list
    pub from_party_idx: u8,
    /// Signature
    #[serde(with = "serde_bytes")]
    pub signature: [u8; SIGNATURE_LENGTH],
    /// Sesssion id
    pub session_id: SessionId,
    /// Commitment hash
    pub commitment_r_i: [u8; 32],
}

/// Type for the sign gen message 2.
#[derive(Clone)]
pub struct SignMsg2 {
    /// Participant Id of the sender
    pub from_party: u8,
    /// Signature
    pub signature: [u8; SIGNATURE_LENGTH],
    /// Sesssion id
    pub session_id: SessionId,
    pub(crate) blind_factor: [u8; 32],
    pub(crate) dlog_proof: DLogProof,
    pub(crate) big_r_i: EdwardsPoint,
}

/// Type for the sign gen message 3.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SignMsg3 {
    /// Participant Id of the sender
    pub from_party: u8,
    /// Signature
    pub signature: [u8; SIGNATURE_LENGTH],
    /// Sesssion id
    pub session_id: SessionId,
    /// Partial signature
    pub s_i: Scalar,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
/// Signature completed message
pub struct SignComplete {
    pub(crate) from_party: u8,
    pub(crate) session_id: SessionId,
    pub(crate) signature: [u8; SIGNATURE_LENGTH],
}

impl_basemessage!(SignMsg1, SignMsg2, SignMsg3);

use elliptic_curve::Group;
use zeroize::{Zeroize, ZeroizeOnDrop};
// * MY CODE: ADDED, add serde_bytes to the imports
use serde_bytes;

use crate::common::{
    traits::GroupElem,
    utils::{BaseMessage, SessionId},
    DLogProof,
};

/// Type for the sign gen message 1.
// * MY CODE: ADDED, add serde_bytes for the session_id and commitment_r_i fields
/// Type for the sign gen message 1.
// #[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
// * MY CODE: ADDED, add Debug
#[derive(Clone, Debug)]
pub struct SignMsg1 {
    /// Participant Id of the sender
    pub from_party: u8,
    // * MY CODE: ADDED
    /// Sesssion id (serialize as raw bytes)
    #[serde(with = "serde_bytes")]
    pub session_id: SessionId,
    // * MY CODE: ADDED
    /// Commitment hash (serialize as raw bytes)
    #[serde(with = "serde_bytes")]
    pub commitment_r_i: [u8; 32],
}

/// Type for the sign gen message 2.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
// * MY CODE: ADDED, add Debug
#[derive(Clone, Debug)]
pub struct SignMsg2<G: GroupElem> {
    /// Participant Id of the sender
    pub from_party: u8,
    /// Sesssion id
    pub session_id: SessionId,
    // * MY CODE: ADDED, made the field public
    pub blind_factor: [u8; 32],
    #[cfg_attr(
        feature = "serde",
        serde(bound(
            serialize = "G::Scalar: serde::Serialize",
            deserialize = "G::Scalar: serde::Deserialize<'de>"
        ))
    )]
    // * MY CODE: ADDED, made the field public
    pub dlog_proof: DLogProof<G>,
    // * MY CODE: ADDED, made the field public
    pub big_r_i: Vec<u8>,
}

/// Type for the sign gen message 3.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
// * MY CODE: ADDED, add Debug
#[derive(Clone, Debug)]
pub struct SignMsg3<G: Group> {
    /// Participant Id of the sender
    pub from_party: u8,
    /// Sesssion id
    pub session_id: SessionId,
    /// Partial signature
    pub s_i: G::Scalar,
}

/// Signature completed message
// * MY CODE: ADDED, add serde_bytes for the signature field and session_id field
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SignComplete {
    // * MY CODE: ADDED, made the field public
    pub from_party: u8,
    // * MY CODE: ADDED, made the field public and added serde_bytes
    #[serde(with = "serde_bytes")]
    pub session_id: SessionId,
    // * MY CODE: ADDED, made the field public and added serde_bytes
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl<G> BaseMessage for SignMsg2<G>
where
    G: GroupElem,
{
    fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    fn party_id(&self) -> u8 {
        self.from_party
    }
}

impl<G> BaseMessage for SignMsg3<G>
where
    G: Group,
{
    fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    fn party_id(&self) -> u8 {
        self.from_party
    }
}

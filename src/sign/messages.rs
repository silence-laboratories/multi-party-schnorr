use curve25519_dalek::{EdwardsPoint, Scalar};
use ed25519_dalek::{Signature, SIGNATURE_LENGTH};
use elliptic_curve::Group;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    common::{
        traits::GroupElem,
        utils::{BaseMessage, SessionId},
        DLogProof,
    },
    impl_basemessage,
};

/// Type for the sign gen message 1.
#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SignMsg1 {
    /// Participant Id of the sender
    pub from_party: u8,
    /// Sesssion id
    pub session_id: SessionId,
    /// Commitment hash
    pub commitment_r_i: [u8; 32],
}

/// Type for the sign gen message 2.
#[derive(Clone)]
pub struct SignMsg2<G: GroupElem> {
    /// Participant Id of the sender
    pub from_party: u8,
    /// Sesssion id
    pub session_id: SessionId,
    pub(crate) blind_factor: [u8; 32],
    pub(crate) dlog_proof: DLogProof<G>,
    pub(crate) big_r_i: G,
}

/// Type for the sign gen message 3.
#[derive(Clone)]
pub struct SignMsg3<G: Group> {
    /// Participant Id of the sender
    pub from_party: u8,
    /// Sesssion id
    pub session_id: SessionId,
    /// Partial signature
    pub s_i: G::Scalar,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
/// Signature completed message
pub struct SignComplete {
    pub(crate) from_party: u8,
    pub(crate) session_id: SessionId,
    pub(crate) signature: [u8; SIGNATURE_LENGTH],
}

// TODO:Don't need base macro
impl_basemessage!(SignMsg1);

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

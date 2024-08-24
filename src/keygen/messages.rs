use std::hash::Hash;


use elliptic_curve::{Group};
use serde::{Deserialize, Serialize};



use crate::{
    common::{
        get_lagrange_coeff,
        traits::{GroupElem, ScalarReduce},
        utils::{EncryptedScalar, HashBytes, SessionId},
        DLogProof,
    },
    impl_basemessage,
};

use super::KeyRefreshData;

/// Type for the key generation protocol's message 1.
///
#[derive(Hash, Clone)]
// #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct KeygenMsg1 {
    /// Participant Id of the sender
    pub from_party: u8,

    /// Sesssion id
    pub session_id: SessionId,

    /// Participants commitment
    pub commitment: HashBytes,
}

/// Type for the key generation protocol's message 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenMsg2<G>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    /// Participant Id of the sender
    pub from_party: u8,

    /// Sesssion id
    pub session_id: SessionId,

    /// Random 32 bytes
    pub r_i: [u8; 32],

    /// Participants Fik values
    pub big_a_i_poly: Vec<Vec<u8>>,

    /// Ciphertext list
    pub c_i_list: Vec<EncryptedScalar>,

    /// Participants dlog proof
    #[serde(bound(
        serialize = "G::Scalar: Serialize",
        deserialize = "G::Scalar: Deserialize<'de>"
    ))]
    pub dlog_proofs_i: Vec<DLogProof<G>>,
}

/// Keyshare of a party.
#[derive(Clone, Serialize, Deserialize)]
pub struct Keyshare<G>
where
    G: Group,
{
    /// Threshold value
    pub threshold: u8,
    /// Total number of parties
    pub total_parties: u8,
    /// Party Id of the sender
    pub party_id: u8,
    pub(crate) d_i: G::Scalar,
    /// Public key of the generated key.
    pub public_key: G,
    pub key_id: [u8; 32],
    pub(crate) big_a_poly: Vec<G>,
}

impl<G> Keyshare<G>
where
    G: Group,
{
    /// Start the key refresh protocol.
    /// This will return a [`KeyRefreshData`] instance which can be use to initialize the KeygenParty which can be driven
    /// to completion and will return the refreshed keyshare.
    pub fn get_refresh_data(&self) -> KeyRefreshData<G> {
        self.create_refresh(vec![])
    }

    /// Start the key recovery protocol.
    /// When some parties lose their keyshare, they can recover their keyshare using this protocol.
    /// This will return a [`KeyRefreshData`] instance which can be use to initialize the KeygenParty which can be driven
    /// to completion and will return the refreshed keyshare.
    /// This protocol will refresh keyshares that weren't lost and generate a new keyshare for the lost parties.
    /// # Arguments
    /// * `lost_keyshare_party_ids`: List of party ids that lost their keyshare.
    pub fn get_recovery_data(&self, lost_keyshare_party_ids: Vec<u8>) -> KeyRefreshData<G> {
        self.create_refresh(lost_keyshare_party_ids)
    }

    fn create_refresh(&self, lost_keyshare_party_ids: Vec<u8>) -> KeyRefreshData<G> {
        // Calculate the additive share s_i_0 of the party
        let mut partys_with_keyshares = vec![];
        let lambda = if lost_keyshare_party_ids.is_empty() {
            get_lagrange_coeff::<G>(&self.party_id, 0..self.total_parties)
        } else {
            for pid in 0..self.total_parties {
                if lost_keyshare_party_ids.contains(&pid) {
                    continue;
                }
                partys_with_keyshares.push(pid);
            }
            get_lagrange_coeff::<G>(&self.party_id, partys_with_keyshares.into_iter())
        };
        let s_i_0 = self.d_i * lambda;
        KeyRefreshData {
            d_i_0: s_i_0,
            lost_keyshare_party_ids,
            expected_public_key: self.public_key,
        }
    }
}

impl_basemessage!(KeygenMsg1);

impl<G> crate::common::utils::BaseMessage for KeygenMsg2<G>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    fn party_id(&self) -> u8 {
        self.from_party
    }
}

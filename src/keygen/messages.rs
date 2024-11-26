use std::hash::Hash;

use crypto_bigint::subtle::ConstantTimeEq;
use elliptic_curve::{group::GroupEncoding, Group};
#[cfg(feature = "serde")]
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

#[cfg(feature = "serde")]
use crate::common::utils::{serde_point, serde_vec_point};

use super::KeyRefreshData;

/// Type for the key generation protocol's message 1.
///
#[derive(Hash, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeygenMsg1 {
    /// Participant Id of the sender
    pub from_party: u8,

    /// Sesssion id
    pub session_id: SessionId,

    /// Participants commitment
    pub commitment: HashBytes,
}

/// Type for the key generation protocol's message 2.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone)]
pub struct KeygenMsg2<G>
where
    G: Group + ConstantTimeEq + GroupEncoding,
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    /// Participant Id of the sender
    pub from_party: u8,

    /// Sesssion id
    pub session_id: SessionId,

    /// Random 32 bytes
    pub r_i: [u8; 32],

    /// Participants Fik values
    #[cfg_attr(feature = "serde", serde(with = "serde_vec_point"))]
    pub big_a_i_poly: Vec<G>,

    /// Ciphertext list
    pub c_i_list: Vec<EncryptedScalar>,

    /// Participants dlog proof
    #[cfg_attr(
        feature = "serde",
        serde(bound(
            serialize = "G::Scalar: Serialize",
            deserialize = "G::Scalar: Deserialize<'de>"
        ))
    )]
    pub dlog_proofs_i: Vec<DLogProof<G>>,
}

/// Keyshare of a party.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone)]
pub struct Keyshare<G>
where
    G: Group + GroupEncoding,
{
    /// Threshold value
    pub threshold: u8,
    /// Total number of parties
    pub total_parties: u8,
    /// Party Id of the sender
    pub(crate) party_id: u8,
    /// d_i, internal
    pub(crate) d_i: G::Scalar,
    /// Public key of the generated key.
    #[cfg_attr(feature = "serde", serde(with = "serde_point"))]
    pub public_key: G,
    /// Key ID
    pub key_id: [u8; 32],
    /// Extra data
    pub extra_data: Option<Vec<u8>>,
}

impl<G: Group + GroupEncoding> Keyshare<G> {
    pub fn public_key(&self) -> &G {
        &self.public_key
    }
    /// Get the shamir secret share
    pub fn shamir_share(&self) -> &G::Scalar {
        &self.d_i
    }
    /// Get the scalar share of the party
    pub fn scalar_share(&self) -> G::Scalar {
        let coeff = get_lagrange_coeff::<G>(&self.party_id, 0..self.total_parties);
        self.d_i * coeff
    }
    pub fn party_id(&self) -> u8 {
        self.party_id
    }
}

impl<G> Keyshare<G>
where
    G: Group + GroupEncoding,
{
    /// Start the key refresh protocol.
    /// If some parties lost their keyshare, they can recover their keyshare using this protocol.
    /// This will return a [`KeyRefreshData`] instance which can be use to initialize the KeygenParty which can be driven
    /// to completion and will return the refreshed keyshare.
    pub fn get_refresh_data(&self, lost_ids: Option<Vec<u8>>) -> KeyRefreshData<G> {
        self.create_refresh(lost_ids.unwrap_or_default())
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
            get_lagrange_coeff::<G>(&self.party_id, partys_with_keyshares.iter().copied())
        };
        let s_i_0 = self.d_i * lambda;
        KeyRefreshData {
            threshold: self.threshold,
            total_parties: self.total_parties,
            party_id: self.party_id,
            s_i_0,
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

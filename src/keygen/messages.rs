use std::hash::Hash;

use crypto_bigint::subtle::ConstantTimeEq;
use derivation_path::{ChildIndex, DerivationPath};
use elliptic_curve::{group::GroupEncoding, Group};
use ff::Field;
use hmac::{Hmac, Mac};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use sl_mpc_mate::bip32::BIP32Error;

use crate::{
    common::{
        get_lagrange_coeff,
        traits::{GroupElem, ScalarReduce},
        utils::{EncryptedData, HashBytes, SessionId},
        DLogProof,
    },
    impl_basemessage,
};

#[cfg(feature = "serde")]
use crate::common::utils::{serde_point, serde_vec_point};

use super::KeyRefreshData;
const KEY_SIZE: usize = 32;

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
    pub c_i_list: Vec<EncryptedData>,

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
    pub root_chain_code: [u8; 32],
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

    /// Get the scalar share of the party
    pub fn scalar_share_interpolate(&self, party_id_list: Vec<u8>) -> G::Scalar {
        let coeff = get_lagrange_coeff::<G>(&self.party_id, party_id_list);
        self.d_i * coeff
    }

    pub fn party_id(&self) -> u8 {
        self.party_id
    }
    pub fn extra_data(&self) -> &[u8] {
        match &self.extra_data {
            Some(val) => val,
            None => &[],
        }
    }
    pub fn root_chain_code(&self) -> [u8; 32] {
        self.root_chain_code
    }
    pub fn derive_with_offset(
        &self,
        chain_path: &DerivationPath,
    ) -> Result<(G::Scalar, G), BIP32Error>
    where
        <G as Group>::Scalar: ScalarReduce<[u8; 32]>,
    {
        let mut pubkey = *self.public_key();
        let mut chain_code = self.root_chain_code();
        let mut additive_offset = G::Scalar::ZERO;
        for child_num in chain_path {
            let (il_int, child_pubkey, child_chain_code) =
                self.derive_child_pubkey(&pubkey, chain_code, child_num)?;
            pubkey = child_pubkey;
            chain_code = child_chain_code;
            additive_offset += il_int;
        }

        // Perform the mod q operation to get the additive offset
        Ok((additive_offset, pubkey))
    }
    pub fn derive_child_pubkey(
        &self,
        parent_pubkey: &G,
        parent_chain_code: [u8; 32],
        child_number: &ChildIndex,
    ) -> Result<(G::Scalar, G, [u8; 32]), BIP32Error>
    where
        G::Scalar: ScalarReduce<[u8; 32]>,
    {
        let mut hmac_hasher = Hmac::<sha2::Sha512>::new_from_slice(&parent_chain_code)
            .map_err(|_| BIP32Error::InvalidChainCode)?;

        if child_number.is_normal() {
            hmac_hasher.update(parent_pubkey.to_bytes().as_ref());
        } else {
            return Err(BIP32Error::HardenedChildNotSupported);
        }
        hmac_hasher.update(&child_number.to_bits().to_be_bytes());
        let result = hmac_hasher.finalize().into_bytes();
        let (il_int, child_chain_code) = result.split_at(KEY_SIZE);
        let il_int: &[u8; 32] = il_int[0..32].try_into().unwrap();

        if G::Scalar::check_bip32_left_rnd(il_int).is_err() {
            return Err(BIP32Error::InvalidChildScalar);
        }
        let pubkey = G::generator() * G::Scalar::reduce_from_bytes(il_int);

        let child_pubkey = pubkey + parent_pubkey;

        // Return error if child pubkey is the point at infinity
        if child_pubkey == G::identity() {
            return Err(BIP32Error::PubkeyPointAtInfinity);
        }

        Ok((
            G::Scalar::reduce_from_bytes(il_int),
            child_pubkey,
            child_chain_code.try_into().unwrap(),
        ))
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
            root_chain_code: self.root_chain_code,
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

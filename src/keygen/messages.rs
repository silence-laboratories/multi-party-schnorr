// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::hash::Hash;

use crypto_bigint::subtle::ConstantTimeEq;
use derivation_path::{ChildIndex, DerivationPath};
use elliptic_curve::{group::GroupEncoding, Group};
use ff::Field;
use hmac::{Hmac, Mac};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use sl_mpc_mate::bip32::BIP32Error;

#[cfg(feature = "serde")]
use crate::common::utils::{serde_point, serde_vec_point};

use crate::common::{
    get_lagrange_coeff,
    traits::{BIP32Derive, GroupElem, ScalarReduce},
    utils::{EncryptedData, HashBytes, SessionId},
    DLogProof,
};

pub use crate::common::{Bip32Public, ChildHmacData, Legacy, SoftDeriveChildHmac};

use super::KeyRefreshData;
const KEY_SIZE: usize = 32;

/// Type for the key generation protocol's message 1.
///
#[derive(Hash, Clone, Copy)]
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
    #[cfg(feature = "vrf")]
    #[cfg_attr(feature = "serde", serde(with = "serde_vec_point"))]
    pub(crate) party_public_shares: Vec<G>,
    /// Key ID
    pub key_id: [u8; 32],
    /// Extra data
    pub extra_data: Option<Vec<u8>>,
    pub root_chain_code: [u8; 32],

    #[cfg(feature = "keyshare-session-id")]
    pub final_session_id: [u8; 32],
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

    /// Additive public share K_i for this party (full quorum).
    #[cfg(feature = "vrf")]
    pub fn party_public_share(&self) -> Option<&G> {
        self.party_public_shares.get(self.party_id as usize)
    }

    /// All parties additive public shares K_0, …, K_{n-1}.
    #[cfg(feature = "vrf")]
    pub fn party_public_shares(&self) -> &[G] {
        &self.party_public_shares
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

    /// Soft-derive along chain_path
    pub fn derive_with_offset<F>(
        &self,
        chain_path: &DerivationPath,
    ) -> Result<(G::Scalar, G), BIP32Error>
    where
        G: GroupElem,
        G::Scalar: ScalarReduce<[u8; 32]> + BIP32Derive,
        F: SoftDeriveChildHmac<G>,
    {
        let mut pubkey = *self.public_key();
        let mut chain_code = self.root_chain_code();
        let mut additive_offset = G::Scalar::ZERO;
        for child_num in chain_path {
            let (il_int, child_pubkey, child_chain_code) =
                self.derive_child_pubkey::<F>(&pubkey, chain_code, child_num)?;
            pubkey = child_pubkey;
            chain_code = child_chain_code;
            additive_offset += il_int;
        }

        Ok((additive_offset, pubkey))
    }

    pub fn derive_child_pubkey<F>(
        &self,
        parent_pubkey: &G,
        parent_chain_code: [u8; 32],
        child_number: &ChildIndex,
    ) -> Result<(G::Scalar, G, [u8; 32]), BIP32Error>
    where
        G: GroupElem,
        G::Scalar: ScalarReduce<[u8; 32]> + BIP32Derive,
        F: SoftDeriveChildHmac<G>,
    {
        let hmac_data = F::child_hmac_data(parent_pubkey, child_number)?;
        finalize_soft_derive_child_hmac(parent_chain_code, hmac_data, parent_pubkey)
    }
}

fn hmac_sha512(key: &[u8; 32], message: &[u8]) -> Result<[u8; 64], BIP32Error> {
    let mut hmac_hasher =
        Hmac::<sha2::Sha512>::new_from_slice(key).map_err(|_| BIP32Error::InvalidChainCode)?;
    hmac_hasher.update(message);
    Ok(hmac_hasher.finalize().into_bytes().into())
}

fn finalize_soft_derive_child_hmac<G>(
    parent_chain_code: [u8; 32],
    hmac_data: ChildHmacData,
    parent_pubkey: &G,
) -> Result<(G::Scalar, G, [u8; 32]), BIP32Error>
where
    G: Group + GroupEncoding,
    G::Scalar: BIP32Derive,
{
    // Joint: one HMAC keyed by parent_chain_code
    // Separate: two HMACs keyed by parent_chain_code (Cardano style);
    let (il_int, child_chain_code): ([u8; 32], [u8; 32]) = match hmac_data {
        ChildHmacData::Joint(message) => {
            let result = hmac_sha512(&parent_chain_code, &message)?;
            (
                result[..KEY_SIZE].try_into().unwrap(),
                result[KEY_SIZE..].try_into().unwrap(),
            )
        }
        ChildHmacData::Separate { key, chain_code } => {
            let key_result = hmac_sha512(&parent_chain_code, &key)?;
            let chain_code_result = hmac_sha512(&parent_chain_code, &chain_code)?;
            (
                key_result[..KEY_SIZE].try_into().unwrap(),
                chain_code_result[KEY_SIZE..].try_into().unwrap(),
            )
        }
    };

    let offset_opt = G::Scalar::parse_offset(il_int);

    if offset_opt.is_none().into() {
        return Err(BIP32Error::InvalidChildScalar);
    }

    let offset = offset_opt.unwrap();
    let child_pubkey = G::generator() * offset + parent_pubkey;

    if child_pubkey == G::identity() {
        return Err(BIP32Error::PubkeyPointAtInfinity);
    }

    Ok((offset, child_pubkey, child_chain_code))
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

#[cfg(all(test, feature = "eddsa"))]
mod bip32_ed25519_vectors {
    use super::*;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use derivation_path::DerivationPath;
    use std::str::FromStr;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// BIP32-Ed25519 (Cardano-style) soft derivation, using the Bip32Public two-HMAC scheme.
    #[test]
    fn cardano_soft_derive_vector() {
        let root_pk = unhex("424287c9a39d727126cab0289dc9f55f5f54b34b2554fe45f0c2546d0a8f0e3c");
        let root_cc = unhex("15a62c12ff0bde064aa29d0006adec047a1aceb5dc37506e333e1e44b78a9abd");
        let expected_child_pk =
            unhex("c5fc1d93e7d2e21e3c785417919622510173fb0afdfb22d5e1549ecfb94fc509");
        let expected_child_cc =
            unhex("7ee4600c3c4b86e69304d48556265f232ddfe8a7812141d6054b39f8636262c9");

        let mut pubkey = CompressedEdwardsY(root_pk.as_slice().try_into().unwrap())
            .decompress()
            .expect("valid root public key");
        let mut chain_code: [u8; 32] = root_cc.as_slice().try_into().unwrap();

        let path = DerivationPath::from_str("m/0/1/2").unwrap();
        for child in &path {
            let hmac_data = <Bip32Public as SoftDeriveChildHmac<
                curve25519_dalek::EdwardsPoint,
            >>::child_hmac_data(&pubkey, child)
            .unwrap();
            let (_offset, child_pubkey, child_chain_code) =
                finalize_soft_derive_child_hmac(chain_code, hmac_data, &pubkey).unwrap();
            pubkey = child_pubkey;
            chain_code = child_chain_code;
        }

        assert_eq!(
            pubkey.compress().as_bytes().as_slice(),
            expected_child_pk.as_slice(),
            "derived child public key mismatch"
        );
        assert_eq!(
            chain_code.as_slice(),
            expected_child_cc.as_slice(),
            "derived child chain code mismatch"
        );
    }
}

impl crate::common::utils::BaseMessage for KeygenMsg1 {
    fn party_id(&self) -> u8 {
        self.from_party
    }
}

impl<G> crate::common::utils::BaseMessage for KeygenMsg2<G>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    fn party_id(&self) -> u8 {
        self.from_party
    }
}

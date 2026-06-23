// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Soft-derivation HMAC message formats.

use derivation_path::ChildIndex;
#[cfg(feature = "taproot")]
use elliptic_curve::sec1::ToEncodedPoint;
use sl_mpc_mate::bip32::BIP32Error;

use super::traits::GroupElem;

/// HMAC body: parent_pubkey.to_bytes() || child index BE.
#[derive(Clone, Copy)]
pub struct Legacy;

/// HMAC body: 0x03 || pk (32 bytes) || child index LE.
#[derive(Clone, Copy)]
pub struct Bip32Public;

/// Builds HMAC-SHA512 data bytes for one soft-derivation child step where key is always parent_chain_code.
/// Implemented once per format marker (`Legacy`, `Bip32Public`) and per curve `G`.
pub trait SoftDeriveChildHmac<G: GroupElem> {
    fn child_hmac_data(parent_pubkey: &G, child_number: &ChildIndex)
        -> Result<Vec<u8>, BIP32Error>;
}

fn require_normal_child(child_number: &ChildIndex) -> Result<(), BIP32Error> {
    if child_number.is_normal() {
        Ok(())
    } else {
        Err(BIP32Error::HardenedChildNotSupported)
    }
}

impl<G: GroupElem> SoftDeriveChildHmac<G> for Legacy {
    fn child_hmac_data(
        parent_pubkey: &G,
        child_number: &ChildIndex,
    ) -> Result<Vec<u8>, BIP32Error> {
        require_normal_child(child_number)?;
        let mut data = parent_pubkey.to_bytes().as_ref().to_vec();
        data.extend_from_slice(&child_number.to_bits().to_be_bytes());
        Ok(data)
    }
}

#[cfg(feature = "eddsa")]
impl SoftDeriveChildHmac<curve25519_dalek::EdwardsPoint> for Bip32Public {
    fn child_hmac_data(
        parent_pubkey: &curve25519_dalek::EdwardsPoint,
        child_number: &ChildIndex,
    ) -> Result<Vec<u8>, BIP32Error> {
        require_normal_child(child_number)?;
        let mut data = Vec::with_capacity(37);
        data.push(0x03);
        data.extend_from_slice(parent_pubkey.compress().as_bytes());
        data.extend_from_slice(&child_number.to_bits().to_le_bytes());
        Ok(data)
    }
}

#[cfg(feature = "taproot")]
impl SoftDeriveChildHmac<k256::ProjectivePoint> for Bip32Public {
    fn child_hmac_data(
        parent_pubkey: &k256::ProjectivePoint,
        child_number: &ChildIndex,
    ) -> Result<Vec<u8>, BIP32Error> {
        require_normal_child(child_number)?;
        let encoded = parent_pubkey.to_encoded_point(true);
        let bytes = encoded.as_bytes();
        if bytes.len() != 33 {
            return Err(BIP32Error::InvalidChainCode);
        }
        let mut data = Vec::with_capacity(37);
        data.push(0x03);
        data.extend_from_slice(&bytes[1..33]);
        data.extend_from_slice(&child_number.to_bits().to_le_bytes());
        Ok(data)
    }
}

#[cfg(feature = "redpallas")]
impl SoftDeriveChildHmac<crate::common::redpallas::RedPallasPoint> for Bip32Public {
    fn child_hmac_data(
        _parent_pubkey: &crate::common::redpallas::RedPallasPoint,
        _child_number: &ChildIndex,
    ) -> Result<Vec<u8>, BIP32Error> {
        // Bip32Public is for secp256k1 / Ed25519-style bodies; use [`Legacy`] on RedPallas.
        Err(BIP32Error::InvalidChainCode)
    }
}

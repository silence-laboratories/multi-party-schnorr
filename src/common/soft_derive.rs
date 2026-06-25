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

/// Cardano-style public soft derivation using two HMAC-SHA512 evaluations keyed by parent_chain_code:
/// child key        = HMAC(parent_chain_code, 0x02 || pk (32 bytes) || child index LE)[0..32]
/// child chain code = HMAC(parent_chain_code, 0x03 || pk (32 bytes) || child index LE)[32..64]
#[derive(Clone, Copy)]
pub struct Bip32Public;

/// Describes whether a soft-derivation child step uses one or two HMAC-SHA512 evaluations,
/// and provides the message body/bodies (the HMAC key is always parent_chain_code).
pub enum ChildHmacData {
    /// Single HMAC message body: child key = out[0..32], child chain code = out[32..64].
    Joint(Vec<u8>),
    /// Two HMAC message bodies: child key = HMAC(parent_chain_code, key)[0..32],
    /// child chain code = HMAC(parent_chain_code, chain_code)[32..64].
    Separate { key: Vec<u8>, chain_code: Vec<u8> },
}

/// Builds HMAC-SHA512 data bytes for one soft-derivation child step where key is always parent_chain_code.
/// Implemented once per format marker (Legacy, Bip32Public) and per curve G.
pub trait SoftDeriveChildHmac<G: GroupElem> {
    fn child_hmac_data(
        parent_pubkey: &G,
        child_number: &ChildIndex,
    ) -> Result<ChildHmacData, BIP32Error>;
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
    ) -> Result<ChildHmacData, BIP32Error> {
        require_normal_child(child_number)?;
        let mut data = parent_pubkey.to_bytes().as_ref().to_vec();
        data.extend_from_slice(&child_number.to_bits().to_be_bytes());
        Ok(ChildHmacData::Joint(data))
    }
}

/// Builds prefix || pk (32 bytes) || child index LE for the Cardano-style body.
fn bip32_public_body(prefix: u8, pk: &[u8], child_number: &ChildIndex) -> Vec<u8> {
    let mut data = Vec::with_capacity(1 + pk.len() + 4);
    data.push(prefix);
    data.extend_from_slice(pk);
    data.extend_from_slice(&child_number.to_bits().to_le_bytes());
    data
}

#[cfg(feature = "eddsa")]
impl SoftDeriveChildHmac<curve25519_dalek::EdwardsPoint> for Bip32Public {
    fn child_hmac_data(
        parent_pubkey: &curve25519_dalek::EdwardsPoint,
        child_number: &ChildIndex,
    ) -> Result<ChildHmacData, BIP32Error> {
        require_normal_child(child_number)?;
        let compressed = parent_pubkey.compress();
        let pk = compressed.as_bytes();
        Ok(ChildHmacData::Separate {
            key: bip32_public_body(0x02, pk, child_number),
            chain_code: bip32_public_body(0x03, pk, child_number),
        })
    }
}

#[cfg(feature = "taproot")]
impl SoftDeriveChildHmac<k256::ProjectivePoint> for Bip32Public {
    fn child_hmac_data(
        parent_pubkey: &k256::ProjectivePoint,
        child_number: &ChildIndex,
    ) -> Result<ChildHmacData, BIP32Error> {
        require_normal_child(child_number)?;
        let encoded = parent_pubkey.to_encoded_point(true);
        let bytes = encoded.as_bytes();
        if bytes.len() != 33 {
            return Err(BIP32Error::InvalidChainCode);
        }
        let pk = &bytes[1..33];
        Ok(ChildHmacData::Separate {
            key: bip32_public_body(0x02, pk, child_number),
            chain_code: bip32_public_body(0x03, pk, child_number),
        })
    }
}

#[cfg(feature = "redpallas")]
impl SoftDeriveChildHmac<crate::common::redpallas::RedPallasPoint> for Bip32Public {
    fn child_hmac_data(
        _parent_pubkey: &crate::common::redpallas::RedPallasPoint,
        _child_number: &ChildIndex,
    ) -> Result<ChildHmacData, BIP32Error> {
        // Bip32Public is for secp256k1 / Ed25519-style bodies; use [Legacy] on RedPallas.
        Err(BIP32Error::InvalidChainCode)
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use elliptic_curve::Group;

    /// prefix || pk || child index LE, the expected Cardano-style body.
    #[cfg(any(feature = "eddsa", feature = "taproot"))]
    fn expected_body(prefix: u8, pk: &[u8], index: u32) -> Vec<u8> {
        let mut body = vec![prefix];
        body.extend_from_slice(pk);
        body.extend_from_slice(&index.to_le_bytes());
        body
    }

    #[cfg(feature = "eddsa")]
    #[test]
    fn legacy_returns_joint_eddsa() {
        use curve25519_dalek::EdwardsPoint;

        let pk = EdwardsPoint::generator();
        let child = ChildIndex::Normal(5);
        let data =
            <Legacy as SoftDeriveChildHmac<EdwardsPoint>>::child_hmac_data(&pk, &child).unwrap();

        let ChildHmacData::Joint(body) = data else {
            panic!("Legacy must produce a single (Joint) HMAC body");
        };
        let mut expected = pk.compress().as_bytes().to_vec();
        expected.extend_from_slice(&5u32.to_be_bytes());
        assert_eq!(body, expected);
    }

    #[cfg(feature = "eddsa")]
    #[test]
    fn bip32_public_returns_separate_eddsa() {
        use curve25519_dalek::EdwardsPoint;

        let pk = EdwardsPoint::generator();
        let child = ChildIndex::Normal(5);
        let data = <Bip32Public as SoftDeriveChildHmac<EdwardsPoint>>::child_hmac_data(&pk, &child)
            .unwrap();

        let ChildHmacData::Separate { key, chain_code } = data else {
            panic!("Bip32Public must produce two (Separate) HMAC bodies");
        };
        let pk_bytes = pk.compress().as_bytes().to_vec();
        assert_eq!(key, expected_body(0x02, &pk_bytes, 5));
        assert_eq!(chain_code, expected_body(0x03, &pk_bytes, 5));
        assert_eq!(key[0], 0x02);
        assert_eq!(chain_code[0], 0x03);
        assert_ne!(key, chain_code);
    }

    #[cfg(feature = "taproot")]
    #[test]
    fn bip32_public_returns_separate_taproot() {
        use k256::ProjectivePoint;

        let pk = ProjectivePoint::GENERATOR;
        let child = ChildIndex::Normal(7);
        let data =
            <Bip32Public as SoftDeriveChildHmac<ProjectivePoint>>::child_hmac_data(&pk, &child)
                .unwrap();

        let ChildHmacData::Separate { key, chain_code } = data else {
            panic!("Bip32Public must produce two (Separate) HMAC bodies");
        };
        let encoded = pk.to_encoded_point(true);
        let pk_bytes = encoded.as_bytes()[1..33].to_vec();
        assert_eq!(key, expected_body(0x02, &pk_bytes, 7));
        assert_eq!(chain_code, expected_body(0x03, &pk_bytes, 7));
        assert_ne!(key, chain_code);
    }

    #[cfg(feature = "eddsa")]
    #[test]
    fn hardened_child_is_rejected() {
        use curve25519_dalek::EdwardsPoint;

        let pk = EdwardsPoint::generator();
        let child = ChildIndex::Hardened(0);
        assert!(matches!(
            <Legacy as SoftDeriveChildHmac<EdwardsPoint>>::child_hmac_data(&pk, &child),
            Err(BIP32Error::HardenedChildNotSupported)
        ));
        assert!(matches!(
            <Bip32Public as SoftDeriveChildHmac<EdwardsPoint>>::child_hmac_data(&pk, &child),
            Err(BIP32Error::HardenedChildNotSupported)
        ));
    }

    #[cfg(feature = "redpallas")]
    #[test]
    fn bip32_public_unsupported_on_redpallas() {
        use crate::common::redpallas::RedPallasPoint;

        let pk = RedPallasPoint::generator();
        let child = ChildIndex::Normal(0);
        assert!(
            <Bip32Public as SoftDeriveChildHmac<RedPallasPoint>>::child_hmac_data(&pk, &child)
                .is_err()
        );
    }
}

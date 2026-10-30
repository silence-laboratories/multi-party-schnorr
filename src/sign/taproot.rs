// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use alloc::vec::Vec;

use elliptic_curve::ops::Reduce;
use k256::{schnorr::Signature, ProjectivePoint, Scalar, U256};
use signature::hazmat::PrehashVerifier;

use messages::{SignComplete, SignMsg3};
use sha2::{Digest, Sha256};

use crate::{
    common::traits::{Round, ScalarReduce},
    keygen::Keyshare,
};

use super::*;

#[allow(unused)]
const CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";

/// Concatenation of hash of challenge tag:  [sha256("BIP0340/challenge") || sha256("BIP0340/challenge")]
const CHALLENGE_TAG_HASH: &[u8] = &[
    123, 181, 45, 122, 159, 239, 88, 50, 62, 177, 191, 122, 64, 125, 179, 130, 210, 243, 242, 216,
    27, 177, 34, 79, 73, 254, 81, 143, 109, 72, 211, 124, 123, 181, 45, 122, 159, 239, 88, 50, 62,
    177, 191, 122, 64, 125, 179, 130, 210, 243, 242, 216, 27, 177, 34, 79, 73, 254, 81, 143, 109,
    72, 211, 124,
];

/// Concatenation of hash of tag:  [sha256("TapTweak") || sha256("TapTweak")]
const TAP_TWEAK_HASH: &[u8] = &[
    232, 15, 225, 99, 156, 156, 160, 80, 227, 175, 27, 57, 193, 67, 198, 62, 66, 156, 188, 235, 21,
    217, 64, 251, 181, 197, 161, 244, 175, 87, 197, 233, 232, 15, 225, 99, 156, 156, 160, 80, 227,
    175, 27, 57, 193, 67, 198, 62, 66, 156, 188, 235, 21, 217, 64, 251, 181, 197, 161, 244, 175,
    87, 197, 233,
];

impl Keyshare<k256::ProjectivePoint> {
    /// Return the taproot public key, tweaked according to the Taproot BIP340 specification.
    /// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    pub fn get_taproot_public_key(&self) -> Option<k256::schnorr::VerifyingKey> {
        taproot_public_key(&self.public_key)
    }
}

/// Return the taproot public key, tweaked according to the Taproot BIP340 specification.
/// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
pub fn taproot_public_key(
    public_key: &k256::ProjectivePoint,
) -> Option<k256::schnorr::VerifyingKey> {
    use elliptic_curve::point::AffineCoordinates;
    use elliptic_curve::point::DecompactPoint;
    let pubkey = k256::PublicKey::from_affine(Option::from(k256::AffinePoint::decompact(
        &public_key.to_affine().x(),
    ))?)
    .ok()?;

    k256::schnorr::VerifyingKey::try_from(pubkey).ok()
}

impl Round for SignReady<ProjectivePoint> {
    type InputMessage = ();
    type Input = ();
    type Error = SignError;
    type Output = (PartialSign<ProjectivePoint>, SignMsg3<ProjectivePoint>);

    /// The signer party processes the message to sign and returns the partial signature
    /// # Arguments
    /// * `msg_hash` - 32 bytes hash of the message to sign. It must be the output of a secure hash function.
    fn process(self, _: Self::Input) -> Result<Self::Output, Self::Error> {
        use elliptic_curve::point::AffineCoordinates;
        if self.message.len() != 32 {
            panic!("Message must be 32 bytes, this is a bug");
        }
        let x_only_pubkey = taproot_public_key(&self.public_key).unwrap();
        let tweak: [u8; 32] = Sha256::new()
            .chain_update(TAP_TWEAK_HASH)
            .chain_update(x_only_pubkey.to_bytes())
            .finalize()
            .into();
        let tweak_scalar = Scalar::reduce_from_bytes(&tweak);

        // The spend commits to the even-Y form of the internal key, so the share follows it.
        let mut internal_point = self.public_key;
        let mut internal_share = self.d_i;
        if internal_point.to_affine().y_is_odd().unwrap_u8() == 1 {
            internal_point = -internal_point;
            internal_share = -internal_share;
        }

        let tweaked_big_p =
            (internal_point + ProjectivePoint::GENERATOR * tweak_scalar).to_affine();

        let big_r = self.big_r.to_affine();
        let mut k_i = self.k_i;

        if big_r.y_is_odd().unwrap_u8() == 1 {
            k_i = -k_i;
        }

        let parties = self.pid_list.len();
        let mut tweaked_share =
            internal_share + (tweak_scalar * Scalar::from(parties as u64).invert().unwrap());

        if tweaked_big_p.y_is_odd().unwrap_u8() == 1 {
            tweaked_share = -tweaked_share;
        }

        let e = <k256::Scalar as Reduce<U256>>::reduce_bytes(
            &Sha256::new()
                .chain_update(CHALLENGE_TAG_HASH)
                .chain_update(big_r.x())
                .chain_update(tweaked_big_p.x())
                .chain_update(&self.message)
                .finalize(),
        );

        let s_i = k_i + tweaked_share * e;

        let msg3 = SignMsg3 {
            from_party: self.party_id,
            session_id: self.session_id,
            s_i,
        };

        let next = PartialSign {
            public_key: self.public_key,
            party_id: self.party_id,
            session_id: self.session_id,
            big_r: self.big_r,
            s_i,
            msg_to_sign: self.message,
            pid_list: self.pid_list,
        };

        Ok((next, msg3))
    }
}

impl Round for PartialSign<ProjectivePoint> {
    type InputMessage = SignMsg3<ProjectivePoint>;
    type Input = Vec<SignMsg3<ProjectivePoint>>;
    type Error = SignError;
    type Output = (Signature, SignComplete);

    fn process(self, messages: Self::Input) -> Result<Self::Output, Self::Error> {
        use elliptic_curve::point::AffineCoordinates;
        let messages = validate_input_messages(messages, &self.pid_list)?;
        let mut s = self.s_i;

        for msg in messages {
            if msg.from_party == self.party_id {
                continue;
            }

            s += msg.s_i;
        }

        let r = self.big_r.to_affine().x();
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&r);
        sig_bytes[32..].copy_from_slice(&s.to_bytes());

        let signature =
            Signature::try_from(sig_bytes.as_ref()).map_err(|_| SignError::InvalidSignature)?;

        let x_only_pubkey = taproot_public_key(&self.public_key).unwrap();
        let tweak: [u8; 32] = Sha256::new()
            .chain_update(TAP_TWEAK_HASH)
            .chain_update(x_only_pubkey.to_bytes())
            .finalize()
            .into();
        let tweak_scalar = Scalar::reduce_from_bytes(&tweak);

        // The spend commits to the even-Y form of the internal key.
        let mut internal_point = self.public_key;
        if internal_point.to_affine().y_is_odd().unwrap_u8() == 1 {
            internal_point = -internal_point;
        }

        let tweaked_pubkey = internal_point + ProjectivePoint::GENERATOR * tweak_scalar;
        taproot_public_key(&tweaked_pubkey)
            .unwrap()
            .verify_prehash(&self.msg_to_sign, &signature)
            .map_err(|_| SignError::InvalidSignature)?;

        let sign_complete = SignComplete {
            from_party: self.party_id,
            session_id: self.session_id,
            signature: sig_bytes,
        };

        Ok((signature, sign_complete))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    use derivation_path::DerivationPath;
    use k256::ProjectivePoint;
    use rand::seq::SliceRandom;

    use crate::common::{
        utils::support::{run_keygen, run_round},
        Bip32Public, Legacy, SoftDeriveChildHmac,
    };

    fn finish_sign_rounds(parties: Vec<SignerParty<R0, k256::ProjectivePoint>>) -> Signature {
        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
        let ready_parties = run_round(parties, msgs);
        let (parties, partial_sigs): (Vec<_>, Vec<_>) =
            run_round(ready_parties, ()).into_iter().unzip();
        let (signatures, _): (Vec<_>, Vec<_>) =
            run_round(parties, partial_sigs).into_iter().unzip();
        signatures[0]
    }

    fn run_sign<F>(shares: Vec<Keyshare<k256::ProjectivePoint>>) -> Signature
    where
        F: SoftDeriveChildHmac<k256::ProjectivePoint>,
    {
        let msg = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
        let msg_hash: [u8; 32] = Sha256::digest(msg).into();
        let path: DerivationPath = "m".parse().unwrap();

        let mut rng = rand::thread_rng();
        let parties = shares
            .into_iter()
            .map(Arc::new)
            .map(|keyshare| {
                SignerParty::<_, k256::ProjectivePoint>::new_with_format::<_, F>(
                    keyshare,
                    msg_hash,
                    path.clone(),
                    &mut rng,
                )
            })
            .collect();

        finish_sign_rounds(parties)
    }

    fn run_sign_via_new(shares: Vec<Keyshare<k256::ProjectivePoint>>) {
        let msg = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
        let msg_hash: [u8; 32] = Sha256::digest(msg).into();
        let path: DerivationPath = "m".parse().unwrap();

        let mut rng = rand::thread_rng();
        let parties = shares
            .into_iter()
            .map(Arc::new)
            .map(|keyshare| {
                SignerParty::<_, k256::ProjectivePoint>::new(
                    keyshare,
                    msg_hash,
                    path.clone(),
                    &mut rng,
                )
            })
            .collect();
        finish_sign_rounds(parties);
    }

    fn run_sign_both_formats<const T: usize, const N: usize, const K: usize>() {
        let shares = run_keygen::<T, N, ProjectivePoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), K)
            .cloned()
            .collect();
        run_sign_via_new(subset.clone());
        run_sign::<Legacy>(subset.clone());
        run_sign::<Bip32Public>(subset);
    }

    /// Derives the output key a Bitcoin node computes for a key-path spend,
    /// which commits to the even-Y form of the signers' internal key.
    fn bip341_output_key(internal_key: &ProjectivePoint) -> ProjectivePoint {
        use elliptic_curve::point::{AffineCoordinates, DecompactPoint};

        let x_only = internal_key.to_affine().x();
        let even_y_internal = ProjectivePoint::from(
            k256::AffinePoint::decompact(&x_only).expect("x coordinate lies on the curve"),
        );
        let tweak: [u8; 32] = Sha256::new()
            .chain_update(TAP_TWEAK_HASH)
            .chain_update(x_only)
            .finalize()
            .into();

        even_y_internal + ProjectivePoint::GENERATOR * Scalar::reduce_from_bytes(&tweak)
    }

    /// Signs under `path` with all shares, returning the signature and the
    /// internal key the signers derived for that path.
    fn sign_at_path(
        shares: &[Keyshare<ProjectivePoint>],
        path: &DerivationPath,
        msg_hash: [u8; 32],
    ) -> (Signature, ProjectivePoint) {
        let (_, internal_key) = shares[0]
            .derive_with_offset::<Legacy>(path)
            .expect("path is soft-derivable");

        let mut rng = rand::thread_rng();
        let parties = shares
            .iter()
            .cloned()
            .map(Arc::new)
            .map(|keyshare| {
                SignerParty::<_, ProjectivePoint>::new_with_format::<_, Legacy>(
                    keyshare,
                    msg_hash,
                    path.clone(),
                    &mut rng,
                )
            })
            .collect();

        (finish_sign_rounds(parties), internal_key)
    }

    /// A key-path signature has to verify against the output key derived from the
    /// signers' internal key, since that is the key the spent output commits to.
    ///
    /// Soft derivation can yield an internal key with an odd Y coordinate, and
    /// signing does not take it to its even-Y form before applying the tweak, so
    /// those paths produce signatures no Bitcoin node accepts. The root key is
    /// unaffected because keygen already normalizes it.
    ///
    /// Remove `#[ignore]` once signing normalizes the internal key.
    #[test]
    fn signature_verifies_against_bip341_output_key() {
        use elliptic_curve::point::AffineCoordinates;
        use signature::hazmat::PrehashVerifier;

        let msg_hash: [u8; 32] = Sha256::digest(b"key-path spend").into();
        let shares = run_keygen::<2, 2, ProjectivePoint>();

        let mut odd_y_paths = 0;
        let mut rejected = Vec::new();

        for path_str in
            core::iter::once("m".into()).chain((0..20u32).map(|index| alloc::format!("m/{index}")))
        {
            let path: DerivationPath = path_str.parse().expect("well-formed path");
            let (signature, internal_key) = sign_at_path(&shares, &path, msg_hash);

            if bool::from(internal_key.to_affine().y_is_odd()) {
                odd_y_paths += 1;
            }

            let output_key = taproot_public_key(&bip341_output_key(&internal_key))
                .expect("output key is a valid x-only key");

            if output_key.verify_prehash(&msg_hash, &signature).is_err() {
                rejected.push(path_str);
            }
        }

        assert!(
            odd_y_paths > 0,
            "no odd-Y internal key was derived, so the test did not exercise the case"
        );
        assert!(
            rejected.is_empty(),
            "signatures rejected under the BIP-341 output key for paths: {rejected:?}"
        );
    }

    /// Hard derivation produces a fresh internal key with natural parity, so a
    /// key-path signature under it must still verify against the output key a
    /// Bitcoin node computes, with or without a soft suffix.
    #[cfg(feature = "vrf")]
    #[test]
    fn taproot_hard_derive_verifies_against_bip341_output_key() {
        use elliptic_curve::point::AffineCoordinates;
        use signature::hazmat::PrehashVerifier;

        use crate::vrf::{
            keyshare_after_hard_derive, run_vrf_keygen, HardDeriveParty, MpcDeriveInit, VrfPoint,
        };

        /// Drives one protocol round for every party.
        fn run_local<I, R, O, E>(actors: Vec<R>, msgs: I) -> Vec<O>
        where
            R: Round<Input = I, Output = O, Error = E>,
            I: Clone,
            E: core::fmt::Debug,
        {
            actors
                .into_iter()
                .map(|actor| actor.process(msgs.clone()).unwrap())
                .collect()
        }

        /// Hard-derives `label` with the full quorum and returns the derived shares.
        fn hard_derive(
            root: &[Keyshare<ProjectivePoint>],
            vrf: &[Keyshare<VrfPoint>],
            label: &[u8],
        ) -> Vec<Keyshare<ProjectivePoint>> {
            let party_ids: Vec<u8> = root.iter().map(|ks| ks.party_id()).collect();
            let inits: Vec<_> = root
                .iter()
                .cloned()
                .zip(vrf.iter().cloned())
                .map(|(r, v)| MpcDeriveInit::with_ristretto_vrf(r, v))
                .collect();

            let mut rng = rand::thread_rng();
            let parties: Vec<_> = inits
                .iter()
                .cloned()
                .map(|init| HardDeriveParty::new(init, label.to_vec(), &mut rng).unwrap())
                .collect();

            let (parties, msgs0): (Vec<_>, Vec<_>) = run_local(parties, ()).into_iter().unzip();
            let (parties, msgs1): (Vec<_>, Vec<_>) = run_local(parties, msgs0).into_iter().unzip();
            let outputs: Vec<_> = run_local(parties, msgs1);

            inits
                .iter()
                .zip(&outputs)
                .map(|(init, out)| keyshare_after_hard_derive(init, out, &party_ids))
                .collect()
        }

        let msg_hash: [u8; 32] = Sha256::digest(b"hard derived key-path spend").into();
        let root = run_keygen::<2, 2, ProjectivePoint>();
        let vrf = run_vrf_keygen::<2, 2>();

        let mut odd_y_cases = 0;
        let mut rejected = Vec::new();

        for index in 0..8u32 {
            let label = alloc::format!("m/{index}'");
            let derived = hard_derive(&root, &vrf, label.as_bytes());

            // With no soft suffix, and with one.
            for suffix in ["m", "m/2"] {
                let path: DerivationPath = suffix.parse().unwrap();
                let (signature, internal_key) = sign_at_path(&derived, &path, msg_hash);

                if bool::from(internal_key.to_affine().y_is_odd()) {
                    odd_y_cases += 1;
                }

                let output_key = taproot_public_key(&bip341_output_key(&internal_key)).unwrap();
                if output_key.verify_prehash(&msg_hash, &signature).is_err() {
                    rejected.push(alloc::format!("{label} + {suffix}"));
                }
            }
        }

        assert!(
            odd_y_cases > 0,
            "no odd-Y internal key was produced, so the test did not exercise the case"
        );
        assert!(
            rejected.is_empty(),
            "signatures rejected under the BIP-341 output key for: {rejected:?}"
        );
    }

    #[test]
    fn sign_2_2() {
        run_sign_both_formats::<2, 2, 2>();
    }

    #[test]
    fn sign_2_3() {
        run_sign_both_formats::<2, 3, 2>();
    }

    #[test]
    fn sign_2_3_3() {
        run_sign_both_formats::<2, 3, 3>();
    }

    #[test]
    fn sign_3_3() {
        run_sign_both_formats::<3, 3, 3>();
    }

    #[test]
    fn sign_3_5() {
        run_sign_both_formats::<3, 5, 3>();
    }

    #[test]
    fn sign_5_10() {
        run_sign_both_formats::<5, 10, 5>();
    }
}

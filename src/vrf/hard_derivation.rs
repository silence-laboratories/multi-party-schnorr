// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! MPC hard derivation (Ristretto VRF + generic signing root).

use std::sync::Arc;

#[cfg(feature = "serde")]
use crate::common::ser::Serializable;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    common::{
        shamir_share_from_additive_share,
        traits::{GroupElem, Round},
    },
    derive::{hard_derive::HardDeriveError as HardDeriveTweakError, HARD_DERIVE_VRF_OUTPUT_BITS},
    keygen::Keyshare,
    vrf::{eval::VrfParty, types::VrfError, VrfPoint},
};

pub use crate::derive::hard_derive::HardDeriveOutput;
pub use crate::vrf::messages::VrfMsg0 as HardDeriveMsg0;

/// VRF round-1 message for hard derivation (Ristretto).
pub type HardDeriveMsg1 = crate::vrf::messages::VrfMsg1;

/// Inputs: root signing DKG keyshare + Ristretto VRF DKG keyshare.
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "S: GroupElem + serde::Serialize, S::Scalar: Serializable",
        deserialize = "S: GroupElem + serde::Deserialize<'de>, S::Scalar: Serializable"
    ))
)]
#[derive(Clone)]
pub struct MpcDeriveInit<S: GroupElem> {
    pub vrf_keyshare: Keyshare<VrfPoint>,
    pub root_keyshare: Keyshare<S>,
}

#[derive(Error, Debug)]
pub enum HardDeriveError {
    #[error(transparent)]
    Derive(#[from] HardDeriveTweakError),
    #[error(transparent)]
    Vrf(#[from] VrfError),
}

/// Hard-derivation party: MPC VRF eval (R0–R2, Ristretto) then local tweak of the root keyshare.
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "T: serde::Serialize, S: GroupElem + serde::Serialize, S::Scalar: Serializable",
        deserialize = "T: serde::Deserialize<'de>, S: GroupElem + serde::Deserialize<'de>, S::Scalar: Serializable"
    ))
)]
pub struct HardDeriveParty<T, S: GroupElem> {
    init: MpcDeriveInit<S>,
    vrf: VrfParty<T, VrfPoint>,
}

pub use crate::vrf::eval::{VrfR0 as HardDeriveR0, VrfR1 as HardDeriveR1};

pub type HardDeriveR2 = crate::vrf::eval::VrfR2<VrfPoint>;

impl<S: GroupElem> MpcDeriveInit<S> {
    pub fn with_ristretto_vrf(
        root_keyshare: Keyshare<S>,
        vrf_keyshare: Keyshare<VrfPoint>,
    ) -> Self {
        Self {
            vrf_keyshare,
            root_keyshare,
        }
    }

    #[inline]
    pub fn new(vrf_keyshare: Keyshare<VrfPoint>, root_keyshare: Keyshare<S>) -> Self {
        Self::with_ristretto_vrf(root_keyshare, vrf_keyshare)
    }

    pub fn party_id(&self) -> u8 {
        self.vrf_keyshare.party_id()
    }

    pub fn root_keyshare(&self) -> &Keyshare<S> {
        &self.root_keyshare
    }

    pub fn vrf_keyshare(&self) -> &Keyshare<VrfPoint> {
        &self.vrf_keyshare
    }
}

impl<S: GroupElem> HardDeriveParty<HardDeriveR0, S> {
    pub fn new<R: RngCore + CryptoRng>(
        init: MpcDeriveInit<S>,
        path: Vec<u8>,
        rng: &mut R,
    ) -> Result<Self, HardDeriveError> {
        let vrf = VrfParty::new_with_output_bits(
            Arc::new(init.vrf_keyshare.clone()),
            path,
            HARD_DERIVE_VRF_OUTPUT_BITS,
            rng,
        )?;
        Ok(Self { init, vrf })
    }
}

impl<S: GroupElem> Round for HardDeriveParty<HardDeriveR0, S> {
    type InputMessage = ();
    type Input = ();
    type Error = HardDeriveError;
    type Output = (HardDeriveParty<HardDeriveR1, S>, HardDeriveMsg0);

    fn process(self, _: ()) -> Result<Self::Output, Self::Error> {
        let (vrf, msg) = self.vrf.process(())?;
        Ok((
            HardDeriveParty {
                init: self.init,
                vrf,
            },
            msg,
        ))
    }
}

impl<S: GroupElem> Round for HardDeriveParty<HardDeriveR1, S> {
    type InputMessage = HardDeriveMsg0;
    type Input = Vec<HardDeriveMsg0>;
    type Error = HardDeriveError;
    type Output = (HardDeriveParty<HardDeriveR2, S>, HardDeriveMsg1);

    fn process(self, msgs: Self::Input) -> Result<Self::Output, Self::Error> {
        let (vrf, msg) = self.vrf.process(msgs)?;
        Ok((
            HardDeriveParty {
                init: self.init,
                vrf,
            },
            msg,
        ))
    }
}

impl<S> Round for HardDeriveParty<HardDeriveR2, S>
where
    S: GroupElem + crate::derive::traits::HardDeriveSigning,
{
    type InputMessage = HardDeriveMsg1;
    type Input = Vec<HardDeriveMsg1>;
    type Error = HardDeriveError;
    type Output = HardDeriveOutput<S>;

    fn process(self, msgs: Self::Input) -> Result<Self::Output, Self::Error> {
        let vrf_out = self.vrf.process(msgs)?;
        let threshold = self.init.vrf_keyshare.threshold;
        HardDeriveOutput::apply_hard_derive(
            &self.init.root_keyshare,
            &vrf_out.output,
            threshold,
            &vrf_out.pid_list,
        )
        .map_err(HardDeriveError::Derive)
    }
}

/// Build a [`Keyshare`] for DSG from hard-derivation output (same participant set as VRF).
pub fn keyshare_after_hard_derive<S: GroupElem>(
    init: &MpcDeriveInit<S>,
    output: &HardDeriveOutput<S>,
    participating_party_ids: &[u8],
) -> Keyshare<S> {
    let d_i = shamir_share_from_additive_share::<S>(
        output.xi_prime,
        init.root_keyshare.party_id(),
        participating_party_ids.iter().copied(),
    );

    let key_id = Sha256::digest(output.public_key_prime.to_bytes()).into();

    Keyshare {
        threshold: init.root_keyshare.threshold,
        total_parties: init.root_keyshare.total_parties,
        party_id: init.root_keyshare.party_id(),
        d_i,
        public_key: output.public_key_prime,
        party_public_shares: output.party_public_shares_prime.clone(),
        key_id,
        extra_data: init.root_keyshare.extra_data.clone(),
        root_chain_code: output.chain_code,
        #[cfg(feature = "keyshare-session-id")]
        final_session_id: init.root_keyshare.final_session_id,
    }
}

#[cfg(all(test, feature = "vrf", feature = "test-support"))]
mod tests {
    use std::str::FromStr;

    use curve25519_dalek::EdwardsPoint;
    use derivation_path::DerivationPath;
    use ed25519_dalek::{Verifier, VerifyingKey};
    use elliptic_curve::Group;

    use super::*;
    use crate::{
        common::utils::support::{run_keygen, run_round},
        derive::{
            delta_from_vrf, hard_derive::HardDeriveError as HardDeriveTweakError,
            traits::HardDeriveSigning, HardDeriveOutputEd25519, HardDerivePartyEd25519,
            MpcDeriveInitEd25519, HARD_DERIVE_DELTA_BYTES,
        },
        sign::eddsa::{run_sign, TEST_SIGN_MESSAGE},
        vrf::run_vrf_keygen,
    };

    fn mpc_derive_init<const T: usize, const N: usize>() -> [MpcDeriveInitEd25519; N] {
        let vrf_shares = run_vrf_keygen::<T, N>();
        let root_shares = run_keygen::<T, N, EdwardsPoint>();
        vrf_shares
            .into_iter()
            .zip(root_shares)
            .map(|(vrf, root)| MpcDeriveInit::with_ristretto_vrf(root, vrf))
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| panic!("wrong init array length"))
            .unwrap()
    }

    fn run_hard_derive(
        inits: Vec<MpcDeriveInitEd25519>,
        path: &[u8],
        threshold: usize,
    ) -> Vec<HardDeriveOutputEd25519> {
        let mut rng = rand::thread_rng();
        let parties: Vec<_> = inits
            .iter()
            .cloned()
            .map(|init| HardDerivePartyEd25519::new(init, path.to_vec(), &mut rng).unwrap())
            .collect();

        let (parties, msgs0): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
        let parties: Vec<_> = parties.into_iter().take(threshold).collect();
        let msgs0: Vec<_> = msgs0.into_iter().take(threshold).collect();

        let (parties, msgs1): (Vec<_>, Vec<_>) = run_round(parties, msgs0).into_iter().unzip();
        run_round(parties, msgs1)
    }

    #[test]
    fn mpc_hard_derive_2_of_3() {
        let inits: Vec<_> = mpc_derive_init::<2, 3>().to_vec();
        let path = b"m/44'/0'/0'";
        let q_root = inits[0].root_keyshare.public_key;
        let participating = vec![0u8, 1u8];

        let outputs = run_hard_derive(inits.clone(), path, 2);
        assert_eq!(outputs.len(), 2);

        let q_prime = outputs[0].public_key_prime;
        let chain = outputs[0].chain_code;
        for out in &outputs[1..] {
            assert_eq!(out.public_key_prime, q_prime);
            assert_eq!(out.chain_code, chain);
            assert_eq!(
                out.party_public_shares_prime,
                outputs[0].party_public_shares_prime
            );
        }

        assert_ne!(q_prime, q_root);

        let mut sum_active = EdwardsPoint::identity();
        for pid in 0u8..2 {
            sum_active += outputs[0].party_public_shares_prime[pid as usize];
        }
        assert_eq!(sum_active, q_prime);

        let derived_keyshares: Vec<_> = inits
            .iter()
            .take(2)
            .zip(&outputs)
            .map(|(init, out)| keyshare_after_hard_derive(init, out, &participating))
            .collect();
        for (out, ks) in outputs.iter().zip(&derived_keyshares) {
            assert_eq!(
                ks.scalar_share_interpolate(participating.clone()),
                out.xi_prime
            );
        }

        let soft_path = DerivationPath::from_str("m/0/1").unwrap();
        let mut expected_soft_pk = None;
        for ks in &derived_keyshares {
            let (_additive_offset, soft_pk) = ks
                .derive_with_offset::<crate::common::Bip32Public>(&soft_path)
                .unwrap();
            if let Some(expected) = expected_soft_pk {
                assert_eq!(expected, soft_pk);
            } else {
                expected_soft_pk = Some(soft_pk);
            }
        }
        let expected_soft_pk = expected_soft_pk.unwrap();

        let sig = run_sign::<crate::common::Bip32Public>(derived_keyshares, "m/0/1");
        VerifyingKey::from(expected_soft_pk)
            .verify(TEST_SIGN_MESSAGE, &sig)
            .expect("press the red button");
    }

    #[test]
    fn mpc_hard_derive_full_quorum() {
        let inits: Vec<_> = mpc_derive_init::<2, 2>().to_vec();
        let participating = vec![0u8, 1u8];
        let outputs = run_hard_derive(inits.clone(), b"root/hard", 2);
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].public_key_prime, outputs[1].public_key_prime);

        let derived_keyshares: Vec<_> = inits
            .into_iter()
            .zip(outputs)
            .map(|(init, out)| keyshare_after_hard_derive(&init, &out, &participating))
            .collect();
        let _sig = run_sign::<crate::common::Legacy>(derived_keyshares, "m/0");
    }

    #[test]
    fn split_vrf_output_rejects_wrong_length() {
        assert!(matches!(
            HardDeriveOutput::<EdwardsPoint>::split_vrf_output(&[0u8; 1]),
            Err(HardDeriveTweakError::InvalidVrfOutputLength)
        ));
    }

    #[test]
    fn hard_derive_signing_trait_matches_legacy_delta_from_vrf() {
        let delta_prime = vec![0x42u8; HARD_DERIVE_DELTA_BYTES];
        assert_eq!(
            delta_from_vrf(&delta_prime),
            EdwardsPoint::delta_from_vrf(&delta_prime)
        );
    }
}

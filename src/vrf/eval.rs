// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! MPC-friendly VRF evaluation — thin [`Round`] adapter over [`sl_mpc_vrf`].

use std::{marker::PhantomData, sync::Arc};

use curve25519_dalek::Scalar as RScalar;
use rand::{CryptoRng, RngCore};
use sl_mpc_derive::{VrfPoint, ED25519_VRF_OUTPUT_BITS};
use sl_mpc_vrf::{eval::Context, VrfMsg0, VrfMsg1};

pub use sl_mpc_vrf::VrfOutput;

use crate::{
    common::traits::{GroupElem, Round},
    derive::impls::ristretto::{VrfGroup, VrfScalar},
    keygen::Keyshare,
    vrf::types::VrfError,
};

/// VRF evaluation party (multi-round, t-of-n) over curve group `G`.
///
/// Protocol logic lives in [`sl_mpc_vrf`]; this type only maps [`Round`] transitions.
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "T: serde::Serialize, G: GroupElem + serde::Serialize",
        deserialize = "T: serde::Deserialize<'de>, G: GroupElem + serde::Deserialize<'de>"
    ))
)]
pub struct VrfParty<T, G: GroupElem> {
    ctx: Context,
    _phase: PhantomData<(T, G)>,
}

/// Production VRF on Ristretto (`VrfParty<State, VrfPoint>`).
pub type VrfPartyRistretto<State> = VrfParty<State, VrfPoint>;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VrfR0;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VrfR1;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VrfR2<G: GroupElem> {
    _marker: PhantomData<G>,
}

impl<G> VrfParty<VrfR0, G>
where
    G: GroupElem + VrfGroup,
    G::Scalar: VrfScalar + Into<RScalar>,
    G: Into<VrfPoint>,
{
    pub fn new<R: RngCore + CryptoRng>(
        keyshare: Arc<Keyshare<G>>,
        message: Vec<u8>,
        rng: &mut R,
    ) -> Result<Self, VrfError> {
        Self::new_with_output_bits(keyshare, message, ED25519_VRF_OUTPUT_BITS, rng)
    }

    pub fn new_with_output_bits<R: RngCore + CryptoRng>(
        keyshare: Arc<Keyshare<G>>,
        message: Vec<u8>,
        output_bits: usize,
        rng: &mut R,
    ) -> Result<Self, VrfError> {
        let ks = keyshare.as_ref();
        #[cfg(feature = "keyshare-session-id")]
        let keygen_session_id = Some(ks.final_session_id);
        #[cfg(not(feature = "keyshare-session-id"))]
        let keygen_session_id = None;

        let ctx = Context::new_with_output_bits(
            ks.party_id(),
            ks.threshold,
            ks.total_parties,
            message,
            output_bits,
            (*ks.shamir_share()).into(),
            ks.public_key.into(),
            ks.party_public_shares
                .iter()
                .copied()
                .map(Into::into)
                .collect(),
            keygen_session_id,
            rng,
        )?;

        Ok(Self {
            ctx,
            _phase: PhantomData,
        })
    }
}

impl<G> Round for VrfParty<VrfR0, G>
where
    G: GroupElem + VrfGroup,
    G::Scalar: VrfScalar,
{
    type InputMessage = ();
    type Input = ();
    type Error = VrfError;
    type Output = (VrfParty<VrfR1, G>, VrfMsg0);

    fn process(self, _: ()) -> Result<Self::Output, Self::Error> {
        let mut ctx = self.ctx;
        let msg = ctx.round0_out()?;
        Ok((
            VrfParty {
                ctx,
                _phase: PhantomData,
            },
            msg,
        ))
    }
}

impl<G> Round for VrfParty<VrfR1, G>
where
    G: GroupElem + VrfGroup,
    G::Scalar: VrfScalar,
{
    type InputMessage = VrfMsg0;
    type Input = Vec<VrfMsg0>;
    type Error = VrfError;
    type Output = (VrfParty<VrfR2<G>, G>, VrfMsg1);

    fn process(self, msgs: Self::Input) -> Result<Self::Output, Self::Error> {
        let mut ctx = self.ctx;
        let msg = ctx.round0_in(msgs, None)?;
        Ok((
            VrfParty {
                ctx,
                _phase: PhantomData,
            },
            msg,
        ))
    }
}

impl<G> Round for VrfParty<VrfR2<G>, G>
where
    G: GroupElem + VrfGroup,
    G::Scalar: VrfScalar,
{
    type InputMessage = VrfMsg1;
    type Input = Vec<VrfMsg1>;
    type Error = VrfError;
    type Output = VrfOutput;

    fn process(self, msgs: Self::Input) -> Result<Self::Output, Self::Error> {
        self.ctx.round1_in(msgs)
    }
}

/// Run the full MPC VRF protocol locally (all parties, full quorum).
#[cfg(feature = "test-support")]
pub fn run_vrf_mpc_full<R: RngCore + CryptoRng>(
    keyshares: Vec<Keyshare<VrfPoint>>,
    message: Vec<u8>,
    output_bits: usize,
    rng: &mut R,
) -> Vec<u8> {
    use crate::common::utils::support::run_round;

    let parties: Vec<_> = keyshares
        .into_iter()
        .map(|ks| {
            VrfParty::<VrfR0, VrfPoint>::new_with_output_bits(
                Arc::new(ks),
                message.clone(),
                output_bits,
                rng,
            )
            .unwrap()
        })
        .collect();

    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
    let outputs: Vec<VrfOutput> = run_round(parties, msgs);
    let y = outputs[0].output.clone();
    assert!(outputs.iter().all(|o| o.output == y));
    y
}

/// Run MPC VRF with the first threshold parties (by party id order).
#[cfg(feature = "test-support")]
pub fn run_vrf_mpc_threshold<R: RngCore + CryptoRng>(
    keyshares: Vec<Keyshare<VrfPoint>>,
    message: Vec<u8>,
    output_bits: usize,
    threshold: usize,
    rng: &mut R,
) -> Vec<u8> {
    use crate::common::utils::support::run_round;

    let parties: Vec<_> = keyshares
        .into_iter()
        .map(|ks| {
            VrfParty::<VrfR0, VrfPoint>::new_with_output_bits(
                Arc::new(ks),
                message.clone(),
                output_bits,
                rng,
            )
            .unwrap()
        })
        .collect();

    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
    let subset: Vec<_> = parties.into_iter().take(threshold).collect();
    let subset_msgs: Vec<_> = msgs.into_iter().take(threshold).collect();
    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(subset, subset_msgs).into_iter().unzip();
    let outputs: Vec<VrfOutput> = run_round(parties, msgs);
    let y = outputs[0].output.clone();
    assert!(outputs.iter().all(|o| o.output == y));
    y
}

#[cfg(all(test, feature = "vrf"))]
mod tests {
    use super::*;
    use crate::common::utils::support::run_round;
    use crate::vrf::run_vrf_keygen;

    #[test]
    fn new_rejects_malformed_keyshare_public_shares_len() {
        let mut ks = run_vrf_keygen::<2, 3>()[0].clone();
        ks.party_public_shares.pop();
        assert!(matches!(
            VrfParty::<VrfR0, VrfPoint>::new(Arc::new(ks), vec![], &mut rand::thread_rng()),
            Err(VrfError::InvalidKeyshare)
        ));
    }

    #[test]
    fn new_rejects_malformed_keyshare_party_id() {
        let mut ks = run_vrf_keygen::<2, 3>()[0].clone();
        ks.party_id = ks.total_parties;
        assert!(matches!(
            VrfParty::<VrfR0, VrfPoint>::new(Arc::new(ks), vec![], &mut rand::thread_rng()),
            Err(VrfError::InvalidKeyshare)
        ));
    }

    #[test]
    fn vrf_eval_threshold_subset() {
        let keyshares = run_vrf_keygen::<2, 3>();
        let message = b"threshold-vrf".to_vec();
        let parties: Vec<_> = keyshares
            .into_iter()
            .map(|ks| {
                VrfParty::<VrfR0, VrfPoint>::new(
                    Arc::new(ks),
                    message.clone(),
                    &mut rand::thread_rng(),
                )
                .unwrap()
            })
            .collect();

        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
        let subset: Vec<_> = parties.into_iter().take(2).collect();
        let subset_msgs: Vec<_> = msgs.into_iter().take(2).collect();
        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(subset, subset_msgs).into_iter().unzip();
        let outputs: Vec<_> = run_round(parties, msgs);
        assert_eq!(outputs[0].output, outputs[1].output);
    }
}

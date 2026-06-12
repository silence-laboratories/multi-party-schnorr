// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Shamir VRF DKG — thin [`Round`] adapter over [`sl_mpc_vrf::dkg::Context`].

use std::marker::PhantomData;

use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sl_mpc_derive::VrfPoint;
use sl_mpc_vrf::dkg::{Context, VrfKeyshare};

pub use sl_mpc_vrf::dkg::{Party, VrfKeygenError, VrfKeygenMsg1, VrfKeygenMsg2};

use crate::{common::traits::Round, keygen::Keyshare};

/// VRF DKG party (multi-round, t-of-n) on Ristretto.
///
/// Protocol logic lives in [`sl_mpc_vrf`]; this type only maps [`Round`] transitions.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VrfDkgParty<T> {
    ctx: Context,
    seed: [u8; 32],
    #[cfg_attr(feature = "serde", serde(skip))]
    _phase: PhantomData<T>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VrfDkgR0;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VrfDkgR1;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VrfDkgR2;

impl VrfDkgParty<VrfDkgR0> {
    pub fn new<R: RngCore + CryptoRng>(
        party: Party,
        seed: [u8; 32],
        rng: &mut R,
    ) -> Result<Self, VrfKeygenError> {
        Ok(Self {
            ctx: Context::new(party, rng)?,
            seed,
            _phase: PhantomData,
        })
    }
}

impl Round for VrfDkgParty<VrfDkgR0> {
    type InputMessage = ();
    type Input = ();
    type Error = VrfKeygenError;
    type Output = (VrfDkgParty<VrfDkgR1>, VrfKeygenMsg1);

    fn process(self, _: ()) -> Result<Self::Output, Self::Error> {
        let mut ctx = self.ctx;
        let mut rng = ChaCha20Rng::from_seed(self.seed);
        let msg = ctx.round1_out(&mut rng)?;
        Ok((
            VrfDkgParty {
                ctx,
                seed: rng.gen(),
                _phase: PhantomData,
            },
            msg,
        ))
    }
}

impl Round for VrfDkgParty<VrfDkgR1> {
    type InputMessage = VrfKeygenMsg1;
    type Input = Vec<VrfKeygenMsg1>;
    type Error = VrfKeygenError;
    type Output = (VrfDkgParty<VrfDkgR2>, VrfKeygenMsg2);

    fn process(self, messages: Self::Input) -> Result<Self::Output, Self::Error> {
        let mut ctx = self.ctx;
        let mut rng = ChaCha20Rng::from_seed(self.seed);
        let msg = ctx.round1_in(&mut rng, messages)?;
        Ok((
            VrfDkgParty {
                ctx,
                seed: rng.gen(),
                _phase: PhantomData,
            },
            msg,
        ))
    }
}

impl Round for VrfDkgParty<VrfDkgR2> {
    type InputMessage = VrfKeygenMsg2;
    type Input = Vec<VrfKeygenMsg2>;
    type Error = VrfKeygenError;
    type Output = Keyshare<VrfPoint>;

    fn process(mut self, messages: Self::Input) -> Result<Self::Output, Self::Error> {
        let share = self.ctx.round2_in(messages)?;
        Ok(keyshare_from_vrf(share))
    }
}

fn run_round_local<I, R, O, E>(actors: impl IntoIterator<Item = R>, msgs: I) -> Vec<O>
where
    R: Round<Input = I, Output = O, Error = E>,
    I: Clone,
    E: std::fmt::Debug,
{
    actors
        .into_iter()
        .map(|actor| actor.process(msgs.clone()).unwrap())
        .collect()
}

fn keyshare_from_vrf(share: VrfKeyshare) -> Keyshare<VrfPoint> {
    Keyshare {
        threshold: share.threshold,
        total_parties: share.total_parties,
        party_id: share.party_id,
        d_i: *share.shamir_share(),
        public_key: share.public_key,
        party_public_shares: share.party_public_shares().to_vec(),
        key_id: share.key_id,
        extra_data: None,
        root_chain_code: share.root_chain_code,
        #[cfg(feature = "keyshare-session-id")]
        final_session_id: share.final_session_id,
    }
}

/// Initialize VRF DKG parties for a full quorum (`n` parties, threshold `t`).
pub fn setup_vrf_keygen(
    t: u8,
    n: u8,
) -> Result<Vec<VrfDkgParty<VrfDkgR0>>, VrfKeygenError> {
    let mut rng = rand::thread_rng();

    (0..n)
        .map(|party_id| VrfDkgParty::new(Party::new(n, t, party_id), rng.gen(), &mut rng))
        .collect()
}

/// Run the full VRF DKG protocol locally (all parties, full quorum).
#[cfg(any(test, feature = "test-support"))]
pub fn run_vrf_keygen<const T: usize, const N: usize>() -> [Keyshare<VrfPoint>; N] {
    let actors = setup_vrf_keygen(T as u8, N as u8).expect("valid test parameters");

    let (actors, msgs): (Vec<_>, Vec<_>) = run_round_local(actors, ()).into_iter().unzip();
    let (actors, msgs): (Vec<_>, Vec<_>) = run_round_local(actors, msgs).into_iter().unzip();

    run_round_local(actors, msgs)
        .try_into()
        .map_err(|_| panic!("Failed to convert VRF keyshares"))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_shared_vrf_state(shares: &[Keyshare<VrfPoint>]) {
        let reference = &shares[0];
        let pk = reference.public_key();
        let chain = reference.root_chain_code;
        let key_id = reference.key_id;
        #[cfg(feature = "keyshare-session-id")]
        let final_sid = reference.final_session_id;
        let additive_shares = reference.party_public_shares();

        for share in &shares[1..] {
            assert_eq!(share.public_key(), pk);
            assert_eq!(share.root_chain_code, chain);
            assert_eq!(share.key_id, key_id);
            #[cfg(feature = "keyshare-session-id")]
            assert_eq!(share.final_session_id, final_sid);
            assert_eq!(share.party_public_shares(), additive_shares);
        }

        let sum: VrfPoint = additive_shares.iter().sum();
        assert_eq!(sum, *pk);
    }

    #[test]
    fn vrf_dkg_3_out_of_3() {
        let shares = run_vrf_keygen::<3, 3>();
        assert_eq!(shares.len(), 3);
        assert_shared_vrf_state(&shares);
    }

    #[test]
    fn vrf_dkg_2_out_of_3() {
        let shares = run_vrf_keygen::<2, 3>();
        assert_eq!(shares.len(), 3);
        assert_shared_vrf_state(&shares);
    }
}

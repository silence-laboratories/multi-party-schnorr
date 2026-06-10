// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! RedDSA signing for RedPallas, compatible with Zcash reddsa verification.
//! Challenge: BLAKE2b-512 with personalization "Zcash_RedPallasH", then R || vk || message, reduced to scalar.
//! See: https://github.com/ZcashFoundation/reddsa

use blake2b_simd::Params;
use ff::{FromUniformBytes, PrimeField};
use group::GroupEncoding;
use pasta_curves::Fq;
use reddsa::orchard::SpendAuth;
use reddsa::{Signature, VerificationKey};

use crate::common::redpallas::RedPallasPoint;
use crate::common::traits::Round;

use super::{
    messages::{SignComplete, SignMsg3},
    validate_input_messages, PartialSign, SignError, SignReady,
};

const REDPALLAS_H_STAR_PERSONALIZATION: [u8; 16] = *b"Zcash_RedPallasH";

fn reddsa_challenge(r_bytes: &[u8], vk_bytes: &[u8], message: &[u8]) -> Fq {
    let hash = Params::new()
        .hash_length(64)
        .personal(&REDPALLAS_H_STAR_PERSONALIZATION)
        .to_state()
        .update(r_bytes)
        .update(vk_bytes)
        .update(message)
        .finalize();
    <Fq as FromUniformBytes<64>>::from_uniform_bytes(hash.as_array())
}

fn reddsa_verify(
    vk_bytes: &[u8; 32],
    message: &[u8],
    sig_bytes: &[u8; 64],
) -> Result<(), SignError> {
    let vk = VerificationKey::<SpendAuth>::try_from(*vk_bytes)
        .map_err(|_| SignError::InvalidSignature)?;
    let sig = Signature::<SpendAuth>::from(*sig_bytes);
    vk.verify(message, &sig)
        .map_err(|_| SignError::InvalidSignature)
}

impl Round for SignReady<RedPallasPoint> {
    type InputMessage = ();
    type Input = ();
    type Error = SignError;
    type Output = (PartialSign<RedPallasPoint>, SignMsg3<RedPallasPoint>);

    fn process(self, _: Self::Input) -> Result<Self::Output, Self::Error> {
        let r_bytes = self.big_r.to_bytes();
        let vk_bytes = self.public_key.to_bytes();

        let c = reddsa_challenge(r_bytes.as_ref(), vk_bytes.as_ref(), &self.message);

        let s_i = self.k_i + self.d_i * c;

        let msg3 = SignMsg3 {
            from_party: self.party_id,
            session_id: self.session_id,
            s_i,
        };

        let next = PartialSign {
            party_id: self.party_id,
            session_id: self.session_id,
            public_key: self.public_key,
            big_r: self.big_r,
            s_i,
            msg_to_sign: self.message,
            pid_list: self.pid_list,
        };

        Ok((next, msg3))
    }
}

impl Round for PartialSign<RedPallasPoint> {
    type InputMessage = SignMsg3<RedPallasPoint>;
    type Input = Vec<SignMsg3<RedPallasPoint>>;
    type Error = SignError;
    type Output = ([u8; 64], SignComplete);

    fn process(self, messages: Self::Input) -> Result<Self::Output, Self::Error> {
        let messages = validate_input_messages(messages, &self.pid_list)?;
        let mut s = self.s_i;
        for msg in messages {
            if msg.from_party == self.party_id {
                continue;
            }
            s += msg.s_i;
        }

        let r_bytes = self.big_r.to_bytes();
        let vk_bytes = self.public_key.to_bytes();

        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(s.to_repr().as_ref());

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(r_bytes.as_ref());
        sig_bytes[32..].copy_from_slice(&s_bytes);

        let vk_arr: [u8; 32] = vk_bytes
            .as_ref()
            .try_into()
            .map_err(|_| SignError::InvalidSignature)?;

        reddsa_verify(&vk_arr, &self.msg_to_sign, &sig_bytes)?;

        let sign_complete = SignComplete {
            from_party: self.party_id,
            session_id: self.session_id,
            signature: sig_bytes,
        };

        Ok((sig_bytes, sign_complete))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rand::seq::SliceRandom;

    use super::*;
    use crate::{
        common::{
            utils::support::{run_keygen, run_round},
            Bip32Public, Legacy, SoftDeriveChildHmac,
        },
        keygen::Keyshare,
        sign::{SignerParty, R0},
    };

    fn finish_sign_rounds(parties: Vec<SignerParty<R0, RedPallasPoint>>) -> [u8; 64] {
        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
        let (ready_parties, _alphas): (Vec<_>, Vec<_>) =
            run_round(parties, msgs).into_iter().unzip();
        let (parties, partial_sigs): (Vec<_>, Vec<_>) =
            run_round(ready_parties, ()).into_iter().unzip();
        let (signatures, _): (Vec<_>, Vec<_>) =
            run_round(parties, partial_sigs).into_iter().unzip();
        signatures[0]
    }

    fn run_sign<F>(shares: Vec<Keyshare<RedPallasPoint>>) -> [u8; 64]
    where
        F: SoftDeriveChildHmac<RedPallasPoint>,
    {
        let msg = b"BitGo rules them all";
        let path: derivation_path::DerivationPath = "m/0".parse().unwrap();
        let mut rng = rand::thread_rng();

        let parties = shares
            .into_iter()
            .map(Arc::new)
            .map(|keyshare| {
                SignerParty::<_, RedPallasPoint>::new_with_format::<_, F>(
                    keyshare,
                    msg.to_vec(),
                    path.clone(),
                    &mut rng,
                )
            })
            .collect();

        finish_sign_rounds(parties)
    }

    fn assert_bip32_public_derivation_unsupported(shares: &[Keyshare<RedPallasPoint>]) {
        let path = "m/0".parse().unwrap();
        for ks in shares {
            assert!(
                ks.derive_with_offset::<Bip32Public>(&path).is_err(),
                "Bip32Public is not supported on RedPallas"
            );
        }
    }

    fn run_sign_via_new(shares: Vec<Keyshare<RedPallasPoint>>) {
        let msg = b"BitGo rules them all";
        let path: derivation_path::DerivationPath = "m/0".parse().unwrap();
        let mut rng = rand::thread_rng();
        let parties = shares
            .into_iter()
            .map(Arc::new)
            .map(|keyshare| {
                SignerParty::<_, RedPallasPoint>::new(
                    keyshare,
                    msg.to_vec(),
                    path.clone(),
                    &mut rng,
                )
            })
            .collect();
        finish_sign_rounds(parties);
    }

    fn run_sign_both_formats<const T: usize, const N: usize, const K: usize>() {
        let shares = run_keygen::<T, N, RedPallasPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), K)
            .cloned()
            .collect();
        run_sign_via_new(subset.clone());
        run_sign::<Legacy>(subset.clone());
        assert_bip32_public_derivation_unsupported(&subset);
    }

    #[test]
    fn alpha_consistent_across_parties() {
        let shares = run_keygen::<2, 3, RedPallasPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 2)
            .cloned()
            .collect();
        let msg = b"test alpha consistency";
        let path: derivation_path::DerivationPath = "m/0".parse().unwrap();
        let mut rng = rand::thread_rng();
        let parties: Vec<SignerParty<_, RedPallasPoint>> = subset
            .into_iter()
            .map(Arc::new)
            .map(|ks| SignerParty::<_, RedPallasPoint>::new(ks, msg.to_vec(), path.clone(), &mut rng))
            .collect();
        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
        let (_, alphas): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
        // All parties must compute the same alpha.
        assert_eq!(alphas[0], alphas[1]);
        // Alpha must be non-zero (randomization is applied).
        assert_ne!(alphas[0], pasta_curves::Fq::from(0u64));
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
    fn sign_3_5() {
        run_sign_both_formats::<3, 5, 3>();
    }
}

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
        common::utils::support::{run_keygen, run_round},
        keygen::Keyshare,
        sign::SignerParty,
    };

    fn run_sign(shares: Vec<Keyshare<RedPallasPoint>>) -> [u8; 64] {
        let msg = b"BitGo rules them all";

        let mut rng = rand::thread_rng();

        let parties = shares
            .into_iter()
            .map(Arc::new)
            .map(|keyshare| {
                SignerParty::<_, RedPallasPoint>::new(
                    keyshare,
                    msg.to_vec(),
                    "m/0".parse().unwrap(),
                    &mut rng,
                )
            })
            .collect::<Vec<_>>();

        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
        let ready_parties = run_round(parties, msgs);

        let (parties, partial_sigs): (Vec<_>, Vec<_>) =
            run_round(ready_parties, ()).into_iter().unzip();

        let (signatures, _complete_msg): (Vec<_>, Vec<_>) =
            run_round(parties, partial_sigs).into_iter().unzip();

        signatures[0]
    }

    #[test]
    fn sign_2_2() {
        let shares = run_keygen::<2, 2, RedPallasPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 2)
            .cloned()
            .collect();
        run_sign(subset);
    }

    #[test]
    fn sign_2_3() {
        let shares = run_keygen::<2, 3, RedPallasPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 2)
            .cloned()
            .collect();
        run_sign(subset);
    }

    #[test]
    fn sign_3_5() {
        let shares = run_keygen::<3, 5, RedPallasPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 3)
            .cloned()
            .collect();
        run_sign(subset);
    }
}

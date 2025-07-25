// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use curve25519_dalek::{EdwardsPoint, Scalar};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use elliptic_curve::group::GroupEncoding;
use sha2::{Digest, Sha512};

use crate::common::traits::Round;

use super::{
    messages::{SignComplete, SignMsg3},
    validate_input_messages, PartialSign, SignError, SignReady,
};

impl Round for SignReady<EdwardsPoint> {
    type Input = ();

    type Output = Result<(PartialSign<EdwardsPoint>, SignMsg3<EdwardsPoint>), SignError>;

    /// The signer party processes the message to sign and returns the partial signature
    /// # Arguments
    fn process(self, _: Self::Input) -> Self::Output {
        let big_a = self.public_key.to_bytes();

        let digest = Sha512::new()
            .chain_update(self.big_r.to_bytes())
            .chain_update(big_a)
            .chain_update(&self.message)
            .finalize()
            .into();

        let e = Scalar::from_bytes_mod_order_wide(&digest);
        let s_i = self.k_i + self.d_i * e;

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

impl Round for PartialSign<EdwardsPoint> {
    type Input = Vec<SignMsg3<EdwardsPoint>>;

    type Output = Result<(Signature, SignComplete), SignError>;

    fn process(self, messages: Self::Input) -> Self::Output {
        let messages = validate_input_messages(messages, &self.pid_list)?;
        let mut s = self.s_i;
        for msg in messages {
            if msg.from_party == self.party_id {
                continue;
            }
            s += msg.s_i;
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&self.big_r.to_bytes());
        sig_bytes[32..].copy_from_slice(&s.to_bytes());
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        VerifyingKey::from(self.public_key)
            .verify(&self.msg_to_sign, &signature)
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

    use curve25519_dalek::EdwardsPoint;
    use rand::seq::SliceRandom;

    use super::*;

    use crate::{
        common::utils::{run_keygen, run_round},
        keygen::Keyshare,
        sign::SignerParty,
    };

    fn run_sign(shares: Vec<Keyshare<EdwardsPoint>>) -> Signature {
        let msg = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";

        let mut rng = rand::thread_rng();

        let parties = shares
            .into_iter()
            .map(Arc::new)
            .map(|keyshare| {
                SignerParty::<_, EdwardsPoint>::new(
                    keyshare,
                    msg.into(),
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
        let shares = run_keygen::<2, 2, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 2)
            .cloned()
            .collect();
        run_sign(subset);
    }

    #[test]
    fn sign_2_3() {
        let shares = run_keygen::<2, 3, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 2)
            .cloned()
            .collect();
        run_sign(subset);
    }

    #[test]
    fn sign_2_3_3() {
        let shares = run_keygen::<2, 3, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 3)
            .cloned()
            .collect();
        run_sign(subset);
    }

    #[test]
    fn sign_3_3() {
        let shares = run_keygen::<3, 3, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 3)
            .cloned()
            .collect();
        run_sign(subset);
    }

    #[test]
    fn sign_3_5() {
        let shares = run_keygen::<3, 5, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 3)
            .cloned()
            .collect();
        run_sign(subset);
    }

    #[test]
    fn sign_5_10() {
        let shares = run_keygen::<5, 10, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 5)
            .cloned()
            .collect();
        run_sign(subset);
    }
}

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
    type InputMessage = ();
    type Input = ();
    type Error = SignError;
    type Output = (PartialSign<EdwardsPoint>, SignMsg3<EdwardsPoint>);

    /// The signer party processes the message to sign and returns the partial signature
    /// # Arguments
    fn process(self, _: Self::Input) -> Result<Self::Output, Self::Error> {
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
    type InputMessage = SignMsg3<EdwardsPoint>;
    type Input = Vec<SignMsg3<EdwardsPoint>>;
    type Error = SignError;
    type Output = (Signature, SignComplete);

    fn process(self, messages: Self::Input) -> Result<Self::Output, Self::Error> {
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

#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) const TEST_SIGN_MESSAGE: &[u8] = b"press the blue button";

#[cfg(any(test, feature = "test-support"))]
fn finish_sign_rounds(
    parties: Vec<crate::sign::SignerParty<crate::sign::R0, EdwardsPoint>>,
) -> Signature {
    use crate::common::utils::support::run_round;

    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
    let ready_parties = run_round(parties, msgs);
    let (parties, partial_sigs): (Vec<_>, Vec<_>) =
        run_round(ready_parties, ()).into_iter().unzip();
    let (signatures, _): (Vec<_>, Vec<_>) = run_round(parties, partial_sigs).into_iter().unzip();
    signatures[0]
}

#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn run_sign<F>(
    shares: Vec<crate::keygen::Keyshare<EdwardsPoint>>,
    derivation_path: &str,
) -> Signature
where
    F: crate::common::SoftDeriveChildHmac<EdwardsPoint>,
{
    use std::sync::Arc;

    use crate::sign::SignerParty;

    let path: derivation_path::DerivationPath = derivation_path.parse().unwrap();
    let mut rng = rand::thread_rng();

    let parties = shares
        .into_iter()
        .map(Arc::new)
        .map(|keyshare| {
            SignerParty::<_, EdwardsPoint>::new_with_format::<_, F>(
                keyshare,
                TEST_SIGN_MESSAGE.to_vec(),
                path.clone(),
                &mut rng,
            )
        })
        .collect();

    finish_sign_rounds(parties)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use curve25519_dalek::EdwardsPoint;
    use derivation_path::DerivationPath;
    use rand::seq::SliceRandom;

    use super::*;

    use crate::common::{utils::support::run_keygen, Bip32Public, Legacy};
    use crate::sign::SignerParty;

    fn run_sign_via_new(shares: Vec<crate::keygen::Keyshare<EdwardsPoint>>, derivation_path: &str) {
        let mut rng = rand::thread_rng();
        let path: DerivationPath = derivation_path.parse().unwrap();
        let parties = shares
            .into_iter()
            .map(Arc::new)
            .map(|keyshare| {
                SignerParty::<_, EdwardsPoint>::new(
                    keyshare,
                    TEST_SIGN_MESSAGE.to_vec(),
                    path.clone(),
                    &mut rng,
                )
            })
            .collect();
        let _ = super::finish_sign_rounds(parties);
    }

    fn run_sign_both_formats<const T: usize, const N: usize, const K: usize>() {
        let shares = run_keygen::<T, N, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), K)
            .cloned()
            .collect();
        run_sign_via_new(subset.clone(), "m/0");
        run_sign::<Legacy>(subset.clone(), "m/0");
        run_sign::<Bip32Public>(subset, "m/0");
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

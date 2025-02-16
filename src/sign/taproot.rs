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
    type Input = ();

    type Output = Result<(PartialSign<ProjectivePoint>, SignMsg3<ProjectivePoint>), SignError>;

    /// The signer party processes the message to sign and returns the partial signature
    /// # Arguments
    /// * `msg_hash` - 32 bytes hash of the message to sign. It must be the output of a secure hash function.
    fn process(self, _: Self::Input) -> Self::Output {
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

        let tweaked_big_p =
            (self.public_key + ProjectivePoint::GENERATOR * tweak_scalar).to_affine();

        let big_r = self.big_r.to_affine();
        let mut k_i = self.k_i;
        let internal_share = self.d_i;

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
            threshold: self.threshold,
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
    type Input = Vec<SignMsg3<ProjectivePoint>>;

    type Output = Result<(Signature, SignComplete), SignError>;

    fn process(self, messages: Self::Input) -> Self::Output {
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

        let tweaked_pubkey = self.public_key + ProjectivePoint::GENERATOR * tweak_scalar;
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

#[allow(unused)]
fn tagged_hash(tag: &[u8]) -> Sha256 {
    let tag_hash = Sha256::digest(tag);
    let mut digest = Sha256::new();
    digest.update(tag_hash);
    digest.update(tag_hash);
    digest
}

#[cfg(test)]
pub fn run_sign(shares: &[Keyshare<k256::ProjectivePoint>]) -> Signature {
    use crate::common::utils::run_round;
    let msg = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    let msg_hash: [u8; 32] = Sha256::digest(msg).into();

    let mut rng = rand::thread_rng();
    let parties = shares
        .iter()
        .map(|keyshare| {
            SignerParty::<_, k256::ProjectivePoint>::new(
                keyshare.clone().into(),
                msg_hash,
                "m".parse().unwrap(),
                &mut rng,
            )
        })
        .collect::<Vec<_>>();

    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
    let ready_parties = run_round(parties, msgs);

    // Signature phase
    let (parties, partial_sigs): (Vec<_>, Vec<_>) =
        run_round(ready_parties, ()).into_iter().unzip();

    let (signatures, _complete_msg): (Vec<_>, Vec<_>) =
        run_round(parties, partial_sigs).into_iter().unzip();

    signatures[0]
}

#[cfg(test)]
mod tests {
    use k256::ProjectivePoint;
    use rand::seq::SliceRandom;

    use crate::{common::utils::run_keygen, sign::taproot::run_sign};

    #[test]
    fn sign_2_2() {
        let shares = run_keygen::<2, 2, ProjectivePoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 2)
            .cloned()
            .collect();
        run_sign(&subset);
    }
    #[test]
    fn sign_2_3() {
        let shares = run_keygen::<2, 3, ProjectivePoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 2)
            .cloned()
            .collect();
        run_sign(&subset);
    }
    #[test]
    fn sign_2_3_3() {
        let shares = run_keygen::<2, 3, ProjectivePoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 3)
            .cloned()
            .collect();
        run_sign(&subset);
    }
    #[test]
    fn sign_3_3() {
        let shares = run_keygen::<3, 3, ProjectivePoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 3)
            .cloned()
            .collect();
        run_sign(&subset);
    }

    #[test]
    fn sign_3_5() {
        let shares = run_keygen::<3, 5, ProjectivePoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 3)
            .cloned()
            .collect();
        run_sign(&subset);
    }

    #[test]
    fn sign_5_10() {
        let shares = run_keygen::<5, 10, ProjectivePoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 5)
            .cloned()
            .collect();
        run_sign(&subset);
    }
}

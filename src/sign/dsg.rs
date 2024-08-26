use std::{collections::HashSet, sync::Arc};

use crypto_bigint::subtle::ConstantTimeEq;
use elliptic_curve::{group::GroupEncoding, Group};


use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use crate::{
    common::{
        get_lagrange_coeff,
        traits::{GroupElem, GroupVerifier, Round, ScalarReduce},
        utils::{calculate_final_session_id, run_round, BaseMessage, HashBytes, SessionId},
        DLogProof,
    },
    keygen::Keyshare,
};

use super::{
    messages::{SignComplete, SignMsg1, SignMsg2, SignMsg3},
    types::{SignEntropy, SignError},
};

/// Signer party
pub struct SignerParty<T, G>
where
    G: Group + GroupEncoding,
{
    party_id: u8,
    keyshare: Arc<Keyshare<G>>,
    rand_params: SignEntropy<G>,
    seed: [u8; 32],
    state: T,
}

/// Initial state of a round based protocol.
pub struct R0;

/// Round 1 state of Signer party
pub struct R1<G> {
    big_r_i: G,
}

/// Round 2 state of Signer party
/// State before processing all SignMsg2 messages
pub struct R2<G> {
    final_session_id: SessionId,
    big_r_i: G,
    commitment_list: Vec<[u8; 32]>,
    sid_list: Vec<SessionId>,
    pid_list: Vec<u8>,
}

/// State of Signer party after processing all SignMsg2 messages.
/// Party is ready to sign a message
pub struct SignReady<G: Group> {
    final_session_id: SessionId,
    big_r: G,
    d_i: G::Scalar,
    // party_id_to_idx: Vec<(u8, u8)>,
}
/// State of Signer party after processing all SignMsg3 messages
pub struct PartialSign<G: Group> {
    final_session_id: SessionId,
    big_r: G,
    s_i: G::Scalar,
    msg_to_sign: Vec<u8>,
}

impl<G: Group + GroupEncoding> SignerParty<R0, G> {
    /// Create a new signer party with the given keyshare
    pub fn new<R: CryptoRng + RngCore>(keyshare: Arc<Keyshare<G>>, rng: &mut R) -> Self {
        Self {
            party_id: keyshare.party_id,
            keyshare,
            rand_params: SignEntropy::generate(rng),
            seed: rng.gen(),
            state: R0,
        }
    }
}

impl<G: Group + GroupEncoding> Round for SignerParty<R0, G> {
    type Input = ();

    type Output = Result<(SignerParty<R1<G>, G>, SignMsg1), SignError>;

    fn process(self, _: ()) -> Self::Output {
        let big_r_i = G::generator() * self.rand_params.k_i;
        let commitment_r_i = hash_commitment_r_i(
            &self.rand_params.session_id,
            self.party_id,
            &big_r_i,
            &self.rand_params.blind_factor,
        );

        let msg1 = SignMsg1 {
            from_party: self.keyshare.party_id,
            session_id: self.rand_params.session_id,
            commitment_r_i,
        };

        let next_state = SignerParty {
            party_id: self.party_id,
            keyshare: self.keyshare,
            rand_params: self.rand_params,
            state: R1 { big_r_i },
            seed: self.seed,
        };

        Ok((next_state, msg1))
    }
}

impl<G: GroupElem> Round for SignerParty<R1<G>, G>
where
    G: ConstantTimeEq,
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    type Input = Vec<SignMsg1>;

    type Output = Result<(SignerParty<R2<G>, G>, SignMsg2<G>), SignError>;

    fn process(self, mut msgs: Self::Input) -> Self::Output {
        let mut commitment_list = Vec::with_capacity(self.keyshare.threshold as usize);
        let mut sid_list = Vec::with_capacity(self.keyshare.threshold as usize);
        let mut party_ids = Vec::with_capacity(self.keyshare.threshold as usize);
        msgs.sort_by_key(|m| m.party_id());

        for msg in msgs {
            commitment_list.push(msg.commitment_r_i);
            sid_list.push(msg.session_id);
            party_ids.push(msg.from_party);
        }

        let final_sid = calculate_final_session_id(party_ids.iter().copied(), &sid_list);

        use sha2::digest::Update;
        let dlog_sid = Sha256::new()
            .chain(b"SL-EDDSA-SIGN")
            .chain(final_sid.as_ref())
            .chain((self.party_id as u32).to_be_bytes())
            .chain(b"DLOG-SID")
            .finalize()
            .into();

        let mut rng = ChaCha20Rng::from_seed(self.seed);
        let dlog_proof = DLogProof::prove(&dlog_sid, &self.rand_params.k_i, &mut rng);

        let msg2 = SignMsg2 {
            from_party: self.keyshare.party_id,
            session_id: final_sid,
            dlog_proof,
            blind_factor: self.rand_params.blind_factor,
            big_r_i: self.state.big_r_i.to_bytes().as_ref().to_vec(),
        };

        let next = SignerParty {
            party_id: self.party_id,
            keyshare: self.keyshare,
            rand_params: self.rand_params,
            state: R2 {
                final_session_id: final_sid,
                commitment_list,
                sid_list,
                big_r_i: self.state.big_r_i,
                pid_list: party_ids,
            },
            seed: rng.gen(),
        };

        Ok((next, msg2))
    }
}

impl<G: GroupElem> Round for SignerParty<R2<G>, G>
where
    G: ConstantTimeEq,
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    type Input = Vec<SignMsg2<G>>;

    type Output = Result<SignerParty<SignReady<G>, G>, SignError>;

    fn process(self, mut msgs: Self::Input) -> Self::Output {
        msgs.sort_by_key(|m| m.party_id());

        let mut big_r_i = self.state.big_r_i;

        for (idx, msg) in msgs.iter().enumerate() {
            if msg.from_party == self.keyshare.party_id {
                continue;
            }

            let mut encoding = G::Repr::default();
            if encoding.as_ref().len() != msg.big_r_i.len() {
                return Err(SignError::InvalidBigRi);
            }
            encoding.as_mut().copy_from_slice(&msg.big_r_i);
            let msg_big_r_i = G::from_bytes(&encoding);
            let msg_big_r_i = if msg_big_r_i.is_some().into() {
                msg_big_r_i.unwrap()
            } else {
                return Err(SignError::InvalidBigRi);
            };
            if msg_big_r_i.is_identity().into() {
                return Err(SignError::InvalidBigRi);
            }

            let sid = self.state.sid_list[idx];
            let commitment = self.state.commitment_list[idx];

            verify_commitment_r_i(
                &sid,
                msg.from_party,
                &msg_big_r_i,
                &msg.blind_factor,
                &commitment,
            )
            .then_some(())
            .ok_or(SignError::InvalidCommitment(msg.from_party))?;

            let mut h = Sha256::new();
            h.update(b"SL-EDDSA-SIGN");
            h.update(self.state.final_session_id.as_ref());
            h.update((msg.from_party as u32).to_be_bytes());
            h.update(b"DLOG-SID");

            let dlog_sid = h.finalize().into();

            msg.dlog_proof
                .verify(&dlog_sid, &msg_big_r_i)
                .then_some(())
                .ok_or(SignError::InvalidDLogProof(msg.from_party))?;

            big_r_i += msg_big_r_i;
        }

        // FIXME: do we need copied?
        let coeff = get_lagrange_coeff::<G>(&self.party_id, self.state.pid_list.iter().copied());

        let d_i = coeff * self.keyshare.d_i;

        let next = SignerParty {
            party_id: self.party_id,
            keyshare: self.keyshare,
            rand_params: self.rand_params,
            state: SignReady {
                final_session_id: self.state.final_session_id,
                big_r: big_r_i,
                d_i,
            },
            seed: self.seed,
        };

        Ok(next)
    }
}

#[cfg(not(feature = "taproot"))]
impl<G: Group + GroupEncoding> Round for SignerParty<SignReady<G>, G>
where
    G::Scalar: ScalarReduce<[u8; 64]>,
{
    type Input = Vec<u8>;

    type Output = Result<(SignerParty<PartialSign<G>, G>, SignMsg3<G>), SignError>;

    /// The signer party processes the message to sign and returns the partial signature
    /// # Arguments
    /// * `msg_to_sign` - The message to sign in bytes
    fn process(self, msg_to_sign: Self::Input) -> Self::Output {
        let big_a = self.keyshare.public_key.to_bytes();

        use sha2::digest::Update;
        let digest = Sha512::new()
            .chain(self.state.big_r.to_bytes())
            .chain(big_a)
            .chain(&msg_to_sign);

        let e = G::Scalar::reduce_from_bytes(&digest.finalize().into());
        let s_i = self.rand_params.k_i + self.state.d_i * e;

        let msg3 = SignMsg3 {
            from_party: self.keyshare.party_id,
            session_id: self.state.final_session_id,
            s_i,
        };

        let next = SignerParty {
            party_id: self.party_id,
            keyshare: self.keyshare,
            rand_params: self.rand_params,
            state: PartialSign {
                final_session_id: self.state.final_session_id,
                big_r: self.state.big_r,
                s_i,
                msg_to_sign,
            },
            seed: self.seed,
        };

        Ok((next, msg3))
    }
}

#[cfg(not(feature = "taproot"))]
impl<G: Group + GroupEncoding + GroupVerifier> Round for SignerParty<PartialSign<G>, G> {
    type Input = Vec<SignMsg3<G>>;

    type Output = Result<([u8; 64], SignComplete), SignError>;

    fn process(self, mut messages: Self::Input) -> Self::Output {
        let mut s = self.state.s_i;
        messages.sort_by_key(|m| m.from_party);

        for msg in messages {
            if msg.from_party == self.keyshare.party_id {
                continue;
            }

            s += msg.s_i;
        }

        let signature: [u8; 64] = [self.state.big_r.to_bytes().as_ref(), s.to_repr().as_ref()]
            .concat()
            .try_into()
            .expect("Sign must be 64 bytes");

        self.keyshare
            .public_key
            .verify(&signature, &self.state.msg_to_sign)?;

        self.keyshare
            .public_key
            .verify(&signature, &self.state.msg_to_sign)
            .expect("Invalid signature");

        let sign_complete = SignComplete {
            from_party: self.keyshare.party_id,
            session_id: self.state.final_session_id,
            signature,
        };

        Ok((signature, sign_complete))
    }
}

#[cfg(feature = "taproot")]
mod taproot {

    const CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";
    

    use super::*;
    use elliptic_curve::ops::Reduce;
    use k256::{ProjectivePoint, U256};

    impl Round for SignerParty<SignReady<ProjectivePoint>, ProjectivePoint> {
        type Input = Vec<u8>;

        type Output = Result<
            (
                SignerParty<PartialSign<ProjectivePoint>, ProjectivePoint>,
                SignMsg3<ProjectivePoint>,
            ),
            SignError,
        >;

        /// The signer party processes the message to sign and returns the partial signature
        /// # Arguments
        /// * `msg_hash` - 32 bytes hash of the message to sign. It must be the output of a secure hash function.
        fn process(self, msg_to_sign: Self::Input) -> Self::Output {
            use elliptic_curve::point::AffineCoordinates;
            let hash = Sha256::digest(&msg_to_sign);
            let big_p = self.keyshare.public_key.to_affine();
            let big_r = self.state.big_r.to_affine();
            let mut k_i = self.rand_params.k_i;
            let mut d_i = self.state.d_i;

            if big_r.y_is_odd().unwrap_u8() == 1 {
                k_i = -k_i;
            }

            if big_p.y_is_odd().unwrap_u8() == 1 {
                d_i = -d_i;
            }

            let e = <k256::Scalar as Reduce<U256>>::reduce_bytes(
                &tagged_hash(CHALLENGE_TAG)
                    .chain_update(big_r.x())
                    .chain_update(big_p.x())
                    .chain_update(hash)
                    .finalize(),
            );

            let s_i = k_i + d_i * e;

            let msg3 = SignMsg3 {
                from_party: self.keyshare.party_id,
                session_id: self.state.final_session_id,
                s_i,
            };

            let next = SignerParty {
                party_id: self.party_id,
                keyshare: self.keyshare,
                rand_params: self.rand_params,
                state: PartialSign {
                    final_session_id: self.state.final_session_id,
                    big_r: self.state.big_r,
                    s_i,
                    msg_to_sign,
                },
                seed: self.seed,
            };

            Ok((next, msg3))
        }
    }

    impl Round for SignerParty<PartialSign<ProjectivePoint>, ProjectivePoint> {
        type Input = Vec<SignMsg3<ProjectivePoint>>;

        type Output = Result<([u8; 64], SignComplete), SignError>;

        fn process(self, mut messages: Self::Input) -> Self::Output {
            use elliptic_curve::point::AffineCoordinates;
            messages.sort_by_key(|m| m.from_party);
            let mut s = self.state.s_i;

            for msg in messages {
                if msg.from_party == self.keyshare.party_id {
                    continue;
                }

                s += msg.s_i;
            }

            let r = self.state.big_r.to_affine().x();
            let r: &[u8] = r.as_ref();

            let signature: [u8; 64] = [r, s.to_bytes().as_ref()]
                .concat()
                .try_into()
                .expect("Sign must be 64 bytes");

            self.keyshare
                .public_key
                .verify(&signature, &self.state.msg_to_sign)?;

            let sign_complete = SignComplete {
                from_party: self.keyshare.party_id,
                session_id: self.state.final_session_id,
                signature,
            };

            Ok((signature, sign_complete))
        }
    }

    fn tagged_hash(tag: &[u8]) -> Sha256 {
        let tag_hash = Sha256::digest(tag);
        let mut digest = Sha256::new();
        digest.update(tag_hash);
        digest.update(tag_hash);
        digest
    }
}

#[cfg(feature = "taproot")]
pub fn run_sign(shares: &[Keyshare<k256::ProjectivePoint>]) -> [u8; 64] {
    let mut rng = rand::thread_rng();
    let parties = shares
        .iter()
        .map(|keyshare| SignerParty::new(keyshare.clone().into(), &mut rng))
        .collect::<Vec<_>>();

    // Pre-Signature phase
    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
    let ready_parties = run_round(parties, msgs);

    // Signature phase
    let msg = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    let (parties, partial_sigs): (Vec<_>, Vec<_>) =
        run_round(ready_parties, msg.into()).into_iter().unzip();

    let (signatures, _complete_msg): (Vec<_>, Vec<_>) =
        run_round(parties, partial_sigs).into_iter().unzip();

    signatures[0]
}

fn hash_commitment_r_i<G: Group + GroupEncoding>(
    session_id: &SessionId,
    party_id: u8,
    big_r_i: &G,
    blind_factor: &[u8; 32],
) -> HashBytes {
    use sha2::digest::Update;
    Sha256::new()
        .chain(session_id.as_ref())
        .chain((party_id as u32).to_be_bytes())
        .chain(big_r_i.to_bytes())
        .chain(blind_factor)
        .finalize()
        .into()
}

fn validate_input_messages<M: BaseMessage>(
    mut msgs: Vec<M>,
    threshold: u8,
    party_id_to_idx: &[(u8, u8)],
) -> Result<Vec<M>, SignError> {
    if msgs.len() as u8 != threshold {
        return Err(SignError::InvalidMsgCount);
    }

    let party_ids = msgs
        .iter()
        .map(|msg| msg.party_id())
        .collect::<HashSet<u8>>();

    if party_ids.len() as u8 != threshold {
        return Err(SignError::DuplicatePartyId);
    }

    for (pid, _) in party_id_to_idx {
        if !party_ids.contains(pid) {
            return Err(SignError::InvalidMsgPartyId);
        }
    }
    msgs.sort_by_key(BaseMessage::party_id);
    Ok(msgs)
}

fn verify_commitment_r_i<G: Group + GroupEncoding>(
    sid: &SessionId,
    pid: u8,
    big_r_i: &G,
    blind_factor: &[u8; 32],
    commitment: &HashBytes,
) -> bool {
    let compare_commitment = hash_commitment_r_i(sid, pid, big_r_i, blind_factor);
    commitment.ct_eq(&compare_commitment).into()
}

#[cfg(not(feature = "taproot"))]
pub fn run_sign<G>(shares: &[Keyshare<G>]) -> [u8; 64]
where
    G: GroupElem + GroupVerifier,
    G::Scalar: ScalarReduce<[u8; 32]>,
    G::Scalar: ScalarReduce<[u8; 64]>,
{
    let mut rng = rand::thread_rng();
    let parties = shares
        .iter()
        .map(|keyshare| SignerParty::new(keyshare.clone().into(), &mut rng))
        .collect::<Vec<_>>();

    // Pre-Signature phase
    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
    let ready_parties = run_round(parties, msgs);

    // Signature phase
    let msg = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    let (parties, partial_sigs): (Vec<_>, Vec<_>) =
        run_round(ready_parties, msg.into()).into_iter().unzip();

    let (signatures, _complete_msg): (Vec<_>, Vec<_>) =
        run_round(parties, partial_sigs).into_iter().unzip();

    signatures[0]
}

#[cfg(test)]
mod tests {
    use crate::common::utils::run_keygen;
    

    #[test]
    fn sign() {
        #[cfg(feature = "taproot")]
        {
            use k256::ProjectivePoint;
            let shares = run_keygen::<2, 3, ProjectivePoint>();
            let _ = super::run_sign(&shares[0..2]);
        }

        #[cfg(not(feature = "taproot"))]
        {
            let shares = run_keygen::<2, 3, EdwardsPoint>();
            _ = super::run_sign(&shares[0..2]);
        }
    }
}

use std::collections::HashSet;

use crypto_bigint::subtle::ConstantTimeEq;
use curve25519_dalek::{traits::IsIdentity, EdwardsPoint, Scalar};
use ed25519_dalek::{DigestSigner, DigestVerifier, Signature, SigningKey, Verifier, VerifyingKey};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256, Sha512};
use sl_mpc_mate::message::Opaque;

use crate::{
    common::{
        get_lagrange_coeff,
        traits::Round,
        utils::{calculate_final_session_id, BaseMessage, HashBytes, SessionId},
        DLogProof,
    },
    keygen::Keyshare,
};

use super::{
    messages::{SignComplete, SignMsg1, SignMsg2, SignMsg3},
    types::{SignEntropy, SignError, SignParams},
};

/// Signer party
pub struct SignerParty<T> {
    params: SignParams,
    rand_params: SignEntropy,
    seed: [u8; 32],
    state: T,
}

/// Initial state of a round based protocol.
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct R0;

/// Round 1 state of Signer party
pub struct R1 {
    big_r_i: EdwardsPoint,
}

/// Round 2 state of Signer party
/// State before processing all SignMsg2 messages
pub struct R2 {
    final_session_id: SessionId,
    big_r_i: EdwardsPoint,
    commitment_list: Vec<[u8; 32]>,
    sid_list: Vec<SessionId>,
    party_id_to_idx: Vec<(u8, u8)>,
}

/// State of Signer party after processing all SignMsg2 messages.
/// Party is ready to sign a message
pub struct SignReady {
    final_session_id: SessionId,
    big_r: [u8; 32],
    d_i: Scalar,
    party_id_to_idx: Vec<(u8, u8)>,
}
/// State of Signer party after processing all SignMsg3 messages
pub struct PartialSign {
    final_session_id: SessionId,
    big_r: [u8; 32],
    s_i: Scalar,
    msg_to_sign: Vec<u8>,
    party_id_to_idx: Vec<(u8, u8)>,
}

impl SignerParty<R0> {
    /// Create a new signer party with the given keyshare
    pub fn new<R: CryptoRng + RngCore>(
        keyshare: Keyshare,
        signing_key: SigningKey,
        party_pubkeys: Vec<VerifyingKey>,
        rng: &mut R,
    ) -> Result<Self, SignError> {
        let my_pk = &signing_key.verifying_key();
        let my_party_idx = party_pubkeys
            .iter()
            .position(|key| key == my_pk)
            .ok_or(SignError::PartyKeyNotFound)?;

        if party_pubkeys.len() < keyshare.threshold.into() {
            return Err(SignError::InvalidMsgCount);
        }

        Ok(Self {
            params: SignParams {
                party_id: keyshare.party_id,
                party_index: my_party_idx as u8,
                keyshare,
                signing_key,
                party_pubkeys,
            },
            rand_params: SignEntropy::generate(rng),
            seed: rng.gen(),
            state: R0,
        })
    }
    /// Get the public keys of the signer party
    pub fn get_public_keys(&self) -> VerifyingKey {
        self.params.signing_key.verifying_key()
    }
}

impl Round for SignerParty<R0> {
    type Input = ();

    type Output = Result<(SignerParty<R1>, SignMsg1), SignError>;

    fn process(self, _: ()) -> Self::Output {
        let big_r_i = EdwardsPoint::mul_base(&self.rand_params.k_i);
        let commitment_r_i = hash_commitment_r_i(
            &self.rand_params.session_id,
            self.params.party_id,
            &big_r_i,
            &self.rand_params.blind_factor,
        );

        let msg_hash = digest_msg_1(
            self.rand_params.session_id,
            self.params.keyshare.party_id,
            commitment_r_i,
        );

        let signature = self.params.signing_key.sign_digest(msg_hash);
        let msg1 = SignMsg1 {
            from_party: self.params.keyshare.party_id,
            from_party_idx: self.params.party_index,
            signature: signature.to_bytes(),
            session_id: self.rand_params.session_id,
            commitment_r_i,
        };

        let next_state = SignerParty {
            params: self.params,
            rand_params: self.rand_params,
            state: R1 { big_r_i },
            seed: self.seed,
        };

        Ok((next_state, msg1))
    }
}

impl Round for SignerParty<R1> {
    type Input = Vec<SignMsg1>;

    type Output = Result<(SignerParty<R2>, SignMsg2), SignError>;

    fn process(self, messages: Self::Input) -> Self::Output {
        let mut party_id_to_idx = messages
            .iter()
            .map(|msg| (msg.from_party, msg.from_party_idx))
            .collect::<Vec<_>>();

        party_id_to_idx.sort_by_key(|msg| msg.0);

        let msgs =
            validate_input_messages(messages, self.params.keyshare.threshold, &party_id_to_idx)?;

        let mut commitment_list = Vec::with_capacity(self.params.keyshare.threshold as usize);
        let mut sid_list = Vec::with_capacity(self.params.keyshare.threshold as usize);
        for msg in msgs {
            commitment_list.push(msg.commitment_r_i);
            sid_list.push(msg.session_id);

            // Skip if the message is from self
            if msg.from_party == self.params.keyshare.party_id {
                continue;
            }

            let party_idx = party_id_to_idx
                .iter()
                .find(|(pid, _)| pid == &msg.from_party)
                .map(|(_, pidx)| pidx)
                .unwrap();

            let verify_key = self.params.party_pubkeys[*party_idx as usize];

            let msg_hash = digest_msg_1(msg.session_id, msg.from_party, msg.commitment_r_i);

            verify_key.verify_digest(msg_hash, &Signature::from(msg.signature))?;
        }

        let party_ids = party_id_to_idx.iter().map(|(pid, _)| *pid);
        let final_sid = calculate_final_session_id(party_ids, &sid_list);

        use sha2::digest::Update;
        let dlog_sid = Sha256::new()
            .chain(b"SL-EDDSA-SIGN")
            .chain(final_sid.as_ref())
            .chain((self.params.party_id as u32).to_be_bytes())
            .chain(b"DLOG-SID")
            .finalize()
            .into();

        let mut rng = ChaCha20Rng::from_seed(self.seed);
        let dlog_proof = DLogProof::prove(&dlog_sid, &self.rand_params.k_i, &mut rng);

        let msg_hash = digest_msg_2(
            &final_sid,
            &commitment_list,
            &self.state.big_r_i,
            &self.rand_params.blind_factor,
        );

        let signature = self.params.signing_key.sign_digest(msg_hash);

        let msg2 = SignMsg2 {
            from_party: self.params.keyshare.party_id,
            signature: signature.to_bytes(),
            session_id: final_sid,
            dlog_proof,
            blind_factor: self.rand_params.blind_factor,
            big_r_i: Opaque::from(self.state.big_r_i),
        };

        let next = SignerParty {
            params: self.params,
            rand_params: self.rand_params,
            state: R2 {
                final_session_id: final_sid,
                commitment_list,
                sid_list,
                big_r_i: self.state.big_r_i,
                party_id_to_idx,
            },
            seed: rng.gen(),
        };

        Ok((next, msg2))
    }
}

impl Round for SignerParty<R2> {
    type Input = Vec<SignMsg2>;

    type Output = Result<SignerParty<SignReady>, SignError>;

    fn process(self, messages: Self::Input) -> Self::Output {
        //  self._check_messages_len_and_set_of_participants(messages)
        let msgs = validate_input_messages(
            messages,
            self.params.keyshare.threshold,
            &self.state.party_id_to_idx,
        )?;

        let mut big_r_i = self.state.big_r_i;

        for (idx, msg) in msgs.iter().enumerate() {
            if msg.from_party == self.params.keyshare.party_id {
                continue;
            }

            let party_idx = self
                .state
                .party_id_to_idx
                .iter()
                .find(|(pid, _)| pid == &msg.from_party)
                .map(|(_, pidx)| pidx)
                .unwrap();

            let verify_key = self.params.party_pubkeys[*party_idx as usize];

            let msg_hash = digest_msg_2(
                &self.state.final_session_id,
                &self.state.commitment_list,
                &msg.big_r_i,
                &msg.blind_factor,
            );

            verify_key.verify_digest(msg_hash, &Signature::from(msg.signature))?;

            if msg.big_r_i.0.is_identity() {
                return Err(SignError::InvalidBigRi);
            }

            let sid = self.state.sid_list[idx];
            let commitment = self.state.commitment_list[idx];

            verify_commitment_r_i(
                &sid,
                msg.from_party,
                &msg.big_r_i,
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
                .verify(&dlog_sid, &msg.big_r_i)
                .then_some(())
                .ok_or(SignError::InvalidDLogProof(msg.from_party))?;

            big_r_i += msg.big_r_i.0;
        }

        let big_r = big_r_i.compress();
        let party_ids = self.state.party_id_to_idx.iter().map(|(pid, _)| *pid);
        let coeff = get_lagrange_coeff(&self.params.keyshare.party_id, party_ids);

        let d_i = coeff * self.params.keyshare.d_i.0;

        let next = SignerParty {
            params: self.params,
            rand_params: self.rand_params,
            state: SignReady {
                final_session_id: self.state.final_session_id,
                big_r: big_r.as_bytes().to_owned(),
                d_i,
                party_id_to_idx: self.state.party_id_to_idx,
            },
            seed: self.seed,
        };

        Ok(next)
    }
}

impl Round for SignerParty<SignReady> {
    type Input = Vec<u8>;

    type Output = Result<(SignerParty<PartialSign>, SignMsg3), SignError>;

    fn process(self, msg_to_sign: Self::Input) -> Self::Output {
        let big_a = self.params.keyshare.public_key.compress().to_bytes();

        use sha2::digest::Update;
        let digest = Sha512::new()
            .chain(self.state.big_r)
            .chain(big_a)
            .chain(&msg_to_sign);

        let e = Scalar::from_hash(digest);
        let s_i = self.rand_params.k_i + self.state.d_i * e;

        let msg_hash_3 = digest_msg_3(&self.state.final_session_id, &s_i);

        let signature = self.params.signing_key.sign_digest(msg_hash_3);

        let msg3 = SignMsg3 {
            from_party: self.params.keyshare.party_id,
            session_id: self.state.final_session_id,
            s_i: Opaque::from(s_i),
            signature: signature.to_bytes(),
        };

        let next = SignerParty {
            params: self.params,
            rand_params: self.rand_params,
            state: PartialSign {
                final_session_id: self.state.final_session_id,
                big_r: self.state.big_r,
                s_i,
                msg_to_sign,
                party_id_to_idx: self.state.party_id_to_idx,
            },
            seed: self.seed,
        };

        Ok((next, msg3))
    }
}

impl Round for SignerParty<PartialSign> {
    type Input = Vec<SignMsg3>;

    type Output = Result<(ed25519_dalek::Signature, SignComplete), SignError>;

    fn process(self, messages: Self::Input) -> Self::Output {
        let messages = validate_input_messages(
            messages,
            self.params.keyshare.threshold,
            &self.state.party_id_to_idx,
        )?;

        let mut s = self.state.s_i;

        for msg in messages {
            if msg.from_party == self.params.keyshare.party_id {
                continue;
            }

            let party_idx = self
                .state
                .party_id_to_idx
                .iter()
                .find(|(pid, _)| pid == &msg.from_party)
                .map(|(_, pidx)| pidx)
                .unwrap();

            let verify_key = self.params.party_pubkeys[*party_idx as usize];

            let msg_hash_3 = digest_msg_3(&self.state.final_session_id, &msg.s_i);

            verify_key.verify_digest(msg_hash_3, &Signature::from(msg.signature))?;

            s += msg.s_i.0;
        }

        let sig: [u8; 64] = [self.state.big_r, s.to_bytes()]
            .concat()
            .try_into()
            .expect("Sign must be 64 bytes");

        let public_key =
            VerifyingKey::from_bytes(self.params.keyshare.public_key.compress().as_bytes())
                .unwrap();

        let signature = ed25519_dalek::Signature::from_bytes(&sig);

        public_key
            .verify(&self.state.msg_to_sign, &signature)
            .expect("Invalid signature");

        let sign_complete = SignComplete {
            from_party: self.params.keyshare.party_id,
            session_id: self.state.final_session_id,
            signature: signature.to_bytes(),
        };

        Ok((signature, sign_complete))
    }
}

fn hash_commitment_r_i(
    session_id: &SessionId,
    party_id: u8,
    big_r_i: &EdwardsPoint,
    blind_factor: &[u8; 32],
) -> HashBytes {
    use sha2::digest::Update;
    Sha256::new()
        .chain(session_id.as_ref())
        .chain((party_id as u32).to_be_bytes())
        .chain(big_r_i.compress().to_bytes())
        .chain(blind_factor)
        .finalize()
        .into()
}

fn digest_msg_1(sid: SessionId, pid: u8, commitment_r_i: HashBytes) -> Sha512 {
    use sha2::digest::Update;
    Sha512::new()
        .chain(b"SignMsg1")
        .chain(sid.as_ref())
        .chain((pid).to_be_bytes())
        .chain(commitment_r_i.as_ref())
}
fn digest_msg_2(
    sid: &SessionId,
    commitments: &[HashBytes],
    big_r_i: &EdwardsPoint,
    blind_factor: &[u8; 32],
) -> Sha512 {
    let mut hasher = Sha512::new();

    hasher.update(b"SignMsg2");
    hasher.update(sid.as_ref());

    for c in commitments {
        hasher.update(c.as_ref());
    }

    hasher.update(big_r_i.compress().to_bytes());
    hasher.update(blind_factor);

    hasher
}

fn digest_msg_3(sid: &SessionId, s_i: &Scalar) -> Sha512 {
    use sha2::digest::Update;
    Sha512::new()
        .chain(b"SignMsg3")
        .chain(sid.as_ref())
        .chain(s_i.as_bytes())
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

fn verify_commitment_r_i(
    sid: &SessionId,
    pid: u8,
    big_r_i: &EdwardsPoint,
    blind_factor: &[u8; 32],
    commitment: &HashBytes,
) -> bool {
    let compare_commitment = hash_commitment_r_i(sid, pid, big_r_i, blind_factor);

    commitment.ct_eq(&compare_commitment).into()
}

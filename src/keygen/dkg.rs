// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::sync::Arc;

use crypto_bigint::subtle::ConstantTimeEq;
use crypto_box::{PublicKey, SecretKey};
use elliptic_curve::{group::GroupEncoding, Group};
use ff::{Field, PrimeField};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{digest::Update, Digest, Sha256};
use zeroize::Zeroizing;

use sl_mpc_mate::math::GroupPolynomial;

use crate::common::{
    ser::Serializable,
    traits::{GroupElem, InitRound, Round, RoundSize, ScalarReduce},
    utils::{
        calculate_final_session_id, decrypt_message, encrypt_message, BaseMessage, EncryptedData,
        HashBytes, SessionId,
    },
    DLogProof,
};

use super::{
    types::{KeyEntropy, KeygenError, KeygenParams},
    KeyRefreshData, KeygenMsg1, KeygenMsg2, Keyshare,
};

/// LABEL for the keygen protocol
pub const DKG_LABEL: &[u8] = b"SilenceLaboratories-Schnorr-DKG";

/// Keygen party
/// The keygen party is a state machine that implements the keygen protocol.
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "T: serde::Serialize",
        deserialize = "T: serde::Deserialize<'de>"
    ))
)]
pub struct KeygenParty<T, G>
where
    G: Group + GroupEncoding,
    G::Scalar: Serializable,
{
    params: KeygenParams,
    rand_params: KeyEntropy<G>,
    seed: [u8; 32],
    state: T,
    key_refresh_data: Option<KeyRefreshData<G>>,
}

impl<T, G> RoundSize for KeygenParty<T, G>
where
    G: Group + GroupEncoding,
    G::Scalar: Serializable,
{
    fn message_count(&self) -> usize {
        self.params.n as usize
    }
}

#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "R: serde::Serialize",
        deserialize = "R: serde::Deserialize<'de>"
    ))
)]
pub struct Session<R>
where
    R: Round,
    R::InputMessage: Serializable,
{
    state: R,
    messages: Vec<R::InputMessage>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct R0;

/// State of a keygen party after receiving public keys of all parties and generating the first message.
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "G: Group + GroupEncoding",
        deserialize = "G: Group + GroupEncoding"
    ))
)]
pub struct R1<G>
where
    G: Group + GroupEncoding,
{
    big_a_i: GroupPolynomial<G>,
    c_i_j: Vec<EncryptedData>,
    commitment: HashBytes,
}

/// State of a keygen party after processing the first message.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct R2 {
    final_session_id: SessionId,
    commitment_list: Vec<HashBytes>,
    sid_i_list: Vec<SessionId>,
}

fn validate_input(
    t: u8,
    n: u8,
    party_id: u8,
    my_enc_key: &PublicKey,
    party_enc_keys: &[(u8, PublicKey)],
) -> Result<(), KeygenError> {
    if party_id >= n {
        return Err(KeygenError::InvalidPid);
    }

    if t > n || t < 2 {
        return Err(KeygenError::InvalidT);
    }

    if party_enc_keys.len() != n as usize {
        return Err(KeygenError::InvalidParticipantSet);
    }

    // Check if all the keys are present
    for pid in 0..n {
        let Some(enc_key) = find_enc_key(pid, party_enc_keys) else {
            return Err(KeygenError::InvalidParticipantSet);
        };

        if pid == party_id && enc_key != my_enc_key {
            return Err(KeygenError::InvalidParticipantSet);
        }
    }

    Ok(())
}

impl<G> KeygenParty<R0, G>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]>,
    G::Scalar: Serializable,
{
    /// Create a new keygen party.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        t: u8,
        n: u8,
        party_id: u8,
        decryption_key: Arc<SecretKey>,
        encyption_keys: Vec<(u8, PublicKey)>,
        refresh_data: Option<KeyRefreshData<G>>,
        key_id: Option<[u8; 32]>,
        seed: [u8; 32],
        extra_data: Option<Vec<u8>>,
    ) -> Result<Self, KeygenError> {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut rand_params = KeyEntropy::generate(t, &mut rng);

        // Set the constant polynomial to the keyshare secret.
        // s_i_0 is the current party's additive share of the private key
        if let Some(ref v) = refresh_data {
            rand_params.polynomial.set_constant(v.s_i_0);
            rand_params.chain_code_id = v.root_chain_code;
        }

        Self::new_with_context(
            t,
            n,
            party_id,
            decryption_key,
            encyption_keys,
            rand_params,
            refresh_data,
            key_id,
            rng.gen(),
            extra_data,
        )
    }

    /// Create a new keygen protocol instance with a given context. Used for testing purposes internally.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_context(
        t: u8,
        n: u8,
        party_id: u8,
        dec_key: Arc<crypto_box::SecretKey>,
        party_enc_keys: Vec<(u8, PublicKey)>,
        rand_params: KeyEntropy<G>,
        key_refresh_data: Option<KeyRefreshData<G>>,
        key_id: Option<[u8; 32]>,
        seed: [u8; 32],
        extra_data: Option<Vec<u8>>,
    ) -> Result<Self, KeygenError> {
        validate_input(t, n, party_id, &dec_key.public_key(), &party_enc_keys)?;

        // Validate refresh data
        if let Some(ref v) = key_refresh_data {
            let is_lost = v.lost_keyshare_party_ids.contains(&party_id);
            let cond1 = v.expected_public_key == G::identity();
            let cond2 = v.lost_keyshare_party_ids.len() > (n - t).into();
            let cond3 = rand_params.polynomial.get_constant() != &v.s_i_0;
            let cond4 = if is_lost {
                v.s_i_0 != G::Scalar::ZERO
            } else {
                v.s_i_0 == G::Scalar::ZERO
            };
            if cond1 || cond2 || cond3 || cond4 {
                return Err(KeygenError::InvalidRefresh);
            }
        }

        Ok(Self {
            params: KeygenParams {
                t,
                n,
                party_id,
                dec_key,
                party_enc_keys,
                key_id,
                extra_data,
            },
            rand_params,
            seed,
            key_refresh_data,
            state: R0,
        })
    }

    pub fn encryption_key(&self) -> crypto_box::PublicKey {
        self.params.dec_key.public_key()
    }

    pub fn into_session(self) -> Result<Session<KeygenParty<R1<G>, G>>, KeygenError> {
        Session::init(self)
    }
}

// Protocol 12 from https://eprint.iacr.org/2022/374.pdf
// Simple Three-Round Multiparty Schnorr Signing with Full Simulatability
impl<G> Round for KeygenParty<R0, G>
where
    G: GroupElem,
    G::Scalar: Serializable,
{
    type InputMessage = ();
    type Input = ();
    type Error = KeygenError;
    type Output = (KeygenParty<R1<G>, G>, KeygenMsg1);

    /// Protocol 21, step 2. From https://eprint.iacr.org/2022/374.pdf.
    fn process(self, _: ()) -> Result<Self::Output, Self::Error> {
        // 12.2(a) Sampling random session-id was done in KeyEntropy.

        // 12.2(b) Sampling random polynomial was done in KeyEntropy.
        let big_a_i = self.rand_params.polynomial.commit();

        // 12.2(c)
        let mut rng = ChaCha20Rng::from_seed(self.seed);
        let c_i_j = (0..self.params.n)
            .map(|party_id| {
                // party_id is also the index of the party's data in all the lists.
                let ek_i = find_enc_key(party_id, &self.params.party_enc_keys)
                    .ok_or(KeygenError::InvalidPid)?;

                // Party's point is just party-id. (Adding 1 because party-id's start from 0).
                let d_i = self
                    .rand_params
                    .polynomial
                    .evaluate_at(&G::Scalar::from((party_id + 1) as u64));

                let mut plaintext = [0u8; 64];
                plaintext[..32].copy_from_slice(d_i.to_repr().as_ref());
                plaintext[32..].copy_from_slice(&self.rand_params.chain_code_id);

                let enc_data = encrypt_message(
                    (&self.params.dec_key, self.params.party_id),
                    (ek_i, party_id),
                    &plaintext,
                    &mut rng,
                )
                .ok_or(KeygenError::EncryptionError)?;

                Ok(enc_data)
            })
            .collect::<Result<Vec<_>, KeygenError>>()?;

        // 12.2(d)
        let commitment = hash_commitment(
            &self.rand_params.session_id,
            self.params.party_id,
            &big_a_i,
            &c_i_j,
            &self.rand_params.r_i,
        );

        // 12.2(f)
        let msg1 = KeygenMsg1 {
            from_party: self.params.party_id,
            session_id: self.rand_params.session_id,
            commitment,
        };

        let next_state = KeygenParty {
            params: self.params,
            rand_params: self.rand_params,
            key_refresh_data: self.key_refresh_data,
            state: R1 {
                big_a_i,
                commitment,
                c_i_j,
            },
            seed: rng.gen(),
        };

        Ok((next_state, msg1))
    }
}

impl<G> InitRound for KeygenParty<R0, G>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]>,
    G::Scalar: Serializable,
{
    type OutputMessage = KeygenMsg1;

    type Next = KeygenParty<R1<G>, G>;

    type Error = KeygenError;

    fn init(self) -> Result<(Self::Next, Self::OutputMessage), Self::Error> {
        Self::process(self, ())
    }
}

impl<G> Round for KeygenParty<R1<G>, G>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]>,
    G::Scalar: Serializable,
{
    type InputMessage = KeygenMsg1;
    type Input = Vec<KeygenMsg1>;
    type Error = KeygenError;
    type Output = (KeygenParty<R2, G>, KeygenMsg2<G>);

    fn process(self, messages: Self::Input) -> Result<Self::Output, Self::Error> {
        let n = self.params.n as usize;
        let messages = validate_input_messages(messages, self.params.n)?;
        let mut sid_i_list = Vec::with_capacity(n);
        let mut commitment_list = Vec::with_capacity(n);
        let mut party_id_list = Vec::with_capacity(n);

        // 12.4(a)
        for message in &messages {
            if message.party_id() == self.params.party_id {
                let cond1 = self.rand_params.session_id == message.session_id;
                let cond2 = self.state.commitment == message.commitment;
                if !(cond1 && cond2) {
                    return Err(KeygenError::Abort("Invalid message in list"));
                }
            }
            let party_pubkey_idx = message.party_id();

            sid_i_list.push(message.session_id);
            commitment_list.push(message.commitment);
            party_id_list.push(party_pubkey_idx);
        }

        let final_sid = calculate_final_session_id(party_id_list.iter().copied(), &sid_i_list, &[]);

        // 12.4(b)
        let mut rng = ChaCha20Rng::from_seed(self.seed);
        let dlog_sid = Sha256::new()
            .chain(b"SL-EDDSA-DLOG-PROOF")
            .chain(final_sid.as_ref())
            .chain((self.params.party_id as u32).to_be_bytes())
            .chain(b"DLOG-PROOF-1-SID")
            .finalize()
            .into();

        let dlog_proofs = self
            .rand_params
            .polynomial
            .iter()
            .map(|f_i| DLogProof::<G>::prove(&dlog_sid, f_i, &mut rng))
            .collect::<Vec<_>>();

        // 12.4(d)
        let msg2 = KeygenMsg2 {
            from_party: self.params.party_id,
            session_id: final_sid,
            big_a_i_poly: self.state.big_a_i.coeffs,
            c_i_list: self.state.c_i_j,
            r_i: self.rand_params.r_i,
            dlog_proofs_i: dlog_proofs,
        };

        let next_state = KeygenParty {
            params: self.params,
            state: R2 {
                final_session_id: final_sid,
                commitment_list,
                sid_i_list,
            },
            key_refresh_data: self.key_refresh_data,
            rand_params: self.rand_params,
            seed: rng.gen(),
        };

        Ok((next_state, msg2))
    }
}

impl<G> Round for KeygenParty<R2, G>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]>,
    G::Scalar: Serializable,
{
    type InputMessage = KeygenMsg2<G>;
    type Input = Vec<KeygenMsg2<G>>;
    type Error = KeygenError;
    type Output = Keyshare<G>;

    fn process(self, messages: Self::Input) -> Result<Self::Output, Self::Error> {
        let messages = validate_input_messages(messages, self.params.n)?;

        messages.iter().try_for_each(|msg| {
            if msg.session_id != self.state.final_session_id {
                return Err(KeygenError::InvalidParticipantSet);
            }

            // 12.6(b)-i Verify commitments.
            let party_id = msg.party_id();
            let sid = &self.state.sid_i_list[party_id as usize];
            let commitment = &self.state.commitment_list[party_id as usize];
            let commit_hash =
                hash_commitment(sid, party_id, &msg.big_a_i_poly, &msg.c_i_list, &msg.r_i);
            let commit_cond = bool::from(commit_hash.ct_eq(commitment));

            // 12.6(b)-ii Verify DLog proofs
            // Verify DLog proofs.
            let dlog_sid = Sha256::new()
                .chain(b"SL-EDDSA-DLOG-PROOF")
                .chain(self.state.final_session_id.as_ref())
                .chain((party_id as u32).to_be_bytes())
                .chain(b"DLOG-PROOF-1-SID")
                .finalize()
                .into();

            let dlog_cond = verfiy_dlog_proofs(
                &msg.dlog_proofs_i,
                &msg.big_a_i_poly,
                &dlog_sid,
                self.params.t,
            );

            if !(dlog_cond && commit_cond) {
                return Err(KeygenError::ProofError);
            }

            Ok::<(), KeygenError>(())
        })?;

        let mut d_i_vals = Vec::with_capacity(messages.len());

        let mut chain_code_sids: Vec<[u8; 32]> = Vec::with_capacity(messages.len());

        // 12.6(c)
        for (party_id, msg) in messages.iter().enumerate() {
            let party_id = party_id as u8;

            let encrypted_d_i = &msg.c_i_list[self.params.party_id as usize];
            let sender_pubkey = find_enc_key(msg.party_id(), &self.params.party_enc_keys)
                .ok_or(KeygenError::InvalidPid)?;

            let plaintext = Zeroizing::new(
                decrypt_message(&self.params.dec_key, sender_pubkey, encrypted_d_i)
                    .ok_or(KeygenError::DecryptionError)?,
            );

            // Decode the scalar from the bytes.
            let mut encoding = <G::Scalar as PrimeField>::Repr::default();
            encoding.as_mut().copy_from_slice(&plaintext[..32]);

            let d_i = G::Scalar::from_repr(encoding)
                .into_option()
                .ok_or(KeygenError::InvalidDiPlaintext)?;

            d_i_vals.push(d_i);

            let chain_code_sid = plaintext[32..].try_into().unwrap();

            let is_lost = self
                .key_refresh_data
                .as_ref()
                .map(|r| r.lost_party_ids().contains(&party_id))
                .unwrap_or(false);

            if !is_lost {
                chain_code_sids.push(chain_code_sid);
            }
        }

        let d_i_share: G::Scalar = d_i_vals.iter().sum();

        let root_chain_code: [u8; 32] = if self.key_refresh_data.is_some() {
            let root_chain_code = chain_code_sids[0];

            if !chain_code_sids.iter().all(|&item| item == root_chain_code) {
                return Err(KeygenError::InvalidRefresh);
            }

            root_chain_code
        } else {
            chain_code_sids
                .into_iter()
                .fold(
                    Sha256::new().chain_update(b"SL-Keygen-ChainCode"),
                    |hasher, sid| hasher.chain_update(sid),
                )
                .finalize()
                .into()
        };

        let empty_poly = (0..self.params.t).map(|_| G::identity()).collect();
        let mut big_a_poly = GroupPolynomial::new(empty_poly);

        // Validate polynomial constant terms
        for msg in messages {
            let mut is_lost = false;
            if let Some(ref data) = self.key_refresh_data {
                is_lost = data.lost_keyshare_party_ids.contains(&msg.party_id());
            }
            let is_identity = msg.big_a_i_poly[0] == G::identity();

            if (is_lost && !is_identity) || (!is_lost && is_identity) {
                return Err(KeygenError::InvalidRefresh);
            }

            // 12.6(d)
            big_a_poly.add_mut(&msg.big_a_i_poly);

            // 12.6(e)
            let d_i = d_i_vals[msg.party_id() as usize];
            // let expected_point = EdwardsPoint::mul_base(&d_i);
            let expected_point = G::generator() * d_i;

            let calc_point = GroupPolynomial::new(msg.big_a_i_poly)
                .evaluate_at(&G::Scalar::from((self.params.party_id + 1) as u64));

            if !bool::from(expected_point.ct_eq(&calc_point)) {
                return Err(KeygenError::Abort(
                    "invalid d_i share/ given group polynomial",
                ));
            }
        }

        let public_key = big_a_poly.get_constant();

        // 12.6(e)
        let expected_point: G = G::generator() * d_i_share;
        let calc_point =
            big_a_poly.evaluate_at(&G::Scalar::from((self.params.party_id + 1) as u64));

        if !bool::from(expected_point.ct_eq(&calc_point)) {
            return Err(KeygenError::Abort(
                "invalid d_i share/ given group polynomial",
            ));
        }

        // Check if refresh is valid
        if let Some(data) = self.key_refresh_data {
            if public_key != data.expected_public_key {
                return Err(KeygenError::InvalidRefresh);
            }
        }

        let key_id = self
            .params
            .key_id
            .unwrap_or_else(|| sha2::Sha256::digest(public_key.to_bytes()).into());

        #[cfg(feature = "taproot")]
        let (public_key, d_i_share) = match std::any::type_name::<G>() {
            // If the type is ProjectivePoint, then we are using Taproot
            // We return the tweaked public key
            "k256::arithmetic::projective::ProjectivePoint" => {
                use elliptic_curve::point::AffineCoordinates;
                use std::{any::Any, ops::Neg};
                let taproot_pubkey = (&public_key as &dyn Any)
                    .downcast_ref::<k256::ProjectivePoint>()
                    .unwrap();
                if taproot_pubkey.to_affine().y_is_odd().unwrap_u8() == 1 {
                    (public_key.neg(), d_i_share.neg())
                } else {
                    (public_key, d_i_share)
                }
            }
            // Otherwise, we return the compressed public key
            _ => (public_key, d_i_share),
        };

        let keyshare = Keyshare {
            threshold: self.params.t,
            total_parties: self.params.n,
            party_id: self.params.party_id,
            key_id,
            d_i: d_i_share,
            public_key,
            extra_data: self.params.extra_data,
            root_chain_code,
            #[cfg(feature = "keyshare-session-id")]
            final_session_id: self.state.final_session_id,
        };
        Ok(keyshare)
    }
}

fn hash_commitment<G: GroupElem>(
    session_id: &SessionId,
    party_id: u8,
    big_f_i_vec: &[G],
    ciphertexts: &[EncryptedData],
    r_i: &[u8; 32],
) -> HashBytes {
    let mut hasher = Sha256::new()
        .chain_update(b"SL-Keygen-Commitment")
        .chain_update(session_id.as_ref())
        .chain_update(party_id.to_be_bytes());
    for point in big_f_i_vec.iter() {
        sha2::Digest::update(&mut hasher, point.to_bytes());
    }
    for c in ciphertexts {
        sha2::Digest::update(&mut hasher, bytemuck::bytes_of(c));
    }
    sha2::Digest::update(&mut hasher, r_i);
    hasher.finalize().into()
}

// makes sure a party receives the correct number of message, sorts by
// party-id.
fn validate_input_messages<M: BaseMessage>(
    mut messages: Vec<M>,
    n: u8,
) -> Result<Vec<M>, KeygenError> {
    if messages.len() != n as usize {
        return Err(KeygenError::InvalidMsgCount);
    }

    messages.sort_by_key(|msg| msg.party_id());

    messages
        .iter()
        .enumerate()
        .all(|(pid, msg)| msg.party_id() as usize == pid)
        .then_some(messages)
        .ok_or(KeygenError::InvalidParticipantSet)
}

fn verfiy_dlog_proofs<G: GroupElem>(
    proofs: &[DLogProof<G>],
    points: &[G],
    dlog_sid: &SessionId,
    threshold: u8,
) -> bool
where
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    let mut valid = true;
    if proofs.len() != points.len() || proofs.len() != threshold as usize {
        valid = false;
    }

    for (proof, point) in proofs.iter().zip(points) {
        if !proof.verify(dlog_sid, point) {
            valid = false;
        }
    }

    valid
}

fn find_enc_key(pid: u8, party_enc_keys: &[(u8, PublicKey)]) -> Option<&PublicKey> {
    party_enc_keys
        .iter()
        .find(|(id, _)| id == &pid)
        .map(|(_, key)| key)
}

impl<R, M> Session<R>
where
    M: Serializable,
    R: Round<Input = Vec<M>, InputMessage = M>,
    R: RoundSize,
    M: Clone,
{
    /// Create initial session.
    pub fn init<I>(state: I) -> Result<Self, I::Error>
    where
        I: InitRound<Next = R, OutputMessage = R::InputMessage>,
    {
        let (state, msg) = state.init()?;
        let mut messages = Vec::with_capacity(state.message_count());
        messages.push(msg);

        Ok(Self { state, messages })
    }

    /// Create second round session using values retuned by method
    /// `handle_messages()`.
    pub fn next(state: R, prev: M) -> Self {
        let mut messages = Vec::with_capacity(state.message_count());
        messages.push(prev);

        Self { state, messages }
    }

    /// Call a passed clozure with a reference to a broadcast message.
    pub fn with_first_message<O, F>(&self, f: F) -> O
    where
        F: FnOnce(&R::InputMessage) -> O,
    {
        f(&self.messages[0])
    }

    /// Make a clone of broadcast message created by the session.
    /// It uses method `with_first_message()` to clone the message.
    pub fn output_message(&self) -> R::InputMessage {
        self.with_first_message(|m| m.clone())
    }

    /// Receive a broadcast message. Returns `true` if all messages
    /// received and session ready to call method
    /// `process_messages()`.
    pub fn recv_message(&mut self, msg: M) -> bool {
        self.messages.push(msg);
        self.messages.len() == self.state.message_count()
    }

    /// Process message collected by `recv_message()` and return next
    /// state and message or key share.
    pub fn process_messages(self) -> Result<R::Output, R::Error> {
        self.state.process(self.messages)
    }
}

#[cfg(any(feature = "eddsa", feature = "taproot"))]
#[cfg(test)]
mod test {
    use super::*;

    use crate::{common::utils::support::run_keygen, keygen::utils::setup_keygen};

    fn run_dkg_session<const T: usize, const N: usize, G: GroupElem>()
    where
        G::Scalar: ScalarReduce<[u8; 32]>,
        G::Scalar: Serializable,
    {
        let mut first_round = setup_keygen::<G>(T as u8, N as u8)
            .map(Session::init)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        // collect first broadcast message from all sessions
        let msgs = first_round
            .iter()
            .map(|s| s.output_message())
            .collect::<Vec<_>>();

        // broadcast the first message to a appropriate sessions
        for (p, msg) in msgs.into_iter().enumerate() {
            first_round
                .iter_mut()
                .enumerate()
                .filter(|&(other, _)| other != p)
                .for_each(|(_, s)| {
                    s.recv_message(msg.clone());
                });
        }

        // Handle the first round, create new session/state and
        // collect second broadcast message from the new sessions.
        let (mut second_round, msgs): (Vec<_>, Vec<_>) = first_round
            .into_iter()
            .map(|s| {
                let (state, msg) = s.process_messages().unwrap();
                let state = Session::next(state, msg.clone());

                (state, msg)
            })
            .unzip();

        // broadcast the second message to a appropriate sessions
        for (p, msg) in msgs.into_iter().enumerate() {
            second_round
                .iter_mut()
                .enumerate()
                .filter(|&(other, _)| other != p)
                .for_each(|(_, s)| {
                    s.recv_message(msg.clone());
                });
        }

        // Process messages of the second round and output key shares.
        let _shares = second_round
            .into_iter()
            .map(|s| s.process_messages().unwrap())
            .collect::<Vec<_>>();
    }

    #[cfg(feature = "eddsa")]
    #[test]
    fn keygen_curve25519() {
        use curve25519_dalek::EdwardsPoint;

        run_keygen::<2, 2, EdwardsPoint>();
        run_keygen::<2, 3, EdwardsPoint>();
        run_keygen::<3, 5, EdwardsPoint>();
        run_keygen::<5, 5, EdwardsPoint>();
        run_keygen::<5, 10, EdwardsPoint>();
        run_keygen::<10, 10, EdwardsPoint>();
        run_keygen::<9, 20, EdwardsPoint>();
    }

    #[cfg(feature = "taproot")]
    #[test]
    fn keygen_taproot() {
        use k256::ProjectivePoint;

        run_keygen::<2, 2, ProjectivePoint>();
        run_keygen::<2, 3, ProjectivePoint>();
        run_keygen::<3, 5, ProjectivePoint>();
        run_keygen::<5, 10, ProjectivePoint>();
        run_keygen::<9, 20, ProjectivePoint>();
    }

    #[cfg(feature = "eddsa")]
    #[test]
    fn session_curve25519() {
        use curve25519_dalek::EdwardsPoint;

        run_dkg_session::<2, 2, EdwardsPoint>();
        run_dkg_session::<2, 3, EdwardsPoint>();
        run_dkg_session::<3, 5, EdwardsPoint>();
        run_dkg_session::<5, 5, EdwardsPoint>();
        run_dkg_session::<5, 10, EdwardsPoint>();
        run_dkg_session::<10, 10, EdwardsPoint>();
        run_dkg_session::<9, 20, EdwardsPoint>();
    }

    #[cfg(feature = "taproot")]
    #[test]
    fn session_taproot() {
        use k256::ProjectivePoint;

        run_dkg_session::<2, 2, ProjectivePoint>();
        run_dkg_session::<2, 3, ProjectivePoint>();
        run_dkg_session::<3, 5, ProjectivePoint>();
        run_dkg_session::<5, 5, ProjectivePoint>();
        run_dkg_session::<5, 10, ProjectivePoint>();
        run_dkg_session::<10, 10, ProjectivePoint>();
        run_dkg_session::<9, 20, ProjectivePoint>();
    }

    #[cfg(all(feature = "serde", feature = "server-storage"))]
    fn run_dkg_server_session<const T: usize, const N: usize, G: GroupElem>()
    where
        G::Scalar: ScalarReduce<[u8; 32]>,
        G::Scalar: Serializable,
    {
        use std::sync::Arc;

        use crate::common::storage::InMemoryDB;
        use crate::keygen::{
            client::DkgClient,
            server::{DkgServer, ServerError},
        };
        use rand::RngCore;

        // ServerSession wrapper to match Session API
        struct ServerSessionRound0<G>
        where
            G: GroupElem + GroupEncoding,
            G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
        {
            session_id: SessionId,
            server: Arc<DkgServer<G, InMemoryDB>>,
            output_msg: KeygenMsg1,
            messages: Vec<KeygenMsg1>,
            n: usize,
        }

        impl<G> ServerSessionRound0<G>
        where
            G: GroupElem + GroupEncoding,
            G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
        {
            fn init(
                session_id: SessionId,
                server: Arc<DkgServer<G, InMemoryDB>>,
                party: KeygenParty<R0, G>,
                n: usize,
            ) -> Result<Self, ServerError> {
                let output_msg = server.start_round_0(session_id, party)?;
                Ok(Self {
                    session_id,
                    server,
                    output_msg: output_msg.clone(),
                    messages: vec![output_msg],
                    n,
                })
            }

            fn output_message(&self) -> KeygenMsg1 {
                self.output_msg.clone()
            }

            fn recv_message(&mut self, msg: KeygenMsg1) -> bool {
                self.messages.push(msg);
                self.messages.len() == self.n
            }

            fn process_messages(
                self,
            ) -> Result<(ServerSessionRound1<G>, KeygenMsg2<G>), ServerError> {
                let msg2 = self
                    .server
                    .process_round_1(self.session_id, self.messages)?;
                let msg2_clone = msg2.clone();
                Ok((
                    ServerSessionRound1 {
                        session_id: self.session_id,
                        server: self.server,
                        output_msg: msg2_clone.clone(),
                        messages: vec![msg2_clone],
                        n: self.n,
                    },
                    msg2,
                ))
            }
        }

        struct ServerSessionRound1<G>
        where
            G: GroupElem + GroupEncoding + ConstantTimeEq,
            G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
        {
            session_id: SessionId,
            server: Arc<DkgServer<G, InMemoryDB>>,
            output_msg: KeygenMsg2<G>,
            messages: Vec<KeygenMsg2<G>>,
            n: usize,
        }

        impl<G> ServerSessionRound1<G>
        where
            G: GroupElem + GroupEncoding + ConstantTimeEq,
            G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
        {
            fn next(
                session_id: SessionId,
                server: Arc<DkgServer<G, InMemoryDB>>,
                prev: KeygenMsg2<G>,
                n: usize,
            ) -> Self {
                Self {
                    session_id,
                    server,
                    output_msg: prev.clone(),
                    messages: vec![prev],
                    n,
                }
            }

            fn output_message(&self) -> KeygenMsg2<G> {
                self.output_msg.clone()
            }

            fn recv_message(&mut self, msg: KeygenMsg2<G>) -> bool {
                self.messages.push(msg);
                self.messages.len() == self.n
            }

            fn process_messages(self) -> Result<Keyshare<G>, ServerError> {
                // Extract final_session_id from the first message
                // KeygenMsg2.session_id is the final_session_id computed in round 1
                let final_session_id = self.messages[0].session_id;
                self.server
                    .process_round_2(self.session_id, final_session_id, self.messages)
            }
        }

        // Setup: Create encryption keys for all parties
        let parties = setup_keygen::<G>(T as u8, N as u8);
        let party_list: Vec<KeygenParty<R0, G>> = parties.collect();

        // Server setup: Create server with encryption key and database
        let mut encryption_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut encryption_key);
        let db = Arc::new(InMemoryDB::new());
        let server = Arc::new(DkgServer::<G, _>::new(encryption_key, db.clone()));

        // Each party generates its own session_id for server state storage
        let mut party_session_ids = Vec::new();
        for _ in 0..N {
            party_session_ids.push(DkgClient::generate_session_id());
        }

        // Round 0: Initialize DKG for each party using server
        let mut first_round: Vec<ServerSessionRound0<G>> = party_list
            .into_iter()
            .enumerate()
            .map(|(i, party)| {
                let session_id = party_session_ids[i];
                ServerSessionRound0::init(session_id, server.clone(), party, N).unwrap()
            })
            .collect();

        // collect first broadcast message from all sessions
        let msgs = first_round
            .iter()
            .map(|s| s.output_message())
            .collect::<Vec<_>>();

        // broadcast the first message to appropriate sessions
        for (p, msg) in msgs.into_iter().enumerate() {
            first_round
                .iter_mut()
                .enumerate()
                .filter(|&(other, _)| other != p)
                .for_each(|(_, s)| {
                    s.recv_message(msg.clone());
                });
        }

        // Handle the first round, create new session/state and
        // collect second broadcast message from the new sessions.
        let (mut second_round, msgs): (Vec<_>, Vec<_>) = first_round
            .into_iter()
            .map(|s| {
                let (state, msg) = s.process_messages().unwrap();
                let state =
                    ServerSessionRound1::next(state.session_id, state.server, msg.clone(), N);
                (state, msg)
            })
            .unzip();

        // broadcast the second message to appropriate sessions
        for (p, msg) in msgs.into_iter().enumerate() {
            second_round
                .iter_mut()
                .enumerate()
                .filter(|&(other, _)| other != p)
                .for_each(|(_, s)| {
                    s.recv_message(msg.clone());
                });
        }

        // Process messages of the second round and output key shares.
        let keyshares = second_round
            .into_iter()
            .map(|s| s.process_messages().unwrap())
            .collect::<Vec<_>>();

        // Verify all parties have the same public key
        let public_key = keyshares[0].public_key();
        assert!(keyshares.iter().all(|ks| ks.public_key() == public_key));
    }

    #[cfg(all(feature = "eddsa", feature = "serde", feature = "server-storage"))]
    #[test]
    fn server_session_curve25519() {
        use curve25519_dalek::EdwardsPoint;

        run_dkg_server_session::<2, 2, EdwardsPoint>();
        run_dkg_server_session::<2, 3, EdwardsPoint>();
        run_dkg_server_session::<3, 5, EdwardsPoint>();
        run_dkg_server_session::<5, 5, EdwardsPoint>();
    }

    #[cfg(all(feature = "taproot", feature = "serde", feature = "server-storage"))]
    #[test]
    fn server_session_taproot() {
        use k256::ProjectivePoint;

        run_dkg_server_session::<2, 2, ProjectivePoint>();
        run_dkg_server_session::<2, 3, ProjectivePoint>();
        run_dkg_server_session::<3, 5, ProjectivePoint>();
    }
}

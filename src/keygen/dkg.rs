use crypto_bigint::subtle::ConstantTimeEq;
use crypto_box::{PublicKey, SecretKey};
use elliptic_curve::{group::GroupEncoding, Group};

use std::sync::Arc;

use ff::{Field, PrimeField};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use sha2::{digest::Update, Digest, Sha256};
use sl_mpc_mate::math::GroupPolynomial;

use crate::common::{
    traits::{GroupElem, Round, ScalarReduce},
    utils::{
        calculate_final_session_id, decrypt_message, encrypt_message, BaseMessage, EncryptedScalar,
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
pub struct KeygenParty<T, G>
where
    G: Group,
{
    params: KeygenParams,
    rand_params: KeyEntropy<G>,
    seed: [u8; 32],
    state: T,
    key_refresh_data: Option<KeyRefreshData<G>>,
}

pub struct R0;

/// State of a keygen party after receiving public keys of all parties and generating the first message.
pub struct R1<G>
where
    G: Group + GroupEncoding,
{
    big_a_i: GroupPolynomial<G>,
    c_i_j: Vec<EncryptedScalar>,
    commitment: HashBytes,
}

/// State of a keygen party after processing the first message.
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
        let enc_key = find_enc_key(pid, party_enc_keys);
        if enc_key.is_none() {
            return Err(KeygenError::InvalidParticipantSet);
        }

        if pid == party_id && enc_key.unwrap() != my_enc_key {
            return Err(KeygenError::InvalidParticipantSet);
        }
    }

    Ok(())
}

impl<G> KeygenParty<R0, G>
where
    G: Group,
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
        let mut rand_params = KeyEntropy::generate(t, n, &mut rng);

        // Set the constant polynomial to the keyshare secret.
        // s_i_0 is the current party's additive share of the private key
        if let Some(ref v) = refresh_data {
            rand_params.polynomial.set_constant(v.s_i_0);
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
}

// Protocol 12 from https://eprint.iacr.org/2022/374.pdf
// Simple Three-Round Multiparty Schnorr Signing with Full Simulatability
impl<G: GroupElem> Round for KeygenParty<R0, G> {
    type Input = ();

    type Output = Result<(KeygenParty<R1<G>, G>, KeygenMsg1), KeygenError>;

    /// Protocol 21, step 2. From https://eprint.iacr.org/2022/374.pdf.
    fn process(self, _: ()) -> Self::Output {
        // 12.2(a) Sampling random session-id was done in KeyEntropy.

        // 12.2(b) Sampling random polynomial was done in KeyEntropy.
        let big_a_i = self.rand_params.polynomial.commit();

        // 12.2(c)
        let mut rng = ChaCha20Rng::from_seed(self.seed);
        let c_i_j = (0..self.params.n)
            .map(|party_id| {
                // party_id is also the index of the party's data in all the lists.
                let ek_i = find_enc_key(party_id, &self.params.party_enc_keys).unwrap();

                // Party's point is just party-id. (Adding 1 because party-id's start from 0).
                let d_i = self
                    .rand_params
                    .polynomial
                    .evaluate_at(&G::Scalar::from((party_id + 1) as u64));

                let enc_data = encrypt_message::<_, G>(
                    (&self.params.dec_key, self.params.party_id),
                    (ek_i, party_id),
                    d_i,
                    &mut rng,
                )
                .ok_or(KeygenError::EncryptionError)?;

                Ok(enc_data)
            })
            .collect::<Result<Vec<_>, KeygenError>>()?;

        // 12.2(d)
        let commitment = hash_commitment(
            self.rand_params.session_id,
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

impl<G> Round for KeygenParty<R1<G>, G>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    type Input = Vec<KeygenMsg1>;

    type Output = Result<(KeygenParty<R2, G>, KeygenMsg2<G>), KeygenError>;

    fn process(self, messages: Self::Input) -> Self::Output {
        let n = self.params.n as usize;
        // We pass None for expected_sid because we don't know the final session id yet.
        // We don't expect the session-ids to be equal for all messages in this round.
        let messages = validate_input_messages(messages, self.params.t, None)?;
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

        let final_sid =
            calculate_final_session_id(party_id_list.iter().copied(), &sid_i_list, None);

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
            session_id: final_sid,
            from_party: self.params.party_id,
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
{
    type Input = Vec<KeygenMsg2<G>>;

    type Output = Result<Keyshare<G>, KeygenError>;

    fn process(self, messages: Self::Input) -> Self::Output {
        let messages =
            validate_input_messages(messages, self.params.t, Some(self.state.final_session_id))?;

        messages.par_iter().try_for_each(|msg| {
            // 12.6(b)-i Verify commitments.
            let party_id = msg.party_id();
            let sid = self.state.sid_i_list[party_id as usize];

            let commitment = self.state.commitment_list[party_id as usize];
            let commit_hash =
                hash_commitment(sid, party_id, &msg.big_a_i_poly, &msg.c_i_list, &msg.r_i);
            let commit_cond = bool::from(commit_hash.ct_eq(&commitment));

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

        // 12.6(c)
        let d_i_vals = messages
            .iter()
            .map(|msg| {
                let encrypted_d_i = &msg.c_i_list[self.params.party_id as usize];
                let sender_pubkey =
                    find_enc_key(msg.party_id(), &self.params.party_enc_keys).unwrap();

                let d_i_bytes = decrypt_message(&self.params.dec_key, sender_pubkey, encrypted_d_i)
                    .ok_or(KeygenError::DecryptionError)?;

                // Decode the scalar from the bytes.
                let mut encoding = <G::Scalar as PrimeField>::Repr::default();
                encoding.as_mut().copy_from_slice(&d_i_bytes);

                let d_i = G::Scalar::from_repr(encoding);
                if d_i.is_none().into() {
                    return Err(KeygenError::InvalidDiPlaintext);
                }

                Ok(d_i.unwrap())
            })
            .collect::<Result<Vec<_>, KeygenError>>()?;

        // 12.6(c)
        let d_i_share = d_i_vals.iter().sum();

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

        let key_id = if let Some(key_id) = self.params.key_id {
            key_id
        } else {
            sha2::Sha256::digest(public_key.to_bytes()).into()
        };

        let keyshare = Keyshare {
            threshold: self.params.t,
            total_parties: self.params.n,
            party_id: self.params.party_id,
            key_id,
            d_i: d_i_share,
            public_key,
            extra_data: self.params.extra_data,
        };
        Ok(keyshare)
    }
}

fn hash_commitment<G: GroupElem>(
    session_id: SessionId,
    party_id: u8,
    big_f_i_vec: &[G],
    ciphertexts: &[EncryptedScalar],
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

fn validate_input_messages<M: BaseMessage>(
    mut messages: Vec<M>,
    t: u8,
    expected_sid: Option<SessionId>,
) -> Result<Vec<M>, KeygenError> {
    if messages.len() < t as usize {
        return Err(KeygenError::InvalidMsgCount);
    }

    messages.sort_by_key(|msg| msg.party_id());

    messages
        .iter()
        .enumerate()
        .all(|(pid, msg)| {
            let pid_match = msg.party_id() as usize == pid;
            let sid_match = expected_sid
                .as_ref()
                .map(|sid| sid == msg.session_id())
                .unwrap_or(true);

            pid_match && sid_match
        })
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

#[cfg(test)]
mod test {
    use crate::common::utils::run_keygen;
    use curve25519_dalek::EdwardsPoint;
    use k256::ProjectivePoint;

    #[test]
    fn keygen_curve25519() {
        run_keygen::<2, 2, EdwardsPoint>();
        run_keygen::<2, 3, EdwardsPoint>();
        run_keygen::<3, 5, EdwardsPoint>();
        run_keygen::<5, 5, EdwardsPoint>();
        run_keygen::<5, 10, EdwardsPoint>();
        run_keygen::<10, 10, EdwardsPoint>();
        run_keygen::<9, 20, EdwardsPoint>();
    }

    #[test]
    fn keygen_taproot() {
        run_keygen::<2, 2, ProjectivePoint>();
        run_keygen::<2, 3, ProjectivePoint>();
        run_keygen::<3, 5, ProjectivePoint>();
        run_keygen::<5, 5, EdwardsPoint>();
        run_keygen::<5, 10, ProjectivePoint>();
        run_keygen::<10, 10, EdwardsPoint>();
        run_keygen::<9, 20, ProjectivePoint>();
    }
}

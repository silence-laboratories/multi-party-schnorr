use crypto_bigint::subtle::ConstantTimeEq;
use crypto_box::SecretKey;
use curve25519_dalek::{traits::Identity, EdwardsPoint, Scalar};
use ed25519_dalek::{DigestSigner, DigestVerifier, Signature, SigningKey};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use sha2::{Digest, Sha256, Sha512};
use sl_mpc_mate::message::{Opaque, GR};

use crate::common::{
    traits::{PersistentObj, Round},
    utils::{
        calculate_final_session_id, decrypt_message, encrypt_message, BaseMessage, EncryptedData,
        HashBytes, SessionId,
    },
    DLogProof, GroupPolynomial, PartyKeys, PartyPublicKeys,
};

use super::{
    types::{KeyEntropy, KeygenError, KeygenParams},
    KeyRefreshData, KeygenMsg1, KeygenMsg2, Keyshare,
};

/// LABEL for the keygen protocol
pub const DKG_LABEL: &[u8] = b"SilenceLaboratories-EDDSA-DKG";

/// Keygen party
/// The keygen party is a state machine that implements the keygen protocol.
// #[derive(Clone, bincode::Encode, bincode::Decode)]
pub struct KeygenParty<T> {
    params: KeygenParams,
    rand_params: KeyEntropy,
    seed: [u8; 32],
    state: T,
    key_refresh_data: Option<KeyRefreshData>,
}

pub struct R0;

/// State of a keygen party after receiving public keys of all parties and generating the first message.
// #[derive(Clone, bincode::Encode, bincode::Decode)]
pub struct R1 {
    big_a_i: GroupPolynomial,
    c_i_j: Vec<EncryptedData>,
    commitment: HashBytes,
}
/// State of a keygen party after processing the first message.
// #[derive(Clone, bincode::Encode, bincode::Decode)]
pub struct R2 {
    final_session_id: SessionId,
    commitment_list: Vec<HashBytes>,
    sid_i_list: Vec<SessionId>,
}

fn validate_input(t: u8, n: u8, party_id: u8) -> Result<(), KeygenError> {
    if party_id >= n {
        return Err(KeygenError::InvalidPid);
    }

    if t > n || t < 2 {
        return Err(KeygenError::InvalidT);
    }

    Ok(())
}

impl KeygenParty<R0> {
    /// Create a new keygen party.
    pub fn new<R: CryptoRng + RngCore>(
        t: u8,
        n: u8,
        party_id: u8,
        keys: &PartyKeys,
        party_pubkeys_list: Vec<PartyPublicKeys>,
        refresh_data: Option<KeyRefreshData>,
        rng: &mut R,
    ) -> Result<Self, KeygenError> {
        let mut rand_params = KeyEntropy::generate(t, n, rng);
        let seed = rng.gen();

        // Set the constant polynomial to the keyshare secret.
        // d_i_0 is the current party's additive share of the private key
        if let Some(ref v) = refresh_data {
            rand_params.polynomial.coeffs[0] = v.d_i_0;
        }

        Self::new_with_context(
            t,
            n,
            party_id,
            keys,
            rand_params,
            party_pubkeys_list,
            refresh_data,
            seed,
        )
    }
    /// Create a new keygen protocol instance with a given context. Used for testing purposes internally.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_context(
        t: u8,
        n: u8,
        party_id: u8,
        party_keys: &PartyKeys,
        rand_params: KeyEntropy,
        party_pubkeys_list: Vec<PartyPublicKeys>,
        key_refresh_data: Option<KeyRefreshData>,
        seed: [u8; 32],
    ) -> Result<Self, KeygenError> {
        validate_input(t, n, party_id)?;
        let my_pubkeys = party_keys.public_keys();
        validate_pubkeys(&party_pubkeys_list, n, party_id, &my_pubkeys)?;

        // Validate refresh data
        if let Some(ref v) = key_refresh_data {
            let is_lost = v.lost_keyshare_party_ids.contains(&party_id);
            let cond1 = v.expected_public_key == EdwardsPoint::identity();
            let cond2 = v.lost_keyshare_party_ids.len() > (n - t).into();
            let cond3 = rand_params.polynomial.coeffs[0] != v.d_i_0;
            let cond4 = if is_lost {
                v.d_i_0 != Scalar::ZERO
            } else {
                v.d_i_0 == Scalar::ZERO
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
                party_pubkeys_list,
                x_i: Scalar::from(party_id + 1),
                signing_key: party_keys.signing_key.to_bytes(),
                enc_secret_key: party_keys.encryption_secret_key.to_scalar(),
            },
            rand_params,
            seed,
            key_refresh_data,
            state: R0,
        })
    }
    pub fn public_keys(&self) -> PartyPublicKeys {
        PartyPublicKeys {
            verify_key: SigningKey::from(self.params.signing_key).verifying_key(),
            encryption_key: crypto_box::SecretKey::from(self.params.enc_secret_key).public_key(),
        }
    }
}

// Protocol 11 from https://eprint.iacr.org/2022/374.pdf
// Simple Three-Round Multiparty Schnorr Signing with Full Simulatability
impl Round for KeygenParty<R0> {
    type Input = ();

    type Output = Result<(KeygenParty<R1>, KeygenMsg1), KeygenError>;

    /// Protocol 11, step 2. From https://eprint.iacr.org/2022/374.pdf.
    fn process(self, _: ()) -> Self::Output {
        // 11.2(a) Sampling random session-id was done in KeyEntropy.

        // 11.2(b) Sampling random polynomial was done in KeyEntropy.
        let big_a_i = self.rand_params.polynomial.commit();

        // 11.2(c)
        let mut rng = ChaCha20Rng::from_seed(self.seed);
        let c_i_j = (0..self.params.n)
            .map(|party_id| {
                // party_id is also the index of the party's data in all the lists.
                let ek_i = &self.params.party_pubkeys_list[party_id as usize].encryption_key;

                // Party's point is just party-id. (Adding 1 because party-id's start from 0).
                let d_i = self
                    .rand_params
                    .polynomial
                    .evaluate_at(Scalar::from(party_id + 1));

                let enc_data = encrypt_message(
                    (
                        &crypto_box::SecretKey::from(self.params.enc_secret_key),
                        self.params.party_id,
                    ),
                    (&ek_i, party_id),
                    &d_i.to_bytes(),
                    &mut rng,
                )
                .ok_or(KeygenError::EncryptionError)?;

                Ok(enc_data)
            })
            .collect::<Result<Vec<_>, KeygenError>>()?;

        // 11.2(d)
        let commitment = hash_commitment(
            self.rand_params.session_id,
            self.params.party_id,
            &big_a_i,
            &c_i_j,
            &self.rand_params.r_i,
        );

        // 11.2(e)
        let msg_hash = digest_msg1(&self.rand_params.session_id, &commitment);
        let signature = SigningKey::from(self.params.signing_key).sign_digest(msg_hash);

        // 11.2(f)
        let msg1 = KeygenMsg1 {
            from_party: self.params.party_id,
            session_id: self.rand_params.session_id,
            commitment,
            signature: signature.to_bytes(),
        };

        let next_state = KeygenParty {
            params: self.params,
            rand_params: self.rand_params,
            seed: self.seed,
            key_refresh_data: self.key_refresh_data,
            state: R1 {
                big_a_i,
                commitment,
                c_i_j,
            },
        };

        Ok((next_state, msg1))
    }
}

impl Round for KeygenParty<R1> {
    type Input = Vec<KeygenMsg1>;

    type Output = Result<(KeygenParty<R2>, KeygenMsg2), KeygenError>;

    fn process(self, messages: Self::Input) -> Self::Output {
        let n = self.params.n as usize;
        // We pass None for expected_sid because we don't know the final session id yet.
        // We don't expect the session-ids to be equal for all messages in this round.
        let messages = validate_input_messages(messages, self.params.n, None)?;
        let mut sid_i_list = Vec::with_capacity(n);
        let mut commitment_list = Vec::with_capacity(n);
        let mut party_id_list = Vec::with_capacity(n);

        // 11.4(a)
        for message in &messages {
            if message.party_id() == self.params.party_id {
                let cond1 = self.rand_params.session_id == message.session_id;
                let cond2 = self.state.commitment == message.commitment;
                if !(cond1 && cond2) {
                    return Err(KeygenError::Abort("Invalid message in list"));
                }
            }
            let party_pubkey_idx = message.party_id();

            let PartyPublicKeys { verify_key, .. } =
                &self.params.party_pubkeys_list[party_pubkey_idx as usize];

            let message_hash = digest_msg1(&message.session_id, &message.commitment);
            verify_key.verify_digest(message_hash, &message.signature())?;

            sid_i_list.push(message.session_id);
            commitment_list.push(message.commitment);
            party_id_list.push(party_pubkey_idx);
        }

        let final_sid = calculate_final_session_id(party_id_list.iter().copied(), &sid_i_list);

        // 11.4(b)
        let mut rng = ChaCha20Rng::from_seed(self.seed);
        use sha2::digest::Update;
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
            .map(|f_i| DLogProof::prove(&dlog_sid, f_i, &mut rng))
            .collect::<Vec<_>>();

        // 11.4(c)
        let digest_message_2 = digest_msg2(
            &final_sid,
            &commitment_list,
            &self.state.big_a_i,
            &self.rand_params.r_i,
            &self.state.c_i_j,
            &dlog_proofs,
        );
        let signature = SigningKey::from(self.params.signing_key).sign_digest(digest_message_2);

        // 11.4(d)
        let msg2 = KeygenMsg2 {
            session_id: final_sid,
            from_party: self.params.party_id,
            big_a_i_poly: self.state.big_a_i,
            c_i_list: self.state.c_i_j,
            r_i: self.rand_params.r_i,
            dlog_proofs_i: dlog_proofs,
            signature: signature.to_bytes(),
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

impl Round for KeygenParty<R2> {
    type Input = Vec<KeygenMsg2>;

    type Output = Result<Keyshare, KeygenError>;

    fn process(self, messages: Self::Input) -> Self::Output {
        let messages =
            validate_input_messages(messages, self.params.n, Some(self.state.final_session_id))?;

        messages.par_iter().try_for_each(|msg| {
            // Verify signature.
            let message_hash = digest_msg2(
                &self.state.final_session_id,
                &self.state.commitment_list,
                &msg.big_a_i_poly,
                &msg.r_i,
                &msg.c_i_list,
                &msg.dlog_proofs_i,
            );

            // 11.6(a)
            let verifying_key = &self.params.party_pubkeys_list[msg.from_party as usize].verify_key;
            verifying_key.verify_digest(message_hash, &Signature::from(msg.signature))?;

            // 11.6(b)-i Verify commitments.
            let party_id = msg.party_id();
            let sid = self.state.sid_i_list[party_id as usize];

            let commitment = self.state.commitment_list[party_id as usize];
            let commit_hash =
                hash_commitment(sid, party_id, &msg.big_a_i_poly, &msg.c_i_list, &msg.r_i);
            let commit_cond = bool::from(commit_hash.ct_eq(&commitment));

            // 11.6(b)-ii Verify DLog proofs
            use sha2::digest::Update;
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

        // 11.6(c)
        let d_i_vals = messages
            .iter()
            .map(|msg| {
                let encrypted_d_i = &msg.c_i_list[self.params.party_id as usize];
                let sender_pubkey =
                    &self.params.party_pubkeys_list[msg.party_id() as usize].encryption_key;

                let d_i_bytes = decrypt_message(
                    &SecretKey::from(self.params.enc_secret_key),
                    sender_pubkey,
                    encrypted_d_i,
                )
                .ok_or(KeygenError::DecryptionError)?
                .try_into()
                .map_err(|_| KeygenError::InvalidDiPlaintext)?;

                let d_i = Scalar::from_canonical_bytes(d_i_bytes);

                if d_i.is_none().into() {
                    return Err(KeygenError::InvalidDiPlaintext);
                }

                Ok(d_i.unwrap())
            })
            .collect::<Result<Vec<_>, KeygenError>>()?;

        // 11.6(c)
        let d_i_share = d_i_vals.iter().sum();

        let empty_poly = (0..self.params.t)
            .map(|_| EdwardsPoint::identity().into())
            .collect();

        let mut big_a_poly = GroupPolynomial::new(empty_poly);

        // Validate polynomial constant terms
        for msg in &messages {
            let mut is_lost = false;
            if let Some(ref data) = self.key_refresh_data {
                is_lost = data.lost_keyshare_party_ids.contains(&msg.party_id());
            }
            let is_identity = msg.big_a_i_poly.get_constant() == EdwardsPoint::identity();

            if (is_lost && !is_identity) || (!is_lost && is_identity) {
                return Err(KeygenError::InvalidRefresh);
            }
        }

        for msg in &messages {
            // 11.6(d)
            big_a_poly.add_mut(&msg.big_a_i_poly);

            // 11.6(e)
            let d_i = d_i_vals[msg.party_id() as usize];
            let expected_point = EdwardsPoint::mul_base(&d_i);
            let calc_point = msg
                .big_a_i_poly
                .evaluate_at(&Scalar::from(self.params.party_id + 1));

            if !bool::from(expected_point.ct_eq(&calc_point)) {
                return Err(KeygenError::Abort(
                    "invalid d_i share/ given group polynomial",
                ));
            }
        }

        let public_key = big_a_poly.get_constant();

        // 11.6(e)
        let expected_point = EdwardsPoint::mul_base(&d_i_share);
        let calc_point = big_a_poly.evaluate_at(&Scalar::from(self.params.party_id + 1));

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

        let keyshare = Keyshare {
            threshold: self.params.t,
            total_parties: self.params.n,
            party_id: self.params.party_id,
            big_a_poly: big_a_poly.coeffs,
            d_i: Opaque::from(d_i_share),
            public_key: Opaque::from(public_key),
        };
        Ok(keyshare)
    }
}
fn hash_commitment(
    session_id: SessionId,
    party_id: u8,
    big_f_i_vec: &GroupPolynomial,
    ciphertexts: &[EncryptedData],
    r_i: &[u8; 32],
) -> HashBytes {
    let mut hasher = Sha256::new();
    sha2::Digest::update(&mut hasher, b"SL-Keygen-Commitment");
    sha2::Digest::update(&mut hasher, session_id.as_ref());
    sha2::Digest::update(&mut hasher, party_id.to_be_bytes());
    for point in big_f_i_vec.iter() {
        sha2::Digest::update(&mut hasher, point.compress().as_bytes());
    }
    for c in ciphertexts {
        sha2::Digest::update(&mut hasher, c.to_bytes().unwrap());
    }
    sha2::Digest::update(&mut hasher, r_i);
    hasher.finalize().into()
}

fn digest_msg1(session_id: &SessionId, commitment: &HashBytes) -> Sha512 {
    let mut hasher = Sha512::new();

    sha2::Digest::update(&mut hasher, DKG_LABEL);
    sha2::Digest::update(&mut hasher, b"KeygenMsg1");
    sha2::Digest::update(&mut hasher, session_id.as_ref());
    sha2::Digest::update(&mut hasher, commitment.as_ref());

    hasher
}
fn digest_msg2(
    session_id: &SessionId,
    commitment_i_list: &[HashBytes],
    big_a_i: &[Opaque<EdwardsPoint, GR>],
    r_i: &[u8; 32],
    c_i_list: &[EncryptedData],
    dlog_proofs: &[DLogProof],
) -> Sha512 {
    let mut hasher = Sha512::new();

    sha2::Digest::update(&mut hasher, DKG_LABEL);
    sha2::Digest::update(&mut hasher, b"KeygenMsg2");
    sha2::Digest::update(&mut hasher, session_id.as_ref());

    for commitment in commitment_i_list {
        sha2::Digest::update(&mut hasher, commitment.as_ref());
    }

    for point in big_a_i {
        sha2::Digest::update(&mut hasher, point.compress().as_bytes());
    }
    for c_i in c_i_list {
        sha2::Digest::update(&mut hasher, c_i.to_bytes().unwrap());
    }

    sha2::Digest::update(&mut hasher, r_i);

    for proof in dlog_proofs {
        sha2::Digest::update(&mut hasher, proof.to_bytes().unwrap())
    }

    hasher
}

fn _hash_complete_msg(session_id: &SessionId, public_key: &EdwardsPoint) -> Sha512 {
    let mut hasher = Sha512::new();

    sha2::Digest::update(&mut hasher, DKG_LABEL);
    sha2::Digest::update(&mut hasher, b"KeygenCompleteMsg");
    sha2::Digest::update(&mut hasher, session_id.as_ref());
    sha2::Digest::update(&mut hasher, public_key.compress().as_bytes());

    hasher
}

fn validate_pubkeys(
    pubkeys: &[PartyPublicKeys],
    n: u8,
    my_party_id: u8,
    my_pks: &PartyPublicKeys,
) -> Result<(), KeygenError> {
    if pubkeys.len() != n as usize {
        return Err(KeygenError::InvalidMessageLength);
    }

    let expected_pks = &pubkeys[my_party_id as usize];

    if expected_pks != my_pks {
        return Err(KeygenError::InvalidParticipantSet);
    }

    Ok(())
}

fn validate_input_messages<M: BaseMessage>(
    mut messages: Vec<M>,
    n: u8,
    expected_sid: Option<SessionId>,
) -> Result<Vec<M>, KeygenError> {
    if messages.len() != n as usize {
        return Err(KeygenError::InvalidMessageLength);
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
fn verfiy_dlog_proofs(
    proofs: &[DLogProof],
    points: &[Opaque<EdwardsPoint, GR>],
    dlog_sid: &SessionId,
    threshold: u8,
) -> bool {
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

#[cfg(test)]
mod test {
    use crate::keygen::utils::process_keygen;

    #[test]
    fn keygen() {
        let _ = process_keygen::<3, 5>();
        let _ = process_keygen::<2, 3>();
        let _ = process_keygen::<5, 10>();
        let _ = process_keygen::<9, 20>();
    }
}

// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! MPC-friendly VRF: https://github.com/coinbase/cb-mpc/blob/master/docs/spec/vrf-spec.pdf

use std::sync::Arc;

use crypto_bigint::subtle::ConstantTimeEq;
use elliptic_curve::group::GroupEncoding;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use sha2::{digest::Update, Digest, Sha256};

use crate::{
    common::{
        dh_tuple_transcript, get_lagrange_coeff, participant_public_share,
        traits::{GroupElem, Round, ScalarReduce},
        utils::{calculate_final_session_id, SessionId},
        DhTuplePoints, DhTupleProof,
    },
    derive::impls::ristretto::{VrfGroup, VrfScalar},
    derive::{hash_to_curve::ro_hash_string, ED25519_VRF_OUTPUT_BITS},
    keygen::Keyshare,
    sign::validate_input_messages,
    vrf::{
        messages::{VrfMsg0, VrfMsg1},
        types::{VrfEntropy, VrfError},
        VrfPoint,
    },
};

#[cfg(feature = "serde")]
use crate::common::{
    ser::Serializable,
    utils::{serde_point, serde_vec_point},
};

/// Output of a successful MPC VRF evaluation (ro-hash-string-1P(Z; 640)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfOutput {
    pub output: Vec<u8>,
    pub session_id: SessionId,
    pub pid_list: Vec<u8>,
}

#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "G: GroupElem + serde::Serialize, G::Scalar: Serializable",
        deserialize = "G: GroupElem + serde::Deserialize<'de>, G::Scalar: Serializable"
    ))
)]
struct Params<G: GroupElem> {
    party_id: u8,
    threshold: u8,
    total_parties: u8,
    message: Vec<u8>,
    output_bits: usize,
    shamir_share: G::Scalar,
    #[cfg_attr(feature = "serde", serde(with = "serde_point"))]
    public_key: G,
    #[cfg_attr(feature = "serde", serde(with = "serde_vec_point"))]
    party_public_shares: Vec<G>,
}

/// VRF evaluation party (multi-round, t-of-n) over curve group `G`.
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "T: serde::Serialize, G: GroupElem + serde::Serialize, G::Scalar: Serializable",
        deserialize = "T: serde::Deserialize<'de>, G: GroupElem + serde::Deserialize<'de>, G::Scalar: Serializable"
    ))
)]
pub struct VrfParty<T, G: GroupElem> {
    params: Params<G>,
    rand_params: VrfEntropy,
    state: T,
    #[cfg(feature = "keyshare-session-id")]
    keygen_session_id: [u8; 32],
}

/// Production VRF on Ristretto (`VrfParty<State, VrfPoint>`).
pub type VrfPartyRistretto<State> = VrfParty<State, VrfPoint>;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VrfR0;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VrfR1 {
    h_con: [u8; 32],
}

#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "G: GroupElem + serde::Serialize, G::Scalar: Serializable",
        deserialize = "G: GroupElem + serde::Deserialize<'de>, G::Scalar: Serializable"
    ))
)]
pub struct VrfR2<G: GroupElem> {
    final_session_id: SessionId,
    pid_list: Vec<u8>,
    #[cfg_attr(feature = "serde", serde(with = "serde_point"))]
    m_point: G,
}

fn validate_keyshare_for_vrf<G: GroupElem>(keyshare: &Keyshare<G>) -> Result<(), VrfError> {
    let total_parties = keyshare.total_parties as usize;
    if keyshare.party_id() >= keyshare.total_parties {
        return Err(VrfError::InvalidKeyshare);
    }
    if keyshare.party_public_shares.len() != total_parties {
        return Err(VrfError::InvalidKeyshare);
    }
    Ok(())
}

impl<G> VrfParty<VrfR0, G>
where
    G: GroupElem + VrfGroup,
    G::Scalar: VrfScalar,
{
    pub fn new<R: RngCore + CryptoRng>(
        keyshare: Arc<Keyshare<G>>,
        message: Vec<u8>,
        rng: &mut R,
    ) -> Result<Self, VrfError> {
        Self::new_with_output_bits(keyshare, message, ED25519_VRF_OUTPUT_BITS, rng)
    }

    pub fn new_with_output_bits<R: RngCore + CryptoRng>(
        keyshare: Arc<Keyshare<G>>,
        message: Vec<u8>,
        output_bits: usize,
        rng: &mut R,
    ) -> Result<Self, VrfError> {
        validate_keyshare_for_vrf(keyshare.as_ref())?;
        Ok(Self {
            params: Params {
                party_id: keyshare.party_id(),
                threshold: keyshare.threshold,
                total_parties: keyshare.total_parties,
                message,
                output_bits,
                shamir_share: *keyshare.shamir_share(),
                public_key: keyshare.public_key,
                party_public_shares: keyshare.party_public_shares.clone(),
            },
            rand_params: VrfEntropy::generate(rng),
            state: VrfR0,
            #[cfg(feature = "keyshare-session-id")]
            keygen_session_id: keyshare.final_session_id,
        })
    }
}

impl<G> Round for VrfParty<VrfR0, G>
where
    G: GroupElem + VrfGroup,
    G::Scalar: ScalarReduce<[u8; 32]>,
    G::Scalar: VrfScalar,
{
    type InputMessage = ();
    type Input = ();
    type Error = VrfError;
    type Output = (VrfParty<VrfR1, G>, VrfMsg0);

    fn process(self, _: ()) -> Result<Self::Output, Self::Error> {
        let vrf_ki = get_lagrange_coeff::<G>(&self.params.party_id, 0..self.params.total_parties)
            * self.params.shamir_share;
        let ki = self.params.party_public_shares[self.params.party_id as usize];
        let expected_ki = G::generator() * vrf_ki;
        if !bool::from(expected_ki.ct_eq(&ki)) {
            return Err(VrfError::InvalidLocalKey);
        }

        let mut sum_k = G::identity();
        for share in &self.params.party_public_shares {
            sum_k += *share;
        }
        if !bool::from(sum_k.ct_eq(&self.params.public_key)) {
            return Err(VrfError::InvalidPublicShares);
        }

        let h_con = hash_consistency(
            &self.params.public_key,
            &self.params.party_public_shares,
            &self.params.message,
            self.params.output_bits,
        );

        let msg = VrfMsg0 {
            from_party: self.params.party_id,
            session_id: self.rand_params.session_id,
            h_con,
        };

        Ok((
            VrfParty {
                params: self.params,
                rand_params: self.rand_params,
                state: VrfR1 { h_con },
                #[cfg(feature = "keyshare-session-id")]
                keygen_session_id: self.keygen_session_id,
            },
            msg,
        ))
    }
}

impl<G> Round for VrfParty<VrfR1, G>
where
    G: GroupElem + VrfGroup,
    G::Scalar: ScalarReduce<[u8; 32]>,
    G::Scalar: VrfScalar,
{
    type InputMessage = VrfMsg0;
    type Input = Vec<VrfMsg0>;
    type Error = VrfError;
    type Output = (VrfParty<VrfR2<G>, G>, VrfMsg1<G>);

    fn process(self, mut msgs: Self::Input) -> Result<Self::Output, Self::Error> {
        let mut sid_list = Vec::with_capacity(self.params.threshold as usize);
        let mut party_ids = Vec::with_capacity(self.params.threshold as usize);

        msgs.sort_by_key(|m| m.from_party);

        for msg in &msgs {
            if msg.from_party >= self.params.total_parties {
                return Err(VrfError::InvalidMsgPartyId);
            }
            if msg.h_con != self.state.h_con {
                return Err(VrfError::ConsistencyHashMismatch(msg.from_party));
            }
            sid_list.push(msg.session_id);
            party_ids.push(msg.from_party);
        }

        let local_msg = msgs
            .iter()
            .find(|msg| msg.from_party == self.params.party_id)
            .ok_or(VrfError::InvalidParticipantSet)?;

        if local_msg.session_id != self.rand_params.session_id {
            return Err(VrfError::InvalidParticipantSet);
        }

        party_ids.sort_unstable();
        party_ids.dedup();
        if party_ids.len() != msgs.len() {
            return Err(VrfError::InvalidParticipantSet);
        }

        if party_ids.len() < self.params.threshold as usize
            || party_ids.len() > self.params.total_parties as usize
        {
            return Err(VrfError::InvalidParticipantSet);
        }

        let final_session_id = calculate_final_session_id(
            party_ids.iter().copied(),
            &sid_list,
            #[cfg(feature = "keyshare-session-id")]
            &[&self.params.message, &self.keygen_session_id],
            #[cfg(not(feature = "keyshare-session-id"))]
            &[&self.params.message],
        );

        let m_point = G::hash_vrf_message(&[self.params.message.as_slice()])
            .map_err(|_| VrfError::HashToCurve)?;

        let coeff = get_lagrange_coeff::<G>(&self.params.party_id, party_ids.iter().copied());
        let vrf_ki = coeff * self.params.shamir_share;
        let party_ki = G::generator() * vrf_ki;

        let aux = (self.params.party_id as u32).to_be_bytes();
        let mut rng = ChaCha20Rng::from_seed(self.rand_params.seed);
        let z_i = m_point * vrf_ki;
        let mut transcript = dh_tuple_transcript(&final_session_id, &aux);
        let pi = DhTupleProof::prove(
            DhTuplePoints {
                g: &G::generator(),
                q: &m_point,
                a: &party_ki,
                b: &z_i,
            },
            &vrf_ki,
            &mut transcript,
            &mut rng,
        );

        let msg = VrfMsg1 {
            from_party: self.params.party_id,
            session_id: final_session_id,
            z_i: z_i.to_bytes().as_ref().to_vec(),
            pi,
        };

        Ok((
            VrfParty {
                params: self.params,
                rand_params: self.rand_params,
                state: VrfR2 {
                    final_session_id,
                    pid_list: party_ids,
                    m_point,
                },
                #[cfg(feature = "keyshare-session-id")]
                keygen_session_id: self.keygen_session_id,
            },
            msg,
        ))
    }
}

impl<G> Round for VrfParty<VrfR2<G>, G>
where
    G: GroupElem + VrfGroup,
    G::Scalar: ScalarReduce<[u8; 32]>,
    G::Scalar: VrfScalar,
{
    type InputMessage = VrfMsg1<G>;
    type Input = Vec<VrfMsg1<G>>;
    type Error = VrfError;
    type Output = VrfOutput;

    fn process(self, msgs: Self::Input) -> Result<Self::Output, Self::Error> {
        let msgs = validate_input_messages(msgs, &self.state.pid_list).map_err(map_sign_error)?;

        let g = G::generator();
        let mut z = G::identity();

        for msg in &msgs {
            if msg.from_party >= self.params.total_parties {
                return Err(VrfError::InvalidMsgPartyId);
            }
            if !bool::from(msg.session_id.ct_eq(&self.state.final_session_id)) {
                return Err(VrfError::InvalidDhProof(msg.from_party));
            }
            let z_j = decode_point::<G>(&msg.z_i).ok_or(VrfError::InvalidZ(msg.from_party))?;
            if !G::is_valid_partial_vrf_point(&z_j) {
                return Err(VrfError::InvalidZ(msg.from_party));
            }

            let aux = (msg.from_party as u32).to_be_bytes();
            let k_j = participant_public_share(
                &self.params.party_public_shares[msg.from_party as usize],
                msg.from_party,
                self.params.total_parties,
                self.state.pid_list.iter().copied(),
            );
            let mut transcript = dh_tuple_transcript(&self.state.final_session_id, &aux);
            if !msg.pi.verify(
                DhTuplePoints {
                    g: &g,
                    q: &self.state.m_point,
                    a: &k_j,
                    b: &z_j,
                },
                &mut transcript,
            ) {
                return Err(VrfError::InvalidDhProof(msg.from_party));
            }

            z += z_j;
        }

        let output = ro_hash_string(&[z.to_bytes().as_ref()], self.params.output_bits);

        Ok(VrfOutput {
            output,
            session_id: self.state.final_session_id,
            pid_list: self.state.pid_list,
        })
    }
}

/// Run the full MPC VRF protocol locally (all parties, full quorum).
#[cfg(feature = "test-support")]
pub fn run_vrf_mpc_full<R: RngCore + CryptoRng>(
    keyshares: Vec<Keyshare<VrfPoint>>,
    message: Vec<u8>,
    output_bits: usize,
    rng: &mut R,
) -> Vec<u8> {
    use crate::common::utils::support::run_round;

    let parties: Vec<_> = keyshares
        .into_iter()
        .map(|ks| {
            VrfParty::<VrfR0, VrfPoint>::new_with_output_bits(
                Arc::new(ks),
                message.clone(),
                output_bits,
                rng,
            )
            .unwrap()
        })
        .collect();

    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
    let outputs: Vec<VrfOutput> = run_round(parties, msgs);
    let y = outputs[0].output.clone();
    assert!(outputs.iter().all(|o| o.output == y));
    y
}

/// Run MPC VRF with the first threshold parties (by party id order).
#[cfg(feature = "test-support")]
pub fn run_vrf_mpc_threshold<R: RngCore + CryptoRng>(
    keyshares: Vec<Keyshare<VrfPoint>>,
    message: Vec<u8>,
    output_bits: usize,
    threshold: usize,
    rng: &mut R,
) -> Vec<u8> {
    use crate::common::utils::support::run_round;

    let parties: Vec<_> = keyshares
        .into_iter()
        .map(|ks| {
            VrfParty::<VrfR0, VrfPoint>::new_with_output_bits(
                Arc::new(ks),
                message.clone(),
                output_bits,
                rng,
            )
            .unwrap()
        })
        .collect();

    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
    let subset: Vec<_> = parties.into_iter().take(threshold).collect();
    let subset_msgs: Vec<_> = msgs.into_iter().take(threshold).collect();
    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(subset, subset_msgs).into_iter().unzip();
    let outputs: Vec<VrfOutput> = run_round(parties, msgs);
    let y = outputs[0].output.clone();
    assert!(outputs.iter().all(|o| o.output == y));
    y
}

fn hash_consistency<G: GroupElem>(
    public_key: &G,
    party_shares: &[G],
    message: &[u8],
    output_bits: usize,
) -> [u8; 32] {
    let mut hasher = Sha256::new()
        .chain(b"SL-VRF-CONSISTENCY")
        .chain(public_key.to_bytes())
        .chain((party_shares.len() as u64).to_be_bytes());
    for share in party_shares {
        hasher = hasher.chain(share.to_bytes());
    }
    hasher
        .chain((message.len() as u64).to_be_bytes())
        .chain(message)
        .chain((output_bits as u64).to_be_bytes())
        .finalize()
        .into()
}

fn decode_point<G: GroupElem>(bytes: &[u8]) -> Option<G> {
    let mut encoding = <G as GroupEncoding>::Repr::default();
    if encoding.as_ref().len() != bytes.len() {
        return None;
    }
    encoding.as_mut().copy_from_slice(bytes);
    Option::from(G::from_bytes(&encoding))
}

fn map_sign_error(err: crate::sign::SignError) -> VrfError {
    match err {
        crate::sign::SignError::InvalidMsgCount => VrfError::InvalidMsgCount,
        crate::sign::SignError::DuplicatePartyId => VrfError::DuplicatePartyId,
        crate::sign::SignError::InvalidMsgPartyId => VrfError::InvalidMsgPartyId,
        _ => unreachable!("validate_input_messages returned an unexpected SignError variant"),
    }
}

#[cfg(all(test, feature = "vrf"))]
mod tests {
    use super::*;
    use crate::common::utils::support::{run_keygen, run_round};

    #[test]
    fn new_rejects_malformed_keyshare_public_shares_len() {
        let mut ks = run_keygen::<2, 3, VrfPoint>()[0].clone();
        ks.party_public_shares.pop();
        assert!(matches!(
            VrfParty::<VrfR0, VrfPoint>::new(Arc::new(ks), vec![], &mut rand::thread_rng()),
            Err(VrfError::InvalidKeyshare)
        ));
    }

    #[test]
    fn new_rejects_malformed_keyshare_party_id() {
        let mut ks = run_keygen::<2, 3, VrfPoint>()[0].clone();
        ks.party_id = ks.total_parties;
        assert!(matches!(
            VrfParty::<VrfR0, VrfPoint>::new(Arc::new(ks), vec![], &mut rand::thread_rng()),
            Err(VrfError::InvalidKeyshare)
        ));
    }

    #[test]
    fn vrf_eval_threshold_subset() {
        let keyshares = run_keygen::<2, 3, VrfPoint>();
        let message = b"threshold-vrf".to_vec();
        let parties: Vec<_> = keyshares
            .into_iter()
            .map(|ks| {
                VrfParty::<VrfR0, VrfPoint>::new(
                    Arc::new(ks),
                    message.clone(),
                    &mut rand::thread_rng(),
                )
                .unwrap()
            })
            .collect();

        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
        let subset: Vec<_> = parties.into_iter().take(2).collect();
        let subset_msgs: Vec<_> = msgs.into_iter().take(2).collect();
        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(subset, subset_msgs).into_iter().unzip();
        let outputs: Vec<_> = run_round(parties, msgs);
        assert_eq!(outputs[0].output, outputs[1].output);
    }
}

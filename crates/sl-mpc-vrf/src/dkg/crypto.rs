// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use curve25519_dalek::{RistrettoPoint, Scalar};
use elliptic_curve::group::GroupEncoding;
use ff::Field;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sl_mpc_mate::math::GroupPolynomial;

use super::error::VrfKeygenError;

pub type SessionId = [u8; 32];
pub type HashBytes = [u8; 32];

pub const P2P_SHARE_SIZE: usize = 64;

/// Per-receiver Shamir share and chain-code sid (plaintext P2P payload in round 2).
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P2pShare {
    pub sender_pid: u8,
    pub receiver_pid: u8,
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
    pub data: [u8; P2P_SHARE_SIZE],
}

impl P2pShare {
    pub fn new(sender_pid: u8, receiver_pid: u8, data: [u8; P2P_SHARE_SIZE]) -> Self {
        Self {
            sender_pid,
            receiver_pid,
            data,
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DLogProof {
    pub t: Vec<u8>,
    pub s: Scalar,
}

impl DLogProof {
    pub fn prove<R: rand::CryptoRng + rand::RngCore>(
        session_id: &SessionId,
        x: &Scalar,
        rng: &mut R,
    ) -> Self {
        let r = Scalar::random(rng);
        let t = RistrettoPoint::mul_base(&r);
        let y = RistrettoPoint::mul_base(x);
        let c = Self::fiat_shamir(session_id, &y, &t);
        Self {
            t: t.compress().to_bytes().to_vec(),
            s: r + c * x,
        }
    }

    pub fn verify(&self, session_id: &SessionId, y: &RistrettoPoint) -> bool {
        let t_bytes: [u8; 32] = match self.t.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let t = match Option::<RistrettoPoint>::from(RistrettoPoint::from_bytes(&t_bytes)) {
            Some(point) => point,
            None => return false,
        };
        let c = Self::fiat_shamir(session_id, y, &t);
        let lhs = RistrettoPoint::mul_base(&self.s);
        let rhs = t + *y * c;
        lhs == rhs
    }

    fn fiat_shamir(session_id: &SessionId, y: &RistrettoPoint, t: &RistrettoPoint) -> Scalar {
        let bytes: [u8; 32] = Sha256::new()
            .chain_update(b"DLogProof-Challenge")
            .chain_update(session_id)
            .chain_update(b"y")
            .chain_update(y.compress().as_bytes())
            .chain_update(b"t")
            .chain_update(t.compress().as_bytes())
            .chain_update(b"base-point")
            .chain_update(RistrettoPoint::mul_base(&Scalar::ONE).compress().as_bytes())
            .finalize()
            .into();
        Scalar::from_bytes_mod_order(bytes)
    }
}

pub fn append_p2p_share_for_commitment(hasher: &mut Sha256, share: &P2pShare) {
    hasher.update([share.sender_pid, share.receiver_pid]);
    hasher.update(share.data);
}

pub fn hash_commitment(
    session_id: &SessionId,
    party_id: u8,
    big_a_i_poly: &[RistrettoPoint],
    shares: &[P2pShare],
    r_i: &[u8; 32],
) -> HashBytes {
    let mut hasher = Sha256::new()
        .chain_update(b"SL-Keygen-Commitment")
        .chain_update(session_id)
        .chain_update(party_id.to_be_bytes());
    for point in big_a_i_poly {
        hasher.update(point.compress().as_bytes());
    }
    for share in shares {
        append_p2p_share_for_commitment(&mut hasher, share);
    }
    hasher.update(r_i);
    hasher.finalize().into()
}

pub(crate) fn validate_input_messages<M: VrfKeygenMessage>(
    mut messages: Vec<M>,
    n: u8,
) -> Result<Vec<M>, VrfKeygenError> {
    if messages.len() != n as usize {
        return Err(VrfKeygenError::InvalidMsgCount);
    }
    messages.sort_by_key(|msg| msg.party_id());
    if messages
        .iter()
        .enumerate()
        .all(|(pid, msg)| msg.party_id() as usize == pid)
    {
        Ok(messages)
    } else {
        Err(VrfKeygenError::InvalidParticipantSet)
    }
}

pub fn verify_dlog_proofs(
    proofs: &[DLogProof],
    points: &[RistrettoPoint],
    dlog_sid: &SessionId,
    threshold: u8,
) -> bool {
    if proofs.len() != points.len() || proofs.len() != threshold as usize {
        return false;
    }
    proofs
        .iter()
        .zip(points)
        .all(|(proof, point)| proof.verify(dlog_sid, point))
}

pub fn compute_additive_public_shares(
    big_poly: &GroupPolynomial<RistrettoPoint>,
    n: u8,
) -> Vec<RistrettoPoint> {
    (0..n)
        .map(|j| {
            let public_d_j = big_poly.evaluate_at(&Scalar::from((j + 1) as u64));
            let coeff = lagrange_coeff(&j, 0..n);
            public_d_j * coeff
        })
        .collect()
}

pub fn lagrange_coeff(my_party_id: &u8, party_ids: impl IntoIterator<Item = u8>) -> Scalar {
    let mut coeff = Scalar::ONE;
    let x_i = Scalar::from((my_party_id + 1) as u64);
    for party_id in party_ids {
        let x_j = Scalar::from((party_id + 1) as u64);
        if x_i != x_j {
            let sub = x_j - x_i;
            coeff *= x_j * Field::invert(&sub).unwrap();
        }
    }
    coeff
}

pub(crate) trait VrfKeygenMessage {
    fn party_id(&self) -> u8;
}

impl VrfKeygenMessage for super::messages::VrfKeygenMsg1 {
    fn party_id(&self) -> u8 {
        self.from_party
    }
}

impl VrfKeygenMessage for super::messages::VrfKeygenMsg2 {
    fn party_id(&self) -> u8 {
        self.from_party
    }
}

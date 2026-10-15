// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! MobileCoin `RingMLSAG` (spend layer + amount layer).
//!
//! The amount layer is filled by a central party that knows the blinding difference `z`.
//! Threshold parties only close the spend response `r_{π,0}`.

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    Scalar,
};
use elliptic_curve::Group;
use rand::{CryptoRng, RngCore};

use crate::{
    challenge::challenge, error::MlsagError, hash_to_point::hash_to_point, key_image::KeyImage,
};

/// One ring member: onetime public key and amount commitment.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingMember {
    pub onetime_public: CompressedRistretto,
    pub commitment: CompressedRistretto,
}

/// Public MLSAG inputs. Amounts and blindings stay with the central party.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignPublicInput {
    pub message: Vec<u8>,
    pub ring: Vec<RingMember>,
    pub real_index: usize,
    pub output_commitment: CompressedRistretto,
}

/// Central-party ring tour: decoy responses, amount response, and real-index `L1`.
///
/// Slot `2 * real_index` is unused (the MPC spend response fills it later).
///
/// Delivery: broadcast to the signing quorum, signed only (not encrypted).
/// The zero spend slot identifies `real_index`, so this must not leave the quorum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingTour {
    pub responses: Vec<Scalar>,
    /// `L1 = α1 * G` hashed into the challenge at the real index.
    pub l1: RistrettoPoint,
}

/// MobileCoin `RingMLSAG` wire values (scalars, not prost).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingMLSAG {
    pub c_zero: Scalar,
    pub responses: Vec<Scalar>,
    pub key_image: KeyImage,
}

pub(crate) struct OpenedSignInput {
    pub members: Vec<(RistrettoPoint, RistrettoPoint)>,
    pub output: RistrettoPoint,
}

pub(crate) fn open_sign_input(input: &SignPublicInput) -> Result<OpenedSignInput, MlsagError> {
    if input.ring.is_empty() || input.real_index >= input.ring.len() {
        return Err(MlsagError::IndexOutOfBounds);
    }
    let mut members = Vec::with_capacity(input.ring.len());
    for (i, member) in input.ring.iter().enumerate() {
        let onetime = member
            .onetime_public
            .decompress()
            .filter(|p| !bool::from(p.is_identity()))
            .ok_or(MlsagError::InvalidRingPoint(i))?;
        let commitment = member
            .commitment
            .decompress()
            .ok_or(MlsagError::InvalidRingPoint(i))?;
        members.push((onetime, commitment));
    }
    let output = input
        .output_commitment
        .decompress()
        .ok_or(MlsagError::InvalidCommitment)?;
    Ok(OpenedSignInput { members, output })
}

pub(crate) fn scalar_is_canonical(scalar: &Scalar) -> bool {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*scalar.as_bytes())).is_some()
}

fn random_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> Scalar {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

struct Walk<'a> {
    message: &'a [u8],
    members: &'a [(RistrettoPoint, RistrettoPoint)],
    real_index: usize,
    key_image: &'a KeyImage,
    image: &'a RistrettoPoint,
    output: &'a RistrettoPoint,
    l0: &'a RistrettoPoint,
    r0: &'a RistrettoPoint,
    l1: &'a RistrettoPoint,
    responses: &'a [Scalar],
}

fn walk_challenges(walk: &Walk<'_>) -> Vec<Scalar> {
    let n = walk.members.len();
    let g = RistrettoPoint::generator();
    let mut c = vec![Scalar::ZERO; n];
    for step in 0..n {
        let i = (walk.real_index + step) % n;
        let (p_i, commitment_i) = walk.members[i];
        let (l0, r0, l1) = if i == walk.real_index {
            (*walk.l0, *walk.r0, *walk.l1)
        } else {
            let l0 = g * walk.responses[2 * i] + p_i * c[i];
            let r0 = hash_to_point(&p_i) * walk.responses[2 * i] + walk.image * c[i];
            let l1 = g * walk.responses[2 * i + 1] + (walk.output - commitment_i) * c[i];
            (l0, r0, l1)
        };
        c[(i + 1) % n] = challenge(walk.message, walk.key_image, &l0, &r0, &l1);
    }
    c
}

pub(crate) fn signing_challenges(
    input: &SignPublicInput,
    key_image: &KeyImage,
    l0: &RistrettoPoint,
    r0: &RistrettoPoint,
    tour: &RingTour,
) -> Result<Vec<Scalar>, MlsagError> {
    let opened = open_sign_input(input)?;
    let expected = 2 * opened.members.len();
    if tour.responses.len() != expected {
        return Err(MlsagError::LengthMismatch {
            expected,
            found: tour.responses.len(),
        });
    }
    let image = key_image.decompress().ok_or(MlsagError::InvalidKeyImage)?;
    Ok(walk_challenges(&Walk {
        message: &input.message,
        members: &opened.members,
        real_index: input.real_index,
        key_image,
        image: &image,
        output: &opened.output,
        l0,
        r0,
        l1: &tour.l1,
        responses: &tour.responses,
    }))
}

/// Sample decoy responses and the amount-layer close. `L0`/`R0` are the summed spend nonces.
///
/// Requires `C_out - C_π = z · G` (same value, blinding difference `z`).
///
/// The returned tour is broadcast to the signing quorum, signed only (not
/// encrypted). Every signer must receive the same bytes. Do not publish it
/// outside the quorum: the unset spend slot is zero and identifies the real index.
pub fn fill_ring<R: CryptoRng + RngCore>(
    input: &SignPublicInput,
    key_image: &KeyImage,
    l0: &RistrettoPoint,
    r0: &RistrettoPoint,
    z: &Scalar,
    rng: &mut R,
) -> Result<RingTour, MlsagError> {
    let opened = open_sign_input(input)?;
    let g = RistrettoPoint::generator();
    let (_, c_real) = opened.members[input.real_index];
    if opened.output - c_real != g * z {
        return Err(MlsagError::ValueNotConserved);
    }

    let n = opened.members.len();
    let mut responses = vec![Scalar::ZERO; 2 * n];
    for i in 0..n {
        if i == input.real_index {
            continue;
        }
        responses[2 * i] = random_scalar(rng);
        responses[2 * i + 1] = random_scalar(rng);
    }
    let alpha1 = random_scalar(rng);
    let mut tour = RingTour {
        responses,
        l1: g * alpha1,
    };
    let challenges = signing_challenges(input, key_image, l0, r0, &tour)?;
    tour.responses[2 * input.real_index + 1] = alpha1 - challenges[input.real_index] * z;
    Ok(tour)
}

/// Assemble a signature once the spend response `r_{π,0}` is known.
pub fn assemble_ring_mlsag(
    input: &SignPublicInput,
    key_image: &KeyImage,
    l0: &RistrettoPoint,
    r0: &RistrettoPoint,
    tour: &RingTour,
    r_pi_0: Scalar,
) -> Result<RingMLSAG, MlsagError> {
    let challenges = signing_challenges(input, key_image, l0, r0, tour)?;
    let mut responses = tour.responses.clone();
    responses[2 * input.real_index] = r_pi_0;
    Ok(RingMLSAG {
        c_zero: challenges[0],
        responses,
        key_image: *key_image,
    })
}

/// Single-party signer. Used to check the challenge walk against threshold output.
pub fn sign_with_scalar<R: CryptoRng + RngCore>(
    input: &SignPublicInput,
    onetime_private: &Scalar,
    z: &Scalar,
    rng: &mut R,
) -> Result<RingMLSAG, MlsagError> {
    let opened = open_sign_input(input)?;
    let p = opened.members[input.real_index].0;
    if p != RistrettoPoint::mul_base(onetime_private) {
        return Err(MlsagError::PublicKeyMismatch);
    }
    let key_image = KeyImage::from_scalar(onetime_private);
    let alpha0 = random_scalar(rng);
    let l0 = RistrettoPoint::generator() * alpha0;
    let r0 = hash_to_point(&p) * alpha0;
    let tour = fill_ring(input, &key_image, &l0, &r0, z, rng)?;
    let challenges = signing_challenges(input, &key_image, &l0, &r0, &tour)?;
    let r_pi_0 = alpha0 - challenges[input.real_index] * onetime_private;
    assemble_ring_mlsag(input, &key_image, &l0, &r0, &tour, r_pi_0)
}

impl RingMLSAG {
    /// Recompute the challenge loop. Matches MobileCoin `RingMLSAG::verify`.
    pub fn verify(&self, input: &SignPublicInput) -> Result<(), MlsagError> {
        let opened = open_sign_input(input)?;
        let n = opened.members.len();
        if self.responses.len() != 2 * n {
            return Err(MlsagError::LengthMismatch {
                expected: 2 * n,
                found: self.responses.len(),
            });
        }
        if !scalar_is_canonical(&self.c_zero) {
            return Err(MlsagError::InvalidSignature);
        }
        for response in &self.responses {
            if !scalar_is_canonical(response) {
                return Err(MlsagError::InvalidSignature);
            }
        }
        let image = self
            .key_image
            .decompress()
            .ok_or(MlsagError::InvalidKeyImage)?;
        let g = RistrettoPoint::generator();
        let mut recomputed = vec![Scalar::ZERO; n];
        for (i, (p_i, commitment_i)) in opened.members.iter().copied().enumerate() {
            let c_i = if i == 0 { self.c_zero } else { recomputed[i] };
            let l0 = g * self.responses[2 * i] + p_i * c_i;
            let r0 = hash_to_point(&p_i) * self.responses[2 * i] + image * c_i;
            let l1 = g * self.responses[2 * i + 1] + (opened.output - commitment_i) * c_i;
            recomputed[(i + 1) % n] = challenge(&input.message, &self.key_image, &l0, &r0, &l1);
        }
        if self.c_zero == recomputed[0] {
            Ok(())
        } else {
            Err(MlsagError::InvalidSignature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake2::Digest;

    fn pedersen_h() -> RistrettoPoint {
        let mut hasher = blake2::Blake2b512::new();
        hasher.update(b"sl-mlsag-test-pedersen-h");
        RistrettoPoint::from_hash(hasher)
    }

    fn sample_input<R: CryptoRng + RngCore>(
        value: u64,
        rng: &mut R,
    ) -> (SignPublicInput, Scalar, Scalar) {
        let onetime = random_scalar(rng);
        let y_in = random_scalar(rng);
        let y_out = random_scalar(rng);
        let z = y_out - y_in;
        let h = pedersen_h();
        let value = Scalar::from(value);
        let g = RistrettoPoint::generator();
        let c_in = h * value + g * y_in;
        let c_out = h * value + g * y_out;
        let mut ring = Vec::new();
        for _ in 0..2 {
            ring.push(RingMember {
                onetime_public: RistrettoPoint::mul_base(&random_scalar(rng)).compress(),
                commitment: RistrettoPoint::mul_base(&random_scalar(rng)).compress(),
            });
        }
        ring.insert(
            1,
            RingMember {
                onetime_public: RistrettoPoint::mul_base(&onetime).compress(),
                commitment: c_in.compress(),
            },
        );
        let input = SignPublicInput {
            message: b"mlsag-msg".to_vec(),
            ring,
            real_index: 1,
            output_commitment: c_out.compress(),
        };
        (input, onetime, z)
    }

    #[test]
    fn local_sign_verifies() {
        let mut rng = rand::thread_rng();
        let (input, onetime, z) = sample_input(5, &mut rng);
        let signature = sign_with_scalar(&input, &onetime, &z, &mut rng).unwrap();
        signature.verify(&input).unwrap();

        let mut wrong = input.clone();
        wrong.message = b"other".to_vec();
        assert_eq!(signature.verify(&wrong), Err(MlsagError::InvalidSignature));
    }

    #[test]
    fn fill_ring_rejects_unbalanced_amount() {
        let mut rng = rand::thread_rng();
        let (input, onetime, _z) = sample_input(5, &mut rng);
        let key_image = KeyImage::from_scalar(&onetime);
        let l0 = RistrettoPoint::generator();
        let r0 = RistrettoPoint::generator();
        let err = fill_ring(&input, &key_image, &l0, &r0, &Scalar::from(1u64), &mut rng);
        assert_eq!(err, Err(MlsagError::ValueNotConserved));
    }
}

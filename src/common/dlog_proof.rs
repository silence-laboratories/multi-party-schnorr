// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crypto_bigint::subtle::ConstantTimeEq;
use ff::Field;
use rand::{CryptoRng, RngCore};
use sha2::{digest::Update, Digest, Sha256};

use sl_transcript::TranscriptProtocol;

use super::{
    traits::{GroupElem, ScalarReduce},
    transcript::Sha256Transcript,
    utils::SessionId,
};

/// Domain label for DH-tuple Fiat–Shamir transcripts.
pub const DH_TUPLE_TRANSCRIPT_LABEL: &[u8] = b"ZK-DH-Tuple-Proof";
/// Challenge label inside a DH-tuple transcript.
pub const DH_TUPLE_CHALLENGE_LABEL: &[u8] = b"ZK-DH-Challenge";

/// Initialize the Fiat–Shamir transcript for a DH-tuple proof
pub fn dh_tuple_transcript(session_id: &SessionId, aux: &[u8]) -> Sha256Transcript {
    let mut transcript = Sha256Transcript::new(DH_TUPLE_TRANSCRIPT_LABEL);
    transcript.append_message(b"session_id", session_id.as_ref());
    transcript.append_message(b"aux", aux);
    transcript
}

/// Non-interactive Proof of knowledge of discrete logarithm with Fiat-Shamir transform.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DLogProof<G: GroupElem> {
    pub t: Vec<u8>,
    /// Challenge response
    pub s: G::Scalar,
}

impl<G: GroupElem> DLogProof<G>
where
    G: ConstantTimeEq,
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    /// Prove knowledge of discrete logarithm.
    pub fn prove<R: CryptoRng + RngCore>(
        session_id: &SessionId,
        x: &G::Scalar,
        rng: &mut R,
    ) -> Self {
        let r = <G::Scalar as Field>::random(rng);
        let t = G::generator() * r;
        let y = G::generator() * x;
        let c = Self::fiat_shamir(session_id, &y, &t);

        let s = r + c * x;

        Self {
            t: t.to_bytes().as_ref().to_vec(),
            s,
        }
    }

    /// Verify knowledge of discrete logarithm.
    pub fn verify(&self, session_id: &SessionId, y: &G) -> bool {
        let mut encoding = G::Repr::default();
        if self.t.len() != encoding.as_ref().len() {
            return false;
        }
        encoding.as_mut().copy_from_slice(&self.t);
        let t = G::from_bytes(&encoding);
        let t = if t.is_some().into() {
            t.unwrap()
        } else {
            return false;
        };

        let c = Self::fiat_shamir(session_id, y, &t);
        let lhs = G::generator() * self.s;
        let rhs = t + *y * c;

        lhs.ct_eq(&rhs).into()
    }

    /// Get fiat-shamir challenge for Discrete log proof.
    pub fn fiat_shamir(session_id: &SessionId, y: &G, t: &G) -> G::Scalar {
        let h = Sha256::new()
            .chain(b"DLogProof-Challenge")
            .chain(session_id.as_ref())
            .chain(b"y")
            .chain(y.to_bytes())
            .chain(b"t")
            .chain(t.to_bytes())
            .chain(b"base-point")
            .chain(G::generator().to_bytes());

        let bytes = h.finalize().into();

        G::Scalar::reduce_from_bytes(&bytes)
    }
}

/// Base points (G, Q) and prover values (A, B) for a DH-tuple proof.
#[derive(Clone, Copy)]
pub struct DhTuplePoints<'a, G: GroupElem> {
    pub g: &'a G,
    pub q: &'a G,
    pub a: &'a G,
    pub b: &'a G,
}

/// Fiat–Shamir commitment points (X, Y) = (r·G, r·Q).
#[derive(Clone, Copy)]
pub struct DhTupleCommitments<'a, G: GroupElem> {
    pub x: &'a G,
    pub y: &'a G,
}

/// Non-interactive proof that (G, Q, A, B) is a DH tuple: A = w·G and B = w·Q (zk-proofs-spec §8.3).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhTupleProof<G: GroupElem> {
    /// Fiat–Shamir challenge e.
    pub e: G::Scalar,
    /// Response z = r + e·w.
    pub z: G::Scalar,
}

impl<G: GroupElem> DhTupleProof<G>
where
    G: ConstantTimeEq,
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    pub fn prove<R: CryptoRng + RngCore>(
        points: DhTuplePoints<'_, G>,
        w: &G::Scalar,
        transcript: &mut impl TranscriptProtocol,
        rng: &mut R,
    ) -> Self {
        let r = <G::Scalar as Field>::random(rng);
        let x = *points.g * r;
        let y = *points.q * r;
        let commitments = DhTupleCommitments { x: &x, y: &y };
        let e = Self::fiat_shamir(points, commitments, transcript);
        let z = r + e * w;

        Self { e, z }
    }

    pub fn verify(
        &self,
        points: DhTuplePoints<'_, G>,
        transcript: &mut impl TranscriptProtocol,
    ) -> bool {
        if !is_nonzero_point(points.g)
            || !is_nonzero_point(points.q)
            || !is_nonzero_point(points.a)
            || !is_nonzero_point(points.b)
        {
            return false;
        }

        let x = *points.g * self.z - *points.a * self.e;
        let y = *points.q * self.z - *points.b * self.e;
        let commitments = DhTupleCommitments { x: &x, y: &y };
        let e = Self::fiat_shamir(points, commitments, transcript);

        self.e.ct_eq(&e).into()
    }

    pub fn fiat_shamir(
        points: DhTuplePoints<'_, G>,
        commitments: DhTupleCommitments<'_, G>,
        transcript: &mut impl TranscriptProtocol,
    ) -> G::Scalar {
        transcript.append_message(b"G", points.g.to_bytes().as_ref());
        transcript.append_message(b"Q", points.q.to_bytes().as_ref());
        transcript.append_message(b"A", points.a.to_bytes().as_ref());
        transcript.append_message(b"B", points.b.to_bytes().as_ref());
        transcript.append_message(b"X", commitments.x.to_bytes().as_ref());
        transcript.append_message(b"Y", commitments.y.to_bytes().as_ref());

        let mut challenge = [0u8; 32];
        transcript.challenge_bytes(DH_TUPLE_CHALLENGE_LABEL, &mut challenge);
        G::Scalar::reduce_from_bytes(&challenge)
    }
}

/// Point is on-curve encoding and not the identity (spec: non-zero).
fn is_nonzero_point<G: GroupElem + ConstantTimeEq>(p: &G) -> bool {
    !bool::from(p.ct_eq(&G::identity()))
}

#[cfg(feature = "eddsa")]
#[cfg(test)]
mod tests {
    use curve25519_dalek::{EdwardsPoint, Scalar};
    use rand::{thread_rng, Rng};

    use crate::common::{dh_tuple_transcript, DLogProof, DhTuplePoints, DhTupleProof};

    #[test]
    pub fn test_dlog_proof() {
        use rand::thread_rng;

        let mut rng = thread_rng();

        let session_id = rng.gen();

        let x = Scalar::random(&mut rng);
        let y = EdwardsPoint::mul_base(&x);

        let proof = DLogProof::prove(&session_id, &x, &mut rng);

        assert!(proof.verify(&session_id, &y,));
    }

    #[test]
    pub fn test_wrong_dlog_proof() {
        let mut rng = thread_rng();

        let session_id = rng.gen();
        let x = Scalar::random(&mut rng);
        let wrong_scalar = Scalar::random(&mut rng);
        let y = EdwardsPoint::mul_base(&x);

        let proof = DLogProof::prove(&session_id, &wrong_scalar, &mut rng);

        assert!(!proof.verify(&session_id, &y));
    }

    #[test]
    pub fn test_dlog_proof_fiat_shamir() {
        let mut rng = thread_rng();

        let x = Scalar::random(&mut rng);
        let y = EdwardsPoint::mul_base(&x);

        let session_id = rng.gen();
        let proof = DLogProof::prove(&session_id, &x, &mut rng);

        let new_session_id = rng.gen();

        assert!(
            !proof.verify(&new_session_id, &y),
            "Proof should fail with wrong session id"
        );
    }

    #[test]
    fn test_dh_tuple_proof() {
        let mut rng = thread_rng();
        let session_id = rng.gen();
        let aux = b"vrf-aux";

        let g = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order([7u8; 32]));
        let w = Scalar::random(&mut rng);
        let q = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order([13u8; 32]));
        let a = g * w;
        let b = q * w;

        let points = DhTuplePoints {
            g: &g,
            q: &q,
            a: &a,
            b: &b,
        };
        let mut prove_transcript = dh_tuple_transcript(&session_id, aux);
        let proof = DhTupleProof::prove(points, &w, &mut prove_transcript, &mut rng);
        let mut verify_transcript = dh_tuple_transcript(&session_id, aux);
        assert!(proof.verify(points, &mut verify_transcript));
    }

    #[test]
    fn test_dh_tuple_proof_wrong_witness() {
        let mut rng = thread_rng();
        let session_id = rng.gen();

        let g = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order([7u8; 32]));
        let w = Scalar::random(&mut rng);
        let q = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order([13u8; 32]));
        let a = g * w;
        let b = q * w;

        let points = DhTuplePoints {
            g: &g,
            q: &q,
            a: &a,
            b: &b,
        };
        let wrong_w = Scalar::random(&mut rng);
        let mut prove_transcript = dh_tuple_transcript(&session_id, &[]);
        let proof = DhTupleProof::prove(points, &wrong_w, &mut prove_transcript, &mut rng);
        let mut verify_transcript = dh_tuple_transcript(&session_id, &[]);
        assert!(!proof.verify(points, &mut verify_transcript));
    }

    #[test]
    fn test_dh_tuple_proof_wrong_session() {
        let mut rng = thread_rng();
        let session_id = rng.gen();

        let g = EdwardsPoint::mul_base(&Scalar::ONE);
        let w = Scalar::random(&mut rng);
        let q = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order([2u8; 32]));
        let a = g * w;
        let b = q * w;

        let points = DhTuplePoints {
            g: &g,
            q: &q,
            a: &a,
            b: &b,
        };
        let mut prove_transcript = dh_tuple_transcript(&session_id, &[]);
        let proof = DhTupleProof::prove(points, &w, &mut prove_transcript, &mut rng);
        let mut verify_transcript = dh_tuple_transcript(&rng.gen(), &[]);
        assert!(!proof.verify(points, &mut verify_transcript));
    }

    #[test]
    fn test_dh_tuple_proof_identity_point_rejected() {
        use elliptic_curve::Group;

        let mut rng = thread_rng();
        let session_id = rng.gen();

        let g = EdwardsPoint::mul_base(&Scalar::ONE);
        let w = Scalar::random(&mut rng);
        let q = EdwardsPoint::identity();
        let a = g * w;
        let b = q * w;

        let points = DhTuplePoints {
            g: &g,
            q: &q,
            a: &a,
            b: &b,
        };
        let mut prove_transcript = dh_tuple_transcript(&session_id, &[]);
        let proof = DhTupleProof::prove(points, &w, &mut prove_transcript, &mut rng);
        let mut verify_transcript = dh_tuple_transcript(&session_id, &[]);
        assert!(!proof.verify(points, &mut verify_transcript));
    }

    #[test]
    fn test_dh_tuple_proof_fiat_shamir() {
        let mut rng = thread_rng();
        let session_id = rng.gen();

        let g = EdwardsPoint::mul_base(&Scalar::ONE);
        let w = Scalar::random(&mut rng);
        let q = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order([2u8; 32]));
        let a = g * w;
        let b = q * w;

        let points = DhTuplePoints {
            g: &g,
            q: &q,
            a: &a,
            b: &b,
        };

        let mut prove_transcript = dh_tuple_transcript(&session_id, &[]);
        let proof = DhTupleProof::prove(points, &w, &mut prove_transcript, &mut rng);

        let mut verify_transcript = dh_tuple_transcript(&rng.gen(), &[]);
        assert!(
            !proof.verify(points, &mut verify_transcript),
            "Proof should fail with wrong transcript"
        );
    }
}

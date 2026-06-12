// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use curve25519_dalek::{RistrettoPoint, Scalar};
use elliptic_curve::{subtle::ConstantTimeEq, Group};
use rand::{CryptoRng, RngCore};
use sl_mpc_derive::traits::ScalarReduce;
use sl_transcript::TranscriptProtocol;

use crate::{transcript::Sha256Transcript, types::SessionId};

/// Domain label for DH-tuple Fiat–Shamir transcripts.
pub const DH_TUPLE_TRANSCRIPT_LABEL: &[u8] = b"ZK-DH-Tuple-Proof";
/// Challenge label inside a DH-tuple transcript.
pub const DH_TUPLE_CHALLENGE_LABEL: &[u8] = b"ZK-DH-Challenge";

/// Initialize the Fiat–Shamir transcript for a DH-tuple proof.
pub fn dh_tuple_transcript(session_id: &SessionId, aux: &[u8]) -> Sha256Transcript {
    let mut transcript = Sha256Transcript::new(DH_TUPLE_TRANSCRIPT_LABEL);
    transcript.append_message(b"session_id", session_id);
    transcript.append_message(b"aux", aux);
    transcript
}

/// Base points (G, Q) and prover values (A, B) for a DH-tuple proof.
#[derive(Clone, Copy)]
pub struct DhTuplePoints<'a> {
    pub g: &'a RistrettoPoint,
    pub q: &'a RistrettoPoint,
    pub a: &'a RistrettoPoint,
    pub b: &'a RistrettoPoint,
}

/// Fiat–Shamir commitment points (X, Y) = (r·G, r·Q).
#[derive(Clone, Copy)]
struct DhTupleCommitments<'a> {
    x: &'a RistrettoPoint,
    y: &'a RistrettoPoint,
}

/// Non-interactive proof that (G, Q, A, B) is a DH tuple.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhTupleProof {
    pub e: Scalar,
    pub z: Scalar,
}

impl DhTupleProof {
    pub fn prove<R: CryptoRng + RngCore>(
        points: DhTuplePoints<'_>,
        w: &Scalar,
        transcript: &mut impl TranscriptProtocol,
        rng: &mut R,
    ) -> Self {
        let r = Scalar::random(rng);
        let x = *points.g * r;
        let y = *points.q * r;
        let commitments = DhTupleCommitments { x: &x, y: &y };
        let e = Self::fiat_shamir(points, commitments, transcript);
        let z = r + e * w;
        Self { e, z }
    }

    pub fn verify(
        &self,
        points: DhTuplePoints<'_>,
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

    fn fiat_shamir(
        points: DhTuplePoints<'_>,
        commitments: DhTupleCommitments<'_>,
        transcript: &mut impl TranscriptProtocol,
    ) -> Scalar {
        transcript.append_message(b"G", points.g.compress().as_bytes());
        transcript.append_message(b"Q", points.q.compress().as_bytes());
        transcript.append_message(b"A", points.a.compress().as_bytes());
        transcript.append_message(b"B", points.b.compress().as_bytes());
        transcript.append_message(b"X", commitments.x.compress().as_bytes());
        transcript.append_message(b"Y", commitments.y.compress().as_bytes());

        let mut challenge = [0u8; 32];
        transcript.challenge_bytes(DH_TUPLE_CHALLENGE_LABEL, &mut challenge);
        Scalar::reduce_from_bytes(&challenge)
    }
}

fn is_nonzero_point(p: &RistrettoPoint) -> bool {
    !bool::from(p.ct_eq(&RistrettoPoint::identity()))
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::Scalar;
    use elliptic_curve::Group;
    use rand::{thread_rng, Rng};

    use super::*;

    #[test]
    fn dh_tuple_proof_roundtrip() {
        let mut rng = thread_rng();
        let session_id = rng.gen();
        let aux = b"vrf-aux";

        let g = RistrettoPoint::generator() * Scalar::from(7u64);
        let w = Scalar::random(&mut rng);
        let q = RistrettoPoint::generator() * Scalar::from(13u64);
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
    fn dh_tuple_proof_wrong_witness() {
        let mut rng = thread_rng();
        let session_id = rng.gen();

        let g = RistrettoPoint::generator() * Scalar::from(7u64);
        let w = Scalar::random(&mut rng);
        let q = RistrettoPoint::generator() * Scalar::from(13u64);
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
    fn dh_tuple_proof_wrong_session() {
        let mut rng = thread_rng();
        let session_id = rng.gen();

        let g = RistrettoPoint::generator();
        let w = Scalar::random(&mut rng);
        let q = RistrettoPoint::generator() * Scalar::from(2u64);
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
    fn dh_tuple_proof_identity_point_rejected() {
        let mut rng = thread_rng();
        let session_id = rng.gen();

        let g = RistrettoPoint::generator();
        let w = Scalar::random(&mut rng);
        let q = RistrettoPoint::identity();
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
    fn dh_tuple_proof_fiat_shamir() {
        let mut rng = thread_rng();
        let session_id = rng.gen();

        let g = RistrettoPoint::generator();
        let w = Scalar::random(&mut rng);
        let q = RistrettoPoint::generator() * Scalar::from(2u64);
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

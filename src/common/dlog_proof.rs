use crypto_bigint::subtle::ConstantTimeEq;
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, EdwardsPoint, Scalar};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{digest::Update, Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::utils::SessionId;

/// Non-interactive Proof of knowledge of discrete logarithm with Fiat-Shamir transform.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DLogProof {
    /// Public point `t`.
    pub t: EdwardsPoint,
    /// Challenge response
    pub s: Scalar,
}

impl DLogProof {
    /// Prove knowledge of discrete logarithm.
    pub fn prove<R: CryptoRng + RngCore>(session_id: &SessionId, x: &Scalar, rng: &mut R) -> Self {
        let r = Scalar::random(rng);
        let t = EdwardsPoint::mul_base(&r);
        let y = EdwardsPoint::mul_base(x);
        let c = Self::fiat_shamir(session_id, &y, &t);

        let s = r + c * x;

        Self {
            t: t.into(),
            s: s.into(),
        }
    }

    /// Verify knowledge of discrete logarithm.
    pub fn verify(&self, session_id: &SessionId, y: &EdwardsPoint) -> bool {
        let c = Self::fiat_shamir(session_id, y, &self.t);
        let lhs = EdwardsPoint::mul_base(&self.s);
        let rhs = self.t + y * c;

        lhs.ct_eq(&rhs).into()
    }

    /// Get fiat-shamir challenge for Discrete log proof.
    pub fn fiat_shamir(session_id: &SessionId, y: &EdwardsPoint, t: &EdwardsPoint) -> Scalar {
        let h = Sha256::new()
            .chain(b"DLogProof-Challenge")
            .chain(session_id.as_ref())
            .chain(b"y")
            .chain(y.compress().as_bytes())
            .chain(b"t")
            .chain(t.compress().as_bytes())
            .chain(b"base-point")
            .chain(ED25519_BASEPOINT_POINT.compress().as_bytes());

        let bytes = h.finalize().into();

        Scalar::from_bytes_mod_order(bytes)
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{EdwardsPoint, Scalar};
    use rand::{thread_rng, Rng};

    use crate::common::DLogProof;

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
}

use crypto_bigint::subtle::ConstantTimeEq;
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, EdwardsPoint, Scalar};
use ff::{Field, PrimeField};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{digest::Update, Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    traits::{GroupElem, ScalarReduce},
    utils::SessionId,
};

/// Non-interactive Proof of knowledge of discrete logarithm with Fiat-Shamir transform.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DLogProof<G: GroupElem> {
    /// Public point `t`.
    #[serde(bound(
        serialize = "G::Repr: Serialize",
        deserialize = "G::Repr: Deserialize<'de>"
    ))]
    pub t: G::Repr,
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
        let t = G::generator() * &r;
        let y = G::generator() * x;
        let c = Self::fiat_shamir(session_id, &y, &t);

        let s = r + c * x;

        Self { t: t.to_bytes(), s }
    }

    /// Verify knowledge of discrete logarithm.
    pub fn verify(&self, session_id: &SessionId, y: &G) -> bool {
        let t = G::from_bytes(&self.t);
        let t = if t.is_some().into() {
            t.unwrap()
        } else {
            return false;
        };

        let c = Self::fiat_shamir(session_id, y, &t);
        let lhs = G::generator() * &self.s;
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

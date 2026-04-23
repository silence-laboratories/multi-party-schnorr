#![cfg(all(feature = "eddsa", feature = "ad"))]

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::{EdwardsPoint, Scalar};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::Group;
use sha2::{Digest, Sha256};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug)]
pub struct AssociatedDataProof {
    pub big_r_prime: EdwardsPoint,
}

impl Default for AssociatedDataProof {
    fn default() -> Self {
        Self {
            big_r_prime: <EdwardsPoint as Group>::identity(),
        }
    }
}

impl AssociatedDataProof {
    pub fn ro(ad: &[u8], pk: &EdwardsPoint, big_r_prime: &EdwardsPoint) -> Scalar {
        let digest = Sha256::new()
            .chain_update(ad)
            .chain_update(pk.to_bytes())
            .chain_update(big_r_prime.to_bytes())
            .finalize();

        Scalar::from_bytes_mod_order(digest.into())
    }

    pub fn verify(
        &self,
        vk: &VerifyingKey,
        message: &[u8],
        sig: &Signature,
        ad: &[u8],
        pk: &EdwardsPoint,
    ) -> bool {
        if vk.verify(message, sig).is_err() {
            return false;
        }

        let sig_bytes = sig.to_bytes();
        let r_bytes: [u8; 32] = sig_bytes[..32].try_into().expect("slice length checked");
        let sig_r = match CompressedEdwardsY(r_bytes).decompress() {
            Some(p) => p,
            None => return false,
        };

        let t = Self::ro(ad, pk, &self.big_r_prime);
        let expected_r = self.big_r_prime * t;

        expected_r == sig_r
    }
}

use std::str::FromStr;
use std::sync::Arc;

use crypto_bigint::subtle::ConstantTimeEq;
use derivation_path::DerivationPath;
use thiserror::Error;

use crate::{
    common::traits::{BIP32Derive, GroupElem, Round, ScalarReduce},
    keygen::Keyshare,
};

#[derive(Error, Debug)]
pub enum DeriveError {
    #[error("Invalid party ids on messages list")]
    /// Error in derivation
    DerivationError,
}

pub struct DeriveParty<G>
where
    G: GroupElem,
{
    pub(crate) keyshare: Arc<Keyshare<G>>,
    pub derivation_path: DerivationPath,
}

impl<G: GroupElem> DeriveParty<G> {
    /// Create a new derivation party with the given keyshare
    pub fn new(keyshare: Arc<Keyshare<G>>, derivation_path: &str) -> Self {
        Self {
            keyshare,
            derivation_path: DerivationPath::from_str(derivation_path).unwrap(),
        }
    }
}

impl<G: GroupElem> Round for DeriveParty<G>
where
    G: ConstantTimeEq,
    G::Scalar: ScalarReduce<[u8; 32]> + BIP32Derive,
{
    type Output = Result<G, DeriveError>;

    type Input = ();

    fn process(self, _: ()) -> Self::Output {
        let (_additive_offset, derived_public_key) = self
            .keyshare
            .derive_with_offset(&self.derivation_path)
            .map_err(|_| DeriveError::DerivationError)?;

        Ok(derived_public_key)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::common::utils::{run_keygen, run_round};

    #[allow(unused_imports)]
    use rand::prelude::SliceRandom;

    pub fn run_derivation<G: GroupElem>(
        shares: &[crate::keygen::Keyshare<G>],
        derivation_path: &str,
    ) -> Vec<G>
    where
        G::Scalar: ScalarReduce<[u8; 32]> + BIP32Derive,
    {
        let parties = shares
            .iter()
            .map(|keyshare| DeriveParty::new(keyshare.clone().into(), derivation_path))
            .collect::<Vec<_>>();

        run_round(parties, ())
    }

    #[cfg(feature = "eddsa")]
    #[test]
    fn eddsa_derive_2_2() {
        use curve25519_dalek::EdwardsPoint;

        let shares = run_keygen::<2, 2, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 2)
            .cloned()
            .collect();
        let s = run_derivation(&subset, "m/0");
        println!("{:?}", s[0].compress().to_bytes());
    }

    #[cfg(feature = "taproot")]
    #[test]
    fn taproot_derive_2_2() {
        use elliptic_curve::group::GroupEncoding;

        let shares = run_keygen::<2, 2, k256::ProjectivePoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 2)
            .cloned()
            .collect();
        let s = run_derivation(&subset, "m/0");
        println!("{:?}", s[0].to_bytes());
    }
}

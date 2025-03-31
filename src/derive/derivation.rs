use crate::common::traits::{GroupElem, Round, ScalarReduce, WithinOrder};
use crate::group::{Group, GroupEncoding};
use crate::keygen::Keyshare;
use crypto_bigint::subtle::ConstantTimeEq;
use derivation_path::DerivationPath;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum DeriveError {
    #[error("Invalid party ids on messages list")]
    /// Error in derivation
    DerivationError,
}
struct DeriveParty<G>
where
    G: Group + GroupEncoding,
{
    pub(crate) keyshare: Arc<Keyshare<G>>,
    pub derivation_path: DerivationPath,
}
impl<G: Group + GroupEncoding> DeriveParty<G> {
    /// Create a new derivation party with the given keyshare
    #[allow(dead_code)]
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
    G::Scalar: ScalarReduce<[u8; 32]> + WithinOrder<[u8; 32]>,
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
    use crate::common::utils::run_keygen;
    use crate::derive::derivation::DeriveParty;
    use curve25519_dalek::EdwardsPoint;
    use rand::prelude::SliceRandom;

    pub fn run_derivation(
        shares: &[crate::keygen::Keyshare<EdwardsPoint>],
        derivation_path: &str,
    ) -> Vec<EdwardsPoint> {
        use crate::common::utils::run_round;

        let parties = shares
            .iter()
            .map(|keyshare| DeriveParty::new(keyshare.clone().into(), derivation_path))
            .collect::<Vec<_>>();

        run_round(parties, ())
    }
    #[test]
    fn derive_2_2() {
        let shares = run_keygen::<2, 2, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 2)
            .cloned()
            .collect();
        let s = run_derivation(&subset, "m/0");
        println!("{:?}", s[0].compress().to_bytes());
    }
}

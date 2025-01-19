use crate::common::get_lagrange_coeff;
use crate::common::traits::{GroupElem, Round, ScalarReduce};
use crate::group::{Group, GroupEncoding};
use crate::keygen::Keyshare;
use crypto_bigint::subtle::ConstantTimeEq;
use derivation_path::DerivationPath;
use ff::Field;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;

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
    pub party_id: u8,
    pub(crate) keyshare: Arc<Keyshare<G>>,
    pub derivation_path: DerivationPath,
}
impl<G: Group + GroupEncoding> DeriveParty<G> {
    /// Create a new derivation party with the given keyshare
    pub fn new(keyshare: Arc<Keyshare<G>>, derivation_path: &str) -> Self {
        Self {
            party_id: keyshare.party_id(),
            keyshare,
            derivation_path: DerivationPath::from_str(derivation_path).unwrap(),
        }
    }
}

impl<G: GroupElem> Round for DeriveParty<G>
where
    G: ConstantTimeEq,
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    type Output = Result<G, DeriveError>;

    type Input = ();

    fn process(self, _: ()) -> Self::Output {
        let pid_list = 0..self.keyshare.total_parties;
        let coeff = get_lagrange_coeff::<G>(&self.party_id, pid_list);

        // let d_i = coeff * self.keyshare.shamir_share();

        let (additive_offset, derived_public_key) = self
            .keyshare
            .derive_with_offset(&self.derivation_path)
            .unwrap(); // FIXME: report error
        let threshold_inv = <G as Group>::Scalar::from(self.keyshare.total_parties as u64)
            .invert()
            .unwrap(); // threshold > 0 so it has an invert
        let additive_offset = additive_offset * threshold_inv;

        //tweak the secret key share by the computed additive offset
        // let d_i = d_i + additive_offset;
        Ok(derived_public_key)
    }
}
#[cfg(test)]
use curve25519_dalek::EdwardsPoint;

#[cfg(test)]
mod test {
    use crate::common::utils::run_keygen;
    use curve25519_dalek::EdwardsPoint;
    use rand::prelude::SliceRandom;
    use crate::derive::derivation::DeriveParty;

    pub fn run_derivation(
        shares: &[crate::keygen::Keyshare<EdwardsPoint>],
        derivation_path: &str,
    ) -> Vec<EdwardsPoint> {
        use crate::{common::utils::run_round, sign::SignerParty};

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

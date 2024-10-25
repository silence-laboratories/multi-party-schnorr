use elliptic_curve::Group;
use ff::Field;

use crate::common::traits::GroupElem;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyRefreshData<G>
where
    G: Group,
{
    pub key_id: [u8; 32],
    /// Party id of the key share
    pub party_id: u8,
    pub threshold: u8,
    pub total_parties: u8,
    /// Additive share of participant_i (after interpolation)
    /// \sum_{i=0}^{n-1} s_i_0 = private_key
    /// s_i_0 can be equal to Zero in case when participant lost their key_share
    /// and wants to recover it during key_refresh
    pub(crate) s_i_0: G::Scalar,

    /// list of participants ids who lost their key_shares
    /// should be in range [0, n-1]
    pub(crate) lost_keyshare_party_ids: Vec<u8>,

    /// expected public key for key_refresh
    pub expected_public_key: G,
}

impl<G> KeyRefreshData<G>
where
    G: GroupElem,
{
    /// Create a new KeyRefreshData
    pub fn recovery_data_for_lost(
        lost_keyshare_party_ids: Vec<u8>,
        expected_public_key: G,
        key_id: [u8; 32],
        party_id: u8,
        threshold: u8,
        total_parties: u8,
    ) -> Self {
        KeyRefreshData {
            key_id,
            threshold,
            total_parties,
            party_id,
            s_i_0: <G::Scalar as Field>::ZERO,
            lost_keyshare_party_ids,
            expected_public_key,
        }
    }

    /// Get the private scalar (s_i) (not shamir secret)
    pub fn s_i(&self) -> &G::Scalar {
        &self.s_i_0
    }

    /// Get the list of lost party ids
    pub fn lost_party_ids(&self) -> &[u8] {
        &self.lost_keyshare_party_ids
    }
}

#[cfg(test)]
mod test {
    use crate::{
        common::utils::run_keygen,
        keygen::utils::{run_import, run_recovery, run_refresh},
    };
    use curve25519_dalek::EdwardsPoint;

    #[test]
    fn refresh_curve25519() {
        let _ = run_refresh::<3, 5, EdwardsPoint>();
        let _ = run_refresh::<2, 3, EdwardsPoint>();
        let _ = run_refresh::<5, 10, EdwardsPoint>();
        let _ = run_refresh::<9, 20, EdwardsPoint>();
    }

    #[test]
    fn key_import_curve25519() {
        let _ = run_import::<3, 5, EdwardsPoint>();
        let _ = run_import::<2, 3, EdwardsPoint>();
        let _ = run_import::<5, 10, EdwardsPoint>();
        let _ = run_import::<9, 20, EdwardsPoint>();
    }

    #[test]
    fn recovery_curve25519() {
        let keyshares = run_keygen::<3, 5, EdwardsPoint>();
        run_recovery::<3, 5, EdwardsPoint>(&keyshares, vec![0]).unwrap();
        run_recovery::<3, 5, EdwardsPoint>(&keyshares, vec![1, 2]).unwrap();
        run_recovery::<3, 5, EdwardsPoint>(&keyshares, vec![3, 4]).unwrap();
        run_recovery::<3, 5, EdwardsPoint>(&keyshares, vec![2, 3]).unwrap();
        run_recovery::<3, 5, EdwardsPoint>(&keyshares, vec![4, 1]).unwrap();
    }

    #[test]
    #[should_panic(expected = "Error during key refresh or recovery protocol")]
    fn recovery_invalid_curve25519() {
        let keyshares = run_keygen::<3, 5, EdwardsPoint>();
        if let Err(e) = run_recovery::<3, 5, EdwardsPoint>(&keyshares, vec![1, 2, 3]) {
            panic!("{}", e);
        }
    }

    #[cfg(feature = "taproot")]
    #[test]
    fn refresh_taproot() {
        use k256::ProjectivePoint;
        let _ = run_refresh::<3, 5, ProjectivePoint>();
        let _ = run_refresh::<2, 3, ProjectivePoint>();
        let _ = run_refresh::<5, 10, ProjectivePoint>();
        let _ = run_refresh::<9, 20, ProjectivePoint>();
    }

    #[cfg(feature = "taproot")]
    #[test]
    fn recovery_taproot() {
        use k256::ProjectivePoint;
        let keyshares = run_keygen::<3, 5, ProjectivePoint>();
        run_recovery::<3, 5, ProjectivePoint>(&keyshares, vec![0]).unwrap();
        run_recovery::<3, 5, ProjectivePoint>(&keyshares, vec![1, 2]).unwrap();
        run_recovery::<3, 5, ProjectivePoint>(&keyshares, vec![3, 4]).unwrap();
        run_recovery::<3, 5, ProjectivePoint>(&keyshares, vec![2, 3]).unwrap();
        run_recovery::<3, 5, ProjectivePoint>(&keyshares, vec![4, 1]).unwrap();
    }

    #[cfg(feature = "taproot")]
    #[test]
    #[should_panic(expected = "Error during key refresh or recovery protocol")]
    fn recovery_invalid_taproot() {
        use k256::ProjectivePoint;
        let keyshares = run_keygen::<3, 5, ProjectivePoint>();
        if let Err(e) = run_recovery::<3, 5, ProjectivePoint>(&keyshares, vec![1, 2, 3]) {
            panic!("{}", e);
        }
    }

    #[cfg(feature = "taproot")]
    #[test]
    fn key_import_taproot() {
        use k256::ProjectivePoint;
        let _ = run_import::<3, 5, ProjectivePoint>();
        let _ = run_import::<2, 3, ProjectivePoint>();
        let _ = run_import::<5, 10, ProjectivePoint>();
        let _ = run_import::<9, 20, ProjectivePoint>();
    }
}

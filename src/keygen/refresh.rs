use curve25519_dalek::{EdwardsPoint, Scalar};

pub struct KeyRefreshData {
    /// Additive share of participant_i (after interpolation)
    /// \sum_{i=0}^{n-1} s_i_0 = private_key
    /// s_i_0 can be equal to Zero in case when participant lost their key_share
    /// and wants to recover it during key_refresh
    pub(crate) d_i_0: Scalar,

    /// list of participants ids who lost their key_shares
    /// should be in range [0, n-1]
    pub(crate) lost_keyshare_party_ids: Vec<u8>,

    /// expected public key for key_refresh
    pub(crate) expected_public_key: EdwardsPoint,
    // /// root_chain_code
    // #[allow(unused)]
    // pub(crate) root_chain_code: [u8; 32],
}
impl KeyRefreshData {
    /// Create a new KeyRefreshData
    pub fn recovery_data_for_lost(
        lost_keyshare_party_ids: Vec<u8>,
        expected_public_key: EdwardsPoint,
    ) -> Self {
        KeyRefreshData {
            d_i_0: Scalar::ZERO,
            lost_keyshare_party_ids,
            expected_public_key,
        }
    }
}

#[cfg(test)]
mod test {

    //FIXME: add this later

    // #[test]
    // fn refresh() {
    //     let _ = process_refresh::<3, 5>();
    //     let _ = process_refresh::<2, 3>();
    //     let _ = process_refresh::<5, 10>();
    //     let _ = process_refresh::<9, 20>();
    // }

    // #[test]
    // fn recovery() {
    //     let keyshares = process_keygen::<3, 5>();
    //     process_recovery::<3, 5>(&keyshares, vec![0]).unwrap();
    //     process_recovery::<3, 5>(&keyshares, vec![1, 2]).unwrap();
    //     process_recovery::<3, 5>(&keyshares, vec![3, 4]).unwrap();
    //     process_recovery::<3, 5>(&keyshares, vec![2, 3]).unwrap();
    //     process_recovery::<3, 5>(&keyshares, vec![4, 1]).unwrap();
    // }

    // #[test]
    // #[should_panic(expected = "Error during key refresh or recovery protocol")]
    // fn recovery_invalid() {
    //     let keyshares = process_keygen::<3, 5>();
    //     if let Err(e) = process_recovery::<3, 5>(&keyshares, vec![1, 2, 3]) {
    //         panic!("{}", e);
    //     }
    // }
}

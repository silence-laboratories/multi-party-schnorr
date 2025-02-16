use crypto_bigint::subtle::ConstantTimeEq;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::Group;
use ff::Field;
use rand::Rng;
use rand::{CryptoRng, RngCore};
use sl_mpc_mate::math::Polynomial;

use crate::keygen::KeyRefreshData;
use crate::sign::SignError;
pub fn get_lagrange_coeff<G: Group>(
    my_party_id: &u8,
    party_ids: impl IntoIterator<Item = u8>,
) -> G::Scalar {
    let mut coeff = G::Scalar::ONE;
    let x_i = G::Scalar::from((my_party_id + 1) as u64);
    for party_id in party_ids {
        let x_j = G::Scalar::from((party_id + 1) as u64);
        if x_i.ct_ne(&x_j).into() {
            let sub = x_j - x_i;

            // SAFETY: Invert is safe because we check x_j != x_i, so sub is not zero.
            coeff *= x_j * sub.invert().unwrap();
        }
    }
    coeff
}

pub fn schnorr_split_private_key<G: Group + GroupEncoding, R: CryptoRng + RngCore>(
    private_key: &G::Scalar,
    t: u8,
    n: u8,
    root_chain_code: Option<[u8; 32]>,
    rng: &mut R,
) -> Result<Vec<KeyRefreshData<G>>, SignError> {
    if t < 2 || t > n {
        return Err(SignError::InvalidThreshold);
    }
    let mut poly: Polynomial<G> = Polynomial::random(rng, (t - 1) as usize);
    poly.set_constant(*private_key);
    let root_chain_code = root_chain_code.unwrap_or_else(|| rng.gen());

    let expected_public_key = G::generator() * private_key;
    let res = (0..n)
        .map(|pid| {
            let d_i: G::Scalar = poly.evaluate_at(&G::Scalar::from((pid + 1) as u64));
            // TODO: REMOVE THIS allocation
            let coeff = get_lagrange_coeff::<G>(&pid, 0..n);
            let s_i_0 = d_i * coeff;
            KeyRefreshData {
                threshold: t,
                total_parties: n,
                party_id: pid,
                s_i_0,
                lost_keyshare_party_ids: vec![],
                expected_public_key,
                root_chain_code,
            }
        })
        .collect();
    Ok(res)
}

/// Split the private keys into shares,
pub fn schnorr_split_private_key_with_lost<G: Group + GroupEncoding, R: CryptoRng + RngCore>(
    private_key: &G::Scalar,
    t: u8,
    n: u8,
    lost_ids: Option<Vec<u8>>,
    root_chain_code: Option<[u8; 32]>,
    rng: &mut R,
) -> Result<Vec<KeyRefreshData<G>>, SignError> {
    if t < 2 || t > n {
        return Err(SignError::InvalidThreshold);
    }
    let mut poly: Polynomial<G> = Polynomial::random(rng, (t - 1) as usize);
    poly.set_constant(*private_key);

    let lost_ids = lost_ids.unwrap_or_default();
    let expected_public_key = G::generator() * private_key;
    let partys_with_keyshares = (0..n).filter(|pid| !lost_ids.contains(pid));
    let mut shares = vec![];
    let root_chain_code = root_chain_code.unwrap_or_else(|| rng.gen());

    for pid in partys_with_keyshares.clone() {
        let d_i: G::Scalar = poly.evaluate_at(&G::Scalar::from((pid + 1) as u64));
        let coeff = get_lagrange_coeff::<G>(&pid, partys_with_keyshares.clone());
        let s_i_0 = d_i * coeff;
        shares.push(KeyRefreshData {
            threshold: t,
            total_parties: n,
            party_id: pid,
            s_i_0,
            lost_keyshare_party_ids: lost_ids.clone(),
            expected_public_key,
            root_chain_code,
        });
    }

    Ok(shares)
}

/// Helper method to combine the secret shares into the private key
/// You can use all the shares or the threshold number of shares to
/// combine the private key
/// Note: The list of s_i should be in the same order as the list of pids
/// # Arguments
///
/// * `pid_list` - List of party ids participating in the export
///
/// * `d_i_list` - List of d_i (secret shamir shares of the parties)
pub fn combine_shares<G: Group>(
    pid_list: &[u8],
    d_i_list: &[G::Scalar],
    public_key: &G,
) -> Option<G::Scalar> {
    if pid_list.len() != d_i_list.len() {
        return None;
    }
    let mut s = G::Scalar::ZERO;
    for (pid, d_i) in pid_list.iter().zip(d_i_list.iter()) {
        let coeff = get_lagrange_coeff::<G>(pid, pid_list.iter().copied());
        s += coeff * d_i;
    }

    let calculated_public_key = G::generator() * s;

    (public_key == &calculated_public_key).then_some(s)
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::EdwardsPoint;
    use rand::seq::SliceRandom;

    use crate::common::utils::run_keygen;

    use super::combine_shares;

    #[test]
    fn test_combine() {
        let mut rng = rand::thread_rng();
        let shares = run_keygen::<3, 5, EdwardsPoint>();
        let sample = shares
            .choose_multiple(&mut rng, shares.len())
            .collect::<Vec<_>>();

        // Creating copy of secret, in real scenario, we wouldn't have to do this.
        let d_i_list = sample
            .iter()
            .map(|keyshare| *keyshare.shamir_share())
            .collect::<Vec<_>>();

        let pid_list = sample
            .iter()
            .map(|keyshare| keyshare.party_id())
            .collect::<Vec<_>>();

        combine_shares::<EdwardsPoint>(&pid_list, &d_i_list, sample[0].public_key())
            .expect("Combine shares failed");
    }
}

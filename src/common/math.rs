use crypto_bigint::subtle::ConstantTimeEq;
use elliptic_curve::Group;
use ff::Field;
use sl_mpc_mate::math::Polynomial;

use crate::keygen::KeyRefreshData;

pub fn get_lagrange_coeff<G: Group>(
    my_party_id: &u8,
    party_ids: impl Iterator<Item = u8>,
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

pub fn schnorr_split_private_key<G: Group>(
    private_key: &G::Scalar,
    t: u8,
    n: u8,
    key_id: [u8; 32],
) -> Vec<KeyRefreshData<G>> {
    let mut rng = rand::thread_rng();
    let mut poly: Polynomial<G> = Polynomial::random(&mut rng, (t - 1) as usize);
    poly.set_constant(*private_key);

    let expected_public_key = G::generator() * private_key;
    (0..n)
        .map(|pid| {
            let d_i: G::Scalar = poly.evaluate_at(&G::Scalar::from((pid + 1) as u64));
            let coeff = get_lagrange_coeff::<G>(&pid, 0..n);
            let s_i_0 = d_i * coeff;
            KeyRefreshData {
                key_id,
                threshold: t,
                total_parties: n,
                party_id: pid,
                s_i_0,
                lost_keyshare_party_ids: vec![],
                expected_public_key,
            }
        })
        .collect()
}

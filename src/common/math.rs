use crypto_bigint::subtle::ConstantTimeEq;
use elliptic_curve::Group;
use ff::Field;

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

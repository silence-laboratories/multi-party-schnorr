use elliptic_curve::Group;

use rand::{CryptoRng, Rng, RngCore};

use crate::common::traits::{GroupElem, ScalarReduce};
use crate::common::utils::{generate_pki, run_keygen, run_round};

use super::KeyRefreshData;
use super::R0;

use super::{messages::Keyshare, KeygenError, KeygenParty};

pub fn setup_keygen<G: Group>(t: u8, n: u8) -> Result<Vec<KeygenParty<R0, G>>, KeygenError> {
    let mut rng = rand::thread_rng();
    // Initializing the keygen for each party.
    let (party_key_list, party_pubkey_list) = generate_pki(n.into(), &mut rng);
    let actors = (0..n)
        .map(|idx| {
            KeygenParty::new(
                t,
                n,
                idx,
                party_key_list[idx as usize].clone(),
                party_pubkey_list.clone(),
                None,
                rng.gen(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    Ok(actors)
}

pub fn process_refresh<const T: usize, const N: usize, G: GroupElem>(
    shares: [Keyshare<G>; N],
) -> Result<[Keyshare<G>; N], KeygenError>
where
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    let mut rng = rand::thread_rng();
    let parties0 = setup_refresh(&shares, &mut rng)?;
    let (actors, msgs): (Vec<_>, Vec<_>) = run_round(parties0, ()).into_iter().unzip();
    let (actors, msgs): (Vec<_>, Vec<_>) = run_round(actors, msgs).into_iter().unzip();
    let new_shares = run_round(actors, msgs);

    Ok(new_shares
        .try_into()
        .map_err(|_| panic!("size will be N"))
        .unwrap())
}

pub fn setup_refresh<R: CryptoRng + RngCore, G: GroupElem>(
    shares: &[Keyshare<G>],
    rng: &mut R,
) -> Result<Vec<KeygenParty<R0, G>>, KeygenError> {
    let (party_key_list, party_pubkey_list) = generate_pki(shares.len(), rng);
    let parties0 = shares
        .iter()
        .zip(party_key_list)
        .map(|(keyshare, party_key)| {
            let data = keyshare.get_refresh_data();
            KeygenParty::new(
                keyshare.threshold,
                keyshare.total_parties,
                keyshare.party_id,
                party_key,
                party_pubkey_list.clone(),
                Some(data),
                rng.gen(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(parties0)
}

pub fn run_refresh<const T: usize, const N: usize, G: GroupElem>() -> Result<(), KeygenError>
where
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    let shares = run_keygen::<T, N, G>();
    process_refresh::<T, N, G>(shares)?;
    Ok(())
}
//
pub fn run_recovery<const T: usize, const N: usize, G: GroupElem>(
    keyshares: &[Keyshare<G>],
    lost_party_ids: Vec<u8>,
) -> Result<(), KeygenError>
where
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    let mut rng = rand::thread_rng();
    let (party_key_list, party_pubkey_list) = generate_pki(N, &mut rng);

    // Start refresh protocol
    let mut parties0 = vec![];
    for pid in 0..N {
        let data = if lost_party_ids.contains(&(pid as u8)) {
            KeyRefreshData::recovery_data_for_lost(lost_party_ids.clone(), keyshares[0].public_key)
        } else {
            keyshares[pid].get_recovery_data(lost_party_ids.clone())
        };

        parties0.push(KeygenParty::new(
            T as u8,
            N as u8,
            pid as u8,
            party_key_list[pid].clone(),
            party_pubkey_list.clone(),
            Some(data),
            rng.gen(),
        )?);
    }

    let (actors, msgs): (Vec<_>, Vec<_>) = run_round(parties0, ()).into_iter().unzip();
    let (actors, msgs): (Vec<_>, Vec<_>) = run_round(actors, msgs).into_iter().unzip();
    run_round(actors, msgs);

    Ok(())
}

// pub(crate) fn _check_secret_recovery<'a>(
//     big_a_poly: &'a [EdwardsPoint],
//     public_key: &'a EdwardsPoint,
//     total_parties: u8,
// ) -> Result<(), KeygenError> {
//     // TODO: Avoid allocation here
//     let party_points = (0..total_parties)
//         .map(|i| Scalar::from((i + 1) as u64))
//         .collect::<Vec<_>>();
//
//     let evaluate = |poly: &[EdwardsPoint], point: Scalar| {
//         (0..poly.len())
//             .map(|i| poly[i] * point.pow_vartime([i as u64]))
//             .fold(EdwardsPoint::identity(), |acc, point| acc + point)
//     };
//
//     let coeff_vector = _get_lagrange_coeff_list(&party_points);
//     let big_s_list = party_points
//         .iter()
//         .map(|point| evaluate(big_a_poly, *point));
//
//     let public_key_point = big_s_list
//         .zip(coeff_vector.iter())
//         .fold(EdwardsPoint::identity(), |acc, (point, betta_i)| {
//             acc + point * betta_i
//         });
//
//     (public_key == &public_key_point)
//         .then_some(())
//         .ok_or(KeygenError::InvalidRefresh)?;
//
//     Ok(())
// }

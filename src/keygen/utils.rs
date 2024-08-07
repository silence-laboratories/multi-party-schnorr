use curve25519_dalek::{traits::Identity, EdwardsPoint, Scalar};
use ff::Field;
use rand::Rng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::common::_get_lagrange_coeff_list;
use crate::common::traits::Round;
use crate::common::utils::{generate_pki, run_round};

use super::KeyRefreshData;
use super::R0;
use super::R1;
use super::{messages::Keyshare, KeygenError, KeygenParty};

pub fn setup_keygen(t: u8, n: u8) -> Result<Vec<KeygenParty<R0>>, KeygenError> {
    let mut rng = rand::thread_rng();
    // Initializing the keygen for each party.
    let (party_key_list, party_pubkey_list) = generate_pki(n.into(), &mut rng);
    let actors = (0..n)
        .map(|idx| {
            KeygenParty::new(
                t,
                n,
                idx as u8,
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

// pub fn process_refresh<const T: usize, const N: usize>() -> Result<(), KeygenError> {
//     let keyshares = process_keygen::<T, N>();
//
//     let mut rng = rand::thread_rng();
//     let (party_pubkey_list, party_key_list) = generate_pki(N, &mut rng);
//
//     // Start refresh protocol
//     let parties0 = keyshares
//         .iter()
//         .zip(party_key_list)
//         .map(|(keyshare, party_key)| {
//             let data = keyshare.get_refresh_data();
//             KeygenParty::new(
//                 T as u8,
//                 N as u8,
//                 keyshare.party_id,
//                 &party_key,
//                 party_pubkey_list.clone(),
//                 Some(data),
//                 &mut rng,
//             )
//         })
//         .collect::<Result<Vec<_>, _>>()?;
//
//     run_refresh_protocol(N as u8, parties0);
//
//     Ok(())
// }
//
// pub fn process_recovery<const T: usize, const N: usize>(
//     keyshares: &[Keyshare; N],
//     lost_party_ids: Vec<u8>,
// ) -> Result<(), KeygenError> {
//     let mut rng = rand::thread_rng();
//     let (party_pubkey_list, party_key_list) = generate_pki(N, &mut rng);
//
//     // Start refresh protocol
//     let mut parties0 = vec![];
//     for pid in 0..N {
//         let data = if lost_party_ids.contains(&(pid as u8)) {
//             KeyRefreshData::recovery_data_for_lost(lost_party_ids.clone(), *keyshares[0].public_key)
//         } else {
//             keyshares[pid].get_recovery_data(lost_party_ids.clone())
//         };
//
//         parties0.push(KeygenParty::new(
//             T as u8,
//             N as u8,
//             pid as u8,
//             &party_key_list[pid],
//             party_pubkey_list.clone(),
//             Some(data),
//             &mut rng,
//         )?);
//     }
//
//     run_refresh_protocol(N as u8, parties0);
//     Ok(())
// }

pub(crate) fn _check_secret_recovery<'a>(
    big_a_poly: &'a [EdwardsPoint],
    public_key: &'a EdwardsPoint,
    total_parties: u8,
) -> Result<(), KeygenError> {
    // TODO: Avoid allocation here
    let party_points = (0..total_parties)
        .map(|i| Scalar::from((i + 1) as u64))
        .collect::<Vec<_>>();

    let evaluate = |poly: &[EdwardsPoint], point: Scalar| {
        (0..poly.len())
            .map(|i| poly[i] * point.pow_vartime([i as u64]))
            .fold(EdwardsPoint::identity(), |acc, point| acc + point)
    };

    let coeff_vector = _get_lagrange_coeff_list(&party_points);
    let big_s_list = party_points
        .iter()
        .map(|point| evaluate(big_a_poly, *point));

    let public_key_point = big_s_list
        .zip(coeff_vector.iter())
        .fold(EdwardsPoint::identity(), |acc, (point, betta_i)| {
            acc + point * betta_i
        });

    (public_key == &public_key_point)
        .then_some(())
        .ok_or(KeygenError::InvalidRefresh)?;

    Ok(())
}

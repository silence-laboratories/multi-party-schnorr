use curve25519_dalek::{traits::Identity, EdwardsPoint, Scalar};
use ff::Field;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use sl_mpc_mate::message::{Opaque, GR};

use crate::common::_get_lagrange_coeff_list;
use crate::common::traits::PersistentObj;
use crate::common::traits::Round;
use crate::common::utils::cooridinator::{recv_broadcast, Coordinator};
use crate::common::utils::{generate_pki, run_round};

use super::KeyRefreshData;
use super::R0;
use super::R1;
use super::{messages::Keyshare, KeygenError, KeygenParty};

pub fn setup_keygen<const T: usize, const N: usize>(
) -> Result<(Vec<KeygenParty<R1>>, Coordinator), KeygenError> {
    let mut coord = Coordinator::new(N as u8, 2);
    let mut rng = rand::thread_rng();
    // Initializing the keygen for each party.
    let (party_pubkey_list, party_key_list) = generate_pki(N, &mut rng);

    let actors = party_key_list
        .iter()
        .enumerate()
        .map(|(pid, keys)| {
            KeygenParty::new(
                T as u8,
                N as u8,
                pid as u8,
                keys,
                party_pubkey_list.clone(),
                None,
                &mut rng,
            )
            .and_then(|p1| p1.process(()))
            .map(|(p1, msg1)| {
                coord.send(0, msg1.to_bytes().unwrap()).unwrap();
                p1
            })
        })
        .collect::<Result<Vec<KeygenParty<R1>>, KeygenError>>()?;

    Ok((actors, coord))
}

/// Utility function to process all rounds of keygen
pub fn process_keygen<const T: usize, const N: usize>() -> [Keyshare; N] {
    let (parties, mut coord) = setup_keygen::<T, N>().unwrap();
    let parties1 = run_round(&mut coord, parties, 0);

    let msgs = recv_broadcast(&mut coord, 1);

    let keyshares: Vec<Keyshare> = parties1
        .into_par_iter()
        .map(|actor| actor.process(msgs.clone()).unwrap())
        .collect();

    keyshares
        .try_into()
        .map_err(|_| "Failed to convert keyshares to array")
        .unwrap()
}

pub fn process_refresh<const T: usize, const N: usize>() -> Result<(), KeygenError> {
    let keyshares = process_keygen::<T, N>();

    let mut rng = rand::thread_rng();
    let (party_pubkey_list, party_key_list) = generate_pki(N, &mut rng);

    // Start refresh protocol
    let parties0 = keyshares
        .iter()
        .zip(party_key_list)
        .map(|(keyshare, party_key)| {
            let data = keyshare.get_refresh_data();
            KeygenParty::new(
                T as u8,
                N as u8,
                keyshare.party_id,
                &party_key,
                party_pubkey_list.clone(),
                Some(data),
                &mut rng,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    run_refresh_protocol(N as u8, parties0);

    Ok(())
}

pub fn process_recovery<const T: usize, const N: usize>(
    keyshares: &[Keyshare; N],
    lost_party_ids: Vec<u8>,
) -> Result<(), KeygenError> {
    let mut rng = rand::thread_rng();
    let (party_pubkey_list, party_key_list) = generate_pki(N, &mut rng);

    // Start refresh protocol
    let mut parties0 = vec![];
    for pid in 0..N {
        let data = if lost_party_ids.contains(&(pid as u8)) {
            KeyRefreshData::recovery_data_for_lost(lost_party_ids.clone(), *keyshares[0].public_key)
        } else {
            keyshares[pid].get_recovery_data(lost_party_ids.clone())
        };

        parties0.push(KeygenParty::new(
            T as u8,
            N as u8,
            pid as u8,
            &party_key_list[pid],
            party_pubkey_list.clone(),
            Some(data),
            &mut rng,
        )?);
    }

    run_refresh_protocol(N as u8, parties0);
    Ok(())
}
fn run_refresh_protocol(n: u8, parties: Vec<KeygenParty<R0>>) -> Vec<Keyshare> {
    let mut coord = Coordinator::new(n, 2);
    let parties1 = parties
        .into_iter()
        .map(|party| {
            let (p, msg) = party.process(()).unwrap();
            coord.send(0, msg.to_bytes().unwrap()).unwrap();
            p
        })
        .collect();

    let parties2 = run_round(&mut coord, parties1, 0);

    let msgs = recv_broadcast(&mut coord, 1);
    parties2
        .into_par_iter()
        .map(|actor| actor.process(msgs.clone()).unwrap())
        .collect()
}

pub(crate) fn _check_secret_recovery<'a>(
    big_a_poly: &'a [Opaque<EdwardsPoint, GR>],
    public_key: &'a EdwardsPoint,
    total_parties: u8,
) -> Result<(), KeygenError> {
    // TODO: Avoid allocation here
    let party_points = (0..total_parties)
        .map(|i| Scalar::from((i + 1) as u64))
        .collect::<Vec<_>>();

    let evaluate = |poly: &[Opaque<EdwardsPoint, GR>], point: Scalar| {
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

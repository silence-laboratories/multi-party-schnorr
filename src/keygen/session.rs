// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::sync::Arc;

use crypto_bigint::subtle::ConstantTimeEq;
use crypto_box::{PublicKey, SecretKey};
use zeroize::Zeroizing;

use crate::{
    common::{
        ser::Serializable,
        traits::{GroupElem, Round, ScalarReduce},
    },
    keygen::{KeyRefreshData, KeygenError, KeygenMsg1, KeygenMsg2, KeygenParty, R0, R1, R2},
};

#[derive(Debug)]
pub enum SessionError {
    InvalidPartyId,
    InvalidSessionId,
    StateDecode,
    Dkg(KeygenError),
    Encode,
    Decode,
}

const N: u8 = 3;
const T: u8 = 2;

const ROUND1: u8 = 1;
const ROUND2: u8 = 2;
const ONE_MSG: u8 = 1;
const TWO_MSG: u8 = 2;

impl From<KeygenError> for SessionError {
    fn from(value: KeygenError) -> Self {
        SessionError::Dkg(value)
    }
}

/// Initialize a server-side keygen session and return the first-round
/// message to the client.
///
/// Builds a `KeygenParty<R1>` and `server_msg1` from the provided
/// keys/seed. The session state is serialized and passed to
/// `encrypt_state` as `(ad, payload)` where:
/// - `ad = hdr || client_msg1 || server_msg1`
/// - `payload = P1` (the round-1 party state)
/// - `hdr = [ROUND1, TWO_MSG, offset_le]` with `offset` pointing to `payload`
///
/// `encrypt_state` is responsible for encrypting and persisting the
/// state. It is assumed that caller will use AEAD and store the state
/// blob in following format: ad | encrypted payload | tag.
///
/// Returns `SessionError` on invalid party ID, encoding failure, or
/// underlying keygen errors.
#[allow(clippy::too_many_arguments)]
pub fn server_init<G>(
    client_msg1: &KeygenMsg1, // c_1 from C
    party_id: u8,
    decryption_key: Arc<SecretKey>,
    encyption_keys: Vec<(u8, PublicKey)>,
    refresh_data: Option<KeyRefreshData<G>>,
    key_id: Option<[u8; 32]>,
    seed: [u8; 32],
    extra_data: Option<Vec<u8>>,
    encrypt_state: impl FnOnce(&[u8], &[u8]),
) -> Result<KeygenMsg1, SessionError>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]>,
    G::Scalar: Serializable,
{
    let p0 = KeygenParty::<R0, G>::new(
        T,
        N,
        party_id,
        decryption_key,
        encyption_keys,
        refresh_data,
        key_id,
        seed,
        extra_data,
    )?;

    let (p1, server_msg1) = p0.process(())?;

    let mut buffer = Zeroizing::new(vec![ROUND1, TWO_MSG, 0, 0]);

    ciborium::into_writer(&client_msg1, &mut *buffer).map_err(|_| SessionError::Encode)?;
    ciborium::into_writer(&server_msg1, &mut *buffer).map_err(|_| SessionError::Encode)?;

    let offset = buffer.len();

    buffer[2..4].copy_from_slice(&(offset as u16).to_le_bytes());

    ciborium::into_writer(&p1, &mut *buffer).map_err(|_| SessionError::Encode)?;

    let (ad, plantext) = buffer.split_at(offset);

    encrypt_state(ad, plantext);

    Ok(server_msg1)
}

/// Given server session state created by `server_init()`, extract
/// server message to be handled by `server_round1_finish()`.
///
/// `encrypted_state` is a encrypted state blob in the following
/// format: ad | encrypted-payload | tag. This function extects that
/// prefix of `encrypted_state` is exactly the same as `ad` passed to
/// `encrypt_state` parameter of `server_init()`.
///
/// Returns first server message or ServerError::Decode.
pub fn server_round1_decode_server_message(
    encrypted_state: &[u8],
) -> Result<KeygenMsg1, SessionError> {
    let (hdr, payload) = encrypted_state
        .split_first_chunk::<4>()
        .ok_or(SessionError::Decode)?;

    if hdr[0] != ROUND1 || hdr[1] != TWO_MSG {
        return Err(SessionError::Decode);
    }

    let offset = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;

    let mut ad = payload
        .get(..offset.wrapping_sub(4))
        .ok_or(SessionError::Decode)?;

    let _msg1: KeygenMsg1 = ciborium::from_reader(&mut ad).map_err(|_| SessionError::Decode)?;
    let _msg2: KeygenMsg1 = ciborium::from_reader(&mut ad).map_err(|_| SessionError::Decode)?;

    Ok(_msg2)
}

/// Process third message of first round and call passed callback
/// with encoded state: ([msg1], P2).
///
/// ([msg1, msg2], P1) + msg3 => ([msg1], P2)
///
/// `encrypt_state` is passed with 3 parameters:
/// - `final_session_id`
/// - `ad` = encoded hdr | msg1
/// - `payload` = encoded P2
///
/// `final_session_id` is additional parameter extracted from second
/// round message. It could be used as additional input to derive
/// state id.
///
pub fn server_round1_finish<G>(
    msg3: KeygenMsg1, // a_1 to B or b_1 to A
    session_id: &[u8],
    decrypted_state: &[u8],
    encrypt_state: impl FnOnce(&[u8], &[u8], &[u8]),
) -> Result<KeygenMsg2<G>, SessionError>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]>,
    G::Scalar: Serializable,
{
    let (hdr, mut payload) = decrypted_state
        .split_first_chunk::<4>()
        .ok_or(SessionError::Decode)?;

    if hdr[0] != ROUND1 || hdr[1] != TWO_MSG {
        return Err(SessionError::Decode);
    }

    let msg1: KeygenMsg1 = ciborium::from_reader(&mut payload).map_err(|_| SessionError::Decode)?;
    let msg2: KeygenMsg1 = ciborium::from_reader(&mut payload).map_err(|_| SessionError::Decode)?;
    let p1: KeygenParty<R1<G>, G> =
        ciborium::from_reader(&mut payload).map_err(|_| SessionError::Decode)?;

    if session_id.ct_ne(msg1.session_id.as_slice()).into() {
        return Err(SessionError::InvalidSessionId);
    }

    let (p2, server_msg1) = p1.process(vec![msg1, msg2, msg3])?;

    let mut buffer = Zeroizing::new(vec![ROUND2, ONE_MSG, 0, 0]);

    ciborium::into_writer(&server_msg1, &mut *buffer).map_err(|_| SessionError::Encode)?;

    let offset = buffer.len();

    buffer[2..4].copy_from_slice(&(offset as u16).to_le_bytes());

    ciborium::into_writer(&p2, &mut *buffer).map_err(|_| SessionError::Encode)?;

    let (ad, plantext) = buffer.split_at(offset);

    encrypt_state(server_msg1.session_id.as_slice(), ad, plantext);

    Ok(server_msg1)
}

/// Given encypted state created by `server_round1_finish()` or
/// `server_round2_message()`.
///
/// The function is similar to `server_round1_decode_server_message()`
/// and follows the same convension for `encrypted_state`.
///
/// Returns first server message or ServerError::Decode.
pub fn server_round2_decode_server_message<G>(
    encrypted_state: &[u8],
) -> Result<KeygenMsg2<G>, SessionError>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
{
    let (hdr, payload) = encrypted_state
        .split_first_chunk::<4>()
        .ok_or(SessionError::Decode)?;

    if hdr[0] != ROUND2 || !(hdr[1] == ONE_MSG || hdr[1] == TWO_MSG) {
        return Err(SessionError::Decode);
    }

    let offset = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;

    let mut ad = payload
        .get(..offset.wrapping_sub(4))
        .ok_or(SessionError::Decode)?;

    let _msg1: KeygenMsg2<G> = ciborium::from_reader(&mut ad).map_err(|_| SessionError::Decode)?;

    Ok(_msg1)
}

/// Process next message of round2. There are two calls of this
/// function.  First time when processing KeygenMsg2 from client, and
/// second time when processing message form other server.
///
/// ([msg1], P2) + msg2       => ([msg1, msg2], P2)
/// or
/// ([msg1, msg2], P2) + msg3 => Keyshare
///
/// `encrypte_state` accepts 3 parameters:
/// - `final_session_id`
/// - `ad` = encoded hdr | msg1
/// - `payload` = encoded P2 or encoded keyshare.
///
/// If `ad` is empty than `payload` is encoded keyshare.
///
pub fn server_round2_message<G>(
    msg3: KeygenMsg2<G>,
    decrypted_state: &[u8],
    encrypt_state: impl FnOnce(&[u8], &[u8], &[u8]),
) -> Result<(), SessionError>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]> + Serializable,
{
    let (hdr, payload) = decrypted_state
        .split_first_chunk::<4>()
        .ok_or(SessionError::Decode)?;

    if hdr[0] != ROUND2 {
        return Err(SessionError::Decode);
    }

    let offset = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;

    let (mut msgs, payload) = payload
        .split_at_checked(offset.wrapping_sub(4))
        .ok_or(SessionError::Decode)?;

    let p2: KeygenParty<R2, G> =
        ciborium::from_reader(payload).map_err(|_| SessionError::Decode)?;

    match hdr[1] {
        ONE_MSG => {
            let msg1: KeygenMsg2<G> =
                ciborium::from_reader(&mut msgs).map_err(|_| SessionError::Decode)?;

            let mut buffer = Zeroizing::new(vec![ROUND2, TWO_MSG, 0, 0]);

            ciborium::into_writer(&msg1, &mut *buffer).map_err(|_| SessionError::Encode)?;
            ciborium::into_writer(&msg3, &mut *buffer).map_err(|_| SessionError::Encode)?;

            let offset = buffer.len();

            buffer[2..4].copy_from_slice(&(offset as u16).to_le_bytes());

            ciborium::into_writer(&p2, &mut *buffer).map_err(|_| SessionError::Encode)?;

            encrypt_state(&msg3.session_id, &buffer[..offset], &buffer[offset..]);
        }

        TWO_MSG => {
            let msg1: KeygenMsg2<G> =
                ciborium::from_reader(&mut msgs).map_err(|_| SessionError::Decode)?;

            let msg2: KeygenMsg2<G> =
                ciborium::from_reader(&mut msgs).map_err(|_| SessionError::Decode)?;

            let final_session_id = msg3.session_id;

            let share = p2
                .process(vec![msg1, msg2, msg3])
                .map_err(|_| SessionError::Decode)?;

            let mut buffer = Zeroizing::new(vec![]);

            ciborium::into_writer(&share, &mut *buffer).map_err(|_| SessionError::Encode)?;

            encrypt_state(&final_session_id, &[], &buffer);
        }

        _ => return Err(SessionError::Decode),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::utils::generate_pki;

    fn server_session<G>()
    where
        G: GroupElem,
        G::Scalar: ScalarReduce<[u8; 32]>,
        G::Scalar: Serializable,
    {
        let mut rng = rand::thread_rng();
        // Initializing the keygen for each party.
        let (party_key_list, party_pubkey_list) = generate_pki(N as usize, &mut rng);

        // Initiate client first round state and create first client's message.
        let (c1, client_msg1) = KeygenParty::<R0, G>::new(
            T,
            N,
            0,
            party_key_list[0].clone(),
            party_pubkey_list.clone(),
            None,
            None,
            [1; 32],
            None,
        )
        .unwrap()
        .process(())
        .unwrap();

        // Request 1: Client -> Server 1, client receives s1_1
        let mut s1_state_1 = vec![];
        let s1_1 = server_init::<G>(
            &client_msg1,
            1,
            party_key_list[1].clone(),
            party_pubkey_list.clone(),
            None,
            None,
            [2; 32],
            None,
            |ad, payload| {
                // (S1, [c1, s1_msg1])
                s1_state_1.extend_from_slice(ad);
                s1_state_1.extend_from_slice(payload);

                // DB[_id] = s1_state_1
            },
        )
        .unwrap();

        // Request 2: Client -> Server 2, , client receives s2_1
        let mut s2_state_1 = vec![];
        let s2_1 = server_init::<G>(
            &client_msg1,
            2,
            party_key_list[2].clone(),
            party_pubkey_list.clone(),
            None,
            None,
            [3; 32],
            None,
            |ad, payload| {
                s2_state_1.extend_from_slice(ad);
                s2_state_1.extend_from_slice(payload);
                // DB[_id] = s2_state_1
            },
        )
        .unwrap();

        // After communicating with two servers, client could finish
        // its first round and produce its second message.
        let (c2, client_msg2) = c1.process(vec![client_msg1, s1_1, s2_1]).unwrap();

        // Servers exchange its first round messages. It could be done
        // using client or by independent channel.

        let mut s1_state_2 = vec![];
        let s1_2 = server_round1_finish::<G>(
            s2_1,
            &client_msg1.session_id,
            &s1_state_1,
            |_final_session_id, ad, payload| {
                s1_state_2.extend_from_slice(ad);
                s1_state_2.extend_from_slice(payload);
                // DB[_id] = s1_state_2
            },
        )
        .unwrap();

        // We can use `server_round1_decode_server_message()` to
        // extract `s1_1` from encrypted s1_state_1.
        let s1_1_decoded = server_round1_decode_server_message(&s1_state_1).unwrap();

        assert_eq!(s1_1.session_id, s1_1_decoded.session_id);
        assert_eq!(s1_1.commitment, s1_1_decoded.commitment);

        let mut s2_state_2 = vec![];
        let s2_2 = server_round1_finish::<G>(
            s1_1_decoded,
            &client_msg1.session_id,
            &s2_state_1,
            |_final_session_id, ad, payload| {
                s2_state_2.extend_from_slice(ad);
                s2_state_2.extend_from_slice(payload);
                // DB[_id] = s2_state_2
            },
        )
        .unwrap();

        // Request 3: Client -> Serser 1, client receives message s1_2
        let mut s1_state_3 = vec![];
        server_round2_message::<G>(
            client_msg2.clone(),
            &s1_state_2,
            |_final_session_id, ad, payload| {
                s1_state_3.extend_from_slice(ad);
                s1_state_3.extend_from_slice(payload);
                // DB[_id] = s1_state_3
            },
        )
        .unwrap();

        // Request 4: Client -> Serser 2, client receives messages s2_2
        let mut s2_state_3 = vec![];
        server_round2_message::<G>(
            client_msg2.clone(),
            &s2_state_2,
            |_final_session_id, ad, payload| {
                s2_state_3.extend_from_slice(ad);
                s2_state_3.extend_from_slice(payload);
                // DB[_id] = s2_state_3
            },
        )
        .unwrap();

        // After execution of requests 3 & 4, client could finish its
        // second found and calculate its keyshare.
        let _client_keyshare = c2
            .process(vec![client_msg2, s1_2.clone(), s2_2.clone()])
            .unwrap();

        // Now, two servers must exchange its second round messages
        // and calculate its keyshares.
        let mut s1_share = vec![];
        server_round2_message::<G>(s2_2, &s1_state_3, |_final_session_id, _ad, share| {
            s1_share.extend_from_slice(share);
        })
        .unwrap();

        // Here we could use `s1_s` or extract the same message from
        // encrypte state.
        let s1_2_decoded = server_round2_decode_server_message::<G>(&s1_state_3).unwrap();

        let mut s2_share = vec![];
        server_round2_message::<G>(
            s1_2_decoded,
            &s2_state_3,
            |_final_session_id, _ad, share| {
                s2_share.extend_from_slice(share);
            },
        )
        .unwrap();
    }

    #[cfg(feature = "eddsa")]
    #[test]
    fn session_curve25519() {
        use curve25519_dalek::EdwardsPoint;

        server_session::<EdwardsPoint>();
    }

    #[cfg(feature = "taproot")]
    #[test]
    fn session_taproot() {
        use k256::ProjectivePoint;

        server_session::<ProjectivePoint>();
    }
    #[cfg(feature = "redpallas")]
    #[test]
    fn session_redpallas() {
        use crate::common::redpallas::RedPallasPoint;

        server_session::<RedPallasPoint>();
    }
}

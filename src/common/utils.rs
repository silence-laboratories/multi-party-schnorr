use crypto_box::{
    aead::{Aead, AeadCore},
    PublicKey, SalsaBox, SecretKey,
};

use crypto_bigint::{generic_array::GenericArray, rand_core::CryptoRngCore, Encoding, U256};
use curve25519_dalek::Scalar;
use ed25519_dalek::Signature;
use rand::{CryptoRng, RngCore};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use self::cooridinator::{recv_broadcast, Coordinator};

use super::{
    traits::{PersistentObj, Round},
    PartyKeys, PartyPublicKeys,
};

#[derive(Hash, bincode::Encode, bincode::Decode, Zeroize, ZeroizeOnDrop, Clone, Debug)]
pub struct EncryptedData {
    pub sender_pid: u8,
    pub receiver_pid: u8,
    pub ciphertext: Vec<u8>,
    // Size of the nonce is 24
    pub nonce: [u8; 24],
}

impl PersistentObj for EncryptedData {}

// Not using the SessionId type from sl_mpc_mate because it is not serializable.
pub type SessionId = [u8; 32];
pub type HashBytes = [u8; 32];

impl EncryptedData {
    pub fn new(ciphertext: Vec<u8>, nonce: [u8; 24], sender_pid: u8, receiver_pid: u8) -> Self {
        Self {
            ciphertext,
            nonce,
            sender_pid,
            receiver_pid,
        }
    }
}

/// A trait for converting a type to a curve25519 scalar.
pub trait ToCurveScalar {
    /// Converts `self` to a curve25519 scalar.
    fn to_25519_scalar(self) -> Scalar;
}

impl ToCurveScalar for [u8; 32] {
    fn to_25519_scalar(self) -> Scalar {
        Scalar::from_bytes_mod_order(self)
    }
}

impl ToCurveScalar for U256 {
    fn to_25519_scalar(self) -> Scalar {
        Scalar::from_bytes_mod_order(self.to_le_bytes())
    }
}

/// Common trait for all MPC messages.
pub trait BaseMessage {
    // Return the session id of the message.
    fn session_id(&self) -> &SessionId;
    // Return the party id of the message sender.
    fn party_id(&self) -> u8;
}
#[macro_export]
/// Macro to implement the BaseMessage trait for a message type.
macro_rules! impl_basemessage {
    ($($type:ty),*) => {
        $(
            impl $crate::common::utils::BaseMessage for $type {
                fn session_id(&self) -> &SessionId {
                    &self.session_id
                }

                fn party_id(&self) -> u8 {
                    self.from_party
                }
            }
        )*
    }
}

/// Calculates the final session id from the list of session ids.
pub fn calculate_final_session_id(
    party_ids: impl Iterator<Item = u8>,
    sid_i_list: &[SessionId],
) -> SessionId {
    let mut hasher = Sha256::new();

    party_ids.for_each(|pid| hasher.update((pid as u32).to_be_bytes()));
    sid_i_list.iter().for_each(|sid| hasher.update(sid));

    hasher.finalize().into()
}

pub fn encrypt_message<R: CryptoRngCore>(
    sender_secret_info: (&SecretKey, u8),
    receiver_public_info: (&PublicKey, u8),
    message: &[u8],
    rng: &mut R,
) -> Option<EncryptedData> {
    let sender_box = SalsaBox::new(receiver_public_info.0, sender_secret_info.0);
    let nonce = SalsaBox::generate_nonce(rng);
    sender_box.encrypt(&nonce, message).ok().map(|data| {
        EncryptedData::new(
            data,
            nonce.into(),
            sender_secret_info.1,
            receiver_public_info.1,
        )
    })
}

pub fn decrypt_message(
    receiver_private_key: &SecretKey,
    sender_public_key: &PublicKey,
    enc_data: &EncryptedData,
) -> Option<Vec<u8>> {
    let receiver_box = SalsaBox::new(sender_public_key, receiver_private_key);
    receiver_box
        .decrypt(
            &GenericArray::from(enc_data.nonce),
            enc_data.ciphertext.as_slice(),
        )
        .ok()
}

/// Execute one round of DKG protocol, execute parties in parallel
pub fn run_round<I, N, R, M, E>(coord: &mut Coordinator, actors: Vec<R>, round: usize) -> Vec<N>
where
    R: Round<Input = Vec<I>, Output = std::result::Result<(N, M), E>>,
    I: PersistentObj + Clone + Sync,
    M: PersistentObj + Send,
    E: std::fmt::Debug,
    Vec<R>: IntoParallelIterator<Item = R>,
    N: Send,
{
    let msgs = recv_broadcast(coord, round);

    let (actors, msgs): (Vec<N>, Vec<M>) = actors
        .into_par_iter()
        .map(|actor| {
            let (actor, msg) = actor.process(msgs.clone()).unwrap();

            (actor, msg)
        })
        .unzip();

    if round < coord.max_round() as usize {
        msgs.iter().for_each(|msg| {
            coord.send(round + 1, msg.to_bytes().unwrap()).unwrap();
        })
    }
    actors
}

// Basic Coordinator module for running the protocol and testing.
pub mod cooridinator {

    use super::PersistentObj;
    /// Receive a batch broadcast from the coordinator.
    /// Only used internally for testing.
    pub fn recv_broadcast<M: PersistentObj>(coord: &mut Coordinator, round: usize) -> Vec<M> {
        decode_batch(&coord.broadcast(round).unwrap()).unwrap()
    }

    /// Prepare batch of messages
    pub fn encode_batch(msgs: Vec<Vec<u8>>) -> Option<Vec<u8>> {
        bincode::encode_to_vec(msgs, bincode::config::standard()).ok()
    }
    pub fn decode_batch<T: PersistentObj>(bytes: &[u8]) -> Option<Vec<T>> {
        let (bytes, _): (Vec<Vec<u8>>, usize) =
            bincode::decode_from_slice(bytes, bincode::config::standard())
                .ok()
                .unwrap();

        bytes.into_iter().map(|data| T::from_bytes(&data)).collect()
    }

    type Msg = Vec<u8>;

    /// Coordinator
    pub struct Coordinator {
        parties: u8,
        rounds: u8,
        store: Vec<Msg>,
    }

    #[derive(Debug)]
    /// Coordinator errors
    pub enum Error {
        /// Some party tries to send more messages then expected
        RoundFinished,

        /// Some party tries to send message after last round is finished
        TooManyRounds,

        /// Not all messages for a given round are received
        InProgress,
    }

    impl Coordinator {
        /// Create new Coordinator.
        pub fn new(parties: u8, rounds: u8) -> Self {
            Coordinator {
                parties,
                rounds,
                store: Vec::with_capacity((parties * rounds) as usize),
            }
        }

        /// Get the maximum number of rounds.
        pub fn max_round(&self) -> u8 {
            self.rounds
        }

        /// Receive a message from a party for a given round.
        pub fn send(&mut self, round: usize, msg: Msg) -> Result<usize, Error> {
            let len = self.store.len();

            if len == self.store.capacity() {
                return Err(Error::TooManyRounds);
            }

            if len / self.parties as usize != round {
                return Err(Error::RoundFinished);
            }

            let pid = len % self.parties as usize;

            self.store.push(msg);

            Ok(pid)
        }

        /// Broadcast the messages for a given round.
        pub fn broadcast(&self, round: usize) -> Result<Msg, Error> {
            let start = round * self.parties as usize;
            let end = start + self.parties as usize;

            if self.store.len() < end {
                Err(Error::InProgress)
            } else {
                Ok(encode_batch(self.store.get(start..end).unwrap().to_owned()).unwrap())
            }
        }
    }
}

/// Helper method to generate PKI for a set of parties.
pub fn generate_pki<R: CryptoRng + RngCore>(
    total_parties: usize,
    rng: &mut R,
) -> (Vec<PartyPublicKeys>, Vec<PartyKeys>) {
    let mut party_pubkey_list = vec![];
    let party_key_list: Vec<PartyKeys> = (0..total_parties)
        .map(|_pid| {
            // Generate or load from persistent storage
            // set of party's keys
            let party_keys = PartyKeys::generate(rng);

            // extract public keys
            let actor_pubkeys = party_keys.public_keys();
            party_pubkey_list.push(actor_pubkeys);
            party_keys
        })
        .collect();

    (party_pubkey_list, party_key_list)
}

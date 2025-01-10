use std::sync::Arc;

use crypto_box::{
    aead::{Aead, AeadCore},
    PublicKey, SalsaBox, SecretKey,
};

use crypto_bigint::generic_array::typenum::Unsigned;
use crypto_bigint::{generic_array::GenericArray, rand_core::CryptoRngCore};

use ff::PrimeField;
use rand::{CryptoRng, RngCore};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use sha2::{Digest, Sha256};

use crate::keygen::{utils::setup_keygen, Keyshare};

use super::traits::{GroupElem, Round, ScalarReduce};

// Encryption is done inplace, so the size of the ciphertext is the size of the message plus the tag size.
pub const SCALAR_CIPHERTEXT_SIZE: usize = 32 + <SalsaBox as AeadCore>::TagSize::USIZE;

// Custom serde serializer
#[cfg(feature = "serde")]
pub mod serde_point {
    use std::marker::PhantomData;

    use elliptic_curve::group::GroupEncoding;
    use serde::de::Visitor;

    pub fn serialize<S, G: GroupEncoding>(point: &G, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(G::Repr::default().as_ref().len())?;
        for byte in point.to_bytes().as_ref().iter() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }

    pub fn deserialize<'de, D, G: GroupEncoding>(deserializer: D) -> Result<G, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PointVisitor<G: GroupEncoding>(PhantomData<G>);

        impl<'de, G: GroupEncoding> Visitor<'de> for PointVisitor<G> {
            type Value = G;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("a valid point in Edwards y + sign format")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<G, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut encoding = G::Repr::default();
                for (idx, byte) in encoding.as_mut().iter_mut().enumerate() {
                    *byte = seq.next_element()?.ok_or_else(|| {
                        serde::de::Error::invalid_length(idx, &"wrong length of point")
                    })?;
                }

                Option::from(G::from_bytes(&encoding))
                    .ok_or(serde::de::Error::custom("point decompression failed"))
            }
        }

        deserializer.deserialize_tuple(G::Repr::default().as_ref().len(), PointVisitor(PhantomData))
    }
}

#[cfg(feature = "serde")]
pub mod serde_vec_point {
    use elliptic_curve::group::GroupEncoding;

    pub fn serialize<S, G: GroupEncoding>(points: &[G], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::with_capacity(points.len() * G::Repr::default().as_ref().len());
        points.iter().for_each(|point| {
            bytes.extend_from_slice(point.to_bytes().as_ref());
        });
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D, G: GroupEncoding>(deserializer: D) -> Result<Vec<G>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        let point_size = G::Repr::default().as_ref().len();
        if bytes.len() % point_size != 0 {
            return Err(serde::de::Error::custom("Invalid number of bytes"));
        }
        let mut points = Vec::with_capacity(bytes.len() / point_size);
        for i in 0..bytes.len() / point_size {
            let mut encoding = G::Repr::default();
            encoding
                .as_mut()
                .copy_from_slice(&bytes[i * point_size..(i + 1) * point_size]);
            points.push(
                Option::from(G::from_bytes(&encoding))
                    .ok_or(serde::de::Error::custom("Invalid point"))?,
            );
        }
        Ok(points)
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct EncryptedScalar {
    pub sender_pid: u8,
    pub receiver_pid: u8,
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
    pub ciphertext: [u8; SCALAR_CIPHERTEXT_SIZE],
    // Size of the nonce is 24
    pub nonce: [u8; <SalsaBox as AeadCore>::NonceSize::USIZE],
}

const _: () = assert!(core::mem::align_of::<EncryptedScalar>() == 1);

// Not using the SessionId type from sl_mpc_mate because it is not serializable.
pub type SessionId = [u8; 32];
pub type HashBytes = [u8; 32];

impl EncryptedScalar {
    pub fn new(
        ciphertext: [u8; SCALAR_CIPHERTEXT_SIZE],
        nonce: [u8; 24],
        sender_pid: u8,
        receiver_pid: u8,
    ) -> Self {
        Self {
            ciphertext,
            nonce,
            sender_pid,
            receiver_pid,
        }
    }
}

/// Common trait for all MPC messages.
pub trait BaseMessage {
    // Return the session id of the message.
    fn session_id(&self) -> &SessionId;
    // Return the party id of the message sender.
    fn party_id(&self) -> u8;
}

/// Common trait for all MPC P2P messages.
pub trait BaseP2PMessage {
    // Returns participant index of the sender
    #[allow(clippy::wrong_self_convention)]
    fn from_party(&self) -> usize;

    // Returns participant index of the receiver
    fn to_party(&self) -> usize;
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

pub fn encrypt_message<R: CryptoRngCore, G: GroupElem>(
    sender_secret_info: (&SecretKey, u8),
    receiver_public_info: (&PublicKey, u8),
    message: G::Scalar,
    rng: &mut R,
) -> Option<EncryptedScalar> {
    // FIXME: Handle this better
    if std::mem::size_of::<<G::Scalar as PrimeField>::Repr>() != 32 {
        panic!("We don't support scalars of size other than 32 bytes!");
    }
    let sender_box = SalsaBox::new(receiver_public_info.0, sender_secret_info.0);
    let nonce = SalsaBox::generate_nonce(rng);
    sender_box
        .encrypt(&nonce, message.to_repr().as_ref())
        .ok()
        .and_then(|data| {
            Some(EncryptedScalar::new(
                data.try_into().ok()?,
                nonce.into(),
                sender_secret_info.1,
                receiver_public_info.1,
            ))
        })
}

pub fn decrypt_message(
    receiver_private_key: &SecretKey,
    sender_public_key: &PublicKey,
    enc_data: &EncryptedScalar,
) -> Option<Vec<u8>> {
    let receiver_box = SalsaBox::new(sender_public_key, receiver_private_key);
    receiver_box
        .decrypt(
            &GenericArray::from(enc_data.nonce),
            enc_data.ciphertext.as_slice(),
        )
        .ok()
}

/// Helper method to generate PKI for a set of parties.
pub fn generate_pki<R: CryptoRng + RngCore>(
    total_parties: usize,
    rng: &mut R,
) -> (
    Vec<Arc<crypto_box::SecretKey>>,
    Vec<(u8, crypto_box::PublicKey)>,
) {
    let mut party_pubkey_list = vec![];

    let party_key_list: Vec<Arc<crypto_box::SecretKey>> = (0..total_parties)
        .map(|pid| {
            let sk = crypto_box::SecretKey::generate(rng);
            party_pubkey_list.push((pid as u8, sk.public_key()));
            Arc::new(sk)
        })
        .collect();

    (party_key_list, party_pubkey_list)
}

/// Execute one round of DKG protocol locally, execute parties in parallel
/// Used for testing purposes.
pub fn run_round<I, R, O, E>(actors: Vec<R>, msgs: I) -> Vec<O>
where
    R: Round<Input = I, Output = std::result::Result<O, E>>,
    I: Clone + Sync,
    E: std::fmt::Debug,
    Vec<R>: IntoParallelIterator<Item = R>,
    O: Send,
{
    actors
        .into_par_iter()
        .map(|actor| actor.process(msgs.clone()).unwrap())
        .collect()
}

/// Utility function to run the keygen protocol.
pub fn run_keygen<const T: usize, const N: usize, G: GroupElem>() -> [Keyshare<G>; N]
where
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    let actors = setup_keygen(T as u8, N as u8).unwrap();
    let (actors, msgs): (Vec<_>, Vec<_>) = run_round(actors, ()).into_iter().unzip();
    let (actors, msgs): (Vec<_>, Vec<_>) = run_round(actors, msgs).into_iter().unzip();
    run_round(actors, msgs)
        .try_into()
        .map_err(|_| panic!("Failed to convert keyshares"))
        .unwrap()
}

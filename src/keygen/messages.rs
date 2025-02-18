use std::hash::Hash;

use crypto_bigint::subtle::ConstantTimeEq;
use elliptic_curve::{group::GroupEncoding, Group};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
// * MY CODE: ADDED
use serde::{Serializer, Deserializer};
use curve25519_dalek::scalar::Scalar;
use serde::ser::SerializeStruct;

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::traits::Identity;

use sha2::{Sha256, Digest};
use bs58;
use bs58::Alphabet;
use std::convert::TryInto;

use crate::{
    common::{
        get_lagrange_coeff,
        traits::{GroupElem, ScalarReduce},
        utils::{EncryptedScalar, HashBytes, SessionId},
        DLogProof,
    },
    impl_basemessage,
};

#[cfg(feature = "serde")]
use crate::common::utils::{serde_point, serde_vec_point};

use super::KeyRefreshData;

/// Type for the key generation protocol's message 1.
// * MY CODE: COMMENTED OUT
// #[derive(Hash, Clone)]
// * MY CODE: ADDED
#[derive(Debug, Hash, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeygenMsg1 {
    /// Participant Id of the sender
    pub from_party: u8,

    /// Sesssion id
    pub session_id: SessionId, // * MY CODE: ADDED, Shared session ID

    /// Participants commitment
    pub commitment: HashBytes,

    // * MY CODE: ADDED, to keep flexibility for future extensions if needed
    pub extra_data: Option<Vec<u8>>,

    // * MY CODE: ADDED, now used to store the server's public key
    pub public_key: String,
}

/// Type for the key generation protocol's message 2.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
// * MY CODE: ADDED
#[derive(Clone, Debug)]
pub struct KeygenMsg2<G>
where
    G: Group + ConstantTimeEq + GroupEncoding,
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    /// Participant Id of the sender
    pub from_party: u8,

    /// Sesssion id
    pub session_id: SessionId,           // * MY CODE: ADDED, Round-specific session ID
    pub shared_session_id: SessionId,   // * MY CODE: ADDED, Protocol-wide shared session ID

    /// Random 32 bytes
    pub r_i: [u8; 32],

    /// Participants Fik values
    #[cfg_attr(feature = "serde", serde(with = "serde_vec_point"))]
    pub big_a_i_poly: Vec<G>,

    /// Ciphertext list
    pub c_i_list: Vec<EncryptedScalar>,

    /// Participants dlog proof
    #[cfg_attr(
        feature = "serde",
        serde(bound(
            serialize = "G::Scalar: Serialize",
            deserialize = "G::Scalar: Deserialize<'de>"
        ))
    )]
    pub dlog_proofs_i: Vec<DLogProof<G>>,
}

// TODO: my adjusted to Debug fields print
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug)] // Add Debug here
pub struct Keyshare<G>
where
    G: Group + GroupEncoding,
{
    /// Threshold value
    pub threshold: u8,
    /// Total number of parties
    pub total_parties: u8,
    /// Party Id of the sender
    // * MY CODE: ADDED, make party_id public
    pub party_id: u8,
    /// d_i, internal
    pub d_i: G::Scalar, // * MY CODE: d_i public
    /// Public key of the generated key.
    #[cfg_attr(feature = "serde", serde(with = "serde_point"))]
    pub public_key: G,
    /// Key ID
    pub key_id: [u8; 32],
    /// Extra data
    pub extra_data: Option<Vec<u8>>,
}

// TODO: that one was the original usage
/// Keyshare of a party.
// #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
// #[derive(Clone)]
// pub struct Keyshare<G>
// where
//     G: Group + GroupEncoding,
// {
//     /// Threshold value
//     pub threshold: u8,
//     /// Total number of parties
//     pub total_parties: u8,
//     /// Party Id of the sender
//     pub(crate) party_id: u8,
//     /// d_i, internal
//     pub(crate) d_i: G::Scalar,
//     /// Public key of the generated key.
//     #[cfg_attr(feature = "serde", serde(with = "serde_point"))]
//     pub public_key: G,
//     /// Key ID
//     pub key_id: [u8; 32],
//     /// Extra data
//     pub extra_data: Option<Vec<u8>>,
// }

impl<G: Group + GroupEncoding> Keyshare<G> {
    pub fn public_key(&self) -> &G {
        &self.public_key
    }
    /// Get the shamir secret share
    pub fn shamir_share(&self) -> &G::Scalar {
        &self.d_i
    }
    /// Get the scalar share of the party
    pub fn scalar_share(&self) -> G::Scalar {
        let coeff = get_lagrange_coeff::<G>(&self.party_id, 0..self.total_parties);
        self.d_i * coeff
    }
    pub fn party_id(&self) -> u8 {
        self.party_id
    }
    pub fn extra_data(&self) -> &[u8] {
        match &self.extra_data {
            Some(val) => val,
            None => &[],
        }
    }
}

impl<G> Keyshare<G>
where
    G: Group + GroupEncoding,
{
    pub fn new(
        threshold: u8,
        total_parties: u8,
        party_id: u8,
        d_i: G::Scalar,
        public_key: G,
        key_id: [u8; 32],
        extra_data: Option<Vec<u8>>,
    ) -> Self {
        Self {
            threshold,
            total_parties,
            party_id,
            d_i,
            public_key,
            key_id,
            extra_data,
        }
    }

    /// Start the key refresh protocol.
    /// If some parties lost their keyshare, they can recover their keyshare using this protocol.
    /// This will return a [`KeyRefreshData`] instance which can be use to initialize the KeygenParty which can be driven
    /// to completion and will return the refreshed keyshare.
    pub fn get_refresh_data(&self, lost_ids: Option<Vec<u8>>) -> KeyRefreshData<G> {
        self.create_refresh(lost_ids.unwrap_or_default())
    }

    fn create_refresh(&self, lost_keyshare_party_ids: Vec<u8>) -> KeyRefreshData<G> {
        // Calculate the additive share s_i_0 of the party
        let mut partys_with_keyshares = vec![];
        let lambda = if lost_keyshare_party_ids.is_empty() {
            get_lagrange_coeff::<G>(&self.party_id, 0..self.total_parties)
        } else {
            for pid in 0..self.total_parties {
                if lost_keyshare_party_ids.contains(&pid) {
                    continue;
                }
                partys_with_keyshares.push(pid);
            }
            get_lagrange_coeff::<G>(&self.party_id, partys_with_keyshares.iter().copied())
        };
        let s_i_0 = self.d_i * lambda;
        KeyRefreshData {
            threshold: self.threshold,
            total_parties: self.total_parties,
            party_id: self.party_id,
            s_i_0,
            lost_keyshare_party_ids,
            expected_public_key: self.public_key,
        }
    }
}

// * MY CODE: ADDED, Serialize and Deserialize for Keyshare
impl Keyshare<EdwardsPoint> {
    pub fn serialize(&self) -> (String, String) {
        let d_i_serialized = serialize_scalar_to_base58::<EdwardsPoint>(&self.d_i);
        let public_key_serialized = serialize_public_key_to_base58(&self.public_key);

        (d_i_serialized, public_key_serialized)
    }

    pub fn deserialize(d_i_str: &str, pub_key_str: &str) -> Result<Self, String> {
        let d_i = deserialize_scalar_from_base58(d_i_str)?;
        let public_key = deserialize_public_key_from_base58(pub_key_str)?;

        Ok(Self {
            threshold: 2, // Example default values
            // * MY CODE: ADDED, set total_parties to 2
            total_parties: 2,
            // * MY CODE: ADDED, set party_id to 0
            party_id: 0,
            d_i,
            public_key,
            key_id: [0u8; 32],
            extra_data: None,
        })
    }
}


impl_basemessage!(KeygenMsg1);

impl<G> crate::common::utils::BaseMessage for KeygenMsg2<G>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]>, // + From<curve25519_dalek::Scalar>, // * MY CODE: ADDED, and COMMENTED OUT
{
    fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    fn party_id(&self) -> u8 {
        self.from_party
    }
}

// * MY CODE: ADDED, Serialize and Deserialize for private key and public key - base58 encoding with checksum
/// Generic function to serialize a scalar (private key) to Base58 with checksum
pub fn serialize_scalar_to_base58<G>(scalar: &Scalar) -> String
where
    G: curve25519_dalek::traits::Identity, // Ensure G is an Identity group
{
    let scalar_bytes = scalar.to_bytes(); // Convert scalar to bytes

    // Compute checksum (SHA-256 twice, first 4 bytes)
    let checksum: [u8; 4] = Sha256::digest(Sha256::digest(scalar_bytes)).as_slice()[..4]
        .try_into()
        .expect("Checksum length error");

    let serialized = [&scalar_bytes[..], &checksum].concat(); // Append checksum
    bs58::encode(serialized)
        .with_alphabet(Alphabet::BITCOIN) // Solana uses the same alphabet as Bitcoin
        .into_string()
}

// * MY CODE: ADDED, Serialize and Deserialize for private key and public key - base58 encoding with checksum
/// Generic function to deserialize a Base58 string back into a Scalar (private key)
// * MY CODE: ADDED, make the function public
pub fn deserialize_scalar_from_base58(encoded_str: &str) -> Result<Scalar, String> {
    let decoded_bytes = bs58::decode(encoded_str)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_vec()
        .map_err(|e| format!("Base58 decode error: {}", e))?;

    if decoded_bytes.len() != 36 {
        return Err("Invalid decoded length".to_string());
    }

    let (data, checksum) = decoded_bytes.split_at(32);
    let expected_checksum: [u8; 4] = Sha256::digest(Sha256::digest(&data))[..4]
        .try_into()
        .expect("Checksum length error");

    if checksum != expected_checksum {
        return Err("Checksum verification failed".to_string());
    }

    // Convert byte slice into an array
    let scalar_bytes: [u8; 32] = data.try_into().map_err(|_| "Failed to convert bytes to scalar".to_string())?;
    Ok(Scalar::from_bytes_mod_order(scalar_bytes))
}

// * MY CODE: ADDED, Serialize and Deserialize for private key and public key - base58 encoding with checksum
/// Generic function to serialize EdwardsPoint (public key) to Base58 with checksum
pub fn serialize_public_key_to_base58(public_key: &EdwardsPoint) -> String {
    let public_key_bytes = public_key.compress().to_bytes(); // Convert public key to bytes

    // Compute checksum
    let checksum: [u8; 4] = Sha256::digest(Sha256::digest(public_key_bytes)).as_slice()[..4]
        .try_into()
        .expect("Checksum length error");

    let serialized = [&public_key_bytes[..], &checksum].concat(); // Append checksum
    bs58::encode(serialized)
        .with_alphabet(bs58::Alphabet::BITCOIN) // Solana uses the same alphabet as Bitcoin
        .into_string()
}

// * MY CODE: ADDED, Serialize and Deserialize for private key and public key - base58 encoding with checksum
/// Generic function to deserialize a Base58-encoded string back into an EdwardsPoint (public key)
pub fn deserialize_public_key_from_base58(encoded_str: &str) -> Result<EdwardsPoint, String> {
    let decoded_bytes = bs58::decode(encoded_str)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_vec()
        .map_err(|e| format!("Base58 decode error: {}", e))?;

    if decoded_bytes.len() != 36 {
        return Err("Invalid decoded length".to_string());
    }

    let (data, checksum) = decoded_bytes.split_at(32);
    let expected_checksum: [u8; 4] = Sha256::digest(Sha256::digest(data))[..4]
        .try_into()
        .expect("Checksum length error");

    if checksum != expected_checksum {
        return Err("Checksum verification failed".to_string());
    }

    // Convert slice to an array and attempt to decompress it to EdwardsPoint
    let public_key_bytes: [u8; 32] = data
        .try_into()
        .map_err(|_| "Failed to convert bytes to public key".to_string())?;

    // Handle the Result and then call decompress()
    let compressed = CompressedEdwardsY::from_slice(&public_key_bytes)
        .map_err(|_| "Invalid compressed public key format".to_string())?;

    compressed
        .decompress()
        .ok_or_else(|| "Failed to decompress public key".to_string())
}

// * MY CODE: ADDED, Serialize and Deserialize for private key and public key - base58 encoding with checksum
fn deserialize_public_key_from_bytes(public_key_bytes: &[u8; 32]) -> Result<EdwardsPoint, String> {
    let compressed = CompressedEdwardsY::from_slice(public_key_bytes)
        .map_err(|_| "Failed to convert slice to CompressedEdwardsY".to_string())?;

    compressed
        .decompress()
        .ok_or_else(|| "Failed to decompress public key".to_string())
}

// TODO: TO BE DELETED:

// #[derive(Debug, Clone, PartialEq, Eq, Hash)]
// pub struct SerializableScalar(pub Scalar);

// impl Serialize for SerializableScalar {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         let bytes = self.0.to_bytes(); // Convert Scalar to bytes
//         serializer.serialize_bytes(&bytes)
//     }
// }


// impl<'de> Deserialize<'de> for SerializableScalar {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
//         let scalar = Scalar::from_canonical_bytes(bytes.try_into().map_err(serde::de::Error::custom)?)
//             .ok_or_else(|| serde::de::Error::custom("Invalid Scalar bytes"))?;
//         Ok(SerializableScalar(scalar))
//     }
// }




// impl<G: GroupElem> Serialize for KeygenMsg2<G>
// where
//     G::Scalar: Serialize,
// {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         let mut state = serializer.serialize_struct("KeygenMsg2", 3)?;
//         state.serialize_field("from_party", &self.from_party)?;
//         state.serialize_field("session_id", &self.session_id)?;
//         // Manually serialize fields
//         state.serialize_field(
//             "big_a_i_poly",
//             &self.big_a_i_poly.iter().map(|g| g.to_bytes()).collect::<Vec<_>>(),
//         )?;
//         state.serialize_field("c_i_list", &self.c_i_list)?;
//         state.serialize_field("dlog_proofs_i", &self.dlog_proofs_i)?;
//         state.end()
//     }
// }

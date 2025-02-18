// * MY CODE: ADDED
use std::error::Error;
// * MY CODE: ADDED
use std::fmt::Debug;
use std::sync::Arc;

use crypto_box::{
    aead::{Aead, AeadCore},
    PublicKey, SalsaBox, SecretKey,
};

use crypto_bigint::generic_array::typenum::Unsigned;
// * MY CODE: ADDED
use crypto_bigint::{Encoding, generic_array::GenericArray, rand_core::CryptoRngCore};
// * MY CODE: ADDED
use curve25519_dalek::EdwardsPoint;
// * MY CODE: ADDED
use elliptic_curve::Group;
// * MY CODE: ADDED
use elliptic_curve::group::GroupEncoding;
// * MY CODE: ADDED
use elliptic_curve::bigint::U256;

use ff::PrimeField;
use rand::{CryptoRng, RngCore};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use sha2::{Digest, Sha256};
// * MY CODE: ADDED
use hex::{encode as hex_encode, decode as hex_decode};
// * MY CODE: ADDED
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize}; // * MY CODE: ADDED, for serialization

use crate::keygen::{utils::setup_keygen, Keyshare, validate_input, validate_input_basic};
// * MY CODE: ADDED
use crate::sign::messages::SignMsg1;

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

// * MY CODE: ADDED, EncryptionKey
#[derive(Clone, Debug)]
pub struct EncryptKey {
    pub enc_keys: Vec<(u8, PublicKey)>,
    pub enc_keys_serialized: String,
    pub enc_keys_deserialized: Vec<(u8, crypto_box::PublicKey)>,  // Deserialized keys
}

impl EncryptKey {
    pub fn new(enc_keys: Vec<(u8, crypto_box::PublicKey)>) -> Self {
        let mut instance = Self {
            enc_keys,
            enc_keys_serialized: String::new(),
            enc_keys_deserialized: Vec::new(),
        };
        instance.serialize_party_enc_keys(); // Automatically serialize on initialization
        instance
    }

    // Serialize the internal enc_keys field into enc_keys_serialized
    pub fn serialize_party_enc_keys(&mut self) {
        let encoded_keys: Vec<String> = self.enc_keys
            .iter()
            .map(|(party_id, key)| format!("{}:{}", party_id, hex::encode(key.to_bytes())))
            .collect();
        self.enc_keys_serialized = encoded_keys.join(","); // Store in struct field
    }

    /// Deserialize a serialized string back into an `EncryptKey` instance
    pub fn deserialize(&mut self, serialized_keys: &str) -> Result<(), String> {
        let parsed_keys = serialized_keys
            .split(',')
            .filter_map(|pair| {
                let parts: Vec<&str> = pair.split(':').collect();
                if parts.len() == 2 {
                    let party_id = parts[0].parse::<u8>().ok()?;
                    let bytes = hex::decode(parts[1]).ok()?;
                    let key_bytes = bytes.try_into().ok()?;
                    let pubkey = crypto_box::PublicKey::from_bytes(key_bytes);
                    Some((party_id, pubkey))
                } else {
                    None
                }
            })
            .collect::<Vec<(u8, crypto_box::PublicKey)>>();

        if parsed_keys.is_empty() {
            Err("Failed to parse encryption keys from serialized string.".to_string())
        } else {
            self.enc_keys_deserialized = parsed_keys;
            self.enc_keys_serialized = serialized_keys.to_string();
            Ok(())
        }
    }

    // Optionally, provide a method to retrieve the serialized keys
    pub fn get_serialized_keys(&self) -> &String {
        &self.enc_keys_serialized
    }

    pub fn get_deserialized_keys(&self) -> Vec<(u8, crypto_box::PublicKey)> {
        self.enc_keys_deserialized.clone()
    }

    /// Print the raw encryption keys (before serialization)
    pub fn print_raw_keys(&self) {
        println!("Raw Encryption Keys:");
        self.enc_keys.iter().for_each(|(party_id, key)| {
            println!("Party ID: {}, Raw Key: {:?}", party_id, key);
        });
    }

    // Method to print encryption keys nicely
    pub fn print_keys(&self) {
        self.enc_keys.iter().for_each(|(party_id, key)| {
            println!("Party ID: {}, Key: {}", party_id, hex::encode(key.to_bytes()));
        });
    }

    /// Print the serialized encryption keys in a readable format
    pub fn print_serialized_keys(&self) {
        println!("Serialized Encryption Keys: {}", self.enc_keys_serialized);
    }

    /// Print deserialized encryption keys after deserialization
    pub fn print_deserialized_keys(&self) {
        if self.enc_keys_deserialized.is_empty() {
            println!("No deserialized encryption keys available.");
        } else {
            println!("Deserialized Encryption Keys:");
            self.enc_keys_deserialized.iter().for_each(|(party_id, key)| {
                println!("Party ID: {}, Deserialized Key: {:?}", party_id, key);
            });
        }
    }

}

// * MY CODE: ADDED, DecryptKey
#[derive(Clone, Debug)]
pub struct DecryptKey {
    pub dec_key: Arc<SecretKey>,
    pub dec_key_serialized: String,
    pub dec_key_deserialized: Option<Arc<SecretKey>>,  // Store deserialized key
}

impl DecryptKey {
    /// Create a new `DecryptKey` instance and automatically serialize the key
    pub fn new(dec_key: Option<Arc<SecretKey>>) -> Self {
        let mut instance = Self {
            dec_key: dec_key.unwrap_or_else(|| Arc::new(SecretKey::from_bytes([0u8; 32]))),
            dec_key_serialized: String::new(),
            dec_key_deserialized: None,
        };
        instance.serialize_dec_key(); // Automatically serialize on initialization
        instance
    }

    /// Serialize the `dec_key` into a hex-encoded string and store it internally
    pub fn serialize_dec_key(&mut self) {
        self.dec_key_serialized = hex::encode(self.dec_key.to_bytes());
    }

    /// Retrieve the serialized decryption key as a string
    pub fn get_serialized_key(&self) -> &String {
        &self.dec_key_serialized
    }

    pub fn get_deserialized_key(&self) -> Option<Arc<SecretKey>> {
        self.dec_key_deserialized.clone()
    }

    /// Deserialize a hex-encoded string back into a `DecryptKey` instance
    pub fn deserialize(&mut self, serialized_key: &str) -> Result<(), String> {
        let bytes = hex::decode(serialized_key)
            .map_err(|e| format!("Failed to decode hex string: {}", e))?;
        let secret_key = SecretKey::from_slice(&bytes)
            .map(Arc::new)
            .map_err(|e| format!("Failed to parse secret key: {:?}", e))?;

        self.dec_key_deserialized = Some(secret_key);
        Ok(())
    }

    /// Print the raw decryption key (before serialization)
    pub fn print_raw_key(&self) {
        println!("Raw Decryption Key: {:?}", self.dec_key.to_bytes());
    }

    /// Print the serialized decryption key in a readable format
    pub fn print_serialized_key(&self) {
        println!("Serialized Decryption Key (hex): {}", self.dec_key_serialized);
    }

    /// Print the deserialized decryption key to verify correctness
    pub fn print_deserialized_key(&self) {
        match &self.dec_key_deserialized {
            Some(key) => {
                println!(
                    "[print_deserialized_key] Deserialized Decryption Key (hex): {}, Original Key (hex): {}",
                    hex::encode(key.to_bytes()), self.dec_key_serialized
                );
                println!(
                    "[print_deserialized_key] Deserialized Decryption Key (Bin): {:?}, Original Key (Bin): {:?}",
                    key.to_bytes(), self.dec_key.to_bytes()
                );
            }
            None => println!("No deserialized key available."),
        }
    }
}

// * MY CODE: ADDED, CommitmentList
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentList {
    pub commitments: Vec<HashBytes>,
    pub commitments_serialized: String,
    #[serde(skip)]
    pub commitments_deserialized: Vec<HashBytes>,
}

impl CommitmentList {
    /// Create a new instance of CommitmentList and serialize immediately
    pub fn new(commitments: Vec<HashBytes>) -> Self {
        let mut instance = Self {
            commitments: commitments.clone(),
            commitments_serialized: String::new(),
            commitments_deserialized: Vec::new(),
        };
        instance.serialize_commitments();
        instance
    }

    /// Serialize the commitments into a hex-encoded string and store it
    pub fn serialize_commitments(&mut self) {
        let encoded: Vec<String> = self.commitments
            .iter()
            .map(|commitment| hex::encode(commitment))
            .collect();
        self.commitments_serialized = encoded.join(",");  // Store serialized format
    }

    /// Deserialize a hex-encoded string back into a Vec<HashBytes>
    pub fn deserialize(&mut self, serialized_data: &str) -> Result<(), String> {
        let mut parsed_commitments: Vec<HashBytes> = Vec::new();

        for hex_str in serialized_data.split(',') {
            if hex_str.is_empty() {
                return Err("Encountered an empty commitment string during deserialization.".to_string());
            }

            let bytes = hex::decode(hex_str)
                .map_err(|e| format!("Hex decode error: {}", e))?;

            if bytes.len() != 32 {
                return Err(format!(
                    "Invalid commitment length: expected 32 bytes, got {} bytes",
                    bytes.len()
                ));
            }

            let commitment: HashBytes = bytes
                .try_into()
                .map_err(|_| "Failed to convert commitment bytes to fixed-size array.".to_string())?;

            parsed_commitments.push(commitment);
        }

        if parsed_commitments.is_empty() {
            Err("No valid commitments found in the serialized string.".to_string())
        } else {
            self.commitments_deserialized = parsed_commitments;
            self.commitments_serialized = serialized_data.to_string();
            Ok(())
        }
    }


    /// Retrieve the serialized commitments
    pub fn get_serialized(&self) -> &String {
        &self.commitments_serialized
    }

    /// Retrieve deserialized commitments
    pub fn get_deserialized(&self) -> Option<Vec<HashBytes>> {
        if self.commitments_deserialized.is_empty() {
            None
        } else {
            Some(self.commitments_deserialized.clone())
        }
    }

    /// Print raw commitment values before serialization
    pub fn print_raw_commitments(&self) {
        println!("Raw Commitments:");
        for (index, commitment) in self.commitments.iter().enumerate() {
            println!("Commitment {}: {:?}", index, commitment);
        }
    }

    /// Print serialized commitment values in a readable format
    pub fn print_serialized_commitments(&self) {
        println!("Serialized Commitments (hex): {}", self.commitments_serialized);
    }

    /// Print deserialized commitment values
    pub fn print_deserialized_commitments(&self) {
        match self.get_deserialized() {
            Some(commitments) => {
                println!("Deserialized Commitments:");
                for (index, commitment) in commitments.iter().enumerate() {
                    println!("Commitment {}: {:?}", index, commitment);
                }
            }
            None => println!("No deserialized commitments available."),
        }
    }
}

// * MY CODE: ADDED, SidIList
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SidIList {
    pub sid_i_list: Vec<SessionId>,
    pub sid_i_list_serialized: String,
    #[serde(skip)]
    pub sid_i_list_deserialized: Vec<SessionId>,
}

impl SidIList {
    /// Create a new instance of SidIList and serialize immediately
    pub fn new(sid_list: Vec<SessionId>) -> Self {
        let mut instance = Self {
            sid_i_list: sid_list,
            sid_i_list_serialized: String::new(),
            sid_i_list_deserialized: Vec::new(),
        };
        instance.serialize_sids();
        instance
    }


    /// Serialize the session IDs into a hex-encoded string and store it
    pub fn serialize_sids(&mut self) {
        let encoded: Vec<String> = self.sid_i_list
            .iter()
            .map(|sid| hex::encode(sid))
            .collect();
        self.sid_i_list_serialized = encoded.join(","); // Store serialized format
    }

    /// Deserialize a hex-encoded string back into a Vec<SessionId>
    pub fn deserialize(&mut self, serialized_data: &str) -> Result<(), String> {
        let mut parsed_sids: Vec<SessionId> = Vec::new();

        for hex_str in serialized_data.split(',') {
            if hex_str.is_empty() {
                return Err("Encountered an empty session ID string during deserialization.".to_string());
            }

            let bytes = hex::decode(hex_str)
                .map_err(|e| format!("Hex decode error: {}", e))?;

            if bytes.len() != 32 {
                return Err(format!(
                    "Invalid session ID length in '{}': expected 32 bytes, got {} bytes",
                    hex_str, bytes.len()
                ));
            }

            let mut sid: SessionId = [0u8; 32];
            sid.copy_from_slice(&bytes);
            parsed_sids.push(sid);
        }

        if parsed_sids.is_empty() {
            Err("No valid session IDs found in the serialized string.".to_string())
        } else {
            self.sid_i_list_deserialized = parsed_sids;
            self.sid_i_list_serialized = serialized_data.to_string();
            Ok(())
        }
    }

    /// Retrieve the serialized session ID list
    pub fn get_serialized(&self) -> &String {
        &self.sid_i_list_serialized
    }

    /// Retrieve deserialized session ID list
    pub fn get_deserialized(&self) -> Option<&Vec<SessionId>> {
        if self.sid_i_list_deserialized.is_empty() {
            None
        } else {
            Some(&self.sid_i_list_deserialized)
        }
    }

    /// Print raw session IDs before serialization
    pub fn print_raw_sids(&self) {
        println!("Raw Session IDs:");
        for (index, sid) in self.sid_i_list.iter().enumerate() {
            println!("Session ID {}: {:?}", index, sid);
        }
    }

    /// Print serialized session IDs in a readable format
    pub fn print_serialized_sids(&self) {
        println!("Serialized Session IDs (hex): {}", self.sid_i_list_serialized);
    }

    /// Print deserialized session IDs
    pub fn print_deserialized_sids(&self) {
        match self.get_deserialized() {
            Some(sids) => {
                println!("Deserialized Session IDs:");
                for (index, sid) in sids.iter().enumerate() {
                    println!("Session ID {}: {:?}", index, sid);
                }
            }
            None => println!("No deserialized session IDs available."),
        }
    }
}

// * MY CODE: ADDED, FinalSessionId 
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalSessionId {
    pub session_id: SessionId,
    pub session_id_serialized: String,
    #[serde(skip)]
    pub session_id_deserialized: Option<SessionId>,
}

impl FinalSessionId {
    /// Create a new instance of FinalSessionId and serialize immediately
    pub fn new(session_id: SessionId) -> Self {
        let mut instance = Self {
            session_id,
            session_id_serialized: String::new(),
            session_id_deserialized: None,
        };
        instance.serialize_session();
        instance
    }

    /// Create an empty (default) FinalSessionId
    pub fn default() -> Self {
        Self::new([0u8; 32])
    }

    /// Serialize the final session ID into a hex-encoded string and store it
    pub fn serialize_session(&mut self) {
        self.session_id_serialized = hex::encode(self.session_id);
    }

    /// Deserialize a hex-encoded string back into a SessionId
    pub fn deserialize(&mut self, serialized_data: &str) -> Result<(), String> {
        if serialized_data.is_empty() {
            return Err("Final session ID string is empty.".to_string());
        }

        let bytes = hex::decode(serialized_data)
            .map_err(|e| format!("Hex decode error: {}", e))?;

        if bytes.len() != 32 {
            return Err(format!(
                "Invalid final session ID length: expected 32 bytes, got {} bytes",
                bytes.len()
            ));
        }

        let mut session_id: SessionId = [0u8; 32];
        session_id.copy_from_slice(&bytes);

        self.session_id_deserialized = Some(session_id);
        self.session_id_serialized = serialized_data.to_string();
        Ok(())
    }

    /// Retrieve the serialized session ID
    pub fn get_serialized(&self) -> &String {
        &self.session_id_serialized
    }

    /// Retrieve the deserialized session ID
    pub fn get_deserialized(&self) -> Option<SessionId> {
        if self.session_id_deserialized.is_none() {
            None
        } else {
            self.session_id_deserialized.clone()
        }
    }

    /// Print raw final session ID before serialization
    pub fn print_raw_session_id(&self) {
        println!("Raw Final Session ID: {:?}", self.session_id);
    }

    /// Print serialized final session ID in a readable format
    pub fn print_serialized_session_id(&self) {
        println!("Serialized Final Session ID (hex): {}", self.session_id_serialized);
    }

    /// Print deserialized final session ID
    pub fn print_deserialized_session_id(&self) {
        match self.get_deserialized() {
            Some(session_id) => println!("Deserialized Final Session ID: {:?}", session_id),
            None => println!("No deserialized session ID available."),
        }
    }
}

/// Define Seed as an alias for a fixed-size array of 32 bytes
pub type Seed = [u8; 32];

// * MY CODE: ADDED, SeedHandler
/// SeedHandler struct to manage serialization and deserialization of Seed
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeedHandler {
    pub seed: Seed,
    pub seed_serialized: String,
    #[serde(skip)]
    pub seed_deserialized: Option<Seed>,
}

impl SeedHandler {
    /// Create a new instance of SeedHandler and serialize immediately
    pub fn new(seed: Seed) -> Self {
        let mut instance = Self {
            seed,
            seed_serialized: String::new(),
            seed_deserialized: None,
        };
        instance.serialize_seed();
        instance
    }

    /// Create an empty (default) SeedHandler
    pub fn default() -> Self {
        Self::new([0u8; 32])
    }

    /// Serialize the seed into a hex-encoded string and store it
    pub fn serialize_seed(&mut self) {
        self.seed_serialized = hex::encode(self.seed);
    }

    /// Deserialize a hex-encoded string back into a Seed
    pub fn deserialize(&mut self, serialized_data: &str) -> Result<(), String> {
        if serialized_data.is_empty() {
            return Err("Seed string is empty.".to_string());
        }

        let bytes = hex::decode(serialized_data)
            .map_err(|e| format!("Hex decode error: {}", e))?;

        if bytes.len() != 32 {
            return Err(format!(
                "Invalid seed length: expected 32 bytes, got {} bytes",
                bytes.len()
            ));
        }

        let mut seed: Seed = [0u8; 32];
        seed.copy_from_slice(&bytes);

        self.seed_deserialized = Some(seed);
        self.seed_serialized = serialized_data.to_string();
        Ok(())
    }

    /// Retrieve the serialized seed
    pub fn get_serialized(&self) -> &String {
        &self.seed_serialized
    }

    /// Retrieve the deserialized seed
    pub fn get_deserialized(&self) -> Option<Seed> {
        if self.seed_deserialized.is_none() {
            None
        } else {
            self.seed_deserialized.clone()
        }
    }

    /// Print raw seed before serialization
    pub fn print_raw_seed(&self) {
        println!("Raw Seed: {:?}", self.seed);
    }

    /// Print serialized seed in a readable format
    pub fn print_serialized_seed(&self) {
        println!("Serialized Seed (hex): {}", self.seed_serialized);
    }

    /// Print deserialized seed
    pub fn print_deserialized_seed(&self) {
        match self.get_deserialized() {
            Some(seed) => println!("Deserialized Seed: {:?}", seed),
            None => println!("No deserialized seed available."),
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
pub struct EncryptedScalar {
    /// Participant ID of the sender
    pub sender_pid: u8,
    /// Participant ID of the receiver
    pub receiver_pid: u8,
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
    /// Encrypted ciphertext
    pub ciphertext: [u8; SCALAR_CIPHERTEXT_SIZE],
    /// Nonce value used in encryption
    /// // Size of the nonce is 24
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

    /// Serialize `EncryptedScalar` into a `Vec<u8>`.
    // Removing due to: the trait `serde::ser::Serialize` is not implemented for `EncryptedScalar`
    pub fn to_vec(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Failed to serialize EncryptedScalar")

    }
    // * MY CODE: ADDED
    /// Serialize EncryptedScalar manually
    pub fn to_bytes(&self) -> Vec<u8> {
        println!("sender_pid: {}", self.sender_pid);
        println!("receiver_pid: {}", self.receiver_pid);
        println!("ciphertext: {:?}", self.ciphertext);
        println!("nonce: {:?}", self.nonce);

        let mut bytes = Vec::new();
        bytes.push(self.sender_pid);
        bytes.push(self.receiver_pid);
        bytes.extend_from_slice(&self.ciphertext);
        bytes.extend_from_slice(&self.nonce);
        bytes
    }

    // * MY CODE: ADDED, deserialize_basic (renamed from_bytes)
    /// Deserialize EncryptedScalar manually
    /// Suitable when the caller ensures data integrity beforehand.
    pub fn deserialize_basic(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 74 {
            return Err(format!("Serialized EncryptedScalar has invalid size: expected 74, got {}", bytes.len()));
        }

        let sender_pid = bytes[0];
        let receiver_pid = bytes[1];
        let ciphertext = {
            let mut array = [0u8; SCALAR_CIPHERTEXT_SIZE];
            array.copy_from_slice(&bytes[2..50]); // Adjusted to match SCALAR_CIPHERTEXT_SIZE (48 bytes)
            array
        };
        let nonce = {
            let mut array = [0u8; <SalsaBox as AeadCore>::NonceSize::USIZE];
            array.copy_from_slice(&bytes[50..74]); // Adjusted to start after ciphertext and span 24 bytes
            array
        };

        Ok(Self {
            sender_pid,
            receiver_pid,
            ciphertext,
            nonce,
        })
    }
    // * MY CODE: ADDED, deserialize_safe

    /// Deserialize EncryptedScalar manually with detailed error handling
    /// Safe deserialization with detailed error handling
    /// Suitable for handling potential data inconsistencies with more granularity.
    pub fn deserialize_safe(bytes: &[u8]) -> Result<Self, String> {
        // Handle prefixed data (assume extra 8 bytes at the beginning)
        let expected_size = 82;
        let scalar_size = 74;

        if bytes.len() == expected_size {
            println!(
                "Detected prefixed EncryptedScalar data, stripping prefix. Raw data: {:?}",
                bytes
            );
            let trimmed_bytes = &bytes[8..]; // Remove the first 8 bytes (prefix)
            return Self::deserialize_safe(trimmed_bytes);
        }

        if bytes.len() != scalar_size {
            let error_message = format!(
                "Serialized EncryptedScalar has an invalid size: expected {}, got {}. Raw data: {:?}",
                scalar_size,
                bytes.len(),
                bytes
            );
            eprintln!("{}", error_message);
            return Err(error_message);
        }

        let sender_pid = bytes[0];
        let receiver_pid = bytes[1];

        let ciphertext = bytes
            .get(2..50)
            .ok_or_else(|| format!("Failed to extract ciphertext bytes. Raw data: {:?}", bytes))
            .and_then(|slice| {
                let mut array = [0u8; SCALAR_CIPHERTEXT_SIZE];
                if slice.len() != SCALAR_CIPHERTEXT_SIZE {
                    return Err(format!(
                        "Invalid ciphertext size: expected {}, got {}. Raw data: {:?}",
                        SCALAR_CIPHERTEXT_SIZE,
                        slice.len(),
                        bytes
                    ));
                }
                array.copy_from_slice(slice);
                Ok(array)
            })?;

        let nonce = bytes
            .get(50..74)
            .ok_or_else(|| format!("Failed to extract nonce bytes. Raw data: {:?}", bytes))
            .and_then(|slice| {
                let mut array = [0u8; <SalsaBox as AeadCore>::NonceSize::USIZE];
                if slice.len() != <SalsaBox as AeadCore>::NonceSize::USIZE {
                    return Err(format!(
                        "Invalid nonce size: expected {}, got {}. Raw data: {:?}",
                        <SalsaBox as AeadCore>::NonceSize::USIZE,
                        slice.len(),
                        bytes
                    ));
                }
                array.copy_from_slice(slice);
                Ok(array)
            })?;

        Ok(Self {
            sender_pid,
            receiver_pid,
            ciphertext,
            nonce,
        })
    }



    // * MY CODE: ADDED, deserialize_try_into
    /// Deserialization using `.try_into()` for direct conversions
    /// Suitable when exact matching of byte slices is guaranteed.
    pub fn deserialize_try_into(bytes: &[u8]) -> Result<Self, String> {
        let expected_len = 74;
        let prefix_len = 8;

        let adjusted_bytes = if bytes.len() == expected_len + prefix_len {
            // Detect and strip 8-byte prefix
            &bytes[prefix_len..]
        } else if bytes.len() == expected_len {
            bytes
        } else {
            return Err(format!(
                "Serialized EncryptedScalar has an invalid size: expected {} or {}, got {}",
                expected_len, expected_len + prefix_len, bytes.len()
            ));
        };

        let sender_pid = adjusted_bytes[0];
        let receiver_pid = adjusted_bytes[1];

        let ciphertext = adjusted_bytes[2..50]
            .try_into()
            .map_err(|_| "Failed to parse ciphertext".to_string())?;

        let nonce = adjusted_bytes[50..74]
            .try_into()
            .map_err(|_| "Failed to parse nonce".to_string())?;

        Ok(Self {
            sender_pid,
            receiver_pid,
            ciphertext,
            nonce,
        })
    }


    // * MY CODE: ADDED, deserialize_fallback
    /// Deserialize a single instance from bytes
    /// Fallback deserialization with default error handling
    /// Useful for last-resort deserialization when leniency is required.
    pub fn deserialize_fallback(bytes: &[u8]) -> Option<Self> {
        let expected_len = 74;
        if bytes.len() == expected_len {
            // No prefix, normal processing
            Some(Self {
                sender_pid: bytes[0],
                receiver_pid: bytes[1],
                ciphertext: bytes[2..66].try_into().ok()?,
                nonce: bytes[66..].try_into().ok()?,
            })
        } else if bytes.len() == expected_len + 8 {
            // Handle prefixed data by skipping first 8 bytes
            Some(Self {
                sender_pid: bytes[8],
                receiver_pid: bytes[9],
                ciphertext: bytes[10..74].try_into().ok()?,
                nonce: bytes[74..].try_into().ok()?,
            })
        } else {
            None
        }
    }

    // * MY CODE: ADDED, from_nested_vec
    /// Deserialize from a nested Vec<Vec<u8>> representation
    pub fn from_nested_vec(vecs: &[Vec<u8>]) -> Result<Vec<Self>, String> {
        vecs.iter()
            .map(|chunk| Self::deserialize_basic(chunk))
            .collect()
    }

    // * MY CODE: ADDED, from_hex
    /// Deserialize from a hex string representation
    pub fn from_hex(hex_str: &str) -> Result<Vec<Self>, String> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| format!("Hex decoding failed: {}", e))?;
        Self::from_flattened_bytes(&bytes)
    }

    // * MY CODE: ADDED, from_flattened_bytes
    /// Deserialize from a flattened byte array
    pub fn from_flattened_bytes(bytes: &[u8]) -> Result<Vec<Self>, String> {
        bytes.chunks_exact(74)
            .map(|chunk| Self::deserialize_basic(chunk)) // No need to convert Result
            .collect() // Collect into Result<Vec<Self>, String>
    }

    // * MY CODE: ADDED, from_bincode
    pub fn from_bincode(vecs: &[Vec<u8>]) -> Result<Vec<Self>, String> {
        vecs.iter()
            .map(|bytes| bincode::deserialize(bytes)
                .map_err(|e| format!("Bincode deserialization failed: {}", e)))
            .collect()
    }

    // * MY CODE: ADDED, from_bincode_flattened
    /// Deserialize EncryptedScalar from a flattened byte array stored using Bincode
    /// - Ensures correct chunking by fixed size.
    /// - Useful for efficient storage and fast retrieval.
    pub fn from_bincode_flattened(bytes: &[u8]) -> Result<Vec<Self>, String> {
        // to be removed:
        const SCALAR_SERIALIZED_SIZE: usize = std::mem::size_of::<EncryptedScalar>();
        println!("Expected Serialized Size: {}", SCALAR_SERIALIZED_SIZE);

        let sample_scalar = EncryptedScalar {
            sender_pid: 0,
            receiver_pid: 0,
            ciphertext: [0u8; SCALAR_CIPHERTEXT_SIZE],
            nonce: [0u8; <SalsaBox as AeadCore>::NonceSize::USIZE],
        };

        let serialized_size = bincode::serialize(&sample_scalar)
            .expect("Failed to serialize EncryptedScalar")
            .len();

        println!("Serialized EncryptedScalar size using Bincode: {}", serialized_size);


        bytes.chunks_exact(SCALAR_SERIALIZED_SIZE)
            .map(|chunk| bincode::deserialize(chunk).map_err(|e| format!("Deserialization failed: {}", e)))
            .collect()
    }

    // * MY CODE: ADDED, serialize_scalars_hex
    // Function to serialize scalar coefficients using Hex encoding
    // Serialize scalar coefficients to hex encoding
    pub fn serialize_scalars_hex(scalars: &Vec<Scalar>) -> Result<String, Box<dyn Error>> {
        let serialized_bytes: Vec<u8> = scalars
            .iter()
            .flat_map(|scalar| scalar.to_bytes().to_vec())  // Convert each scalar to bytes
            .collect();

        Ok(hex_encode(&serialized_bytes))
    }

    // * MY CODE: ADDED, deserialize_scalars_hex
    // Function to deserialize scalar coefficients from Hex encoding
    pub fn deserialize_scalars_hex(encoded: &str) -> Result<Vec<Scalar>, Box<dyn Error>> {
        let decoded_bytes = hex_decode(encoded)?;

        // Scalar size for Curve25519 is 32 bytes
        let scalar_size = 32;

        if decoded_bytes.len() % scalar_size != 0 {
            return Err(Box::<dyn Error>::from("Invalid scalar encoding length"));
        }

        let scalars = decoded_bytes.chunks(scalar_size)
            .map(|chunk| {
                let bytes_array: [u8; 32] = chunk.try_into()
                    .map_err(|_| Box::<dyn Error>::from("Invalid scalar byte length"))?;

                let scalar_ct_option = Scalar::from_canonical_bytes(bytes_array);

                if scalar_ct_option.is_some().unwrap_u8() == 1 {
                    Ok::<Scalar, Box<dyn Error>>(scalar_ct_option.unwrap())
                } else {
                    Err(Box::<dyn Error>::from("Invalid scalar bytes"))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(scalars)
    }

    // * MY CODE: ADDED, serialize_scalars_binary
    // Function to serialize scalar coefficients into binary format
    pub fn serialize_scalars_binary(scalars: &Vec<Scalar>) -> Vec<Vec<u8>> {
        scalars.iter().map(|scalar| scalar.to_bytes().to_vec()).collect()
    }

    // * MY CODE: ADDED, deserialize_scalars_binary
    // Function to deserialize scalar coefficients from binary format
    pub fn deserialize_scalars_binary(serialized_scalars: &Vec<Vec<u8>>) -> Result<Vec<Scalar>, Box<dyn Error>> {
        let scalars = serialized_scalars
            .iter()
            .map(|bytes| {
                let bytes_array: [u8; 32] = bytes.as_slice().try_into()
                    .map_err(|_| Box::<dyn Error>::from("Invalid scalar byte length"))?;

                let scalar_ct_option = Scalar::from_canonical_bytes(bytes_array);

                if scalar_ct_option.is_some().unwrap_u8() == 1 {
                    Ok::<Scalar, Box<dyn Error>>(scalar_ct_option.unwrap())
                } else {
                    Err(Box::<dyn Error>::from("Invalid scalar bytes"))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(scalars)
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

// * MY CODE: ADDED, encrypt_message custom implementation
pub fn encrypt_message<R: CryptoRngCore, G: GroupElem>(
    sender_secret_info: (&SecretKey, u8),
    receiver_public_info: (&PublicKey, u8),
    message: G::Scalar,
    rng: &mut R,
    t: u8,
    n: u8,
    party_enc_keys: &[(u8, PublicKey)],
) -> Option<EncryptedScalar> {


    println!("[encrypt_message] Starting encryption process...");
    println!(
        "[Debug][dec_key] Party {} Key Before Encryption (Hex): {:?}",
        sender_secret_info.1,
        hex::encode(sender_secret_info.0.to_bytes())
    );


    // FIXME: Handle this better
    if std::mem::size_of::<<G::Scalar as PrimeField>::Repr>() != 32 {
        panic!("We don't support scalars of size other than 32 bytes!");
    }

    println!("[encrypt_message] Starting encryption process...");
    println!(
        "[encrypt_message] Using sender key [dec_key - secret]: {:?}, receiver key [enc_key - public]: {:?}",
        hex::encode(sender_secret_info.0.to_bytes()),
        hex::encode(receiver_public_info.0.as_bytes())
    );

    // Logging sender and receiver information
    println!(
        "[encrypt_message][dec_key] Sender private key (first 16 bytes): {:?}, sender ID: {}",
        &sender_secret_info.0.to_bytes()[..16], sender_secret_info.1
    );
    println!(
        "[encrypt_message][enc_key] Receiver public key (first 16 bytes): {:?}, receiver ID: {}",
        &receiver_public_info.0.as_bytes()[..16], receiver_public_info.1
    );

    let sender_box = SalsaBox::new(receiver_public_info.0, sender_secret_info.0);

    // Generate nonce and log it
    let nonce = SalsaBox::generate_nonce(rng);
    println!("[encrypt_message] Generated nonce: {:?}", nonce);

    // Convert the scalar to bytes and log
    let message_bytes = message.to_repr();
    println!(
        "[encrypt_message] Message being encrypted (first 16 bytes): {:?}, length: {}",
        &message_bytes.as_ref()[..16],
        message_bytes.as_ref().len()
    );

    match sender_box.encrypt(&nonce, message_bytes.as_ref()) {
        Ok(data) => {
            println!(
                "[encrypt_message] Encryption successful. Ciphertext (first 16 bytes): {:?}, length: {}",
                &data[..16],
                data.len()
            );

            Some(EncryptedScalar::new(
                data.try_into().ok()?,
                nonce.into(),
                sender_secret_info.1,
                receiver_public_info.1,
            ))
        }
        Err(e) => {
            println!("[encrypt_message] Encryption failed: {:?}", e);
            None
        }
    }
}


// * MY CODE: COMMENTED OUT, encrypt_message previous implementation
// pub fn encrypt_message<R: CryptoRngCore, G: GroupElem>(
//     sender_secret_info: (&SecretKey, u8),
//     receiver_public_info: (&PublicKey, u8),
//     message: G::Scalar,
//     rng: &mut R,
// ) -> Option<EncryptedScalar> {
//     // FIXME: Handle this better
//     if std::mem::size_of::<<G::Scalar as PrimeField>::Repr>() != 32 {
//         panic!("We don't support scalars of size other than 32 bytes!");
//     }
//     let sender_box = SalsaBox::new(receiver_public_info.0, sender_secret_info.0);
//     let nonce = SalsaBox::generate_nonce(rng);
//     sender_box
//         .encrypt(&nonce, message.to_repr().as_ref())
//         .ok()
//         .and_then(|data| {
//             Some(EncryptedScalar::new(
//                 data.try_into().ok()?,
//                 nonce.into(),
//                 sender_secret_info.1,
//                 receiver_public_info.1,
//             ))
//         })
// }

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
    G::Scalar: ScalarReduce<[u8; 32]>, // * MY CODE: ADDED and COMMENTED OUT, + From<curve25519_dalek::Scalar>, // Add the missing constraint
{
    let actors = setup_keygen(T as u8, N as u8).unwrap();
    let (actors, msgs): (Vec<_>, Vec<_>) = run_round(actors, ()).into_iter().unzip();
    let (actors, msgs): (Vec<_>, Vec<_>) = run_round(actors, msgs).into_iter().unzip();
    run_round(actors, msgs)
        .try_into()
        .map_err(|_| panic!("Failed to convert keyshares"))
        .unwrap()
}
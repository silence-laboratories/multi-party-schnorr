use std::collections::HashMap;
// * MY CODE: ADDED
use serde::{Serialize, Deserialize};
use crypto_bigint::subtle::ConstantTimeEq;
// * MY CODE: ADDED, key_size is 32
use crypto_box::{KEY_SIZE, PublicKey, SecretKey};
use elliptic_curve::{group::GroupEncoding, Group};

use std::sync::Arc;
// * MY CODE: ADDED
use curve25519_dalek::EdwardsPoint;
// * MY CODE: ADDED and COMMENTED OUT
// use std::fmt;
// * MY CODE: ADDED and COMMENTED OUT
// use curve25519_dalek::{EdwardsPoint, Scalar};

use ff::{Field, PrimeField};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
// * MY CODE: ADDED
use serde::de::DeserializeOwned;
use sha2::{digest::Update, Digest, Sha256};
use sl_mpc_mate::math::GroupPolynomial;

// MY CUSTOM ADD - TO REMOVE
use sl_mpc_mate::math::Polynomial;
// * MY CODE: COMMENTED OUT
// use serde::Serialize;
// * MY CODE: ADDED, Seed and Value
use serde_json::Value;
// * MY CODE: ADDED, imports
use crate::common::utils::{Seed, SerializableEdwardsPoint};
// * MY CODE: ADDED, imports
use bytemuck;
use std::fmt::Write;
// * MY CODE: ADDED, imports
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::traits::Identity;

// * MY CODE: ADDED
pub trait GroupPolynomialExtension<G>
where
    G: Group + GroupEncoding,
{
    /// Commit to this polynomial by multiplying each coefficient by the generator.
    // NOT IN USE< HAVE G * G issue
    // fn commit(&self) -> GroupPolynomial<G>;
    fn set_constant(&mut self, constant: G);
}


impl<G> GroupPolynomialExtension<G> for GroupPolynomial<G>
where
    G: Group + GroupEncoding,
{
    /// Set the constant term of the polynomial.
    fn set_constant(&mut self, constant: G) {
        if let Some(first_coeff) = self.coeffs.get_mut(0) {
            *first_coeff = constant;
        }
    }
}

use crate::common::{
    traits::{GroupElem, Round, ScalarReduce},
    utils::{
        calculate_final_session_id, decrypt_message, encrypt_message,  // * MY CODE: ADDED
        BaseMessage, EncryptedScalar,
        HashBytes, SessionId,
    },
    DLogProof,
};

// * MY CODE: ADDED, IMPORTS
use super::{types::{KeyEntropy, KeygenError, KeygenParams}, KeyRefreshData, KeygenMsg1, KeygenMsg2, Keyshare, serialize_scalar_to_base58, serialize_public_key_to_base58};

/// LABEL for the keygen protocol
pub const DKG_LABEL: &[u8] = b"SilenceLaboratories-Schnorr-DKG";
// * MY CODE: ADDED, WRAPPER FOR KeygenMsg1, KeygenMsg2<G>, KeygenParty<R1<G>, G> and KeygenParty<R2, G>
pub struct ClientKeygenPartyR1<G: GroupElem>(pub KeygenParty<R1<G>, G>); // For R1 state
pub struct ClientKeygenPartyR2<G: GroupElem>(pub KeygenParty<R2, G>); // For R2 state
// * MY CODE: ADDED, WRAPPER FOR Keyshare<G>, G>
// pub struct ClientKeyShare<G: GroupElem>(Keyshare<G>); // Private Share for the client
pub struct ClientKeyShare<G>
where
    G: Group + GroupEncoding,
{
    pub private_scalar: G::Scalar,      // Corresponds to `d_i`
    pub public_key_point: G,            // Corresponds to `public_key`
    pub threshold: u8,                   // Added threshold field
    pub total_parties: u8,                // Added total_parties field
    pub party_id: u8,                      // Added party_id field
    pub key_id: [u8; 32],                   // Added key_id field
    pub extra_data: Option<Vec<u8>>,        // Added extra_data field
}


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientKeygenMsg1(pub KeygenMsg1);

// * MY CODE: ADDED, WRAPPER FOR KeygenMsg2<G>, KeygenParty<R1<G>, G> and KeygenParty<R2, G>
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientKeygenMsg2<G: GroupElem>(pub KeygenMsg2<G>) // Wrap KeygenMsg2<G>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]> + DeserializeOwned + Serialize; // * MY CODE: ADDED, DeserializeOwned + Serialize

impl<G> ClientKeygenPartyR1<G>
where
    G: GroupElem + GroupEncoding + ConstantTimeEq,
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    pub fn process_second_round(
        self,
        messages: Vec<KeygenMsg1>,
    ) -> Result<(ClientKeygenPartyR2<G>, KeygenMsg2<G>), KeygenError> {
        let (next_state, msg) = self.0.process(messages)?;
        // Wrap the resulting KeygenParty<R1<G>, G> into ClientKeygenPartyR1
        Ok((ClientKeygenPartyR2(next_state), msg))
    }

    pub fn get_state(&self) -> &KeygenParty<R1<G>, G> {
        &self.0
    }
}


impl<G> ClientKeygenPartyR2<G>
where
    G: GroupElem + GroupEncoding + ConstantTimeEq,
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    pub fn process_third_round(
        self,
        messages: Vec<KeygenMsg2<G>>,
    ) -> Result<ClientKeyShare<G>, KeygenError> {
        let key_share = self.0.process(messages)?;
        // * MY CODE: ADDED, Wrap the resulting Keyshare<G> into ClientKeyShare<G>
        Ok(ClientKeyShare {
            private_scalar: key_share.d_i,        
            public_key_point: key_share.public_key,
            threshold: key_share.threshold,
            total_parties: key_share.total_parties,
            party_id: key_share.party_id,
            key_id: key_share.key_id,
            extra_data: key_share.extra_data,
        })
    }

    pub fn get_state(&self) -> &KeygenParty<R2, G> {
        &self.0
    }

    pub fn get_rand_params(&self) -> &KeyEntropy<G> {
        self.0.get_rand_params()
    }

    pub fn get_params(&self) -> &KeygenParams {
        self.0.get_params()
    }
}

// * MY CODE: ADDED, SERIALIZATION
impl ClientKeyShare<EdwardsPoint> {
    pub fn serialize(&self) -> (String, String) {
        let d_i_serialized = serialize_scalar_to_base58::<EdwardsPoint>(&self.private_scalar);
        let public_key_serialized = serialize_public_key_to_base58(&self.public_key_point);

        (d_i_serialized, public_key_serialized)
    }
}



pub struct ServerKeygenPartyR1<G: GroupElem>(KeygenParty<R1<G>, G>); // For R1 state
pub struct ServerKeygenPartyR2<G: GroupElem>(KeygenParty<R2, G>); // For R2 state

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerKeygenMsg1(pub KeygenMsg1);// Wrap KeygenMsg1

// * MY CODE: ADDED, WRAPPER FOR KeygenMsg2<G>
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerKeygenMsg2<G>(pub KeygenMsg2<G>)  // Wrap KeygenMsg2<G>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]> + DeserializeOwned + Serialize; // * MY CODE: ADDED, DeserializeOwned + Serialize


pub struct ServerKeyShare<G: GroupElem>(Keyshare<G>); // Private Share for the server

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct ServerKeygenMsg2Wrapper {
    pub from_party: u8,
    pub session_id: SessionId,
    pub r_i: [u8; 32],
    pub c_i_list: Vec<EncryptedScalar>,
}

impl<G> ServerKeygenPartyR1<G>
where
    G: GroupElem + GroupEncoding + ConstantTimeEq,
    G::Scalar: ScalarReduce<[u8; 32]>,
{

    pub fn process_second_round(
        self,
        messages: (ClientKeygenMsg1, ServerKeygenMsg1),
    // ) -> Result<(ServerKeygenPartyR2<G>, ServerKeygenMsg2<G>), KeygenError> {
    ) -> Result<(ServerKeygenPartyR2<G>, ServerKeygenMsg2Wrapper), KeygenError> {
        // Decompose the tuple into client and server messages
        let client_msg = &messages.0 .0; // Extract the inner KeygenMsg1 from ClientKeygenMsg1
        let server_msg = &messages.1 .0; // Extract the inner KeygenMsg1 from ServerKeygenMsg1

        // Collect the messages into a vector for processing
        let mut message_vec = vec![client_msg, server_msg];

        // Validate party IDs
        let expected_party_ids = [self.0.params.party_id, client_msg.from_party];
        for (msg, expected_party_id) in message_vec.iter().zip(expected_party_ids.iter()) {
            if msg.from_party != *expected_party_id {
                return Err(KeygenError::InvalidPartyId(format!(
                    "Expected partyId {}, got {}",
                    expected_party_id, msg.from_party
                )));
            }
        }

        // Sort messages by party ID
        message_vec.sort_by_key(|msg| msg.from_party);

        // Validate session IDs
        let expected_session_id = message_vec[0].session_id;
        if message_vec.iter().any(|msg| msg.session_id != expected_session_id) {
            return Err(KeygenError::InvalidSessionId(
                "Mismatched session IDs in second round".to_string(),
            ));
        }

        // Check for duplicates
        let mut seen_party_ids = std::collections::HashSet::new();
        for msg in &message_vec {
            if !seen_party_ids.insert(msg.from_party) {
                return Err(KeygenError::DuplicateMessage(format!(
                    "Duplicate message from partyId {}",
                    msg.from_party
                )));
            }
        }

        // Check message count
        if message_vec.len() != self.0.params.n as usize {
            return Err(KeygenError::InvalidMsgCountMismatch(format!(
                "Expected {} messages, got {}",
                self.0.params.n, message_vec.len()
            )));
        }

        let owned_message_vec: Vec<KeygenMsg1> = message_vec.into_iter().cloned().collect();
        // Pass the validated and sorted messages to the process function
        let (next_state, msg) = self.0.process(owned_message_vec)?;

        let response_msg = ServerKeygenMsg2Wrapper {
            from_party: msg.from_party,
            session_id: msg.session_id,
            r_i: msg.r_i,
            c_i_list: msg.c_i_list.clone(), // Keep only necessary parts
        };

        Ok((ServerKeygenPartyR2(next_state), response_msg))


    }


    pub fn get_state(&self) -> &KeygenParty<R1<G>, G> {
        &self.0
    }
}


impl<G> ServerKeygenPartyR2<G>
where
    G: GroupElem + GroupEncoding + ConstantTimeEq,
    G::Scalar: ScalarReduce<[u8; 32]> + for<'de> Deserialize<'de> + Serialize, // * MY CODE: ADDED, Deserialize + Serialize
{
    pub fn process_third_round(
        self,
        messages: (ClientKeygenMsg2<G>, ServerKeygenMsg2<G>),
    ) -> Result<ServerKeyShare<G>, KeygenError> {
        // Decompose the tuple into client and server messages
        let client_msg = &messages.0 .0; // Extract a reference to the inner KeygenMsg2
        let server_msg = &messages.1 .0; // Extract a reference to the inner KeygenMsg2
        // Collect the messages into a vector for processing
        let mut message_vec = vec![client_msg, server_msg];

        // Check for duplicates
        let mut seen_party_ids = std::collections::HashSet::new();
        for msg in &message_vec {
            if !seen_party_ids.insert(msg.from_party) {
                return Err(KeygenError::DuplicateMessage(format!(
                    "Duplicate message from partyId {}",
                    msg.from_party
                )));
            }
        }

        // Validate the number of messages
        if message_vec.len() != self.0.params.n as usize {
            return Err(KeygenError::InvalidMsgCountMismatch(format!(
                "Expected {} messages, got {}",
                self.0.params.n, message_vec.len()
            )));
        }

        // Validate party IDs
        let expected_party_ids = [self.0.params.party_id, client_msg.from_party];
        for (msg, expected_party_id) in message_vec.iter().zip(expected_party_ids.iter()) {
            if msg.from_party != *expected_party_id {
                return Err(KeygenError::InvalidPartyId(format!(
                    "Expected partyId {}, got {}",
                    expected_party_id, msg.from_party
                )));
            }
        }

        // Sort messages by party ID
        message_vec.sort_by_key(|msg| msg.from_party);

        // Validate session IDs
        let expected_session_id = message_vec[0].session_id;
        if message_vec.iter().any(|msg| msg.session_id != expected_session_id) {
            return Err(KeygenError::InvalidSessionId(
                "Mismatched session IDs in third round".to_string(),
            ));
        }

        // **Validate the final session ID:**
        if expected_session_id != self.0.state.final_session_id {
            return Err(KeygenError::InvalidSessionId(format!(
                "Final session ID mismatch: expected {:?}, got {:?}",
                self.0.state.final_session_id, expected_session_id
            )));
        }

        let owned_message_vec: Vec<KeygenMsg2<G>> = message_vec.into_iter().cloned().collect();

        // Pass the validated and sorted messages to the process function
        let key_share = self.0.process(owned_message_vec)?;

        // Wrap and return the resulting key share
        Ok(ServerKeyShare(key_share))
    }

    pub fn get_state(&self) -> &KeygenParty<R2, G> {
        &self.0
    }
}

// * MY CODE: ADDED
pub fn hash_session_id(session_id: &SessionId, party_id: u8) -> SessionId {
    use digest::Digest;

    let mut hasher = Sha256::new();
    digest::Digest::update(&mut hasher, session_id.as_ref()); // Hash the session ID
    digest::Digest::update(&mut hasher, &party_id.to_be_bytes()); // Hash the party ID
    hasher.finalize().into()
}

/// Keygen party
/// The keygen party is a state machine that implements the keygen protocol.
// #[derive(Debug)]   // TODO: by opening this engine can access all PRIVATE fields like state, rand_params, params to be stored to DB
// * MY CODE: ADDED
#[derive(Debug)]
pub struct KeygenParty<T, G>
where
    G: Group + GroupEncoding, // * MY CODE: ADDED
{
    params: KeygenParams,
    rand_params: KeyEntropy<G>,
    seed: Seed, // * MY CODE: ADDED, Add Seed type 
    state: T,
    key_refresh_data: Option<KeyRefreshData<G>>,
}

impl<T, G> KeygenParty<T, G>
where
    G: Group + GroupEncoding, // * MY CODE: ADDED
{
    // * MY CODE: ADDED constructor
    // NOT USED AND NEED TO DELETE:
    // pub fn new_r2(
    //     params: KeygenParams,
    //     rand_params: KeyEntropy<G>,
    //     key_refresh_data: Option<KeyRefreshData<G>>,
    //     state: T,
    //     seed: [u8; 32],
    // ) -> Self {
    //     Self {
    //         params,
    //         rand_params,
    //         key_refresh_data,
    //         state,
    //         seed,
    //     }
    // }

    /// Getter for `rand_params`.
    pub fn get_rand_params(&self) -> &KeyEntropy<G> {
        &self.rand_params
    }

    /// Getter for `state`.
    pub fn get_state(&self) -> &T {
        &self.state
    }

    /// Getter for `session_id` from `rand_params`.
    pub fn get_session_id(&self) -> &[u8; 32] {
        self.rand_params.get_session_id()
    }

    /// Getter for `r_i` from `rand_params`.
    pub fn get_r_i(&self) -> &[u8; 32] {
        self.rand_params.get_r_i()
    }

    /// Getter for `point-based polynomial` from `rand_params`.
    // * MY CODE: ADDED, GETTER FOR POINT-BASED POLYNOMIAL
    pub fn get_point_based_polynomial(&self) -> &GroupPolynomial<G> {
        self.rand_params.get_point_based_polynomial()
    }

    /// Getter for `scalar-based polynomial` from `rand_params`.
    // * MY CODE: ADDED, GETTER FOR SCALAR-BASED POLYNOMIAL
    pub fn get_scalar_based_polynomial(&self) -> &Polynomial<G> {
        self.rand_params.get_scalar_based_polynomial()
    }

    /// Getter for `scalar coeffs of polynomial` from `rand_params`.
    // * MY CODE: ADDED, GETTER FOR SCALAR COEFFICIENTS
    pub fn get_scalars(&self) -> &Vec<G::Scalar> {
        self.rand_params.get_scalar_coeffs()
    }

    pub fn get_params(&self) -> &KeygenParams {
        &self.params
    }

    pub fn get_key_refresh_data(&self) -> Option<&KeyRefreshData<G>> {
        self.key_refresh_data.as_ref()
    }

    // * MY CODE: ADDED, GETTER FOR SEED
    pub fn get_seed(&self) -> &Seed {
        &self.seed
    }
}


pub struct R0;

/// State of a keygen party after receiving public keys of all parties and generating the first message.
#[derive(Debug)]
pub struct R1<G>
where
    G: Group + GroupEncoding,
{
    big_a_i: GroupPolynomial<G>,
    c_i_j: Vec<EncryptedScalar>,
    commitment: HashBytes,
}

// * MY CODE: ADDED
impl<G> R1<G>
where
    G: Group + GroupEncoding,
{
    /// Constructor for R1
    // * MY CODE: ADDED, PUBLIC CONSTRUCTOR TO R1
    pub fn new(
        big_a_i: GroupPolynomial<G>,
        c_i_j: Vec<EncryptedScalar>,
        commitment: HashBytes,
    ) -> Self {
        Self {
            big_a_i,
            c_i_j,
            commitment,
        }
    }

    /// Getter for `commitment`.
    pub fn get_commitment(&self) -> &HashBytes {
        &self.commitment
    }

    /// Getter for `big_a_i`.
    pub fn get_big_a_i(&self) -> &GroupPolynomial<G> {
        &self.big_a_i
    }

    /// Getter for `c_i_j`.
    pub fn get_c_i_j(&self) -> &Vec<EncryptedScalar> {
        &self.c_i_j
    }
}

/// State of a keygen party after processing the first message.
// * MY CODE: ADDED
#[derive(Debug)]
pub struct R2 {
    pub final_session_id: SessionId,      // * MY CODE: ADDED, Round-specific session ID
    pub shared_session_id: SessionId,     // * MY CODE: ADDED, Protocol-wide shared session ID
    commitment_list: Vec<HashBytes>,
    sid_i_list: Vec<SessionId>,           // * MY CODE: ADDED, contains hashed session IDs
}

// * MY CODE: ADDED PUBLIC CONSTRUCTOR TO R2
/// State of a keygen party after processing the first message.
impl R2 {
    /// Constructor for R2
    pub fn new(
        final_session_id: SessionId,
        shared_session_id: SessionId, // * MY CODE: ADDED, Protocol-wide shared session ID
        commitment_list: Vec<HashBytes>,
        sid_i_list: Vec<SessionId>,
    ) -> Self {
        Self {
            final_session_id,
            shared_session_id, // * MY CODE: ADDED, Protocol-wide shared session ID
            commitment_list,
            sid_i_list,
        }
    }

    pub fn get_final_session_id(&self) -> &SessionId {
        &self.final_session_id
    }

    pub fn get_commitment_list(&self) -> &Vec<HashBytes> {
        &self.commitment_list
    }

    pub fn get_sid_i_list(&self) -> &Vec<SessionId> {
        &self.sid_i_list
    }

    // * MY CODE: ADDED, GETTER FOR SHARED SESSION ID
    pub fn get_shared_session_id(&self) -> &SessionId {
        &self.shared_session_id
    }
}

// * MY CODE: ADDED, added validate_input_basic for R2
pub fn validate_input_basic(
    t: u8,
    n: u8,
    party_id: u8,
    my_dec_key: Option<Arc<crypto_box::SecretKey>>, // * MY CODE: ADDED, decryption key as Option
    my_enc_key: &PublicKey,
    party_enc_keys: &[(u8, PublicKey)],
) -> Result<(), KeygenError> {
    // Validate and print the decryption key if provided
    println!("[KeygenParty][dec_key] Validating decryption key...");

    // Validate the decryption key if provided, added check
    if let Some(dec_key) = my_dec_key {
        if dec_key.to_bytes().iter().all(|&b| b == 0) {
            return Err(KeygenError::InvalidDecryptionKey);
        }
        println!(
            "[validate_input_basic][KeygenParty][dec_key] Decryption Key (first 16 bytes): {:?}, party ID: {}",
            &dec_key.to_bytes()[..16], party_id
        );
    } else {
        println!("[validate_input_basic][KeygenParty][dec_key] No decryption key provided, skipping validation.");
    }
    // Call the full validate_input function with self for sender and receiver
    validate_input(t, n, party_id, party_id, my_enc_key, my_enc_key, party_enc_keys)
}

// * MY CODE: ADDED, VALIDATE INPUT adjusted for sender and receiver
pub fn validate_input(
    t: u8,
    n: u8,
    sender_party_id: u8,
    receiver_party_id: u8,
    sender_enc_key: &PublicKey,
    receiver_enc_key: &PublicKey,
    party_enc_keys: &[(u8, PublicKey)],
) -> Result<(), KeygenError> {
    println!("[Validation] Checking inputs...");

    // * MY CODE: ADDED, Validate sender and receiver party ID
    if sender_party_id >= n || receiver_party_id >= n {
        println!(
            "[Validation Error] Invalid sender/receiver party ID: sender {}, receiver {} out of {}",
            sender_party_id, receiver_party_id, n
        );
        return Err(KeygenError::InvalidPid);
    }

    if t > n || t < 2 {
        println!("[Validation Error] Invalid threshold: {} out of {}", t, n);
        return Err(KeygenError::InvalidT);
    }

    // * MY CODE: ADDED, Check number of party encryption keys
    if party_enc_keys.is_empty() {
        println!("[Validation Error][enc_keys] Encryption key list is empty.");
        return Err(KeygenError::InvalidParticipantSet);
    }

    if party_enc_keys.len() != n as usize {
        // * MY CODE: ADDED, log
        println!(
            "[Validation Error][enc_keys] Incorrect number of party keys: expected {}, got {}",
            n,
            party_enc_keys.len()
        );
        return Err(KeygenError::InvalidParticipantSet);
    }

    // * MY CODE: ADDED, Print party encryption keys
    for (pid, key) in party_enc_keys.iter() {
        println!(
            "[Validation][enc_keys] Checking party {} key (first 16 bytes): {:?}",
            pid,
            &key.as_bytes()[..16]
        );
    }

    // * MY CODE: ADDED, Sort the keys by party ID for comparison
    let mut party_enc_keys_sorted = party_enc_keys.to_vec();
    party_enc_keys_sorted.sort_by_key(|k| k.0);

    // * MY CODE: ADDED, Validate sender's key
    if let Some((_, key)) = party_enc_keys_sorted.iter().find(|(pid, _)| *pid == sender_party_id) {
        if key.as_bytes() != sender_enc_key.as_bytes() {
            println!(
                "[Validation Error][enc_keys] Sender key mismatch! Expected: {:?}, but got: {:?}",
                hex::encode(sender_enc_key.as_bytes()),
                hex::encode(key.as_bytes())
            );
            return Err(KeygenError::InvalidParticipantSet);
        }
    } else {
        println!("[Validation Error] Missing sender key for party ID: {}", sender_party_id);
        return Err(KeygenError::InvalidParticipantSet);
    }

    // * MY CODE: ADDED, Validate receiver's key
    if let Some((_, key)) = party_enc_keys_sorted.iter().find(|(pid, _)| *pid == receiver_party_id) {
        if key.as_bytes() != receiver_enc_key.as_bytes() {
            println!(
                "[Validation Error][enc_keys] Receiver key mismatch! Expected: {:?}, but got: {:?}",
                hex::encode(receiver_enc_key.as_bytes()),
                hex::encode(key.as_bytes())
            );
            return Err(KeygenError::InvalidParticipantSet);
        }
    } else {
        println!("[Validation Error] Missing receiver key for party ID: {}", receiver_party_id);
        return Err(KeygenError::InvalidParticipantSet);
    }

    // * MY CODE: ADDED, log
    println!("[Validation] Input validation successful!");
    Ok(())
}

// * MY CODE: ADDED
impl<G> KeygenParty<R0, G>
where
    G: Group + GroupEncoding + for<'a> std::ops::Mul<<G as Group>::Scalar, Output = G>,
    G::Scalar: ScalarReduce<[u8; 32]>, // * MY CODE: ADDED missing constraint
{
    /// Create a new keygen party.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        t: u8,
        n: u8,
        party_id: u8,
        decryption_key: Arc<SecretKey>,
        encryption_keys: Vec<(u8, PublicKey)>,
        refresh_data: Option<KeyRefreshData<G>>,
        key_id: Option<[u8; 32]>,
        seed: Seed, // * MY CODE: ADDED, Add Seed type
        session_id: Option<[u8; 32]>, // * MY CODE: ADDED, session_id
        extra_data: Option<Vec<u8>>,

    ) -> Result<Self, KeygenError> {
        // Initialize RNG using the provided seed
        let mut rng = ChaCha20Rng::from_seed(seed);

        // * MY CODE: ADDED, PRINT SESSION ID
        print!("Session ID: {:?}", session_id);
        // Generate or use the provided session_id
        // * MY CODE: ADDED, DERIVE SESSION ID
        let derived_session_id = session_id.unwrap_or_else(|| rng.gen());
        // * MY CODE: ADDED, PRINT DERIVED SESSION ID
        println!("Derived Session ID: {:?}", derived_session_id);

        // Generate KeyEntropy with a session_id
        // * MY CODE: ADDED, USE DERIVED SESSION ID
        let rand_params = KeyEntropy::generate(t, n, &mut rng, derived_session_id);

        // * MY CODE: COMMENTED OUT
        // Set the constant polynomial to the keyshare secret.
        // if let Some(ref v) = refresh_data {
        //     rand_params.polynomial.set_constant(v.s_i_0);
        // }

        // * MY CODE: ADDED and COMMENTED OUT, need to be reviewed for refresh_data
        // if let Some(ref v) = refresh_data {
        //     rand_params.scalar_polynomial.set_constant(v.s_i_0);
        // }

        // Set the constant polynomial to the keyshare secret.
        // * MY CODE: ADDED and COMMENTED OUT, need to be reviewed for point correctness
        // if let Some(ref v) = refresh_data {
        //     let constant_point = G::generator() * v.s_i_0; // * MY CODE: ADDED, convert scalar to group element
        //     rand_params.polynomial.set_constant(constant_point); // * MY CODE: ADDED, set as the constant term
        // }

        Self::new_with_context(
            t,
            n,
            party_id,
            decryption_key,
            encryption_keys,
            rand_params,
            refresh_data,
            key_id,
            seed,
            extra_data,
        )
    }

    /// Create a new keygen protocol instance with a given context. Used for testing purposes internally.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_context(
        t: u8,
        n: u8,
        party_id: u8,
        dec_key: Arc<crypto_box::SecretKey>,
        party_enc_keys: Vec<(u8, PublicKey)>,
        rand_params: KeyEntropy<G>,
        key_refresh_data: Option<KeyRefreshData<G>>,
        key_id: Option<[u8; 32]>,
        seed: Seed, // * MY CODE: ADDED, Add Seed type
        extra_data: Option<Vec<u8>>,
    ) -> Result<Self, KeygenError>  {
        // * MY CODE: ADDED, sanity check log
        println!(
            "[Validation] Parameters - t: {}, n: {}, party_id: {}",
            t, n, party_id
        );

        // * MY CODE: ADDED, validate_input_basic, check for correctness, added dec_key
        if let Err(e) = validate_input_basic(t, n, party_id, Some(dec_key.clone()), &dec_key.public_key(), &party_enc_keys) {
            println!("[encrypt_message] Validation failed: {:?}", e);
            return Err(KeygenError::InvalidParticipantSet);
        }

        // Validate refresh data
        if let Some(ref v) = key_refresh_data {
            let is_lost = v.lost_keyshare_party_ids.contains(&party_id);
            let cond1 = v.expected_public_key == G::identity();
            let cond2 = v.lost_keyshare_party_ids.len() > (n - t).into();
            // * MY CODE: ADDED, need to be reviewed for correctness
            let cond3 = rand_params.scalar_polynomial.get_constant() != &v.s_i_0;
            // * MY CODE: COMMENTED OUT
            // let cond3 = rand_params.polynomial.get_constant() != &v.s_i_0;
            let cond4 = if is_lost {
                v.s_i_0 != G::Scalar::ZERO
            } else {
                v.s_i_0 == G::Scalar::ZERO
            };
            if cond1 || cond2 || cond3 || cond4 {
                return Err(KeygenError::InvalidRefresh);
            }
        }

        Ok(Self {
            params: KeygenParams {
                t,
                n,
                party_id,
                dec_key: Some(dec_key), // * MY CODE: ADDED, decryption key as Option
                party_enc_keys: Some(party_enc_keys), // * MY CODE: ADDED, party_enc_keys as Option
                key_id,
                extra_data,
            },
            rand_params,
            seed,
            key_refresh_data,
            state: R0,
        })
    }
}


// * MY CODE: ADDED, IMPLEMENTATION FOR R1, all new methods
impl<G> KeygenParty<R1<G>, G>
where
    G: Group + GroupEncoding + for<'a> std::ops::Mul<<G as Group>::Scalar, Output = G>,
    G::Scalar: ScalarReduce<[u8; 32]>, // * MY CODE: ADDED missing constraint
{
    /// Create a new keygen party.
    #[allow(clippy::too_many_arguments)]
    // * MY CODE: ADDED, PUBLIC CONSTRUCTOR TO R1
    pub fn new_r1(
        t: u8,
        n: u8,
        party_id: u8,
        polynomial: GroupPolynomial<G>,
        // * MY CODE: ADDED, scalar_polynomial
        scalar_polynomial: Polynomial<G>,
        c_i_j: Vec<EncryptedScalar>,
        commitment: HashBytes,
        shared_session_id_bytes: [u8; 32],
        key_id: Option<[u8; 32]>,
        extra_data: Option<Vec<u8>>,
        r_i: [u8; 32], // * MY CODE: ADDED, random value
        party_enc_keys: Option<Vec<(u8, crypto_box::PublicKey)>>, // * MY CODE: ADDED, party_enc_keys as Option
        dec_key: Option<Arc<crypto_box::SecretKey>>, // * MY CODE: ADDED, decryption key as Option 
    ) -> Result<Self, KeygenError> {

        // * MY CODE: ADDED
        Self::new_with_context(
            t,
            n,
            party_id,
            polynomial,
            // * MY CODE: ADDED, scalar_polynomial
            scalar_polynomial,
            c_i_j,
            commitment,
            shared_session_id_bytes,
            key_id,
            extra_data,
            r_i, // * MY CODE: ADDED, random value
            party_enc_keys, // * MY CODE: ADDED
            dec_key // * MY CODE: ADDED
        )
    }

    // * MY CODE: ADDED,
    /// Create a new keygen protocol instance with a given context. Used for testing purposes internally.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_context(
        t: u8,
        n: u8,
        party_id: u8,
        polynomial: GroupPolynomial<G>,
        // * MY CODE: ADDED, scalar_polynomial
        scalar_polynomial: Polynomial<G>,
        c_i_j: Vec<EncryptedScalar>,
        commitment: HashBytes,
        shared_session_id_bytes: [u8; 32],
        key_id: Option<[u8; 32]>,
        extra_data: Option<Vec<u8>>,
        r_i: [u8; 32], // * MY CODE: ADDED, random value
        party_enc_keys: Option<Vec<(u8, crypto_box::PublicKey)>>, // * MY CODE: ADDED, party_enc_keys as Option
        dec_key: Option<Arc<crypto_box::SecretKey>>, // * MY CODE: ADDED, decryption key as Option
    ) -> Result<Self, KeygenError>  {
        // TODO: Validate input if needed
        // * MY CODE: ADDED, sanity check log
        println!(
            "[Validation] Parameters - t: {}, n: {}, party_id: {}",
            t, n, party_id
        );

        // * MY CODE: ADDED, validate_input_basic, check for correctness, added dec_key, dec_key_public and party_enc_keys as Option
        let dec_key_public = dec_key
            .as_ref()
            .map(|dk| dk.public_key())
            .unwrap_or_else(|| {
                eprintln!("Warning: No decryption key provided, using default.");
                PublicKey::from_bytes([0u8; 32]) // Provide a default public key
            });

        if let Err(e) = validate_input_basic(
            t,
            n,
            party_id,
            dec_key.clone(),
            &dec_key_public,
            party_enc_keys.as_ref().unwrap_or(&vec![])  // Borrow without moving
        ) {
            println!("[encrypt_message] Validation failed: {:?}", e);
            return Err(KeygenError::InvalidParticipantSet);
        }


        Ok(Self {
            params: KeygenParams { 
                t,
                n,
                party_id,
                dec_key, // * MY CODE: ADDED
                party_enc_keys,  // * MY CODE: ADDED, party_enc_keys as Option
                key_id,
                extra_data,
            },
            rand_params: KeyEntropy {
                t,
                n,
                session_id: shared_session_id_bytes,
                r_i, // * MY CODE: ADDED, random value
                polynomial: polynomial.clone(),
                scalars: vec![],
                // * MY CODE: ADDED, scalar_polynomial
                scalar_polynomial,
            },
            seed: [0; 32],
            key_refresh_data: None,
            state: R1 {
                big_a_i: polynomial,
                c_i_j,
                commitment,
            },
        })
    }
}


// * MY CODE: ADDED, IMPLEMENTATION FOR R2, all new methods
impl<G> KeygenParty<R2, G>
where
    G: Group + GroupEncoding + for<'a> std::ops::Mul<<G as Group>::Scalar, Output = G>,
    G::Scalar: ScalarReduce<[u8; 32]>, // * MY CODE: ADDED missing constraint
{
    // * MY CODE: ADDED,
    /// Create a new keygen party.
    #[allow(clippy::too_many_arguments)]
    pub fn new_r2(
        t: u8,
        n: u8,
        party_id: u8,
        commitment_list: Vec<HashBytes>,
        final_session_id: SessionId,
        sid_i_list: Vec<SessionId>,
        shared_session_id: SessionId,
        key_id: Option<[u8; 32]>,
        extra_data: Option<Vec<u8>>,
        party_enc_keys: Vec<(u8, crypto_box::PublicKey)>, // * MY CODE: ADDED
        dec_key: Arc<crypto_box::SecretKey>, // * MY CODE: ADDED
        // polynomial: GroupPolynomial<G>,
        // big_a_i_poly: Vec<G>,
        // c_i_list: Vec<EncryptedScalar>,
        // r_i: [u8; 32],
        // dlog_proofs_i: Vec<DLogProof<G>>,
    ) -> Result<Self, KeygenError> {
        // * MY CODE: ADDED,
        Self::new_with_context(
            t,
            n,
            party_id,
            commitment_list,
            final_session_id,
            sid_i_list,
            shared_session_id,
            key_id,
            extra_data,
            party_enc_keys, // * MY CODE: ADDED
            dec_key // * MY CODE: ADDED
        )
    }

    // * MY CODE: ADDED,
    /// Create a new keygen protocol instance with a given context. Used for testing purposes internally.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_context(
        t: u8,
        n: u8,
        party_id: u8,
        commitment_list: Vec<HashBytes>,
        final_session_id: SessionId,
        sid_i_list: Vec<SessionId>,
        shared_session_id: SessionId,
        key_id: Option<[u8; 32]>,
        extra_data: Option<Vec<u8>>,
        party_enc_keys: Vec<(u8, crypto_box::PublicKey)>, // * MY CODE: ADDED
        dec_key: Arc<crypto_box::SecretKey>, // * MY CODE: ADDED
        // big_a_i_poly: Vec<G>,
        // c_i_list: Vec<EncryptedScalar>,
        // r_i: [u8; 32],
        // dlog_proofs_i: Vec<DLogProof<G>>,
    ) -> Result<Self, KeygenError>  {
        // * MY CODE: ADDED, sanity check log
        println!(
            "[Validation] Parameters - t: {}, n: {}, party_id: {}",
            t, n, party_id
        );

        // * MY CODE: ADDED, validate the number of parties
        // Ensure the party encryption keys list contains all parties
        if party_enc_keys.len() != n as usize {
            println!(
                "[Validation Error] Incorrect number of party keys: expected {}, got {}",
                n,
                party_enc_keys.len()
            );
            return Err(KeygenError::InvalidParticipantSet);
        }

        // * MY CODE: ADDED, get the party's own public key
        // Find the party's own public key using its private key
        let my_enc_key = dec_key.public_key();

        // * MY CODE: ADDED, validation 
        // Validate the party's key correctness
        let receiver_public_key = find_enc_key(party_id, &party_enc_keys)
            .ok_or_else(|| {
                println!("[Validation Error] Missing key for party ID: {}", party_id);
                KeygenError::InvalidParticipantSet
            })?;

        // * MY CODE: ADDED, validation for the party's own public key
        // Ensure the party's own public key matches the expected key
        if my_enc_key.as_bytes() != receiver_public_key.as_bytes() {
            println!(
                "[Validation Error] Mismatched key: expected {:?}, but got {:?}",
                hex::encode(my_enc_key.as_bytes()),
                hex::encode(receiver_public_key.as_bytes())
            );
            return Err(KeygenError::InvalidParticipantSet);
        }

        // * MY CODE: ADDED, validate_input
        // Validate the party's key correctness
        // Perform full input validation with sender and receiver keys
        for (pid, key) in &party_enc_keys {
            if let Err(e) = validate_input(
                t,
                n,
                party_id,             // Sender ID (self)
                *pid,                 // Receiver ID (other party)
                &my_enc_key,           // Sender's public key
                key,                   // Receiver's public key
                &party_enc_keys,        // List of all keys
            ) {
                println!("[Validation Error] Input validation failed for party {}: {:?}", pid, e);
                return Err(KeygenError::InvalidParticipantSet);
            }
        }

        println!("[Validation] Input validation successful!");

        println!("Initiating R2 for Round 3, with final session id: {:?}, shared session id for : {:?}, sid_i_list: {:?}", final_session_id, shared_session_id, sid_i_list);

        Ok(Self {
            params: KeygenParams {
                t,
                n,
                party_id,
                // * MY CODE: ADDED, add dec_key and party_enc_keys
                key_id,
                dec_key: Some(dec_key), // * MY CODE: ADDED, decryption key as Option
                party_enc_keys: Some(party_enc_keys), // * MY CODE: ADDED, party_enc_keys as Option
                extra_data,
            },
            rand_params: KeyEntropy { // NOT USED
                t,
                n,
                session_id: [0; 32],
                r_i: [0; 32], // TODO
                polynomial: GroupPolynomial::new(vec![]), // TODO: check polynomial logic
                scalars: vec![],
                scalar_polynomial: Polynomial::new(vec![]), // TODO: check scalar_polynomial logic
            },
            seed: [0; 32],
            key_refresh_data: None,
            state: R2 {
                final_session_id,
                shared_session_id,
                commitment_list,
                sid_i_list,
            },
        })
    }
}

impl<G> KeygenParty<R2, G>
where
    G: Group + GroupEncoding, // * MY CODE: ADDED
{
    pub fn get_r2_state(&self) -> &R2 {
        &self.state
    }
}

// Protocol 12 from https://eprint.iacr.org/2022/374.pdf
// Simple Three-Round Multiparty Schnorr Signing with Full Simulatability
impl<G: GroupElem> Round for KeygenParty<R0, G>
where
    G::Scalar: ScalarReduce<[u8; 32]>, // * MY CODE: ADDED, add this bound
{
    type Input = ();
    // * MY CODE: COMMENTED OUT
    // There was a mismatch in the input type for the first round protocol implementation,
    // The input type should be `KeygenMsg1` instead of `()`.
    // type Input = ();
    // * MY CODE: ADDED AND COMMENTED OUT
    // type Input = Vec<KeygenMsg1>; // Expect KeygenMsg2 as input

    type Output = Result<(KeygenParty<R1<G>, G>, KeygenMsg1), KeygenError>;

    type Scalar = G::Scalar; // * MY CODE: ADDED, properly associate `Scalar` with `G::Scalar`
    type GroupElem = G; // * MY CODE: ADDED, associate GroupElem with G (e.g., EdwardsPoint)

    /// Protocol 21, step 2. From https://eprint.iacr.org/2022/374.pdf.
    fn process(self, _: ()) -> Self::Output {
        // 12.2(a) Sampling random session-id was done in KeyEntropy.

        // 12.2(b) Sampling random polynomial was done in KeyEntropy.
        // * MY CODE: COMMENTED OUT
        // let big_a_i = self.rand_params.polynomial.commit();
        // * MY CODE: ADDED
        let big_a_i = self.rand_params.polynomial.clone();


        // 12.2(c)
        let mut rng = ChaCha20Rng::from_seed(self.seed);
        let c_i_j = (0..self.params.n)
            // * MY CODE: ADDED, renamed party_id to receiver_party_id, represents the receiver
            .map(|receiver_party_id| {
                // * MY CODE: ADDED, find the encryption key for the receiver, receiver_party_id is the receiver ID 
                // adjust find_enc_key to use the receiver_party_id
                let ek_i = find_enc_key(receiver_party_id, self.params.party_enc_keys.as_ref().unwrap_or(&vec![]))
                    .ok_or_else(|| {
                        eprintln!("Receiver's encryption key not found for party ID: {}", receiver_party_id);
                        KeygenError::MissingEncryptionKey
                    })?;

                // * MY CODE: ADDED, print the encryption key for the receiver
                println!(
                    "[encrypt_message] Encrypting data from sender ID: {} to receiver ID: {}",
                    self.params.party_id, receiver_party_id
                );
                // * MY CODE: ADDED, print the receiver's public key
                println!(
                    "[encrypt_message] Receiver public key (first 16 bytes): {:?}",
                    &ek_i.as_bytes()[..16]
                );



                // * MY CODE: ADDED, need to review this part for correctness 
                // Evaluate the scalar-based polynomial at x = (party_id + 1)
                // Party's point is just party-id. (Adding 1 because party-id's start from 0).
                // * MY CODE: REMOVED, party_id is the sender
                // * MY CODE: ADDED, comments, party_id represents the receiver
                // * MY CODE: ADDED, comments, self.params.party_id represents the sender
                // * MY CODE: ADDED, adjust the code to use the receiver_party_id
                let x = G::Scalar::from((receiver_party_id + 1) as u64);
                let d_i = self.rand_params.scalar_polynomial.evaluate_at(&x);
                // * MY CODE: ADDED, add variables for sender and receiver secret info
                let sender_secret_info = (&self.params.dec_key, self.params.party_id);
                let receiver_public_info = (&ek_i, receiver_party_id);

                // * MY CODE: ADDED, validate_input, check for correctness, added sender and receiver secret info
                let sender_pub_key = self.params.dec_key
                    .as_ref()
                    .map(|dec_key| dec_key.public_key())
                    .ok_or_else(|| {
                        eprintln!("Error: Decryption key is missing.");
                        KeygenError::MissingDecryptionKey
                    })?;


                // * MY CODE: ADDED, validate_input
                if let Err(e) = validate_input(
                    self.params.t,
                    self.params.n,
                    self.params.party_id,
                    receiver_party_id,
                    &sender_pub_key,  // Sender's public key safely retrieved, no unwrap
                    &ek_i,            // Unwrapped receiver's public key, no unwrap
                    self.params.party_enc_keys.as_deref().unwrap_or(&[])
                ) {
                    println!("[encrypt_message] Validation failed: {:?}", e);
                    return Err(KeygenError::EncryptionError);
                }

                // * MY CODE: ADDED, encrypt_message, adjust the function signature
                let dec_key_ref: &SecretKey = match &self.params.dec_key {
                    Some(dec_key_arc) => dec_key_arc.as_ref(),
                    None => {
                        eprintln!("Warning: No decryption key available.");
                        return Err(KeygenError::MissingDecryptionKey);
                    }
                };

                // * MY CODE: ADDED, adjusted the function signature
                let enc_data = encrypt_message::<_, G>(
                    (dec_key_ref, self.params.party_id),  // * MY CODE: ADDED, Sender's private key and ID, corrected
                    (&ek_i, receiver_party_id),  // * MY CODE: ADDED, Receiver's public key and ID (corrected), no unwrap
                    d_i,
                    &mut rng,
                    self.params.t, // * MY CODE: ADDED, Threshold
                    self.params.n, // * MY CODE: ADDED, Number of parties
                    &self.params.party_enc_keys.as_deref().unwrap_or(&[]) // * MY CODE: ADDED, Party encryption keys
                ).ok_or(KeygenError::EncryptionError)?;

                Ok(enc_data)
            })
            .collect::<Result<Vec<_>, KeygenError>>()?;

        // 12.2(d)
        let commitment = hash_commitment(
            self.rand_params.session_id,
            self.params.party_id,
            &big_a_i,
            &c_i_j,
            &self.rand_params.r_i,
        );

        // 12.2(f)
        // * MY CODE: ADDED, Retrieve the server's public key
        let enc_key = find_enc_key(
            self.params.party_id,
            self.params.party_enc_keys.as_deref().unwrap_or(&[])
        )
            .ok_or_else(|| {
                println!(
                    "[KeygenParty First Round] Encryption key not found for party ID: {}",
                    self.params.party_id
                );
                KeygenError::MissingEncryptionKey
            })?;

        // * MY CODE: ADDED, Convert the server's public key to a hex-encoded string for transport
        // Convert the server's public key to a hex-encoded string for transport
        let server_public_key_hex = hex::encode(enc_key.as_bytes());
        // * MY CODE: ADDED, validate the public key length
        assert_eq!(enc_key.as_bytes().len(), 32, "Unexpected public key length");


        let msg1 = KeygenMsg1 {
            from_party: self.params.party_id,
            session_id: self.rand_params.session_id,
            commitment,
            extra_data: None, // * MY CODE: ADDED, Reserved for future use
            public_key: server_public_key_hex.clone(), // * MY CODE: ADDED, Store the server's public key
        };

        // * MY CODE: ADDED, PRINT MESSAGE
        println!(
            "[KeygenParty First Round] Preparing message: from_party: {}, session_id: {:?}, commitment: {:?}, public_key (first 16 bytes): {:?}",
            self.params.party_id,
            self.rand_params.session_id,
            &commitment[..16],
            &server_public_key_hex[..16]
        );


        let next_state = KeygenParty {
            params: self.params,
            rand_params: self.rand_params,
            key_refresh_data: self.key_refresh_data,
            state: R1 {
                big_a_i,
                commitment,
                c_i_j,
            },
            seed: rng.gen(),
        };

        Ok((next_state, msg1))
    }

    // * MY CODE: ADDED
    fn from_saved_state(serialized_state: Vec<u8>, private_key: Arc<SecretKey>, party_pubkey_list: Vec<(u8, PublicKey)>, seed: [u8; 32], coefficients_scalars: Vec<Self::Scalar>, coefficients_points: Vec<Self::GroupElem>, session_id: SessionId, c_i_j: Vec<EncryptedScalar>, r_i: [u8; 32]) -> Result<Self, KeygenError>
    {
        todo!()
    }

    // * MY CODE: ADDED, from_saved_state_r2
    fn from_saved_state_r2(
        private_key: Arc<SecretKey>,
        party_pubkey_list: Vec<(u8, PublicKey)>,
        seed: Seed,
        coefficients_scalars: Vec<Self::Scalar>,
        session_id: SessionId,
        shared_session_id: SessionId,
        sid_i_list: Vec<SessionId>,
        commitment_list: Vec<HashBytes>,
        r_i: [u8; 32]
    ) -> Result<Self, KeygenError> {
        todo!()
    }

    // * MY CODE: ADDED, from_saved_state_r1
    fn from_saved_state_r1(commitment: [u8; 32], coefficients_scalars: Vec<Self::Scalar>, shared_session_id: SessionId, c_i_j: Vec<EncryptedScalar>, r_i: [u8; 32], seed: Seed) -> Result<Self, KeygenError> {
        todo!()
    }
}

// * MY CODE: ADDED 
// Define a simplified version of KeygenParty for deserialization
#[derive(Debug, Serialize, Deserialize)]
struct KeygenPartyTemp {
    params: KeygenParamsTemp,
    rand_params: KeyEntropyTemp,
    seed: [u8; 32],
    state: R1Temp,
    key_refresh_data: Option<KeyRefreshDataTemp>,
}

// * MY CODE: ADDED
#[derive(Debug, Serialize, Deserialize)]
struct KeygenParamsTemp {
    n: u8,
    t: u8,
    party_id: u8,
    key_id: Option<[u8; 32]>,
    dec_key: Vec<u8>, // Arc<SecretKey> to Vec<u8> for serialization
    party_enc_keys: Vec<(u8, Vec<u8>)>, // PublicKey as Vec<u8>
    extra_data: Option<Vec<u8>>,
}

// * MY CODE: ADDED
#[derive(Debug, Serialize, Deserialize)]
struct KeyEntropyTemp {
    t: u8,
    n: u8,
    session_id: [u8; 32],
    polynomial: Vec<u8>, // Serialized version of GroupPolynomial<G>
    scalar_polynomial: Vec<u8>, // Serialized scalar polynomial
    scalars: Vec<[u8; 32]>, // Scalars serialized as byte arrays
    r_i: [u8; 32],
}

// * MY CODE: ADDED
#[derive(Debug, Serialize, Deserialize)]
struct R1Temp {
    big_a_i: Vec<u8>, // Serialized version of GroupPolynomial<G>
    c_i_j: Vec<u8>,   // EncryptedScalar as bytes
    commitment: Vec<u8>, // HashBytes as bytes
}


// * MY CODE: ADDED
#[derive(Debug, Serialize, Deserialize)]
struct KeyRefreshDataTemp {
    /// Party id of the key share
    party_id: u8,
    threshold: u8,
    total_parties: u8,

    /// Additive share of participant_i (after interpolation)
    /// \sum_{i=0}^{n-1} s_i_0 = private_key
    /// s_i_0 can be equal to Zero in case when participant lost their key_share
    /// and wants to recover it during key_refresh
    s_i_0: Vec<u8>,  // Serialized G::Scalar as bytes

    /// List of participants IDs who lost their key shares
    /// Should be in range [0, n-1]
    lost_keyshare_party_ids: Vec<u8>,

    /// Expected public key for key refresh
    expected_public_key: Vec<u8>,  // Serialized G as bytes
}

// * MY CODE: ADDED
fn deserialize_keygen_party(serialized_data: &[u8]) -> Result<KeygenPartyTemp, bincode::Error> {
    bincode::deserialize(serialized_data)
}


impl<G> Round for KeygenParty<R1<G>, G>

where
    G: GroupElem + GroupEncoding + ConstantTimeEq, // * MY CODE: ADDED
    G::Scalar: ScalarReduce<[u8; 32]>,
{
    // * MY CODE: COMMENTED OUT
    // There was a mismatch in the input type for the second round protocol implementation,
    // The input type should be `KeygenMsg2<G>` instead of `KeygenMsg1`.
    type Input = Vec<KeygenMsg1>;
    // * MY CODE: ADDED AND COMMENTED OUT
    // type Input = Vec<KeygenMsg2<G>>; // Expect KeygenMsg2 as input


    type Output = Result<(KeygenParty<R2, G>, KeygenMsg2<G>), KeygenError>;
    // * MY CODE: ADDED
    type Scalar = G::Scalar; // Properly associate `Scalar` with `G::Scalar`
    // * MY CODE: ADDED
    type GroupElem = G; // Associate GroupElem with G (e.g., EdwardsPoint)

    // * MY CODE: ADDED
    /// Reinitialize a KeygenParty instance from a saved state.
    // * MY CODE: ADDED, from_saved_state_r1
    fn from_saved_state_r1(
        commitment: [u8; 32],
        coefficients_scalars: Vec<Self::Scalar>,
        shared_session_id: SessionId, // * MY CODE: ADDED, shared_session_id
        c_i_j: Vec<EncryptedScalar>, // * MY CODE: ADDED, c_i_j
        r_i: [u8; 32], // * MY CODE: ADDED, r_i
        seed: Seed, // * MY CODE: ADDED, seed
    ) -> Result<Self, KeygenError> {

        // * MY CODE: ADDED, scalar-based polynomial
        let scalar_based_polynomial = Polynomial::new(coefficients_scalars.clone());
        let point_based_polynomial = scalar_based_polynomial.commit(); // * MY CODE: ADDED, commit the polynomial
        println!("Initialized Polynomial:");
        // * MY CODE: ADDED, print the polynomial
        println!("{:?}", point_based_polynomial);

        // Construct the KeyEntropy (mock example here)
        println!("Shared Session ID for round 3 in bytes: {:?}", shared_session_id); // * MY CODE: ADDED
        // * MY CODE: ADDED
        let rand_params = KeyEntropy {
            t: 2,
            n: 2,
            session_id: shared_session_id, // * MY CODE: ADDED, shared session ID
            r_i, // * MY CODE: ADDED
            polynomial: point_based_polynomial.clone(), // * MY CODE: ADDED
            scalars: coefficients_scalars, // * MY CODE: ADDED
            scalar_polynomial: scalar_based_polynomial, // * MY CODE: ADDED
        };

        // Construct the state manually
        let state: R1<G> = R1 {
            // * MY CODE: ADDED, point_based_polynomial
            big_a_i: point_based_polynomial,
            c_i_j,     // * MY CODE: ADDED
            commitment, // * MY CODE: ADDED, commitment
        };

        Ok(Self {
            params: KeygenParams {
                t: 2, // Threshold
                n: 2, // Total parties
                party_id: 0, // Server's party ID
                dec_key: None, // MY CODE: ADDED, Not used in R1
                party_enc_keys: None, // MY CODE: ADDED, Not used in R1
                key_id: None,
                extra_data: None,
            },
            rand_params,
            state,
            seed,
            key_refresh_data: None,
        }) 
    }

    fn process(self, messages: Self::Input) -> Self::Output {
        let n = self.params.n as usize;
        // We pass None for expected_sid because we don't know the final session id yet.
        // We don't expect the session-ids to be equal for all messages in this round.
        // * MY CODE: ADDED
        let messages = validate_input_messages(messages, self.params.n, None)?;

        // * MY CODE: ADDED, sessionId protocol instanced wide check
        // Ensure all messages share the same session ID as the current round.
        for msg in &messages {
            if msg.session_id != self.rand_params.session_id {
                return Err(KeygenError::InvalidSessionId(format!(
                    "Session ID mismatch: expected {:?}, got {:?}",
                    self.rand_params.session_id, msg.session_id
                )));
            }
        }

        let mut sid_i_list = Vec::with_capacity(n);
        let mut commitment_list = Vec::with_capacity(n);
        let mut party_id_list = Vec::with_capacity(n);

        // 12.4(a)
        for message in &messages {
            if message.party_id() == self.params.party_id {
                let cond1 = self.rand_params.session_id == message.session_id;
                let cond2 = self.state.commitment == message.commitment;
                // * MY CODE: ADDED
                println!("Cond1: {:?}, Cond2: {:?}", cond1, cond2);
                // * MY CODE: ADDED
                println!("Session ID: {:?}, Commitment: {:?}", message.session_id, message.commitment);
                // * MY CODE: ADDED
                println!("State Commitment: {:?}", self.state.commitment);
                if !(cond1 && cond2) {
                    return Err(KeygenError::Abort("Invalid message in list"));
                }
            }

            // * MY CODE: ADDED, hash the session id
            let hashed_sid = hash_session_id(&message.session_id, message.party_id());
            sid_i_list.push(hashed_sid); // * MY CODE: ADDED, store the hashed session id, unique list of session ids

            commitment_list.push(message.commitment);

            let party_pubkey_idx = message.party_id();
            party_id_list.push(party_pubkey_idx);
        }

        let final_sid = calculate_final_session_id(party_id_list.iter().copied(), &sid_i_list);
        println!("sid_i_list populated for next round (3): {:?}", sid_i_list);


        // 12.4(b)
        let mut rng = ChaCha20Rng::from_seed(self.seed);
        let dlog_sid = Sha256::new()
            .chain(b"SL-EDDSA-DLOG-PROOF")
            .chain(final_sid.as_ref())
            .chain((self.params.party_id as u32).to_be_bytes())
            .chain(b"DLOG-PROOF-1-SID")
            .finalize()
            .into();

        // * MY CODE: ADDED, print the polynomial size
        println!("Polynomial size: {}", self.rand_params.scalar_polynomial.len());
        let dlog_proofs = self
            .rand_params
            .scalar_polynomial // * MY CODE ADDED, working with scalar-based polynomial, removed .polynomial 
            .iter()
            .map(|f_i| {
                // * MY CODE: ADDED, print the scalar value
                println!("Processing f_i: {:?}", f_i);
                let proof = DLogProof::<G>::prove(&dlog_sid, f_i, &mut rng);
                // * MY CODE: ADDED, print the Proof
                println!("Generated proof: {:?}", proof);
                proof
            })

            .collect::<Vec<_>>();

        // 12.4(d)
        let msg2 = KeygenMsg2 {
            session_id: final_sid,                // * MY CODE: ADDED, Round-specific session ID, build for round 3
            shared_session_id: self.rand_params.session_id, // * MY CODE: ADDED, Unchanged shared session ID, protocol wide
            from_party: self.params.party_id,
            big_a_i_poly: self.state.big_a_i.coeffs,
            c_i_list: self.state.c_i_j,
            r_i: self.rand_params.r_i,
            dlog_proofs_i: dlog_proofs,
        };

        let next_state = KeygenParty {
            params: self.params,
            state: R2 {
                final_session_id: final_sid, // * MY CODE: ADDED, derived from the session IDs of all parties in the round 2, from messages received from round 1
                shared_session_id: self.rand_params.session_id, // * MY CODE: ADDED Preserve shared session ID
                commitment_list,
                sid_i_list,
            },
            key_refresh_data: self.key_refresh_data,
            rand_params: self.rand_params,
            seed: self.seed, // * MY CODE: ADDED, Preserve the seed
        };

        Ok((next_state, msg2))
    }

    // * MY CODE: ADDED, from_saved_state_r2
    fn from_saved_state_r2(
        private_key: Arc<SecretKey>,
        party_pubkey_list: Vec<(u8, PublicKey)>,
        seed: Seed,
        coefficients_scalars: Vec<Self::Scalar>,
        session_id: SessionId,
        shared_session_id: SessionId,
        sid_i_list: Vec<SessionId>,
        commitment_list: Vec<HashBytes>,
        r_i: [u8; 32]
    ) -> Result<Self, KeygenError> {
        todo!()
    }

    // * MY CODE: ADDED, from_saved_state
    fn from_saved_state(serialized_state: Vec<u8>, private_key: Arc<SecretKey>, party_pubkey_list: Vec<(u8, PublicKey)>, seed: [u8; 32], coefficients_scalars: Vec<Self::Scalar>, coefficients_points: Vec<Self::GroupElem>, session_id: SessionId, c_i_j: Vec<EncryptedScalar>, r_i: [u8; 32]) -> Result<Self, KeygenError>
    where
        Self: Sized
    {
        todo!()
    }
}

impl<G> Round for KeygenParty<R2, G>
where
    G: GroupElem,
    G::Scalar: ScalarReduce<[u8; 32]>, //  + From<curve25519_dalek::Scalar>, // * MY CODE: ADDED AND COMMENTED OUT
{
    type Input = Vec<KeygenMsg2<G>>;

    type Output = Result<Keyshare<G>, KeygenError>;

    // * MY CODE: ADDED
    type Scalar = G::Scalar; // Properly associate `Scalar` with `G::Scalar`
    // * MY CODE: ADDED
    type GroupElem = G; // Associate GroupElem with G (e.g., EdwardsPoint)

    fn process(self, messages: Self::Input) -> Self::Output {
        let messages =
            validate_input_messages(messages, self.params.n, Some(self.state.final_session_id))?;

        // * MY CODE: ADDED, validate the session ID
            // Ensure all messages share the same session ID as the current round.
        for msg in &messages {
            if msg.session_id != self.state.final_session_id {
                return Err(KeygenError::InvalidSessionId(format!(
                    "Session ID mismatch: expected {:?}, got {:?}",
                    self.rand_params.session_id, msg.session_id
                )));
            }
        }
        // * MY CODE: COMMENTED OUT 

        // Potential issue: Since par_iter() is used,
        // it processes items in parallel. If the state is being mutated concurrently or accessed incorrectly,
        // it might lead to inconsistent data visibility.
        // messages.par_iter().try_for_each(|msg| {
        // * MY CODE: ADDED
        messages.iter().try_for_each(|msg| {

            // 12.6(b)-i Verify commitments.
            let party_id = msg.party_id();
            if self.state.sid_i_list.is_empty() {
                return Err(KeygenError::Abort("sid_i_list is unexpectedly empty"));
            }
            // * MY CODE: ADDED, validate the input
            if self.state.sid_i_list.len() <= party_id as usize {
                return Err(KeygenError::Abort("Invalid party_id index for sid_i_list"));
            }
            // * MY CODE: COMMENTED OUT
            // let sid = self.state.sid_i_list[party_id as usize];
            // * MY CODE: ADDED, validate the input
            let sid = self.state.sid_i_list.get(party_id as usize)
                .ok_or(KeygenError::Abort("sid_i_list entry missing"))?.clone();

            println!("sid_i_list (round 3): {:?}", self.state.sid_i_list);

            // * MY CODE: ADDED, validate the input
            if self.state.commitment_list.len() <= party_id as usize {
                return Err(KeygenError::Abort("Invalid party_id index for commitment_list"));
            }
            // * MY CODE: COMMENTED OUT
            // let commitment = self.state.commitment_list[party_id as usize];
            let commitment = self.state.commitment_list.get(party_id as usize)
                .ok_or(KeygenError::Abort("commitment_list entry missing"))?;
            println!("commitment_list (round 3): {:?}", self.state.commitment_list);

            // * MY CODE: ADDED, using protocol wide session ID
            let commit_hash =
                hash_commitment(msg.shared_session_id, party_id, &msg.big_a_i_poly, &msg.c_i_list, &msg.r_i); // TODO: return sid instead of shared session id
            // * MY CODE: COMMENTED OUT
            // let commit_cond = bool::from(commit_hash.ct_eq(&commitment));
            // * MY CODE: ADDED
            let commit_cond = bool::from(commit_hash.ct_eq(&commitment[..]));

            // 12.6(b)-ii Verify DLog proofs
            // Verify DLog proofs.
            let dlog_sid = Sha256::new()
                .chain(b"SL-EDDSA-DLOG-PROOF")
                .chain(self.state.final_session_id.as_ref())
                .chain((party_id as u32).to_be_bytes())
                .chain(b"DLOG-PROOF-1-SID")
                .finalize()
                .into();

            let dlog_cond = verfiy_dlog_proofs(
                &msg.dlog_proofs_i,
                &msg.big_a_i_poly,
                &dlog_sid,
                self.params.t,
            );
            // * MY CODE: COMMENTED OUT
            // * MY CODE: ADDED, print the verification results
            if !(dlog_cond && commit_cond) {
                println!("DLog condition FAILED: {:?}, Commitment condition: {:?}", dlog_cond, commit_cond);
                return Err(KeygenError::ProofError);
            } else {
                println!("DLog condition PASSED: {:?}, Commitment condition PASSED: {:?}, party_id: {:?}, protocol wide session_id: {:?}", dlog_cond, commit_cond, party_id, msg.session_id);
            }

            Ok::<(), KeygenError>(())
        })?;

        // 12.6(c)
        let d_i_vals = messages
            .iter()
            .map(|msg| {
                let encrypted_d_i = &msg.c_i_list[self.params.party_id as usize];
                // * MY CODE: COMMENTED OUT
                // let sender_pubkey =
                //     find_enc_key(msg.party_id(), &self.params.party_enc_keys).unwrap();
                // let sender_pubkey = find_enc_key(msg.party_id(), &self.params.party_enc_keys)
                //     .expect("Failed to find sender public key");

                // * MY CODE: ADDED, validate the input, find the sender's public key
                let empty_keys: Vec<(u8, PublicKey)> = Vec::new();
                let sender_pubkey = find_enc_key(
                    msg.party_id(),
                    self.params.party_enc_keys.as_ref().unwrap_or(&empty_keys)
                ).expect("Failed to find sender public key");

                println!("Retrieved sender public key: {:?}", sender_pubkey.as_bytes());
                
                // * MY CODE: ADDED, validate the input
                let receiver_secret_key = &self.params.dec_key;
                let receiver_party_id = self.params.party_id;

                let sender_pubkey_ref = &sender_pubkey;
                let sender_secret_info = (sender_pubkey_ref, msg.party_id());
                let receiver_public_info = (receiver_secret_key, receiver_party_id);

                // * MY CODE: ADDED, validate the input
                if let Err(e) = validate_input(
                    self.params.t,                      // Threshold
                    self.params.n,                      // Total number of parties
                    msg.party_id(),                      // Sender's party ID
                    self.params.party_id,                // Receiver's party ID
                    sender_pubkey_ref,                    // Sender's encryption key reference
                    &self.params.dec_key.as_ref().unwrap().public_key(),    // * MY CODE: ADDED, Receiver's public key, Receiver's encryption key reference
                    self.params.party_enc_keys.as_deref().unwrap_or(&[])    // * MY CODE: ADDED, Party encryption keys
                ) {
                    println!("[decrypt_message] Validation failed: {:?}", e);
                    return Err(KeygenError::InvalidParticipantSet);
                }

                // * MY CODE: ADDED, print the sender and receiver info
                println!("[Key Check] Sender ID: {}, Receiver ID: {}", sender_secret_info.1, receiver_public_info.1);
                println!("[Key Check] Sender Public Key: {:?}", sender_secret_info.0.as_bytes());
                // * MY CODE: ADDED, print the receiver's public key
                if let Some(dec_key) = receiver_public_info.0.as_ref() {
                    println!("[Key Check] Receiver Public Key: {:?}", dec_key.to_bytes());
                } else {
                    println!("[Key Check] Receiver Public Key is missing.");
                }

                println!("Decrypting message for party {}", msg.party_id());
                println!("Encrypted scalar: {:?}", encrypted_d_i);
                println!("Sender public key: {:?}", sender_pubkey);
                println!("Receiver secret key: {:?}", self.params.dec_key);
                println!("Nonce: {:?}", encrypted_d_i.nonce);

                // * MY CODE: COMMENTED OUT
                // let d_i_bytes = decrypt_message(&self.params.dec_key, sender_pubkey, encrypted_d_i)
                //     .ok_or(KeygenError::DecryptionError)?;
                // * MY CODE: ADDED, dec_key_ref is the decryption key reference
                let dec_key_ref = self.params.dec_key
                    .as_deref()
                    .ok_or_else(|| {
                        println!("Decryption key not found for party {}", msg.party_id());
                        KeygenError::MissingDecryptionKey
                    })?;
                // * MY CODE: ADDED, decrypt the message using dec_key_ref and sender_pubkey
                let d_i_bytes = decrypt_message(dec_key_ref, &sender_pubkey, encrypted_d_i)
                    .ok_or_else(|| {
                        println!("Decryption failed for party {}", msg.party_id());
                        KeygenError::DecryptionError
                    })?;

                // Decode the scalar from the bytes.
                let mut encoding = <G::Scalar as PrimeField>::Repr::default();
                // NOTE to me, this syntax reviles invalid value bytes from d_i_bytes into encoding
                encoding.as_mut().copy_from_slice(&d_i_bytes);

                let d_i = G::Scalar::from_repr(encoding);
                if d_i.is_none().into() {
                    return Err(KeygenError::InvalidDiPlaintext);
                }

                Ok(d_i.unwrap())
            })
            .collect::<Result<Vec<_>, KeygenError>>()?;

        // 12.6(c)
        let d_i_share = d_i_vals.iter().sum();

        let empty_poly = (0..self.params.t).map(|_| G::identity()).collect();

        let mut big_a_poly = GroupPolynomial::new(empty_poly);

        // Validate polynomial constant terms
        for msg in messages {
            let mut is_lost = false;
            // TODO: NO NEED TO CHECK FOR LOST KEYSHARES:
            // if let Some(ref data) = self.key_refresh_data {
            //     is_lost = data.lost_keyshare_party_ids.contains(&msg.party_id());
            // }
            // TODO: REOPEN THIS COMMENTED OUT CODE
            // let is_identity = msg.big_a_i_poly[0] == G::identity();

            // if (is_lost && !is_identity) || (!is_lost && is_identity) {
            //     return Err(KeygenError::InvalidRefresh);
            // }

            // 12.6(d)
            big_a_poly.add_mut(&msg.big_a_i_poly);

            // 12.6(e)
            // * MY CODE: COMMENTED OUT
            let d_i = d_i_vals[msg.party_id() as usize];
            // let expected_point = EdwardsPoint::mul_base(&d_i); // should be commented out
            let expected_point = G::generator() * d_i;

            let calc_point = GroupPolynomial::new(msg.big_a_i_poly)
                .evaluate_at(&G::Scalar::from((self.params.party_id + 1) as u64));

            if !bool::from(expected_point.ct_eq(&calc_point)) {
                // * MY CODE: ADDED, print the error message
                println!("Error: invalid d_i/ given group polynomial");
                return Err(KeygenError::Abort(
                    "invalid d_i share/ given group polynomial",
                ));
            } else {
                // * MY CODE: ADDED, print the success message
                println!("d_i/ given group polynomial is valid");
            }

        }

        // * MY CODE: COMMENTED OUT
        // * MY CODE: ADDED, adding logs
        // TODO: remove this log:
        println!("d_i_share: {:?}", d_i_share);

        println!("Evaluation point: {:?}", G::Scalar::from((self.params.party_id + 1) as u64));
        println!("Polynomial coefficients: {:?}", big_a_poly);

        println!("Polynomial coefficients: {:?}", big_a_poly.coeffs); // the same output as above
        for (i, coeff) in big_a_poly.coeffs.iter().enumerate() { // the same output as above
            println!("Polynomial coefficient {}: {:?}", i, coeff);
        }

        let public_key = big_a_poly.get_constant();
        //
        // 12.6(e)
        let expected_point: G = G::generator() * d_i_share;
        let calc_point =
            big_a_poly.evaluate_at(&G::Scalar::from((self.params.party_id + 1) as u64));

        // * MY CODE: ADDED, print
        println!("Expected point: {:?}", expected_point);
        println!("Calculated point: {:?}", calc_point);
        println!("Compressed Expected Point: {:?}", expected_point.to_bytes().as_ref());
        println!("Compressed Calculated Point: {:?}", calc_point.to_bytes().as_ref());


        println!("Public key: {:?}", public_key);

        // This test is working as expected, the points are equal in compressed coordinates, regardless of the point representation
        // it is the same point in affine coordinates (space)
        
        // * MY CODE: ADDED, are_group_elements_equal
        // TODO: this check will be removed: it is just for debugging purposes
        if !are_group_elements_equal(&expected_point, &calc_point) {
            println!("❌ Points are NOT equal (after compression check)");
        } else {
            println!("✅ Points match in compressed (affine) coordinates");
        }

        if !bool::from(expected_point.ct_eq(&calc_point)) {
            // * MY CODE: ADDED, print the error message
            println!("Error: invalid d_i_share/ given group polynomial");
            return Err(KeygenError::Abort(
                "invalid d_i share/ given group polynomial",
            ));
        } else {
            // * MY CODE: ADDED, print the success message
            println!("d_i_share/ given group polynomial is valid");
        }


        let keyshare = Keyshare {
            threshold: self.params.t,
            total_parties: self.params.n,
            party_id: self.params.party_id,
            key_id: [1; 32], // * MY CODE: ADDED, TODO: key_id is not set
            d_i: d_i_share,
            public_key,
            // * MY CODE: ADDED
            aggregated_public_key: SerializableEdwardsPoint::default(),
            extra_data: self.params.extra_data,
        };
        Ok(keyshare)
    }

    // * MY CODE: ADDED
    fn from_saved_state(serialized_state: Vec<u8>, private_key: Arc<SecretKey>, party_pubkey_list: Vec<(u8, PublicKey)>, seed: [u8; 32], coefficients_scalars: Vec<Self::Scalar>, coefficients_points: Vec<Self::GroupElem>, session_id: SessionId, c_i_j: Vec<EncryptedScalar>, r_i: [u8; 32]) -> Result<Self, KeygenError>
    where
        Self: Sized
    {
        todo!()
    }

    // * MY CODE: ADDED, from_saved_state_r1
    fn from_saved_state_r1(commitment: [u8; 32], coefficients_scalars: Vec<Self::Scalar>, shared_session_id: SessionId, c_i_j: Vec<EncryptedScalar>, r_i: [u8; 32], seed: Seed) -> Result<Self, KeygenError>
    where
        Self: Sized
    {
        todo!()
    }
    fn from_saved_state_r2(
        private_key: Arc<SecretKey>,
        party_pubkey_list: Vec<(u8, PublicKey)>,
        seed: Seed, // Seed
        coefficients_scalars: Vec<Self::Scalar>,
        session_id: SessionId,
        // final_session_id: SessionId,
        shared_session_id: SessionId,
        sid_i_list: Vec<SessionId>,
        commitment_list: Vec<HashBytes>,
        r_i: [u8; 32]
    ) -> Result<Self, KeygenError>

    {
        // * MY CODE: ADDED, scalar-based polynomial
        let scalar_based_polynomial = Polynomial::new(coefficients_scalars.clone());
        let point_based_polynomial = scalar_based_polynomial.commit();
        println!("Initialized Polynomial:");
        println!("{:?}", point_based_polynomial);

        // Construct the KeyEntropy (mock example here)
        println!("Unique Session ID for round 3 in bytes: {:?}", session_id); // final sessionId
        println!("Shared Session ID for protocol specific (rounds 1-3) in bytes: {:?}", shared_session_id);
        let rand_params = KeyEntropy {
            t: 2,
            n: 2,
            session_id,
            r_i,
            polynomial: point_based_polynomial.clone(),
            scalars: coefficients_scalars,
            scalar_polynomial: scalar_based_polynomial,
        };

        // Construct the state manually
        let state: R2 = R2 {
            final_session_id: session_id,
            shared_session_id,
            commitment_list,
            sid_i_list,
        };

        Ok(Self {
            params: KeygenParams {
                t: 2, // Threshold
                n: 2, // Total parties
                party_id: 0, // Server's party ID
                dec_key: Option::from(private_key),
                party_enc_keys: Option::from(party_pubkey_list),
                key_id: None,
                extra_data: None,
            },
            rand_params,
            state,
            seed,
            key_refresh_data: None,
        })
    }
}
// * MY CODE: ADDED, compare group elements, temp verification
fn are_group_elements_equal<G: GroupElem + GroupEncoding>(point1: &G, point2: &G) -> bool {
    point1.to_bytes().as_ref() == point2.to_bytes().as_ref()
}

// * MY CODE: ADDED, add debug print
fn hash_commitment<G: GroupElem>(
    session_id: SessionId,
    party_id: u8,
    big_f_i_vec: &[G],
    ciphertexts: &[EncryptedScalar],
    r_i: &[u8; 32],
) -> HashBytes {
    // * MY CODE: ADDED, add debug print
    println!("[hash_commitment] Starting hash_commitment computation...");

    // Convert session_id to hex for better readability
    let session_id_hex = hex::encode(session_id.as_ref());
    // * MY CODE: ADDED, add debug print
    println!("[hash_commitment] Session ID: {}", session_id_hex);
    // * MY CODE: ADDED, add debug print
    println!("[hash_commitment] Party ID: {}", party_id);

    let mut hasher = Sha256::new()
        .chain_update(b"SL-Keygen-Commitment")
        .chain_update(session_id.as_ref())
        .chain_update(party_id.to_be_bytes());
    // * MY CODE: ADDED, add debug print
    // Log BigF_i vector elements
    let mut big_f_i_hex = String::new();
    for (i, point) in big_f_i_vec.iter().enumerate() {
        let bytes = point.to_bytes();
        write!(&mut big_f_i_hex, "[{}]: {}\n", i, hex::encode(&bytes)).unwrap();
        sha2::Digest::update(&mut hasher, bytes);
    }
    // * MY CODE: ADDED, add debug print
    println!("[hash_commitment] BigF_i vector: \n{}", big_f_i_hex);

    // * MY CODE: ADDED, add debug print
    // Log ciphertexts
    let mut ciphertexts_hex = String::new();
    for (i, c) in ciphertexts.iter().enumerate() {
        let bytes = bytemuck::bytes_of(c);
        write!(&mut ciphertexts_hex, "[{}]: {}\n", i, hex::encode(&bytes)).unwrap();
        sha2::Digest::update(&mut hasher, bytes);
    }
    // * MY CODE: ADDED, add debug print
    println!("[hash_commitment] Ciphertexts: \n{}", ciphertexts_hex);

    // Log r_i value
    let r_i_hex = hex::encode(r_i);
    // * MY CODE: ADDED, add debug print
    println!("[hash_commitment][V] Random nonce (r_i): {}", r_i_hex);
    sha2::Digest::update(&mut hasher, r_i);

    let result_hash = hasher.finalize();
    let result_hash_hex = hex::encode(result_hash);
    // * MY CODE: ADDED, add debug print
    println!("[hash_commitment] Final commitment hash: {}", result_hash_hex);

    result_hash.into()
}

pub fn validate_input_messages<M: BaseMessage>(
    mut messages: Vec<M>,
    n: u8,
    expected_sid: Option<SessionId>,
) -> Result<Vec<M>, KeygenError> {
    if messages.len() != n as usize {
        return Err(KeygenError::InvalidMsgCount);
    }

    messages.sort_by_key(|msg| msg.party_id());
    // * MY CODE: ADDED, print the party_id and session_id
    println!("message server party_id: {:?}", messages[0].party_id());
    println!("message client party_id: {:?}", messages[1].party_id());
    println!("message server session_id: {:?}", messages[0].session_id());
    println!("message client session_id: {:?}", messages[1].session_id());

    messages
        .iter()
        .enumerate()
        .all(|(pid, msg)| {
            let pid_match = msg.party_id() as usize == pid;
            let sid_match = expected_sid
                .as_ref()
                .map(|sid| sid == msg.session_id())
                .unwrap_or(true);

            pid_match && sid_match
        })
        .then_some(messages)
        .ok_or(KeygenError::InvalidParticipantSet)
}
fn verfiy_dlog_proofs<G: GroupElem>(
    proofs: &[DLogProof<G>],
    points: &[G],
    dlog_sid: &SessionId,
    threshold: u8,
) -> bool
where
    G::Scalar: ScalarReduce<[u8; 32]>, // + From<curve25519_dalek::Scalar>, // * MY CODE: ADDED AND COMMENTED OUT
{
    let mut valid = true;
    if proofs.len() != points.len() || proofs.len() != threshold as usize {
        valid = false;
    }
    for (proof, point) in proofs.iter().zip(points) {
        if !proof.verify(dlog_sid, point) {
            valid = false;
        }
    }

    valid
}

// * MY CODE: ADDED, find_enc_key custom implementation
fn find_enc_key(party_id: u8, party_enc_keys: &[(u8, PublicKey)]) -> Option<PublicKey> {
    let key = party_enc_keys.iter().find(|(id, _)| *id == party_id);
    if let Some((id, key)) = key {
        println!(
            "[Debug] Found key for party {}: {:?}",
            id,
            hex::encode(key.as_bytes())
        );
    } else {
        println!("[Error] No key found for party ID: {}", party_id);
    }
    key.map(|(_, k)| k.clone())
}

// * MY CODE: COMMENTED OUT, find_enc_key previously used
// fn find_enc_key(pid: u8, party_enc_keys: &[(u8, PublicKey)]) -> Option<&PublicKey> {
//     party_enc_keys
//         .iter()
//         .find(|(id, _)| id == &pid)
//         .map(|(_, key)| key)
// }

#[cfg(test)]
mod test {
    use crate::common::utils::run_keygen;
    use curve25519_dalek::EdwardsPoint;
    use k256::ProjectivePoint;

    #[test]
    fn keygen_curve25519() {
        run_keygen::<2, 2, EdwardsPoint>();
        run_keygen::<2, 3, EdwardsPoint>();
        run_keygen::<3, 5, EdwardsPoint>();
        run_keygen::<5, 5, EdwardsPoint>();
        run_keygen::<5, 10, EdwardsPoint>();
        run_keygen::<10, 10, EdwardsPoint>();
        run_keygen::<9, 20, EdwardsPoint>();
    }

    #[test]
    fn keygen_taproot() {
        run_keygen::<2, 2, ProjectivePoint>();
        run_keygen::<2, 3, ProjectivePoint>();
        run_keygen::<3, 5, ProjectivePoint>();
        run_keygen::<5, 5, EdwardsPoint>();
        run_keygen::<5, 10, ProjectivePoint>();
        run_keygen::<10, 10, EdwardsPoint>();
        run_keygen::<9, 20, ProjectivePoint>();
    }
}
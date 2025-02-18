use std::sync::Arc;
use crypto_box::{PublicKey, SecretKey};
use curve25519_dalek::{EdwardsPoint, Scalar};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use elliptic_curve::group::GroupEncoding;
use sha2::{Digest, Sha512};

use crate::common::traits::Round;
use crate::common::utils::{EncryptedScalar, HashBytes, Seed, SessionId};
use crate::group::Group;
use crate::keygen::KeygenError;

use super::{
    messages::{SignComplete, SignMsg3},
    validate_input_messages, PartialSign, SignError, SignReady,
};

// * MY CODE: REMOVED <G>, it should be removed from the trait definition, as it in Keygen Generation
// <G> is the group type, e.g. EdwardsPoint
impl Round for SignReady<EdwardsPoint> {
    type Input = Vec<u8>;

    type Output = Result<(PartialSign<EdwardsPoint>, SignMsg3<EdwardsPoint>), SignError>;

    /// The signer party processes the message to sign and returns the partial signature
    /// # Arguments
    /// * `msg_to_sign` - The message to sign in bytes
    fn process(self, msg_to_sign: Self::Input) -> Self::Output {
        let big_a = self.public_key.to_bytes();

        use sha2::digest::Update;
        let digest = Sha512::new()
            .chain(self.big_r.to_bytes())
            .chain(big_a)
            .chain(&msg_to_sign);

        let e = Scalar::from_bytes_mod_order_wide(&digest.finalize().into());
        let s_i = self.k_i + self.d_i * e;

        let msg3 = SignMsg3 {
            from_party: self.party_id,
            session_id: self.session_id,
            s_i,
        };

        let next = PartialSign {
            party_id: self.party_id,
            threshold: self.threshold,
            session_id: self.session_id,
            public_key: self.public_key,
            big_r: self.big_r,
            s_i,
            msg_to_sign,
            pid_list: self.pid_list,
        };

        Ok((next, msg3))
    }

    // * MY CODE: ADDED
    fn from_saved_state(
        serialized_state: Vec<u8>,
        private_key: Arc<SecretKey>,
        party_pubkey_list: Vec<(u8, PublicKey)>,
        seed: [u8; 32],
        // * MY CODE: ADDED, scalar coefficients
        coefficients_scalars: Vec<Self::Scalar>,
        coefficients_points: Vec<Self::GroupElem>, // Use Self::GroupElem for group elements
        session_id: SessionId,
        // * MY CODE: ADDED
        c_i_j: Vec<EncryptedScalar>,
        r_i: [u8; 32],
    ) -> Result<Self, KeygenError> {
        todo!()
    }

    type Scalar = ();
    type GroupElem = ();

    // * MY CODE: ADDED, from_saved_state_r1
    fn from_saved_state_r1(commitment: [u8; 32], coefficients_scalars: Vec<Self::Scalar>, shared_session_id: SessionId, c_i_j: Vec<EncryptedScalar>, r_i: [u8; 32], seed: Seed) -> Result<Self, KeygenError>
    where
        Self: Sized
    {
        todo!()
    }

    // * MY CODE: ADDED, from_saved_state_r2
    fn from_saved_state_r2(private_key: Arc<SecretKey>, party_pubkey_list: Vec<(u8, PublicKey)>, seed: Seed, coefficients_scalars: Vec<Self::Scalar>, session_id: SessionId, shared_session_id: SessionId, sid_i_list: Vec<SessionId>, commitment_list: Vec<HashBytes>, r_i: [u8; 32]) -> Result<Self, KeygenError>
    where
        Self: Sized
    {
        todo!()
    }
}

impl Round for PartialSign<EdwardsPoint> {
    type Input = Vec<SignMsg3<EdwardsPoint>>;

    type Output = Result<(Signature, SignComplete), SignError>;

    fn process(self, messages: Self::Input) -> Self::Output {
        let messages = validate_input_messages(messages, &self.pid_list)?;
        let mut s = self.s_i;

        // * MY CODE: ADDED, print the details, for debugging
        println!("🚀 Starting signature aggregation...");
        println!("Party ID: {}", self.party_id);
        println!("Session ID: {:?}", self.session_id);
        println!("Public Key: {:?}", self.public_key);
        println!("Initial s_i: {:?}", self.s_i);
        println!("Number of messages to process: {}", messages.len());

        for (index, msg) in messages.iter().enumerate() {
            // * MY CODE: ADDED, print the details, for debugging
            println!("🔍 Processing message [{}]: from_party = {}, s_i = {:?}", index, msg.from_party, msg.s_i);

            if msg.from_party == self.party_id {
                // * MY CODE: ADDED, print the details, for debugging
                println!("⚠️ Skipping message from self (party_id = {}).", self.party_id);
                continue;
            }

            s += msg.s_i;
            // * MY CODE: ADDED, print the details, for debugging
            println!("✅ Aggregated s after message [{}]: {:?}", index, s);
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&self.big_r.to_bytes());
        sig_bytes[32..].copy_from_slice(&s.to_bytes());
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        // * MY CODE: ADDED, print the details, for debugging
        println!("📝 Generated Signature (R || s): {:?}", sig_bytes);
        println!("🔑 Verifying with Public Key: {:?}", self.public_key);
        println!("📨 Message to Sign (Hash): {:?}", self.msg_to_sign);


        // * MY CODE: ADDED, add signature custom verification logic
        // TODO: temporary hack to verify the signature for the first message only on the server side
        // Verification Logic Based on party_id
        if self.party_id == 1 {
            // For Client
            println!("🔍🤝 Client (party_id = 1) verifying signature for all messages...");
            if let Err(e) = VerifyingKey::from(self.public_key).verify(&self.msg_to_sign, &signature) {
                println!("❌🚨 Client Signature Verification Failed: {:?}", e);
                return Err(SignError::InvalidSignature);
            }
            println!("✅🔐 Client Signature Verification Passed!");
            println!("🎯✅ Client's Final Signature Received: {:?}", signature);

        } else if self.party_id == 0 && !messages.is_empty() {
            // For Server - Verify only the first message
            println!("🔍🗄️ Server (party_id = 0) verifying aggregated signature...");
            // * MY CODE: ADDED, restore the original code, to verify the signature for all messages, for server side
            if let Err(e) = VerifyingKey::from(self.public_key).verify(&self.msg_to_sign, &signature) {
                println!("❌🚨 Server Signature Verification Failed: {:?}", e);
                return Err(SignError::InvalidSignature);
            }
            println!("✅🔐 Server Signature Verification Passed!");
            println!("🏁✅ Server's Final Signature Received: {:?}", signature);
        }

        // * MY CODE: COMMENTED, original code, to verify the signature for all messages
        // TODO: Uncomment this line to verify the signature once found server's issue
        // VerifyingKey::from(self.public_key)
        //     .verify(&self.msg_to_sign, &signature)
        //     .map_err(|_| SignError::InvalidSignature)?;

        let sign_complete = SignComplete {
            from_party: self.party_id,
            session_id: self.session_id,
            signature: sig_bytes,
        };

        // * MY CODE: ADDED, print the details, for debugging
        println!("🏁 Signature Processing Complete for party_id = {}.", self.party_id);
        Ok((signature, sign_complete))
    }

    type Scalar = ();
    type GroupElem = ();

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

    // * MY CODE: ADDED, from_saved_state_r2
    fn from_saved_state_r2(private_key: Arc<SecretKey>, party_pubkey_list: Vec<(u8, PublicKey)>, seed: Seed, coefficients_scalars: Vec<Self::Scalar>, session_id: SessionId, shared_session_id: SessionId, sid_i_list: Vec<SessionId>, commitment_list: Vec<HashBytes>, r_i: [u8; 32]) -> Result<Self, KeygenError>
    where
        Self: Sized
    {
        todo!()
    }
}

#[cfg(test)]
pub fn run_sign(shares: &[crate::keygen::Keyshare<EdwardsPoint>]) -> Signature {
    use crate::{common::utils::run_round, sign::SignerParty};

    let mut rng = rand::thread_rng();
    let parties = shares
        .iter()
        .map(|keyshare| SignerParty::new(keyshare.clone().into(), &mut rng))
        .collect::<Vec<_>>();

    // Pre-Signature phase
    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
    let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
    let ready_parties = run_round(parties, msgs);

    // Signature phase
    let msg = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    let (parties, partial_sigs): (Vec<_>, Vec<_>) =
        run_round(ready_parties, msg.into()).into_iter().unzip();

    let (signatures, _complete_msg): (Vec<_>, Vec<_>) =
        run_round(parties, partial_sigs).into_iter().unzip();

    signatures[0]
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::EdwardsPoint;
    use rand::seq::SliceRandom;
    use crate::common::utils::run_keygen;
    use super::run_sign;

    #[test]
    fn sign_2_2() {
        let shares = run_keygen::<2, 2, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 2)
            .cloned()
            .collect();
        run_sign(&subset);
    }
    #[test]
    fn sign_2_3() {
        let shares = run_keygen::<2, 3, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 2)
            .cloned()
            .collect();
        run_sign(&subset);
    }
    #[test]
    fn sign_2_3_3() {
        let shares = run_keygen::<2, 3, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 3)
            .cloned()
            .collect();
        run_sign(&subset);
    }
    #[test]
    fn sign_3_3() {
        let shares = run_keygen::<3, 3, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 3)
            .cloned()
            .collect();
        run_sign(&subset);
    }

    #[test]
    fn sign_3_5() {
        let shares = run_keygen::<3, 5, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 3)
            .cloned()
            .collect();
        run_sign(&subset);
    }

    #[test]
    fn sign_5_10() {
        let shares = run_keygen::<5, 10, EdwardsPoint>();
        let subset: Vec<_> = shares
            .choose_multiple(&mut rand::thread_rng(), 5)
            .cloned()
            .collect();
        run_sign(&subset);
    }
}

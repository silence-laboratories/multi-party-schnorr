// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use js_sys::Error;
use rand::rngs::OsRng;
use wasm_bindgen::{prelude::*, throw_str};

use sl_mpc_mlsag::{
    dkg::{MlsagDkgContextR0, MlsagDkgContextR1, MlsagDkgContextR2, MlsagDkgContextR3},
    KeyshareMsg, MlsagDkgContext, MlsagDkgParty, MlsagKeyshare, VrfKeygenMsg1, VrfKeygenMsg2,
};

use crate::{
    keyshare::Keyshare,
    message::{Message, MessageRouting},
};

#[allow(clippy::large_enum_variant)]
enum KeygenRound {
    Init(MlsagDkgContext<MlsagDkgContextR0>),
    WaitMsg1(MlsagDkgContext<MlsagDkgContextR1>),
    WaitMsg2(MlsagDkgContext<MlsagDkgContextR2>),
    WaitMsg3(MlsagDkgContext<MlsagDkgContextR3>),
    Share { share: MlsagKeyshare },
    Failed { reason: String },
}

/// One party's MLSAG key-generation session.
///
/// The session lives in memory only and cannot be serialised: replaying a
/// round from a saved copy against different peer messages would reuse its
/// secret randomness. If a session is lost, every party starts a new one.
#[wasm_bindgen]
pub struct KeygenSession {
    round: KeygenRound,
    pending: Vec<Message>,
    total: usize,
    party_id: u8,
}

#[wasm_bindgen]
impl KeygenSession {
    /// Creates a new MLSAG key-generation session for a party.
    #[wasm_bindgen(constructor)]
    pub fn new(participants: u8, threshold: u8, party_id: u8) -> KeygenSession {
        let party = MlsagDkgContext::new(
            MlsagDkgParty::new(participants, threshold, party_id),
            &mut OsRng,
        );

        let party = match party {
            Ok(party) => party,
            Err(err) => throw_str(&err.to_string()),
        };

        KeygenSession {
            round: KeygenRound::Init(party),
            pending: vec![],
            total: participants as usize,
            party_id,
        }
    }

    /// Returns the protocol error that caused the session to fail, if
    /// any.
    #[wasm_bindgen(js_name = error)]
    pub fn error(&self) -> Option<Error> {
        match &self.round {
            KeygenRound::Failed { reason } => Some(Error::new(reason)),
            _ => None,
        }
    }

    /// Produces the first broadcast message of the DKG protocol. Calling this
    /// again after success, or after a failure, returns an error and marks the
    /// session as failed.
    #[wasm_bindgen(js_name = createFirstMessage)]
    pub fn create_first_message(&mut self) -> Message {
        let party = match core::mem::replace(
            &mut self.round,
            KeygenRound::Failed {
                reason: "invalid state".into(),
            },
        ) {
            KeygenRound::Init(party) => party,
            KeygenRound::Failed { reason } => {
                self.round = KeygenRound::Failed { reason };
                throw_str("failed");
            }
            other => {
                self.round = other;
                throw_str("invalid state");
            }
        };

        match party.round1_out(&mut OsRng) {
            Ok((next, msg)) => {
                self.round = KeygenRound::WaitMsg1(next);
                let msg = Message::encode(msg);
                self.pending.push(msg.clone());
                msg
            }
            Err(err) => self.fail(err),
        }
    }

    /// Buffers an incoming peer message and drives the protocol once a full
    /// round of messages has been collected. When the batch completes, the
    /// method returns the next messages for the caller to relay; otherwise
    /// it returns an empty list while waiting for more input.
    #[wasm_bindgen(js_name = receiveMessage)]
    pub fn recv_message(&mut self, msg: Message) -> Vec<Message> {
        self.pending.push(msg);

        if self.pending.len() == self.total {
            let messages = core::mem::take(&mut self.pending);
            let next = self.handle_messages(messages);
            for m in &next {
                // receive own broadcast and self-addressed messages
                if m.dst_party_id().is_none() || m.dst_party_id() == Some(self.party_id) {
                    self.pending.push(m.clone());
                }
            }
            return next;
        }

        vec![]
    }

    /// Consumes the session and returns the final key share once the
    /// protocol completes. Attempting to call this early yields an
    /// error.
    #[wasm_bindgen(js_name = keyshare)]
    pub fn into_keyshare(self) -> Keyshare {
        match self.round {
            KeygenRound::Share { share } => Keyshare::new(share),
            KeygenRound::Failed { .. } => throw_str("failed"),
            _ => throw_str("keygen-in-progress"),
        }
    }

    #[wasm_bindgen(js_name = isFinished)]
    pub fn is_finished(&self) -> bool {
        matches!(
            &self.round,
            KeygenRound::Share { .. } | KeygenRound::Failed { .. }
        )
    }

    pub fn state_name(&self) -> String {
        match &self.round {
            KeygenRound::Init(_) => String::from("init"),
            KeygenRound::WaitMsg1(_) => String::from("wait1"),
            KeygenRound::WaitMsg2(_) => String::from("wait2"),
            KeygenRound::WaitMsg3(_) => String::from("wait3"),
            KeygenRound::Share { .. } => String::from("share"),
            KeygenRound::Failed { .. } => String::from("failed"),
        }
    }
}

impl KeygenSession {
    fn handle_messages(&mut self, messages: Vec<Message>) -> Vec<Message> {
        match core::mem::replace(
            &mut self.round,
            KeygenRound::Failed {
                reason: "invalid state".into(),
            },
        ) {
            KeygenRound::WaitMsg1(party) => {
                let msgs = Message::decode_vec::<VrfKeygenMsg1>(&messages);
                match party.round1_in(&mut OsRng, msgs) {
                    Ok((next, msgs)) => {
                        self.round = KeygenRound::WaitMsg2(next);
                        Message::encode_vec(msgs)
                    }
                    Err(err) => self.fail(err),
                }
            }

            KeygenRound::WaitMsg2(party) => {
                let msgs = Message::decode_vec::<VrfKeygenMsg2>(&messages);
                match party.round2_in(&mut OsRng, msgs) {
                    Ok((next, msg)) => {
                        self.round = KeygenRound::WaitMsg3(next);
                        vec![Message::encode(msg)]
                    }
                    Err(err) => self.fail(err),
                }
            }

            KeygenRound::WaitMsg3(party) => {
                let msgs = Message::decode_vec::<KeyshareMsg>(&messages);
                match party.round3_in(msgs) {
                    Ok(share) => {
                        self.round = KeygenRound::Share { share };
                        vec![]
                    }
                    Err(err) => self.fail(err),
                }
            }

            KeygenRound::Failed { reason } => {
                self.round = KeygenRound::Failed { reason };
                throw_str("failed");
            }

            other => {
                self.round = other;
                throw_str("invalid state");
            }
        }
    }

    fn fail(&mut self, err: impl std::error::Error) -> ! {
        let reason = format!("party: {} {}", self.party_id, err);
        self.round = KeygenRound::Failed {
            reason: reason.clone(),
        };
        throw_str(&reason);
    }
}

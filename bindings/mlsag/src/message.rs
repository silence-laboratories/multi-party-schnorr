// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::{prelude::*, UnwrapThrowExt};

use sl_mpc_mlsag::{KeyshareMsg, SignMsg1, SignMsg2, SignMsg3, VrfKeygenMsg1, VrfKeygenMsg2};

pub trait MessageRouting {
    fn src_party_id(&self) -> u8;
    fn dst_party_id(&self) -> Option<u8>;
}

#[derive(Clone)]
#[wasm_bindgen]
pub struct Message {
    from_id: u8,
    to_id: Option<u8>,
    payload: Vec<u8>,
}

#[wasm_bindgen]
impl Message {
    /// Creates a new message wrapper with the provided payload and sender id.
    #[wasm_bindgen(constructor)]
    pub fn new(payload: Vec<u8>, from: u8) -> Self {
        Self {
            from_id: from,
            to_id: None,
            payload,
        }
    }

    /// Returns a copy of the CBOR-encoded payload.
    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }

    /// Returns the identifier of the party that produced the message.
    #[wasm_bindgen(js_name = sender)]
    pub fn sender(&self) -> u8 {
        self.from_id
    }

    /// Returns the receiver identifier or undefined for broadcast messages.
    #[wasm_bindgen(js_name = receiver)]
    pub fn receiver(&self) -> Option<u8> {
        self.to_id
    }

    /// Creates a deep copy of the message so it can be forwarded to
    /// additional sessions.
    #[wasm_bindgen(js_name = clone)]
    pub fn clone_message(&self) -> Message {
        Message {
            from_id: self.from_id,
            to_id: self.to_id,
            payload: self.payload.clone(),
        }
    }
}

impl Message {
    /// Serialises a protocol message into the transferable `Message` wrapper.
    pub fn encode<T: Serialize + MessageRouting>(msg: T) -> Self {
        let mut buffer = vec![];
        ciborium::into_writer(&msg, &mut buffer).expect_throw("CBOR serialization failure");
        Message {
            from_id: msg.src_party_id(),
            to_id: msg.dst_party_id(),
            payload: buffer,
        }
    }

    /// Deserialises the contained payload into the requested type.
    pub fn decode<T: DeserializeOwned>(&self) -> T {
        ciborium::from_reader(self.payload.as_slice()).expect_throw("CBOR decode failure")
    }

    /// Convenience helper that decodes a slice of messages into strongly typed
    /// protocol payloads.
    pub fn decode_vec<T: DeserializeOwned>(msgs: &[Message]) -> Vec<T> {
        msgs.iter().map(Self::decode).collect()
    }

    /// Serialises a vector of protocol payloads into transferable messages.
    pub fn encode_vec<T: Serialize + MessageRouting>(msgs: Vec<T>) -> Vec<Message> {
        msgs.into_iter().map(Self::encode).collect()
    }
}

impl MessageRouting for VrfKeygenMsg1 {
    fn src_party_id(&self) -> u8 {
        self.from_party
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}

/// Carries the recipient's Shamir share: the host must encrypt it to
/// `to_party` and sign it as `from_party`.
impl MessageRouting for VrfKeygenMsg2 {
    fn src_party_id(&self) -> u8 {
        self.from_party
    }

    fn dst_party_id(&self) -> Option<u8> {
        Some(self.to_party)
    }
}

impl MessageRouting for KeyshareMsg {
    fn src_party_id(&self) -> u8 {
        self.from_party
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}

impl MessageRouting for SignMsg1 {
    fn src_party_id(&self) -> u8 {
        self.from_party
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}

impl MessageRouting for SignMsg2 {
    fn src_party_id(&self) -> u8 {
        self.from_party
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}

impl MessageRouting for SignMsg3 {
    fn src_party_id(&self) -> u8 {
        self.from_party
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}

impl MessageRouting for Message {
    fn src_party_id(&self) -> u8 {
        self.from_id
    }

    fn dst_party_id(&self) -> Option<u8> {
        self.to_id
    }
}

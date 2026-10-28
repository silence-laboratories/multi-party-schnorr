// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::sync::Arc;

use wasm_bindgen::{prelude::*, UnwrapThrowExt};

use sl_mpc_mlsag::MlsagKeyshare;

#[wasm_bindgen]
pub struct Keyshare {
    inner: Arc<MlsagKeyshare>,
}

impl Keyshare {
    pub(crate) fn new(inner: MlsagKeyshare) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    pub(crate) fn as_inner(&self) -> &MlsagKeyshare {
        self.inner.as_ref()
    }
}

#[wasm_bindgen]
impl Keyshare {
    /// Restores a key share that was previously serialised with
    /// [`to_bytes`](Self::to_bytes).
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Keyshare, JsError> {
        let inner = ciborium::from_reader(bytes.as_slice()).expect_throw("CBOR decode error");
        Ok(Keyshare {
            inner: Arc::new(inner),
        })
    }

    /// Serialises the key share into CBOR so it can be persisted or moved
    /// between environments.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        ciborium::into_writer(self.inner.as_ref(), &mut buffer).expect_throw("CBOR encode error");
        buffer
    }

    /// Returns the compressed Ristretto onetime public key `P = x·G`.
    #[wasm_bindgen(js_name = publicKey, getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key().compress().to_bytes().to_vec()
    }

    /// Returns the compressed key image `I = x·H_p(P)` shared by every party.
    #[wasm_bindgen(js_name = keyImage, getter)]
    pub fn key_image(&self) -> Vec<u8> {
        self.inner.key_image().as_bytes().to_vec()
    }

    /// Returns the signing threshold encoded on the share.
    #[wasm_bindgen(js_name = threshold, getter)]
    pub fn threshold(&self) -> u8 {
        self.inner.threshold
    }

    /// Returns the total number of participants that took part in the DKG.
    #[wasm_bindgen(js_name = participants, getter)]
    pub fn participants(&self) -> u8 {
        self.inner.total_parties
    }

    /// Returns the numeric party id that owns this share.
    #[wasm_bindgen(js_name = partyId, getter)]
    pub fn party_id(&self) -> u8 {
        self.inner.party_id
    }

    /// Returns the key identifier that uniquely identifies the signing group.
    #[wasm_bindgen(js_name = keyId, getter)]
    pub fn key_id(&self) -> Vec<u8> {
        self.inner.key_id.to_vec()
    }

    /// Returns the root chain code derived during DKG.
    #[wasm_bindgen(js_name = rootChainCode, getter)]
    pub fn root_chain_code(&self) -> Vec<u8> {
        self.inner.root_chain_code.to_vec()
    }
}

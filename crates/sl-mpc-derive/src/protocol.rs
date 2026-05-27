// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

pub const SCALAR_FIELD_BITS: usize = 256;
pub const STAT_SEC_PARAM_BITS: usize = 128;
pub const VRF_CHAINCODE_BITS: usize = 256;
pub const VRF_OUTPUT_BITS: usize = SCALAR_FIELD_BITS + STAT_SEC_PARAM_BITS + VRF_CHAINCODE_BITS;
pub const VRF_OUTPUT_LEN: usize = VRF_OUTPUT_BITS.div_ceil(8);
pub const HARD_DERIVE_DELTA_BITS: usize = SCALAR_FIELD_BITS + STAT_SEC_PARAM_BITS;
pub const HARD_DERIVE_CHAINCODE_BITS: usize = VRF_CHAINCODE_BITS;
pub const HARD_DERIVE_VRF_OUTPUT_BITS: usize = VRF_OUTPUT_BITS;
pub const HARD_DERIVE_DELTA_BYTES: usize = HARD_DERIVE_DELTA_BITS.div_ceil(8);
pub const HARD_DERIVE_CHAINCODE_BYTES: usize = HARD_DERIVE_CHAINCODE_BITS.div_ceil(8);
pub const ED25519_SCALAR_FIELD_BITS: usize = SCALAR_FIELD_BITS;
pub const ED25519_VRF_OUTPUT_BITS: usize = VRF_OUTPUT_BITS;
pub const ED25519_VRF_OUTPUT_LEN: usize = VRF_OUTPUT_LEN;

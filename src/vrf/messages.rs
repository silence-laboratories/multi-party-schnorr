// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crate::common::utils::BaseMessage;

pub use sl_mpc_vrf::messages::VrfMsg0;
pub use sl_mpc_vrf::messages::VrfMsg1;

impl BaseMessage for VrfMsg1 {
    fn party_id(&self) -> u8 {
        self.from_party
    }
}

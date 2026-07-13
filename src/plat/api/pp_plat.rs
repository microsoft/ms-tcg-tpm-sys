// Copyright (C) Microsoft Corporation. All rights reserved.

//! PPPlat.c

use super::super::MsTpm185PlatformImpl;

impl MsTpm185PlatformImpl {
    fn physical_presence_asserted(&mut self) -> bool {
        false
    }
}

mod c_api {
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__PhysicalPresenceAsserted() -> i32 {
        platform!().physical_presence_asserted() as i32
    }

    // NOTE: _plat__Signal_PhysicalPresenceOn / _plat__Signal_PhysicalPresenceOff
    // were only ever called by the upstream simulator and are not part of the
    // v1.85 platform interface that the core library uses.
}

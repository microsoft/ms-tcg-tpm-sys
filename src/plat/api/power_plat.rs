// Copyright (C) Microsoft Corporation. All rights reserved.

//! PowerPlat.c

use serde::Deserialize;
use serde::Serialize;

use crate::error::Error;

use super::super::MsTpm184PlatformImpl;

#[derive(Clone, Serialize, Deserialize)]
pub struct PowerPlatState {
    power_lost: bool,
}

impl PowerPlatState {
    pub fn new() -> PowerPlatState {
        PowerPlatState { power_lost: false }
    }
}

impl MsTpm184PlatformImpl {
    pub fn signal_power_on(&mut self) -> Result<(), Error> {
        self.timer_reset();
        self.state.power_plat.power_lost = true;
        self.nv_enable()?;
        Ok(())
    }

    pub fn signal_power_off(&mut self) {
        self.nv_disable(false);
        self.act_enable_ticks(false);
    }

    fn was_power_lost(&mut self) -> bool {
        let ret = self.state.power_plat.power_lost;
        self.state.power_plat.power_lost = false;
        ret
    }
}

mod c_api {
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__WasPowerLost() -> i32 {
        platform!().was_power_lost() as i32
    }

    // NOTE: _plat__Signal_PowerOn, _plat__Signal_PowerOff, and _plat__Signal_Reset
    // were only ever called by the upstream simulator. Power transitions are now
    // driven from Rust via MsTpm184Platform::{initialize,reset,drop}, which
    // call signal_power_on() / signal_power_off() directly. Reset goes through
    // MsTpm184Platform::reset which calls _TPM_Init explicitly outside the
    // platform mutex.
}

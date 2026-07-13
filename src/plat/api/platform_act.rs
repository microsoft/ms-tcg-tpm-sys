// Copyright (C) Microsoft Corporation. All rights reserved.

//! PlatformACT.c

use super::super::MsTpm185PlatformImpl;

// TODO: model ACTs using `PlatformCallbacks`?
impl MsTpm185PlatformImpl {
    fn act_get_implemented(&mut self, _act: u32) -> bool {
        true // must report true, or else TPM_Manufacture fails
    }

    fn act_get_remaining(&mut self, _act: u32) -> u32 {
        0
    }

    fn act_get_signaled(&mut self, _act: u32) -> i32 {
        0
    }

    fn act_set_signaled(&mut self, _act: u32, _on: i32) {}

    fn act_update_counter(&mut self, _act: u32, _new_value: u32) -> bool {
        true
    }

    pub fn act_enable_ticks(&mut self, _enable: bool) {}

    fn act_initialize(&mut self) -> bool {
        false
    }
}

mod c_api {
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__ACT_GetImplemented(act: u32) -> i32 {
        platform!().act_get_implemented(act) as i32
    }

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__ACT_GetRemaining(act: u32) -> u32 {
        platform!().act_get_remaining(act)
    }

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__ACT_GetSignaled(act: u32) -> i32 {
        platform!().act_get_signaled(act)
    }

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__ACT_SetSignaled(act: u32, on: i32) {
        platform!().act_set_signaled(act, on)
    }

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__ACT_UpdateCounter(act: u32, new_value: u32) -> i32 {
        platform!().act_update_counter(act, new_value) as i32
    }

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__ACT_EnableTicks(enable: i32) {
        platform!().act_enable_ticks(enable != 0)
    }

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__ACT_Initialize() -> i32 {
        platform!().act_initialize() as i32
    }

    // NOTE: _plat__ACT_GetPending and _plat__ACT_Tick were only ever called by
    // the upstream simulator and are not part of the v1.85 platform interface
    // that the core library uses.
}

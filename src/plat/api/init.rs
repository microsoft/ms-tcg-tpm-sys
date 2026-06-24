// Copyright (C) Microsoft Corporation. All rights reserved.

//! Init.c
//!
//! TPM init notification hooks. The core library calls `_plat__StartTpmInit`
//! at the very start of `_TPM_Init()` and `_plat__EndOkTpmInit` at the very
//! end of a successful init. We have no per-init platform state to bring up,
//! so these are no-ops.

mod c_api {
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__StartTpmInit() {}

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__EndOkTpmInit() {}
}

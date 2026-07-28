// Copyright (C) Microsoft Corporation. All rights reserved.

//! Init.c
//!
//! TPM init notification hooks. The core library calls `_plat__StartTpmInit`
//! at the very start of `_TPM_Init()` and `_plat__EndOkTpmInit` at the very
//! end of a successful init.

mod c_api {
    #[unsafe(export_name = "ms_tcg_tpm_185__plat__StartTpmInit")]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn plat_start_tpm_init() {
        platform!().reset_failure();
    }

    #[unsafe(export_name = "ms_tcg_tpm_185__plat__EndOkTpmInit")]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn plat_end_ok_tpm_init() {}
}

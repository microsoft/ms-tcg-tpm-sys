// Copyright (C) Microsoft Corporation. All rights reserved.

//! SelfTest.c
//!
//! Allows the platform to tweak which self-tests run on SelfTest. We let the
//! core library run whatever the caller passes in (the `pToTestVector` buffer
//! is pre-populated with the algorithms the library tracks).

use core::ffi::c_void;

mod c_api {
    use super::c_void;

    #[unsafe(export_name = "ms_tcg_tpm_185__plat_GetEnabledSelfTest")]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn plat_get_enabled_self_test(
        _full_test: u8,
        _p_to_test_vector: *mut c_void,
        _to_test_vector_size: usize,
    ) {
        // No platform-specific gating: leave the test vector untouched.
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Failure.c
//!
//! Platform failure-mode state. The core library calls into the platform to
//! record and query failure mode (e.g. `FAIL(...)` macros eventually invoke
//! `_plat__Fail`, and the library then queries `_plat__InFailureMode`).

use serde::Deserialize;
use serde::Serialize;

use super::super::MsTpm185PlatformImpl;

#[derive(Clone, Serialize, Deserialize)]
pub struct FailureState {
    failure_code: u32,
    failure_location: u64,
    in_failure_mode: bool,
}

impl FailureState {
    pub fn new() -> FailureState {
        FailureState {
            failure_code: 0,
            failure_location: 0,
            in_failure_mode: false,
        }
    }
}

impl MsTpm185PlatformImpl {
    pub(super) fn reset_failure(&mut self) {
        self.state.failure = FailureState::new();
    }

    fn fail(&mut self, location_code: u64, failure_code: i32) {
        if !self.state.failure.in_failure_mode {
            self.state.failure.failure_code = failure_code as u32;
            self.state.failure.failure_location = location_code;
            self.state.failure.in_failure_mode = true;
        }
    }

    fn in_failure_mode(&self) -> bool {
        self.state.failure.in_failure_mode
    }

    fn failure_code(&self) -> u32 {
        self.state.failure.failure_code
    }

    fn failure_location(&self) -> u64 {
        self.state.failure.failure_location
    }
}

mod c_api {
    /// Records the first failure reported by the TPM library.
    #[unsafe(export_name = "ms_tcg_tpm_185__plat__Fail")]
    #[tracing::instrument(level = "trace", skip(_function))]
    pub unsafe extern "C" fn plat_fail(
        _function: *const std::ffi::c_char,
        _line: i32,
        location_code: u64,
        failure_code: i32,
    ) {
        platform!().fail(location_code, failure_code);
    }

    /// Indicates to the TPM library that a failure has occurred.
    #[unsafe(export_name = "ms_tcg_tpm_185__plat__InFailureMode")]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn plat_in_failure_mode() -> i32 {
        platform!().in_failure_mode() as i32
    }

    /// Vendor-defined failure-reason code reported via TPM2_GetTestResult.
    #[unsafe(export_name = "ms_tcg_tpm_185__plat__GetFailureCode")]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn plat_get_failure_code() -> u32 {
        platform!().failure_code()
    }

    /// Vendor-defined 64-bit location code reported via TPM2_GetTestResult.
    #[unsafe(export_name = "ms_tcg_tpm_185__plat__GetFailureLocation")]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn plat_get_failure_location() -> u64 {
        platform!().failure_location()
    }
}

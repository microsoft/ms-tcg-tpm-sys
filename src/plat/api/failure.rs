// Copyright (C) Microsoft Corporation. All rights reserved.

//! Failure.c
//!
//! Platform failure-mode state. The core library calls into the platform to
//! record and query failure mode (e.g. `FAIL(...)` macros eventually invoke
//! `_plat__Fail`, and the library then queries `_plat__InFailureMode`).
//!
//! The Rust wrapper owns the `_plat__Fail`/longjmp path inside
//! `src/plat/RunCommand.c`, so here we only need to expose enough state for
//! the core library to ask whether we are in failure mode.

mod c_api {
    /// Indicates to the TPM library that a failure has occurred.
    ///
    /// We never enter failure mode from the Rust platform layer, so this
    /// always returns `FALSE`.
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__InFailureMode() -> i32 {
        // BOOL = int; FALSE = 0
        0
    }

    /// Vendor-defined failure-reason code reported via TPM2_GetTestResult.
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__GetFailureCode() -> u32 {
        0
    }

    /// Vendor-defined 64-bit location code reported via TPM2_GetTestResult.
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__GetFailureLocation() -> u64 {
        0
    }
}

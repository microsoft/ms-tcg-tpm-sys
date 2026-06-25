// Copyright (C) Microsoft Corporation. All rights reserved.

//! NVVirtual.c
//!
//! "Virtual" NV indices are platform-synthesized NV indices used by some
//! reference implementations for things like baked-in EK certificates. The
//! Rust platform stores everything in regular NV, so we report "no virtual
//! indices" and the rest of these entry points are unreachable.
//!
//! Note: these symbols are unconditional in v1.84 — the core library calls
//! them through a runtime check (`if (_plat__IsNvVirtualIndex(...)) { ... }`),
//! not behind a `#if EXTERNAL_NV` guard. So even with `EXTERNAL_NV NO`, the
//! symbols still need to exist for linking.

use core::ffi::c_void;

// TPM_RC = UINT32. RC_VER1 = 0x100, TPM_RC_NO_RESULT = RC_VER1 + 0x054.
const TPM_RC_NO_RESULT: u32 = 0x154;

// TPMI_YES_NO = BYTE. NO = 0.
const TPMI_NO: u8 = 0;

// BOOL = int. FALSE = 0.
const BOOL_FALSE: i32 = 0;

mod c_api {
    use super::*;

    /// Report whether `handle` refers to a platform-virtualized NV index.
    /// We never advertise virtual indices, so this is always FALSE — which in
    /// turn means the `_plat__NvVirtual_*` entry points below are unreachable.
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__IsNvVirtualIndex(_handle: u32) -> i32 {
        BOOL_FALSE
    }

    /// Report whether a given command code accepts virtual NV handles.
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__NvOperationAcceptsVirtualHandles(_command_code: u32) -> i32 {
        BOOL_FALSE
    }

    /// Populate a virtual NV index's public area and auth value. Unreachable
    /// (gated at runtime by `_plat__IsNvVirtualIndex`).
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__NvVirtual_PopulateNvIndexInfo(
        _handle: u32,
        _public_area: *mut c_void,
        _auth_value: *mut c_void,
    ) -> u32 {
        TPM_RC_NO_RESULT
    }

    /// Service `TPM2_NV_Read` for a virtual index. Unreachable.
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__NvVirtual_Read(_in: *mut c_void, _out: *mut c_void) -> u32 {
        TPM_RC_NO_RESULT
    }

    /// Service `TPM2_NV_ReadPublic` for a virtual index. Unreachable.
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__NvVirtual_ReadPublic(
        _in: *mut c_void,
        _out: *mut c_void,
    ) -> u32 {
        TPM_RC_NO_RESULT
    }

    /// Append virtual-NV handles to a `GetCapability` list. We have none.
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__NvVirtual_CapGetIndex(
        _handle: u32,
        _count: u32,
        _handle_list: *mut c_void,
    ) -> u8 {
        TPMI_NO
    }
}

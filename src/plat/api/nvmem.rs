// Copyright (C) Microsoft Corporation. All rights reserved.

//! NVMem.c

use serde::Deserialize;
use serde::Serialize;

use crate::error::Error;

use super::super::MsTpm185PlatformImpl;

/// The size of the non-volatile memory.
///
/// The TPM library is compiled with this as its `NV_MEMORY_SIZE` and has no way
/// to ask the platform how much NV memory actually exists, so it reads and
/// writes anywhere in this range. The platform's NV region must therefore be
/// exactly this size, and a region of any other size is rejected with
/// [`NvError::MismatchedBlobSize`].
pub const NV_MEMORY_SIZE: usize = 128 * 1024; // 128 KiB

#[derive(Clone, Serialize, Deserialize)]
pub struct NvState {
    region: Vec<u8>,
    pub is_init: bool,
}

impl NvState {
    pub fn new() -> NvState {
        NvState {
            region: vec![0; NV_MEMORY_SIZE],
            is_init: false,
        }
    }
}

#[derive(Debug)]
/// An error that can occur when working with non-volatile memory.
pub enum NvError {
    /// The non-volatile memory is already initialized.
    AlreadyInitialized,
    /// The size of the non-volatile memory does not match the size the TPM
    /// library was built for.
    MismatchedBlobSize {
        /// The size the TPM library was built for, i.e. [`NV_MEMORY_SIZE`].
        pub expected: usize,
        /// The size that was provided.
        pub actual: usize,
    },
    /// An invalid access was attempted.
    InvalidAccess {
        /// The starting offset of the invalid access.
        start_offset: usize,
        /// The length of the invalid access.
        len: usize,
    },
}

impl From<NvError> for Error {
    fn from(e: NvError) -> Error {
        Error::NvMem(e)
    }
}

/// Check that an NV region is the size the TPM library was built for.
///
/// The library has no runtime way to learn how much NV memory the platform
/// provides: it is compiled with [`NV_MEMORY_SIZE`] and reads and writes
/// anywhere in that range.
///
/// A shorter region does not fail cleanly. `NvRead()` returns `void` and simply
/// skips the read when the platform rejects it, so the library carries on using
/// whatever was already in the caller's stack buffer.
pub fn validate_nv_size(size: usize) -> Result<(), Error> {
    if size != NV_MEMORY_SIZE {
        return Err(NvError::MismatchedBlobSize {
            expected: NV_MEMORY_SIZE,
            actual: size,
        }
        .into());
    }

    Ok(())
}

#[expect(dead_code)]
enum NvAvailability {
    Available = 0,    // NV_READY
    WriteFailure = 1, // NV_WRITEFAILURE
    RateLimit = 2,    // NV_RATE_LIMIT
}

impl MsTpm185PlatformImpl {
    pub fn nv_enable_from_blob(&mut self, blob: &[u8]) -> Result<(), Error> {
        if self.state.nvmem.is_init {
            return Err(NvError::AlreadyInitialized.into());
        }

        validate_nv_size(blob.len())?;

        self.state.nvmem.region = blob.to_vec();
        self.state.nvmem.is_init = true;

        Ok(())
    }

    pub fn nv_enable(&mut self) -> Result<(), Error> {
        // This may be called after nv_enable_from_blob, so don't error if we're
        // already initialized
        if !self.state.nvmem.is_init {
            self.state.nvmem.region = vec![0; NV_MEMORY_SIZE];
            self.state.nvmem.is_init = true;
        }

        Ok(())
    }

    pub fn nv_disable(&mut self) {
        self.state.nvmem.is_init = false;
    }

    fn is_nv_available(&mut self) -> NvAvailability {
        NvAvailability::Available
    }

    fn nv_range(&mut self, start_offset: usize, len: usize) -> Result<&mut [u8], Error> {
        match self
            .state
            .nvmem
            .region
            .get_mut(start_offset..(start_offset + len))
        {
            Some(region) => Ok(region),
            None => Err(NvError::InvalidAccess { start_offset, len }.into()),
        }
    }

    fn nv_memory_read(&mut self, start_offset: usize, buf: &mut [u8]) -> Result<(), Error> {
        match self.nv_range(start_offset, buf.len()) {
            Ok(region) => {
                buf.copy_from_slice(region);
                Ok(())
            }
            Err(e) => {
                // `NvRead()` is `void` and discards this failure, leaving the
                // library to carry on with whatever `buf` already held. Zero it
                // rather than leaving it uninitialized.
                buf.fill(0);
                Err(e)
            }
        }
    }

    fn nv_is_different(&mut self, start_offset: usize, buf: &[u8]) -> Result<bool, Error> {
        let is_different = self.nv_range(start_offset, buf.len())? != buf;
        Ok(is_different)
    }

    fn nv_memory_write(&mut self, start_offset: usize, buf: &[u8]) -> Result<(), Error> {
        self.nv_range(start_offset, buf.len())?.copy_from_slice(buf);
        Ok(())
    }

    fn nv_memory_clear(&mut self, start_offset: usize, size: usize) -> Result<(), Error> {
        self.nv_range(start_offset, size)?.fill(0);
        Ok(())
    }

    fn nv_memory_move(
        &mut self,
        source_offset: usize,
        dest_offset: usize,
        size: usize,
    ) -> Result<(), Error> {
        if source_offset + size > self.state.nvmem.region.len() {
            return Err(NvError::InvalidAccess {
                start_offset: source_offset,
                len: size,
            }
            .into());
        }

        if dest_offset + size > self.state.nvmem.region.len() {
            return Err(NvError::InvalidAccess {
                start_offset: dest_offset,
                len: size,
            }
            .into());
        }

        self.state
            .nvmem
            .region
            .copy_within(source_offset..(source_offset + size), dest_offset);

        Ok(())
    }

    fn nv_commit(&mut self) -> Result<(), Error> {
        self.callbacks
            .commit_nv_state(&self.state.nvmem.region)
            .map_err(Error::PlatformCallback)
    }
}

mod c_api {
    use core::ffi::c_void;

    #[unsafe(export_name = "ms_tcg_tpm_185__plat__NVEnable")]
    #[tracing::instrument(level = "trace", ret)]
    pub unsafe extern "C" fn plat_nv_enable(plat_parameter: *mut c_void) -> i32 {
        match platform!().nv_enable() {
            Ok(()) => 0,
            Err(e) => {
                tracing::error!("error calling _plat__NVEnable({:?}): {}", plat_parameter, e);
                -1 // TODO: assign different error IDs to each error variant?
            }
        }
    }

    #[unsafe(export_name = "ms_tcg_tpm_185__plat__GetNvReadyState")]
    #[tracing::instrument(level = "trace", ret)]
    pub unsafe extern "C" fn plat_get_nv_ready_state() -> i32 {
        platform!().is_nv_available() as i32
    }

    #[unsafe(export_name = "ms_tcg_tpm_185__plat__NvMemoryRead")]
    #[tracing::instrument(level = "trace", ret)]
    pub unsafe extern "C" fn plat_nv_memory_read(
        start_offset: u32,
        size: u32,
        data: *mut c_void,
    ) -> i32 {
        assert!(!data.is_null());

        // SAFETY: caller ensures `data` and `size` are valid
        let buf = unsafe { core::slice::from_raw_parts_mut(data.cast(), size as usize) };

        match platform!().nv_memory_read(start_offset as usize, buf) {
            Ok(()) => true as i32,
            Err(e) => {
                tracing::error!(
                    "error calling _plat__NvMemoryRead(start_offset: {:#x?}, size: {:#x?}, data: {:?}): {}",
                    start_offset,
                    size,
                    data,
                    e
                );
                false as i32
            }
        }
    }

    #[unsafe(export_name = "ms_tcg_tpm_185__plat__NvGetChangedStatus")]
    #[tracing::instrument(level = "trace", ret)]
    pub unsafe extern "C" fn plat_nv_get_changed_status(
        start_offset: u32,
        size: u32,
        data: *mut c_void,
    ) -> i32 {
        const NV_INVALID_LOCATION: i32 = -1;

        assert!(!data.is_null());

        // SAFETY: caller ensures `data` and `size` are valid
        let buf = unsafe { core::slice::from_raw_parts(data as *const u8, size as usize) };

        match platform!().nv_is_different(start_offset as usize, buf) {
            Ok(is_diff) => is_diff as i32,
            Err(e) => {
                tracing::error!(
                    "error calling _plat__NvGetChangedStatus(start_offset: {:#x?}, size: {:#x?}, data: {:?}): {}",
                    start_offset,
                    size,
                    data,
                    e
                );
                NV_INVALID_LOCATION
            }
        }
    }

    #[unsafe(export_name = "ms_tcg_tpm_185__plat__NvMemoryWrite")]
    #[tracing::instrument(level = "trace", ret)]
    pub unsafe extern "C" fn plat_nv_memory_write(
        start_offset: u32,
        size: u32,
        data: *mut c_void,
    ) -> i32 {
        assert!(!data.is_null());

        // SAFETY: caller ensures `data` and `size` are valid
        let buf = unsafe { core::slice::from_raw_parts(data as *const u8, size as usize) };

        match platform!().nv_memory_write(start_offset as usize, buf) {
            Ok(()) => true as i32,
            Err(e) => {
                tracing::error!(
                    "error calling _plat__NvMemoryWrite(start_offset: {:#x?}, size: {:#x?}, data: {:?}): {}",
                    start_offset,
                    size,
                    data,
                    e
                );
                false as i32
            }
        }
    }

    #[unsafe(export_name = "ms_tcg_tpm_185__plat__NvMemoryClear")]
    #[tracing::instrument(level = "trace", ret)]
    pub unsafe extern "C" fn plat_nv_memory_clear(start: u32, size: u32) -> i32 {
        match platform!().nv_memory_clear(start as usize, size as usize) {
            Ok(()) => true as i32,
            Err(e) => {
                tracing::error!(
                    "error calling _plat__NvMemoryClear(start: {:#x?}, size: {:#x?}): {}",
                    start,
                    size,
                    e
                );
                false as i32
            }
        }
    }

    #[unsafe(export_name = "ms_tcg_tpm_185__plat__NvMemoryMove")]
    #[tracing::instrument(level = "trace", ret)]
    pub unsafe extern "C" fn plat_nv_memory_move(
        source_offset: u32,
        dest_offset: u32,
        size: u32,
    ) -> i32 {
        match platform!().nv_memory_move(
            source_offset as usize,
            dest_offset as usize,
            size as usize,
        ) {
            Ok(()) => true as i32,
            Err(e) => {
                tracing::error!(
                    "error calling _plat__NvMemoryMove(source_offset: {:#x?}, dest_offset: {:#x?}, size: {:#x?}): {}",
                    source_offset,
                    dest_offset,
                    size,
                    e
                );
                false as i32
            }
        }
    }

    #[unsafe(export_name = "ms_tcg_tpm_185__plat__NvCommit")]
    #[tracing::instrument(level = "trace", ret)]
    pub unsafe extern "C" fn plat_nv_commit() -> i32 {
        match platform!().nv_commit() {
            Ok(()) => 0,
            Err(e) => {
                tracing::error!("error calling _plat__NvCommit(): {}", e);
                1
            }
        }
    }

    #[unsafe(export_name = "ms_tcg_tpm_185__plat__TearDown")]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn plat_teardown() {}
}

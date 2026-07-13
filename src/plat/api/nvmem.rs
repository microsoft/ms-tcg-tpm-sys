// Copyright (C) Microsoft Corporation. All rights reserved.

//! NVMem.c

use serde::Deserialize;
use serde::Serialize;

use crate::error::Error;

use super::super::MsTpm185PlatformImpl;

/// The size of the non-volatile memory.
pub const NV_MEMORY_SIZE: usize = 131072;

#[derive(Clone, Serialize, Deserialize)]
pub struct NvState {
    pub region: Vec<u8>,
    pub is_init: bool,
}

impl NvState {
    pub fn new(size: usize) -> NvState {
        NvState {
            region: vec![0; size],
            is_init: false,
        }
    }
}

#[derive(Debug)]
/// An error that can occur when working with non-volatile memory.
pub enum NvError {
    /// The non-volatile memory is already initialized.
    AlreadyInitialized,
    /// The size of the blob does not match the expected size.
    MismatchedBlobSize,
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

#[expect(dead_code)]
enum NvAvailability {
    Available = 0,
    WriteFailure = 1,
    RateLimit = 2,
}

impl MsTpm185PlatformImpl {
    pub fn nv_enable_from_blob(&mut self, blob: &[u8]) -> Result<(), Error> {
        if self.state.nvmem.is_init {
            return Err(NvError::AlreadyInitialized.into());
        }

        if blob.len() > NV_MEMORY_SIZE {
            return Err(NvError::MismatchedBlobSize.into());
        }

        self.state.nvmem.region = blob.to_vec();
        self.state.nvmem.is_init = true;

        Ok(())
    }
}

impl MsTpm185PlatformImpl {
    pub fn nv_enable(&mut self) -> Result<(), Error> {
        if !self.state.nvmem.is_init {
            tracing::debug!("calling __plat_NvEnable before `nv_enable_from_blob` was called");
            self.state.nvmem.region = vec![0; self.nv_size()];
            self.state.nvmem.is_init = true;
        }

        Ok(())
    }

    pub fn nv_disable(&mut self, delete: bool) {
        // `delete` is only ever used by the simulator code.
        assert_eq!(delete, false);
        self.state.nvmem.is_init = false;
    }

    fn is_nv_available(&mut self) -> NvAvailability {
        NvAvailability::Available
    }

    fn nv_memory_read(&mut self, start_offset: usize, buf: &mut [u8]) -> Result<(), Error> {
        match self
            .state
            .nvmem
            .region
            .get(start_offset..(start_offset + buf.len()))
        {
            Some(region) => buf.copy_from_slice(region),
            None => {
                buf.fill(0);
                return Err(NvError::InvalidAccess {
                    start_offset,
                    len: buf.len(),
                }
                .into());
            }
        }

        Ok(())
    }

    fn nv_is_different(&mut self, start_offset: usize, buf: &[u8]) -> Result<bool, Error> {
        let is_different = match self
            .state
            .nvmem
            .region
            .get_mut(start_offset..(start_offset + buf.len()))
        {
            Some(region) => region != buf,
            None => {
                return Err(NvError::InvalidAccess {
                    start_offset,
                    len: buf.len(),
                }
                .into());
            }
        };

        Ok(is_different)
    }

    fn nv_memory_write(&mut self, start_offset: usize, buf: &[u8]) -> Result<(), Error> {
        match self
            .state
            .nvmem
            .region
            .get_mut(start_offset..(start_offset + buf.len()))
        {
            Some(region) => region.copy_from_slice(buf),
            None => {
                return Err(NvError::InvalidAccess {
                    start_offset,
                    len: buf.len(),
                }
                .into());
            }
        }

        Ok(())
    }

    fn nv_memory_clear(&mut self, start: usize, size: usize) -> Result<(), Error> {
        match self.state.nvmem.region.get_mut(start..(start + size)) {
            Some(region) => region.fill(0),
            None => {
                return Err(NvError::InvalidAccess {
                    start_offset: start,
                    len: size,
                }
                .into());
            }
        }

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

    fn nv_size(&self) -> usize {
        self.state.nvmem.region.len()
    }
}

mod c_api {
    use core::ffi::c_void;

    // NOTE: The commented out functions are only ever called from the simulator,
    // and as such, they really shouldn't have been specified as part of the the
    // platform interface...

    // #[unsafe(no_mangle)]
    // pub unsafe extern "C" fn _plat__NvErrors(
    //     recoverable: i32,
    //     unrecoverable: i32
    // ) {
    //      platform!().nv_errors(recoverable != 0, unrecoverable != 0)
    // }

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace", ret)]
    pub unsafe extern "C" fn _plat__NVEnable(plat_parameter: *mut c_void) -> i32 {
        match platform!().nv_enable() {
            Ok(()) => 0,
            Err(e) => {
                tracing::error!("error calling _plat__NVEnable({:?}): {}", plat_parameter, e);
                -1 // TODO: assign different error IDs to each error variant?
            }
        }
    }

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace", ret)]
    pub unsafe extern "C" fn _plat__GetNvReadyState() -> i32 {
        // v1.85 renamed _plat__IsNvAvailable -> _plat__GetNvReadyState.
        // Return values are unchanged: 0 = NV_READY, 1 = NV_WRITEFAILURE,
        // 2 = NV_RATE_LIMIT.
        platform!().is_nv_available() as i32
    }

    // NOTE: Why doesn't NvMemoryRead return a bool like NvMemoryWrite??
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace", ret)]
    pub unsafe extern "C" fn _plat__NvMemoryRead(start_offset: u32, size: u32, data: *mut c_void) {
        assert!(!data.is_null());

        // SAFETY: caller ensures `data` and `size` are valid
        let buf = unsafe { core::slice::from_raw_parts_mut(data.cast(), size as usize) };

        match platform!().nv_memory_read(start_offset as usize, buf) {
            Ok(()) => {}
            Err(e) => {
                tracing::error!(
                    "error calling _plat__NvMemoryRead(start_offset: {:#x?}, size: {:#x?}, data: {:?}): {}",
                    start_offset,
                    size,
                    data,
                    e
                );
            }
        }
    }

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace", ret)]
    pub unsafe extern "C" fn _plat__NvGetChangedStatus(
        start_offset: u32,
        size: u32,
        data: *mut c_void,
    ) -> i32 {
        // v1.85 renamed _plat__NvIsDifferent -> _plat__NvGetChangedStatus and
        // added a third return value:
        //   NV_HAS_CHANGED      ( 1) the NV location differs from the test value
        //   NV_IS_SAME          ( 0) the NV location matches the test value
        //   NV_INVALID_LOCATION (-1) the NV location is invalid (triggers failure mode)
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

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace", ret)]
    pub unsafe extern "C" fn _plat__NvMemoryWrite(
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

    // NOTE: Why doesn't NvMemoryClear return a bool??
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace", ret)]
    pub unsafe extern "C" fn _plat__NvMemoryClear(start: u32, size: u32) {
        match platform!().nv_memory_clear(start as usize, size as usize) {
            Ok(()) => {}
            Err(e) => {
                tracing::error!(
                    "error calling _plat__NvMemoryClear(start: {:#x?}, size: {:#x?}): {}",
                    start,
                    size,
                    e
                );
            }
        }
    }

    // NOTE: Why doesn't NvMemoryClear return a bool??
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace", ret)]
    pub unsafe extern "C" fn _plat__NvMemoryMove(source_offset: u32, dest_offset: u32, size: u32) {
        match platform!().nv_memory_move(
            source_offset as usize,
            dest_offset as usize,
            size as usize,
        ) {
            Ok(()) => {}
            Err(e) => {
                tracing::error!(
                    "error calling _plat__NvMemoryMove(source_offset: {:#x?}, dest_offset: {:#x?}, size: {:#x?}): {}",
                    source_offset,
                    dest_offset,
                    size,
                    e
                );
            }
        }
    }

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace", ret)]
    pub unsafe extern "C" fn _plat__NvCommit() -> i32 {
        match platform!().nv_commit() {
            Ok(()) => 0,
            Err(e) => {
                tracing::error!("error calling _plat__NvCommit(): {}", e);
                1
            }
        }
    }
}

// Copyright (C) Microsoft Corporation. All rights reserved.

//! Entropy.c

use serde::Deserialize;
use serde::Serialize;

use crate::error::Error;

use super::super::MsTpm185PlatformImpl;

// FIPS 140-2 section 4.9.2 requires the first 4-byte block to be discarded and
// each subsequent block to differ from its predecessor.
const ENTROPY_BLOCK_SIZE: usize = size_of::<u32>();

#[derive(Clone, Serialize, Deserialize)]
pub struct EntropyState {
    previous_block: Option<[u8; ENTROPY_BLOCK_SIZE]>,
}

impl EntropyState {
    pub fn new() -> EntropyState {
        EntropyState {
            previous_block: None,
        }
    }
}

impl MsTpm185PlatformImpl {
    fn read_entropy_block(&mut self) -> Result<[u8; ENTROPY_BLOCK_SIZE], Error> {
        let mut block = [0; ENTROPY_BLOCK_SIZE];
        let mut written = 0;

        while written < block.len() {
            let remaining = &mut block[written..];
            let requested = remaining.len();
            let returned = self
                .callbacks
                .get_crypt_random(remaining)
                .map_err(Error::PlatformCallback)?;

            if returned == 0 || returned > requested {
                return Err(Error::InvalidEntropyCallbackLength {
                    requested,
                    returned,
                });
            }

            written += returned;
        }

        Ok(block)
    }

    fn initialize_entropy(&mut self) -> Result<(), Error> {
        self.state.entropy.previous_block = Some(self.read_entropy_block()?);
        Ok(())
    }

    /// Only provides entropy up to 32 bits at a time to match the reference platform.
    fn get_entropy(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        assert!(self.state.entropy.previous_block.is_some());

        let block = self.read_entropy_block()?;
        if self.state.entropy.previous_block == Some(block) {
            return Err(Error::EntropyHealthTestFailed);
        }

        self.state.entropy.previous_block = Some(block);
        let returned = buf.len().min(block.len());
        buf[..returned].copy_from_slice(&block[..returned]);
        Ok(returned)
    }
}

mod c_api {
    #[unsafe(export_name = "ms_tcg_tpm_185__plat__GetEntropy")]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn plat_get_entropy(entropy: *mut u8, amount: u32) -> i32 {
        // The TPM core library uses a zero-length call to initialize the source.
        // Capture and discard the first block for the continuous RNG test.
        if amount == 0 {
            match platform!().initialize_entropy() {
                Ok(()) => 0,
                Err(e) => {
                    tracing::error!("error initializing entropy source: {}", e);
                    -1
                }
            }
        } else {
            // SAFETY: Caller guarantees `entropy` and `amount` are valid and matching.
            let buf = unsafe { core::slice::from_raw_parts_mut(entropy, amount as usize) };

            match platform!().get_entropy(buf) {
                Ok(len) => len as i32,
                Err(e) => {
                    tracing::error!(
                        "error calling _plat__GetEntropy(entropy: {:#x?}, amount: {:#x?}): {}",
                        entropy,
                        amount,
                        e
                    );
                    -1
                }
            }
        }
    }
}

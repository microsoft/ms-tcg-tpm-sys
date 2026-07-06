// Copyright (C) Microsoft Corporation. All rights reserved.

//! Entropy.c

// TODO FIPS: FIPS 140-2, annex C:
//
// "If each call to an RNG produces blocks of n bits (where n > 15), the first
// n-bit block generated after power-up, initialization, or reset shall not be
// used, but shall be saved for comparison with the next n-bit block to be
// generated. Each subsequent generation of an n-bit block shall be compared with
// the previously generated block. The test shall fail if any two compared n-bit
// blocks are equal."

use crate::error::Error;

use super::super::MsTpm184PlatformImpl;

impl MsTpm184PlatformImpl {
    fn get_entropy(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.callbacks
            .get_crypt_random(buf)
            .map_err(Error::PlatformCallback)
    }
}

mod c_api {
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__GetEntropy(entropy: *mut u8, amount: u32) -> i32 {
        // The TPM core library calls _plat__GetEntropy(NULL, 0) as a
        // "seed the entropy source" probe. In that case `entropy` is
        // legitimately NULL — return 0 (no bytes produced) without trying to
        // dereference the buffer.
        if entropy.is_null() || amount == 0 {
            return 0;
        }

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

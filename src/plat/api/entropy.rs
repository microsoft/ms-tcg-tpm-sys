// Copyright (C) Microsoft Corporation. All rights reserved.

//! Entropy.c

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
        if amount == 0 {
            return 0;
        }

        assert!(!entropy.is_null());

        // SAFETY: Caller guarantees `entropy` and `amount` are valid.
        let buf = unsafe { core::slice::from_raw_parts_mut(entropy, amount as usize) };

        match platform!().get_entropy(buf) {
            Ok(len) => len as i32,
            Err(e) => {
                tracing::error!(
                    "error calling _plat__GetEntropy(entropy: {:?}, amount: {:#x?}): {}",
                    entropy,
                    amount,
                    e
                );
                -1
            }
        }
    }
}

// Copyright (C) Microsoft Corporation. All rights reserved.

//! PlatformPcr.c
//!
//! PCR initialization attributes and default-active banks.
//!
//! This implementation matches the PC Client TPM Profile Specification (the
//! same layout used by the upstream reference platform): 24 PCRs, with PCR
//! 17..22 reset/extend locality-restricted (DRTM territory) and PCRs 16 and
//! 23 reset-allowed.
//!
//! The default active banks are SHA-256 and SHA-384, matching the Hyper-V /
//! OpenVMM vTPM defaults and the algorithms enabled in
//! `overrides/src/TpmConfiguration/TpmConfiguration/TpmProfile_Common.h`.

/// Mirror of `PCR_Attributes` from `pcrstruct.h`. The C definition is a
/// bitfield in a single `unsigned int`; GCC packs LSB-first into one 4-byte
/// unit. We expose it as a `#[repr(transparent)]` wrapper around `u32` so the
/// ABI matches a small struct returned by-value.
#[repr(transparent)]
struct PcrAttributes(u32);

impl PcrAttributes {
    /// Build a `PCR_Attributes` from the same field meanings as the C struct.
    ///
    /// Bit layout (LSB-first):
    /// - bit  0    : `stateSave` (1 bit)
    /// - bit  1    : `doNotIncrementPcrCounter` (1 bit)
    /// - bits 2..4 : `policyAuthGroup` (3 bits, MAX_PCR_GROUP_BITS)
    /// - bits 5..7 : `authValuesGroup` (3 bits)
    /// - bits 8..12: `resetLocality` (5 bits, low bit = locality 0)
    /// - bits 13..17: `extendLocality` (5 bits)
    const fn new(
        state_save: u32,
        do_not_increment: u32,
        policy_auth_group: u32,
        auth_values_group: u32,
        reset_locality: u32,
        extend_locality: u32,
    ) -> Self {
        PcrAttributes(
            (state_save & 0x1)
                | ((do_not_increment & 0x1) << 1)
                | ((policy_auth_group & 0x7) << 2)
                | ((auth_values_group & 0x7) << 5)
                | ((reset_locality & 0x1F) << 8)
                | ((extend_locality & 0x1F) << 13),
        )
    }
}

// TPM_ALG_ID = UINT16.
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_SHA384: u16 = 0x000C;

// Number of PCRs the platform implements. Must equal IMPLEMENTATION_PCR in
// TpmProfile_Misc.h (24).
const NUM_PCRS: u32 = 24;

// HCRTM_PCR from TpmProfile_Misc.h.
const HCRTM_PCR: u32 = 0;

// PCR attribute table mirroring `PlatformPcr.c::s_initAttributes`.
// (state_save, do_not_increment, policy_auth_grp, auth_values_grp,
//  reset_locality_bits, extend_locality_bits)
const INIT_ATTRIBUTES: [PcrAttributes; NUM_PCRS as usize] = [
    // PCR 0..15: static RTM, saved, all-locality extend, no reset.
    PcrAttributes::new(1, 0, 0, 0, 0, 0x1F),
    PcrAttributes::new(1, 0, 0, 0, 0, 0x1F),
    PcrAttributes::new(1, 0, 0, 0, 0, 0x1F),
    PcrAttributes::new(1, 0, 0, 0, 0, 0x1F),
    PcrAttributes::new(1, 0, 0, 0, 0, 0x1F),
    PcrAttributes::new(1, 0, 0, 0, 0, 0x1F),
    PcrAttributes::new(1, 0, 0, 0, 0, 0x1F),
    PcrAttributes::new(1, 0, 0, 0, 0, 0x1F),
    PcrAttributes::new(1, 0, 0, 0, 0, 0x1F),
    PcrAttributes::new(1, 0, 0, 0, 0, 0x1F),
    PcrAttributes::new(1, 0, 0, 0, 0, 0x1F),
    PcrAttributes::new(1, 0, 0, 0, 0, 0x1F),
    PcrAttributes::new(1, 0, 0, 0, 0, 0x1F),
    PcrAttributes::new(1, 0, 0, 0, 0, 0x1F),
    PcrAttributes::new(1, 0, 0, 0, 0, 0x1F),
    PcrAttributes::new(1, 0, 0, 0, 0, 0x1F),
    // PCR 16: debug, reset allowed, extend all.
    PcrAttributes::new(0, 0, 0, 0, 0x0F, 0x1F),
    // PCR 17: DRTM locality 4, extend localities 2+.
    PcrAttributes::new(0, 0, 0, 0, 0x10, 0x1C),
    // PCR 18: locality 3, extend localities 2+.
    PcrAttributes::new(0, 0, 0, 0, 0x10, 0x1C),
    // PCR 19: locality 2, extend localities 2..3.
    PcrAttributes::new(0, 0, 0, 0, 0x10, 0x0C),
    // PCR 20..22: support doNotIncrement, policyAuth, authValue (group 1).
    PcrAttributes::new(0, 1, 1, 1, 0x14, 0x0E),
    PcrAttributes::new(0, 1, 1, 1, 0x14, 0x04),
    PcrAttributes::new(0, 1, 1, 1, 0x14, 0x04),
    // PCR 23: app-specific, reset allowed, extend all.
    PcrAttributes::new(0, 0, 0, 0, 0x0F, 0x1F),
];

// Banks active by default in a freshly manufactured TPM.
const DEFAULT_ACTIVE_PCR_BANKS: &[u16] = &[TPM_ALG_SHA256, TPM_ALG_SHA384];

fn digest_size(alg: u16) -> u16 {
    match alg {
        TPM_ALG_SHA256 => 32,
        TPM_ALG_SHA384 => 48,
        _ => 0,
    }
}

mod c_api {
    use super::*;

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _platPcr__NumberOfPcrs() -> u32 {
        NUM_PCRS
    }

    /// Returns the bitfield-packed `PCR_Attributes` for `pcr_number`. Out-of-
    /// range inputs return PCR 0's attributes (matches upstream behavior).
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _platPcr__GetPcrInitializationAttributes(pcr_number: u32) -> u32 {
        let idx = if pcr_number >= NUM_PCRS {
            0
        } else {
            pcr_number as usize
        };
        INIT_ATTRIBUTES[idx].0
    }

    /// True if `pcr_alg` should default to active in a new TPM.
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _platPcr_IsPcrBankDefaultActive(pcr_alg: u16) -> i32 {
        // BOOL = int.
        DEFAULT_ACTIVE_PCR_BANKS.contains(&pcr_alg) as i32
    }

    /// Fill a PCR with its initialization value. PCRs whose reset locality
    /// includes locality 4 (i.e. DRTM PCRs) initialize to 0xFF; all others
    /// initialize to 0x00. PCR `HCRTM_PCR` has its last byte set to the
    /// startup locality.
    ///
    /// Returns:
    /// - `TPM_RC_SUCCESS` (0) on success
    /// - `TPM_RC_PCR` (0x127) if the platform has no value for this PCR
    /// - `TPM_RC_FAILURE` (0x101) if the buffer is too small
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _platPcr__GetInitialValueForPcr(
        pcr_number: u32,
        pcr_alg: u16,
        startup_locality: u8,
        pcr_buffer: *mut u8,
        buffer_size: u16,
        pcr_length: *mut u16,
    ) -> u32 {
        const TPM_RC_SUCCESS: u32 = 0x000;
        const TPM_RC_PCR: u32 = 0x127; // RC_VER1 + 0x027
        const TPM_RC_FAILURE: u32 = 0x101; // RC_VER1 + 0x001

        if pcr_number >= NUM_PCRS || pcr_buffer.is_null() || pcr_length.is_null() {
            return TPM_RC_FAILURE;
        }

        let pcr_size = digest_size(pcr_alg);
        if pcr_size == 0 {
            return TPM_RC_PCR;
        }
        if buffer_size < pcr_size {
            return TPM_RC_FAILURE;
        }

        let attrs = INIT_ATTRIBUTES[pcr_number as usize].0;
        // resetLocality occupies bits 8..12; its high bit (bit 12, value 0x10)
        // marks a DRTM PCR that initializes to all 0xFF.
        let reset_locality = (attrs >> 8) & 0x1F;
        let default_byte: u8 = if (reset_locality & 0x10) != 0 {
            0xFF
        } else {
            0x00
        };

        // SAFETY: caller asserts `pcr_buffer` points to at least `buffer_size`
        // (>= pcr_size) writable bytes.
        unsafe {
            core::ptr::write_bytes(pcr_buffer, default_byte, pcr_size as usize);

            if pcr_number == HCRTM_PCR {
                *pcr_buffer.add((pcr_size - 1) as usize) = startup_locality;
            }

            *pcr_length = pcr_size;
        }

        TPM_RC_SUCCESS
    }
}

// Copyright (C) Microsoft Corporation. All rights reserved.

//! PlatformPcr.c
//!
//! PCR initialization attributes and default-active banks.
//!
//! This implementation matches the PC Client TPM Profile Specification (the
//! same layout used by the upstream reference platform).
//!
//! The default active banks are SHA-256 and SHA-384, matching the Hyper-V /
//! OpenVMM vTPM defaults and the algorithms enabled in
//! `overrides/src/TpmConfiguration/TpmConfiguration/TpmProfile_Common.h`.

/// Mirror of `PCR_Attributes` from `pcrstruct.h`.
#[bitfield_struct::bitfield(u32)]
struct PcrAttributes {
    state_save: bool,
    do_not_increment_pcr_counter: bool,
    #[bits(3)]
    policy_auth_group: u8,
    #[bits(3)]
    auth_values_group: u8,
    #[bits(5)]
    reset_locality: u8,
    #[bits(5)]
    extend_locality: u8,
    #[bits(14)]
    __: u16,
}

impl PcrAttributes {
    const fn with(
        state_save: bool,
        do_not_increment_pcr_counter: bool,
        policy_auth_group: u8,
        auth_values_group: u8,
        reset_locality: u8,
        extend_locality: u8,
    ) -> Self {
        PcrAttributes::new()
            .with_state_save(state_save)
            .with_do_not_increment_pcr_counter(do_not_increment_pcr_counter)
            .with_policy_auth_group(policy_auth_group)
            .with_auth_values_group(auth_values_group)
            .with_reset_locality(reset_locality)
            .with_extend_locality(extend_locality)
    }
}

// Number of PCRs the platform implements. Must equal IMPLEMENTATION_PCR in
// TpmProfile_Misc.h.
const NUM_PCRS: u32 = 24;

// PCR attribute table mirroring `PlatformPcr.c::s_initAttributes`.
const INIT_ATTRIBUTES: [PcrAttributes; NUM_PCRS as usize] = [
    // PCR 0..15: static RTM, saved, all-locality extend, no reset.
    PcrAttributes::with(true, false, 0, 0, 0, 0x1F),
    PcrAttributes::with(true, false, 0, 0, 0, 0x1F),
    PcrAttributes::with(true, false, 0, 0, 0, 0x1F),
    PcrAttributes::with(true, false, 0, 0, 0, 0x1F),
    PcrAttributes::with(true, false, 0, 0, 0, 0x1F),
    PcrAttributes::with(true, false, 0, 0, 0, 0x1F),
    PcrAttributes::with(true, false, 0, 0, 0, 0x1F),
    PcrAttributes::with(true, false, 0, 0, 0, 0x1F),
    PcrAttributes::with(true, false, 0, 0, 0, 0x1F),
    PcrAttributes::with(true, false, 0, 0, 0, 0x1F),
    PcrAttributes::with(true, false, 0, 0, 0, 0x1F),
    PcrAttributes::with(true, false, 0, 0, 0, 0x1F),
    PcrAttributes::with(true, false, 0, 0, 0, 0x1F),
    PcrAttributes::with(true, false, 0, 0, 0, 0x1F),
    PcrAttributes::with(true, false, 0, 0, 0, 0x1F),
    PcrAttributes::with(true, false, 0, 0, 0, 0x1F),
    // PCR 16, Debug, reset allowed, extend all
    PcrAttributes::with(false, false, 0, 0, 0x0F, 0x1F),
    // PCR 17, Locality 4, extend loc 2+
    PcrAttributes::with(false, false, 0, 0, 0x10, 0x1C),
    // PCR 18, Locality 3, extend loc 2+
    PcrAttributes::with(false, false, 0, 0, 0x10, 0x1C),
    // PCR 19, Locality 2, extend loc 2, 3
    PcrAttributes::with(false, false, 0, 0, 0x10, 0x0C),
    // PCR 20, Locality 1, extend loc 1, 2, 3
    PcrAttributes::with(false, true, 1, 1, 0x14, 0x0E),
    // PCR 21, Dynamic OS, extend loc 2
    PcrAttributes::with(false, true, 1, 1, 0x14, 0x04),
    // PCR 22, Dynamic OS, extend loc 2
    PcrAttributes::with(false, true, 1, 1, 0x14, 0x04),
    // PCR 23, reset allowed, App specific, extend all
    PcrAttributes::with(false, false, 0, 0, 0x0F, 0x1F),
];

// TPM_ALG_* from TpmTypes.h
const TPM_ALG_SHA1: u16 = 0x0004;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_SHA384: u16 = 0x000C;
const TPM_ALG_SHA512: u16 = 0x000D;

// DefaultActivePcrBanks from PlatformPcr.c, selected by TpmProfile_Common.h.
// SHA-1 is enabled by default here for UEFI compatibility. Note: the upstream reference platform defaults exclude SHA-1.
const DEFAULT_ACTIVE_PCR_BANKS: &[u16] = &[TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384];

// Digest sizes from TpmAlgorithmDefines.h for all enabled PCR hash algorithms.
const fn digest_size(alg: u16) -> Option<u16> {
    match alg {
        TPM_ALG_SHA1 => Some(20),
        TPM_ALG_SHA256 => Some(32),
        TPM_ALG_SHA384 => Some(48),
        TPM_ALG_SHA512 => Some(64),
        _ => None,
    }
}

mod c_api {
    use super::*;

    #[unsafe(export_name = "ms_tcg_tpm_185__platPcr__NumberOfPcrs")]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn plat_pcr_number_of_pcrs() -> u32 {
        NUM_PCRS
    }

    /// Returns the bitfield-packed `PCR_Attributes` for `pcr_number`. Out-of-
    /// range inputs return PCR 0's attributes (matches upstream behavior).
    #[unsafe(export_name = "ms_tcg_tpm_185__platPcr__GetPcrInitializationAttributes")]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn plat_pcr_get_pcr_initialization_attributes(pcr_number: u32) -> u32 {
        let idx = if pcr_number >= NUM_PCRS {
            0
        } else {
            pcr_number as usize
        };
        INIT_ATTRIBUTES[idx].into()
    }

    /// True if `pcr_alg` should default to active in a new TPM.
    #[unsafe(export_name = "ms_tcg_tpm_185__platPcr_IsPcrBankDefaultActive")]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn plat_pcr_is_pcr_bank_default_active(pcr_alg: u16) -> i32 {
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
    #[unsafe(export_name = "ms_tcg_tpm_185__platPcr__GetInitialValueForPcr")]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn plat_pcr_get_initial_value_for_pcr(
        pcr_number: u32,
        pcr_alg: u16,
        startup_locality: u8,
        pcr_buffer: *mut u8,
        buffer_size: u16,
        pcr_length: *mut u16,
    ) -> u32 {
        // TPM_RC_SUCCESS from TpmTypes.h.
        const TPM_RC_SUCCESS: u32 = 0x000;
        // TPM_RC_PCR from TpmTypes.h (RC_VER1 + 0x027).
        const TPM_RC_PCR: u32 = 0x127;
        // TPM_RC_FAILURE from TpmTypes.h (RC_VER1 + 0x001).
        const TPM_RC_FAILURE: u32 = 0x101;

        // HCRTM_PCR from TpmProfile_Misc.h.
        const HCRTM_PCR: u32 = 0;

        if pcr_number >= NUM_PCRS || pcr_buffer.is_null() || pcr_length.is_null() {
            return TPM_RC_FAILURE;
        }

        let pcr_size = digest_size(pcr_alg);
        let Some(pcr_size) = pcr_size else {
            // SAFETY: caller asserts `pcr_length` is a valid pointer.
            unsafe {
                *pcr_length = 0;
            }
            return TPM_RC_PCR;
        };
        if buffer_size < pcr_size {
            return TPM_RC_FAILURE;
        }

        let default_byte: u8 =
            if (INIT_ATTRIBUTES[pcr_number as usize].reset_locality() & 0x10) != 0 {
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

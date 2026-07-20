// Copyright (C) Microsoft Corporation. All rights reserved.

//! VendorInfo.c
//!
//! Vendor- and platform-identifying constants reported through GetCapability.
//! The TPM core library always invokes these, even in failure mode, so the
//! values must be compile-time-stable.

// 4-char ASCII codes packed big-endian, as expected by `_plat__Get*CapabilityCode`.
const fn ascii4(s: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*s)
}

// Vendor identity. Matches the legacy ms-tpm-20-ref-rs values.
const MANUFACTURER: u32 = ascii4(b"MSFT");
const VENDOR_STRING_1: u32 = ascii4(b"TPM ");
const VENDOR_STRING_2: u32 = ascii4(b"Simu");
const VENDOR_STRING_3: u32 = ascii4(b"lato");
const VENDOR_STRING_4: u32 = ascii4(b"r   ");

// Firmware version. Same as ms-tpm-20-ref-rs.
// TODO: Should we change these?
const FIRMWARE_V1: u32 = 0x20200312;
const FIRMWARE_V2: u32 = 0x00120003;

// Vendor TPM type. Matches the reference code's historical return value.
const VENDOR_TPM_TYPE: u32 = 1;

/// Mirror of the C `SPEC_CAPABILITY_VALUE` struct in
/// `tpm_to_platform_interface.h`.
#[repr(C)]
struct SpecCapabilityValue {
    tpm_spec_level: u32,
    tpm_spec_version: u32,
    tpm_spec_errata: u32,

    platform_family: u32,
    platform_level: u32,
    platform_revision: u32,
    platform_year: u32,
    platform_day_of_year: u32,
}

mod c_api {
    use super::SpecCapabilityValue;

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__GetManufacturerCapabilityCode() -> u32 {
        super::MANUFACTURER
    }

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__GetVendorCapabilityCode(index: i32) -> u32 {
        match index {
            1 => super::VENDOR_STRING_1,
            2 => super::VENDOR_STRING_2,
            3 => super::VENDOR_STRING_3,
            4 => super::VENDOR_STRING_4,
            _ => 0,
        }
    }

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__GetTpmFirmwareVersionHigh() -> u32 {
        super::FIRMWARE_V1
    }

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__GetTpmFirmwareVersionLow() -> u32 {
        super::FIRMWARE_V2
    }

    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__GetVendorTpmType() -> u32 {
        super::VENDOR_TPM_TYPE
    }

    /// Current TPM firmware SVN. We do not implement SVN-limited objects
    /// (`SVN_LIMITED_SUPPORT NO` in TpmProfile_Common.h), but the core
    /// library still queries this.
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__GetTpmFirmwareSvn() -> u16 {
        0
    }

    /// Maximum SVN value the firmware can ever report.
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__GetTpmFirmwareMaxSvn() -> u16 {
        0
    }

    /// Provide platform-supplied bytes for the persistent-data area during
    /// manufacture / Clear. The reference implementation fills with 0xFF; we
    /// have no platform-side data to inject, so we mirror that.
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat__GetPlatformManufactureData(
        platform_persistent_data: *mut u8,
        buffer_size: u32,
    ) {
        if buffer_size == 0 || platform_persistent_data.is_null() {
            return;
        }
        // SAFETY: caller asserts `platform_persistent_data` points to at least
        // `buffer_size` writable bytes.
        unsafe {
            core::ptr::write_bytes(platform_persistent_data, 0xFF, buffer_size as usize);
        }
    }

    /// Fill in the spec-version capability struct (`SPEC_CAPABILITY_VALUE`).
    /// Values mirror what the upstream reference platform reports for v1.85.
    #[unsafe(no_mangle)]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn _plat_GetSpecCapabilityValue(return_data: *mut SpecCapabilityValue) {
        if return_data.is_null() {
            return;
        }
        // SAFETY: caller asserts `return_data` is a valid, writable pointer.
        unsafe {
            *return_data = SpecCapabilityValue {
                // From part 1 of the TPM spec.
                tpm_spec_level: 0,
                // From part 2 of the TPM spec (v1.85, 2025-03-20).
                tpm_spec_version: 185,
                tpm_spec_errata: 0,
                // From the PC Client Platform TPM Profile Specification.
                platform_family: 1,
                platform_level: 0,
                // Matching the reference library
                platform_revision: 0x107,
                platform_year: 0,
                platform_day_of_year: 0,
            };
        }
    }
}

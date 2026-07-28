// Copyright (C) Microsoft Corporation. All rights reserved.

//! PPPlat.c

// TODO: model physical presence using `PlatformCallbacks`?

mod c_api {
    #[unsafe(export_name = "ms_tcg_tpm_185__plat__PhysicalPresenceAsserted")]
    #[tracing::instrument(level = "trace")]
    pub unsafe extern "C" fn plat_physical_presence_asserted() -> i32 {
        false as i32
    }
}
